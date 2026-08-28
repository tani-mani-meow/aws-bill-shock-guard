"""Command-line interface (CLI) for Bill Shock Guard.

Provides:
  - bsg scan: Read-only scan of AWS resources for idle charges.
  - bsg doctor: Verifies credentials and lists read API permissions per region.
  - bsg explain: Explains idle rules, default thresholds, and proposed actions.
  - bsg version: Displays version string.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Callable, Sequence
from datetime import date, datetime, timezone
from typing import Any

import boto3
import botocore.config
import botocore.exceptions

from bill_shock_guard.aws import get_boto_client, get_enabled_regions
from bill_shock_guard.clock import SystemClock
from bill_shock_guard.config import Config, Thresholds, load_config_from_file
from bill_shock_guard.detectors.registry import discover
from bill_shock_guard.interfaces import Detector, ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import ActionKind, Finding, ResourceType
from bill_shock_guard.pricing import PRICE_TABLE_DATE

try:
    from importlib.metadata import version as _pkg_version

    VERSION = _pkg_version("bill-shock-guard")
except Exception:
    VERSION = "0.1.0"


_RESOURCE_TYPE_ALIASES: dict[str, ResourceType] = {
    "ec2": ResourceType.EC2_INSTANCE,
    "ec2-instance": ResourceType.EC2_INSTANCE,
    "ec2_instance": ResourceType.EC2_INSTANCE,
    "eip": ResourceType.ELASTIC_IP,
    "elastic-ip": ResourceType.ELASTIC_IP,
    "elastic_ip": ResourceType.ELASTIC_IP,
    "nat": ResourceType.NAT_GATEWAY,
    "nat-gateway": ResourceType.NAT_GATEWAY,
    "nat_gateway": ResourceType.NAT_GATEWAY,
    "ebs": ResourceType.EBS_VOLUME,
    "ebs-volume": ResourceType.EBS_VOLUME,
    "ebs_volume": ResourceType.EBS_VOLUME,
    "elb": ResourceType.LOAD_BALANCER,
    "alb": ResourceType.LOAD_BALANCER,
    "nlb": ResourceType.LOAD_BALANCER,
    "load-balancer": ResourceType.LOAD_BALANCER,
    "load_balancer": ResourceType.LOAD_BALANCER,
    "rds": ResourceType.RDS_INSTANCE,
    "rds-instance": ResourceType.RDS_INSTANCE,
    "rds_instance": ResourceType.RDS_INSTANCE,
    "sagemaker": ResourceType.SAGEMAKER_NOTEBOOK,
    "sagemaker-notebook": ResourceType.SAGEMAKER_NOTEBOOK,
    "sagemaker_notebook": ResourceType.SAGEMAKER_NOTEBOOK,
}


@dataclasses.dataclass(frozen=True)
class ResourceExplanation:
    """Detailed explanation of detection criteria and action defaults for a resource type."""

    resource_type: ResourceType
    idle_rule: str
    default_thresholds: dict[str, Any]
    proposed_action: ActionKind
    is_enabled_by_default: bool


def get_explanation(resource_type: ResourceType) -> ResourceExplanation:
    """Read idle rule, default thresholds, and proposed actions directly from code constants."""
    t = Thresholds()
    cfg = Config()

    catalog: dict[ResourceType, tuple[str, dict[str, Any], ActionKind]] = {
        ResourceType.EC2_INSTANCE: (
            f"Running EC2 instance with average CPU utilization < {t.ec2_idle_cpu_avg_pct}% "
            f"and average network transfer < {t.ec2_idle_network_avg_bytes_per_sec} bytes/sec "
            f"over the last {t.ec2_idle_window_hours} hours. Excludes instances managed by "
            f"Auto Scaling groups, EKS, Elastic Beanstalk, or Spot.",
            {
                "ec2_idle_window_hours": t.ec2_idle_window_hours,
                "ec2_idle_cpu_avg_pct": t.ec2_idle_cpu_avg_pct,
                "ec2_idle_network_avg_bytes_per_sec": t.ec2_idle_network_avg_bytes_per_sec,
            },
            ActionKind.EC2_STOP,
        ),
        ResourceType.ELASTIC_IP: (
            "Allocated Elastic IP address with no association to an EC2 instance or "
            "network interface (ENI).",
            {
                "unassociated": True,
            },
            ActionKind.EIP_RELEASE,
        ),
        ResourceType.NAT_GATEWAY: (
            f"Available NAT Gateway with 0 BytesOutToDestination metric datapoints "
            f"over the last {t.nat_idle_window_hours} hours.",
            {
                "nat_idle_window_hours": t.nat_idle_window_hours,
            },
            ActionKind.NAT_DELETE,
        ),
        ResourceType.EBS_VOLUME: (
            f"EBS volume in 'available' state with no attachments for longer than "
            f"{t.ebs_unattached_days} days. Proposed action takes a tagged snapshot, waits "
            f"for completion, and only then deletes the volume.",
            {
                "ebs_unattached_days": t.ebs_unattached_days,
            },
            ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        ),
        ResourceType.LOAD_BALANCER: (
            f"Active Application Load Balancer with 0 RequestCount or Network Load Balancer "
            f"with 0 NewFlowCount over {t.elb_idle_window_hours} hours, or any load balancer "
            f"with 0 registered targets across associated target groups.",
            {
                "elb_idle_window_hours": t.elb_idle_window_hours,
            },
            ActionKind.ELB_DELETE,
        ),
        ResourceType.RDS_INSTANCE: (
            f"Standalone Amazon RDS database instance in 'available' state with 0 database "
            f"connections over the last {t.rds_idle_window_hours} hours. Excludes Aurora clusters, "
            f"read replicas, and SQL Server Multi-AZ.",
            {
                "rds_idle_window_hours": t.rds_idle_window_hours,
            },
            ActionKind.RDS_STOP,
        ),
        ResourceType.SAGEMAKER_NOTEBOOK: (
            "SageMaker notebook instance in 'InService' state without active executions.",
            {},
            ActionKind.SM_NOTEBOOK_STOP,
        ),
    }

    rule, thresholds, action = catalog[resource_type]
    return ResourceExplanation(
        resource_type=resource_type,
        idle_rule=rule,
        default_thresholds=thresholds,
        proposed_action=action,
        is_enabled_by_default=action in cfg.enabled_actions,
    )


def format_explanation(expl: ResourceExplanation) -> str:
    """Format an explanation into a clean human-readable text block."""
    lines = [
        f"Resource Type: {expl.resource_type.value}",
        f"Idle Rule: {expl.idle_rule}",
        "Default Thresholds:",
    ]
    if expl.default_thresholds:
        for k, v in expl.default_thresholds.items():
            lines.append(f"  - {k}: {v}")
    else:
        lines.append("  - (none)")

    lines.append(f"Proposed Action: {expl.proposed_action.value}")
    lines.append(f"Enabled by Default: {'Yes' if expl.is_enabled_by_default else 'No'}")
    return "\n".join(lines)


def _friendly_credentials_error_message(detail: str) -> str:
    """Format student-oriented guidance for missing or invalid AWS credentials."""
    return (
        f"Error: Unable to locate valid AWS credentials.\n"
        f"Details: {detail}\n\n"
        f"Guidance for students:\n"
        f"To scan your AWS account or check permissions, configure credentials using one of:\n"
        f"  1. Run 'aws configure' in your terminal and enter your AWS credentials.\n"
        f"  2. Or export environment variables in your terminal:\n"
        f'       AWS_ACCESS_KEY_ID="your-access-key-id"\n'
        f'       AWS_SECRET_ACCESS_KEY="your-secret-access-key"\n'
        f'       AWS_DEFAULT_REGION="us-east-1"\n'
        f"  3. Or use an existing AWS profile:\n"
        f'       export AWS_PROFILE="your-profile-name"\n'
    )


def _json_serial_fallback(obj: Any) -> str:
    """Serialize dates, datetimes, and unrecognized objects to ISO strings."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return str(obj)


def run_version() -> int:
    """Execute the version command."""
    sys.stdout.write(f"bill-shock-guard {VERSION}\n")
    return 0


def run_explain(resource_type_str: str) -> int:
    """Execute the explain command."""
    normalized = resource_type_str.strip().lower()
    res_type = _RESOURCE_TYPE_ALIASES.get(normalized)
    if res_type is None:
        try:
            res_type = ResourceType(normalized)
        except ValueError:
            pass

    if res_type is None:
        valid_types = ", ".join(r.value for r in ResourceType)
        sys.stderr.write(
            f"Error: Unknown resource type '{resource_type_str}'.\n"
            f"Valid resource types: {valid_types}\n"
        )
        return 1

    expl = get_explanation(res_type)
    sys.stdout.write(format_explanation(expl) + "\n")
    return 0


def run_doctor(
    regions_arg: str | None = None,
    session: boto3.Session | None = None,
) -> int:
    """Execute the doctor command: checks STS identity and tests read API permissions."""
    sess = session or boto3.Session()

    # Step 1: Verify STS caller identity
    sys.stdout.write("Checking AWS caller identity...\n")
    try:
        sts = get_boto_client("sts", region_name="us-east-1", session=sess)
        identity = sts.get_caller_identity()
    except (
        botocore.exceptions.NoCredentialsError,
        botocore.exceptions.PartialCredentialsError,
        botocore.exceptions.ClientError,
        botocore.exceptions.EndpointConnectionError,
    ) as exc:
        sys.stderr.write(_friendly_credentials_error_message(str(exc)))
        return 1

    account_id = identity.get("Account", "unknown")
    caller_arn = identity.get("Arn", "unknown")
    user_id = identity.get("UserId", "unknown")

    sys.stdout.write("[OK] AWS Credentials verified\n")
    sys.stdout.write(f"  Account ID: {account_id}\n")
    sys.stdout.write(f"  Caller ARN: {caller_arn}\n")
    sys.stdout.write(f"  User ID:    {user_id}\n\n")

    # Step 2: Determine regions to check
    if regions_arg and regions_arg.strip().lower() not in ("all", "*"):
        target_regions = [r.strip() for r in regions_arg.split(",") if r.strip()]
    else:
        target_regions = get_enabled_regions(session=sess, target_regions=["*"])
        if not target_regions:
            target_regions = ["us-east-1"]

    # Limit to checking up to the specified target regions
    sys.stdout.write(f"Checking read API permissions across {len(target_regions)} region(s)...\n\n")

    api_specs: list[tuple[str, str, str, Callable[[str], Any]]] = [
        (
            "ec2",
            "ec2:DescribeInstances",
            "DescribeInstances",
            lambda reg: get_boto_client("ec2", reg, sess).describe_instances(MaxResults=5),
        ),
        (
            "ec2",
            "ec2:DescribeAddresses",
            "DescribeAddresses",
            lambda reg: get_boto_client("ec2", reg, sess).describe_addresses(),
        ),
        (
            "ec2",
            "ec2:DescribeNatGateways",
            "DescribeNatGateways",
            lambda reg: get_boto_client("ec2", reg, sess).describe_nat_gateways(MaxResults=5),
        ),
        (
            "ec2",
            "ec2:DescribeVolumes",
            "DescribeVolumes",
            lambda reg: get_boto_client("ec2", reg, sess).describe_volumes(MaxResults=5),
        ),
        (
            "elbv2",
            "elasticloadbalancing:DescribeLoadBalancers",
            "DescribeLoadBalancers",
            lambda reg: get_boto_client("elbv2", reg, sess).describe_load_balancers(PageSize=5),
        ),
        (
            "elbv2",
            "elasticloadbalancing:DescribeTargetGroups",
            "DescribeTargetGroups",
            lambda reg: get_boto_client("elbv2", reg, sess).describe_target_groups(PageSize=5),
        ),
        (
            "cloudwatch",
            "cloudwatch:GetMetricData",
            "GetMetricData",
            lambda reg: get_boto_client("cloudwatch", reg, sess).get_metric_data(
                MetricDataQueries=[],
                StartTime=datetime.fromtimestamp(0, tz=timezone.utc),
                EndTime=datetime.fromtimestamp(60, tz=timezone.utc),
            ),
        ),
        (
            "rds",
            "rds:DescribeDBInstances",
            "DescribeDBInstances",
            lambda reg: get_boto_client("rds", reg, sess).describe_db_instances(MaxRecords=20),
        ),
    ]

    missing_permissions_by_region: dict[str, list[str]] = {}

    for region in target_regions:
        sys.stdout.write(f"Region: {region}\n")
        missing_in_reg: list[str] = []

        for svc_name, iam_action, api_name, check_fn in api_specs:
            try:
                check_fn(region)
                sys.stdout.write(f"  [OK] {iam_action}\n")
            except botocore.exceptions.ClientError as exc:
                err_code = exc.response.get("Error", {}).get("Code", "")
                if err_code in (
                    "UnauthorizedOperation",
                    "AccessDenied",
                    "AccessDeniedException",
                    "MissingAction",
                ):
                    sys.stdout.write(f"  [DENIED] {iam_action} ({err_code})\n")
                    missing_in_reg.append(iam_action)
                elif err_code in ("InvalidParameterValue", "DryRunOperation"):
                    # Parameter or dry run confirmation implies read permission exists
                    sys.stdout.write(f"  [OK] {iam_action}\n")
                else:
                    # Invariant I9: unsupported region or specific service error
                    sys.stdout.write(f"  [SKIPPED] {iam_action} ({err_code})\n")
            except Exception as exc:
                sys.stdout.write(f"  [SKIPPED] {iam_action} ({exc})\n")

        if missing_in_reg:
            missing_permissions_by_region[region] = missing_in_reg
        sys.stdout.write("\n")

    if missing_permissions_by_region:
        sys.stdout.write("--- Doctor Finding: Missing Permissions Detected ---\n")
        for reg, missing in missing_permissions_by_region.items():
            sys.stdout.write(f"Region {reg}:\n")
            for m in missing:
                sys.stdout.write(f"  - {m}\n")
        sys.stdout.write(
            "\nTip: Ensure your IAM user or role policy includes the read actions listed above.\n"
        )
        return 1

    sys.stdout.write("All required read permissions are permitted across the checked regions.\n")
    return 0


def _render_findings_table(
    findings: list[Finding],
    total_cost: float,
    confidence: str,
    price_date: str,
    warnings: list[str],
) -> str:
    """Render a text table for CLI findings with summary footer."""
    if not findings:
        lines = [
            "No idle or unattached resources found. Your account is clean!",
            "",
            "--- Scan Summary ---",
            "Total idle resources: 0",
            f"Total estimated monthly cost at risk: $0.00 ({confidence})",
            f"Price table date: {price_date}",
            "Note: Estimated costs are approximate and based on standard on-demand pricing.",
        ]
        if warnings:
            lines.append("")
            lines.append("Warnings during scan (Invariant I9: skipped without aborting):")
            for w in warnings:
                lines.append(f"  - {w}")
        return "\n".join(lines)

    headers = [
        "Region",
        "Resource Type",
        "Resource ID",
        "Reason",
        "Est Cost/Mo",
        "Protected",
    ]

    rows: list[list[str]] = []
    for f in findings:
        cost_str = (
            f"${f.est_monthly_cost_usd:.2f} ({f.cost_confidence})"
            if f.est_monthly_cost_usd is not None
            else f"unknown ({f.cost_confidence})"
        )
        prot_str = f"Yes ({f.protection_reason})" if f.protected else "No"
        rows.append(
            [
                f.region,
                f.resource_type.value,
                f.resource_id,
                f.reason,
                cost_str,
                prot_str,
            ]
        )

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def make_line(items: list[str]) -> str:
        return " | ".join(item.ljust(widths[i]) for i, item in enumerate(items))

    sep = "-+-".join("-" * widths[i] for i in range(len(headers)))

    lines = [
        make_line(headers),
        sep,
    ]
    for row in rows:
        lines.append(make_line(row))

    lines.append("")
    lines.append("--- Scan Summary ---")
    lines.append(f"Total idle resources: {len(findings)}")
    lines.append(f"Total estimated monthly cost at risk: ${total_cost:.2f} ({confidence})")
    lines.append(f"Price table date: {price_date}")
    lines.append("Note: Estimated costs are approximate and based on standard on-demand pricing.")

    if warnings:
        lines.append("")
        lines.append("Warnings during scan (Invariant I9: failures skipped without aborting):")
        for w in warnings:
            lines.append(f"  - {w}")

    return "\n".join(lines)


def run_scan(
    regions_arg: str | None = None,
    output_format: str = "table",
    config_file: str | None = None,
    session: boto3.Session | None = None,
    detectors: list[Detector] | None = None,
) -> int:
    """Execute the scan command: read-only scan of resources, findings table/json output."""
    sess = session or boto3.Session()

    # Step 1: Load and configure options
    if config_file:
        try:
            config = load_config_from_file(config_file)
        except FileNotFoundError:
            sys.stderr.write(f"Error: Config file not found: {config_file}\n")
            return 1
        except Exception as exc:
            sys.stderr.write(f"Error: Failed to load config file: {exc}\n")
            return 1
    else:
        config = Config()

    # Apply CLI regions override if provided
    if regions_arg is not None:
        raw_r = regions_arg.strip().lower()
        if raw_r in ("all", "*"):
            target_regions = ["*"]
        else:
            target_regions = [r.strip() for r in regions_arg.split(",") if r.strip()]
            if not target_regions:
                sys.stderr.write("Error: --regions must specify at least one region or 'all'.\n")
                return 1
        config = dataclasses.replace(config, regions=target_regions)

    # Step 2: Validate credentials via STS (read-only)
    try:
        sts = get_boto_client("sts", region_name="us-east-1", session=sess)
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "unknown")
    except (
        botocore.exceptions.NoCredentialsError,
        botocore.exceptions.PartialCredentialsError,
        botocore.exceptions.ClientError,
        botocore.exceptions.EndpointConnectionError,
    ) as exc:
        sys.stderr.write(_friendly_credentials_error_message(str(exc)))
        return 1

    # Step 3: Resolve regions
    try:
        scanned_regions = get_enabled_regions(
            session=sess, target_regions=config.regions, strict=True
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        sys.stderr.write(f"Error: Region discovery failed: {exc}\n")
        return 1
    if not scanned_regions:
        sys.stderr.write("Error: No configured enabled regions were found.\n")
        return 1

    # Step 4: Discover detectors
    if detectors is None:
        discovered_detectors, _ = discover()
    else:
        discovered_detectors = detectors

    clock = SystemClock()
    now = clock.now()
    run_id = f"bsg-cli-{int(now.timestamp())}"
    logger = JsonLogger(run_id=run_id)

    scan_warnings: list[str] = []
    ctx = ScanContext(
        config=config,
        clock=clock,
        account_id=account_id,
        run_id=run_id,
        logger=logger,
        client_factory=lambda svc, reg: get_boto_client(svc, region_name=reg, session=sess),
        on_scan_error=scan_warnings.append,
    )

    all_findings: list[Finding] = []

    # Step 5: Scan resources (strictly read-only)
    for region in scanned_regions:
        for detector in discovered_detectors:
            try:
                findings = detector.detect(ctx, region)
                all_findings.extend(findings)
            except Exception as exc:
                # Invariant I9: One failing detector/region never aborts others.
                scan_warnings.append(f"Region {region} ({detector.__class__.__name__}): {exc}")

    # Step 6: Compute total costs
    total_cost = sum(
        f.est_monthly_cost_usd for f in all_findings if f.est_monthly_cost_usd is not None
    )
    has_unknown = any(
        f.est_monthly_cost_usd is None or f.cost_confidence == "unknown" for f in all_findings
    )
    overall_confidence = (
        "estimate" if total_cost > 0 else ("unknown" if has_unknown else "estimate")
    )

    # Step 7: Render formatted output
    if output_format == "json":
        json_payload = {
            "run_id": run_id,
            "scanned_regions": scanned_regions,
            "findings_count": len(all_findings),
            "total_est_monthly_cost_usd": round(total_cost, 2),
            "cost_confidence": overall_confidence,
            "price_table_date": PRICE_TABLE_DATE,
            "findings": [
                {
                    "resource_type": f.resource_type.value,
                    "resource_id": f.resource_id,
                    "region": f.region,
                    "reason": f.reason,
                    "evidence": dict(f.evidence),
                    "est_monthly_cost_usd": f.est_monthly_cost_usd,
                    "cost_confidence": f.cost_confidence,
                    "proposed_action": f.proposed_action.value if f.proposed_action else None,
                    "protected": f.protected,
                    "protection_reason": f.protection_reason,
                    "detected_at": f.detected_at.isoformat(),
                }
                for f in all_findings
            ],
            "warnings": scan_warnings,
        }
        sys.stdout.write(json.dumps(json_payload, indent=2, default=_json_serial_fallback) + "\n")
    else:
        table_output = _render_findings_table(
            findings=all_findings,
            total_cost=total_cost,
            confidence=overall_confidence,
            price_date=PRICE_TABLE_DATE,
            warnings=scan_warnings,
        )
        sys.stdout.write(table_output + "\n")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser for the bsg CLI."""
    parser = argparse.ArgumentParser(
        prog="bsg",
        description="Bill Shock Guard - Stop surprise AWS bills before they happen.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"bill-shock-guard {VERSION}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # bsg scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan AWS account for idle resources (read-only, no mutations)",
    )
    scan_parser.add_argument(
        "--regions",
        type=str,
        default=None,
        help="Comma-separated regions (e.g. us-east-1) or 'all' (default: all enabled regions)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format: table (default) or json",
    )
    scan_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to JSON configuration file",
    )

    # bsg doctor
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Check credentials and list permitted read APIs per region",
    )
    doctor_parser.add_argument(
        "--regions",
        type=str,
        default=None,
        help="Comma-separated regions to check (default: all enabled regions)",
    )

    # bsg explain
    explain_parser = subparsers.add_parser(
        "explain",
        help="Explain idle detection rules and default thresholds for a resource type",
    )
    explain_parser.add_argument(
        "resource_type",
        type=str,
        help="Resource type (e.g. ec2_instance, elastic_ip, nat_gateway, ebs_volume)",
    )

    # bsg version
    subparsers.add_parser(
        "version",
        help="Print version string",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint for the bsg command-line tool."""
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    if args.command == "version":
        return run_version()
    if args.command == "explain":
        return run_explain(args.resource_type)
    if args.command == "doctor":
        return run_doctor(regions_arg=args.regions)
    if args.command == "scan":
        return run_scan(
            regions_arg=args.regions,
            output_format=args.format,
            config_file=args.config,
        )

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
