"""Plain-text digest formatting for Bill Shock Guard notifications."""

from datetime import datetime, timezone
from typing import Mapping, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    ResourceType,
)
from bill_shock_guard.pricing import PRICE_TABLE_DATE

ACTION_DESCRIPTIONS: dict[ActionKind, str] = {
    ActionKind.EC2_STOP: "Stop EC2 instance",
    ActionKind.EIP_RELEASE: "Release unassociated Elastic IP",
    ActionKind.NAT_DELETE: "Delete idle NAT gateway",
    ActionKind.EBS_DELETE_AFTER_SNAPSHOT: "Snapshot and delete unattached EBS volume",
    ActionKind.ELB_DELETE: "Delete idle Load Balancer",
    ActionKind.RDS_STOP: "Stop idle RDS instance",
    ActionKind.SM_NOTEBOOK_STOP: "Stop idle SageMaker notebook",
}


def format_timestamp(dt: datetime, display_tz: str = "Asia/Kolkata") -> str:
    """Format a datetime in UTC and display_tz, falling back to UTC if zoneinfo is unavailable.

    Example: '2026-11-12 12:00:00 UTC (2026-11-12 17:30:00 Asia/Kolkata)'
    """
    if dt.tzinfo is None:
        utc_dt = dt.replace(tzinfo=timezone.utc)
    else:
        utc_dt = dt.astimezone(timezone.utc)

    utc_str = utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    if not display_tz or display_tz.upper() == "UTC":
        return utc_str

    try:
        tz = ZoneInfo(display_tz)
        local_dt = utc_dt.astimezone(tz)
        local_str = local_dt.strftime("%Y-%m-%d %H:%M:%S")
        return f"{utc_str} ({local_str} {display_tz})"
    except (ZoneInfoNotFoundError, KeyError, ValueError, Exception):
        return utc_str


def get_exemption_command(
    resource_type: ResourceType,
    resource_id: str,
    region: str,
    tag_key: str = "bsg:keep",
) -> str:
    """Generate the exact AWS CLI command to exempt a resource from Bill Shock Guard actions.

    Includes the permanent tag syntax and date-based temporary exemption.
    """
    if resource_type in (
        ResourceType.EC2_INSTANCE,
        ResourceType.ELASTIC_IP,
        ResourceType.NAT_GATEWAY,
        ResourceType.EBS_VOLUME,
    ):
        cmd = (
            f"aws ec2 create-tags --region {region} "
            f"--resources {resource_id} "
            f"--tags Key={tag_key},Value=true"
        )
    elif resource_type == ResourceType.LOAD_BALANCER:
        cmd = (
            f"aws elbv2 add-tags --region {region} "
            f"--resource-arns {resource_id} "
            f"--tags Key={tag_key},Value=true"
        )
    elif resource_type == ResourceType.RDS_INSTANCE:
        cmd = (
            f"aws rds add-tags-to-resource --region {region} "
            f"--resource-name {resource_id} "
            f"--tags Key={tag_key},Value=true"
        )
    elif resource_type == ResourceType.SAGEMAKER_NOTEBOOK:
        cmd = (
            f"aws sagemaker add-tags --region {region} "
            f"--resource-arn {resource_id} "
            f"--tags Key={tag_key},Value=true"
        )
    else:
        cmd = (
            f"aws ec2 create-tags --region {region} "
            f"--resources {resource_id} "
            f"--tags Key={tag_key},Value=true"
        )

    return cmd


def format_subject(
    findings_count: int,
    total_cost: float | None = None,
    dry_run: bool = True,
    actions_count: int = 0,
) -> str:
    """Format notification subject line under 100 characters for SNS compatibility."""
    prefix = "[DRY RUN] " if dry_run else ""
    if actions_count > 0:
        msg = f"{actions_count} action(s) taken, {findings_count} warning(s)"
        subject = f"{prefix}Bill Shock Guard: {msg}"
    elif findings_count == 0:
        subject = f"{prefix}Bill Shock Guard: All quiet (0 idle resources)"
    elif total_cost is not None and total_cost > 0:
        c_str = f"~${total_cost:.2f}/mo"
        subject = f"{prefix}Bill Shock Guard: {findings_count} resource(s) at risk ({c_str})"
    else:
        subject = f"{prefix}Bill Shock Guard: {findings_count} resource(s) at risk"

    # Truncate to 100 characters for SNS compliance
    return subject[:100]


def format_digest(
    findings: Sequence[Finding] | None = None,
    *,
    warnings: Sequence[Finding] | None = None,
    actions_taken: Sequence[tuple[Finding, ActionResult] | Finding] | None = None,
    actions_failed: Sequence[tuple[Finding, str]] | None = None,
    actions_deferred: Sequence[Finding] | None = None,
    dry_run: bool = True,
    display_tz: str = "Asia/Kolkata",
    deadlines: Mapping[str, datetime] | None = None,
    price_table_date: str | None = None,
    notification_failures: Sequence[str] | None = None,
    now: datetime | None = None,
    tag_key: str = "bsg:keep",
) -> str:
    """Render a detailed plain-text notification digest for email and Telegram."""
    lines: list[str] = []
    pt_date = price_table_date or PRICE_TABLE_DATE
    deadlines_map = deadlines or {}

    # 1. Header / DRY RUN Banner
    banner_width = 72
    lines.append("=" * banner_width)
    if dry_run:
        lines.append("DRY RUN: nothing will be changed.")
        lines.append("In dry run mode, no AWS resources are modified. Proposed actions show")
        lines.append("what would happen if dry run mode were disabled.")
    else:
        lines.append("NOTICE: ACTIVE RUN - Mutating actions are enabled.")
        lines.append("Resources past their grace period may be stopped, released, or deleted.")
    lines.append("=" * banner_width)
    lines.append("")

    # Timestamp
    run_dt = now or datetime.now(timezone.utc)
    lines.append(f"Run Time: {format_timestamp(run_dt, display_tz)}")
    lines.append("")

    # Previous notification delivery failures if any
    if notification_failures:
        lines.append("-" * banner_width)
        lines.append("ATTENTION: Previous notification delivery failures:")
        for failure in notification_failures:
            lines.append(f"  - {failure}")
        lines.append("-" * banner_width)
        lines.append("")

    # Resolve finding collections
    items_to_warn: list[Finding] = []
    if warnings is not None:
        items_to_warn.extend(warnings)
    elif findings is not None:
        items_to_warn.extend(findings)

    # 2. Actions Taken section
    if actions_taken:
        lines.append("ACTIONS TAKEN IN THIS RUN:")
        for entry in actions_taken:
            if isinstance(entry, tuple):
                f, res = entry
                status_str = "SUCCESS" if res.ok else "FAILED"
                lines.append(f"  - [{f.resource_type.value}] {f.resource_id} ({f.region})")
                lines.append(f"    Action: {res.detail} [{status_str}]")
            else:
                f = entry
                action_name = (
                    ACTION_DESCRIPTIONS.get(f.proposed_action, f.proposed_action.value)
                    if f.proposed_action
                    else "None"
                )
                lines.append(f"  - [{f.resource_type.value}] {f.resource_id} ({f.region})")
                lines.append(f"    Action: {action_name}")
        lines.append("")

    # 3. Actions Failed section
    if actions_failed:
        lines.append("ACTIONS FAILED IN THIS RUN:")
        for f, err in actions_failed:
            lines.append(f"  - [{f.resource_type.value}] {f.resource_id} ({f.region})")
            lines.append(f"    Error: {err}")
        lines.append("")

    # 4. Actions Deferred by Circuit Breaker section
    if actions_deferred:
        lines.append("ACTIONS DEFERRED (Circuit breaker limit reached):")
        for f in actions_deferred:
            lines.append(f"  - [{f.resource_type.value}] {f.resource_id} ({f.region})")
            action_name = (
                ACTION_DESCRIPTIONS.get(f.proposed_action, f.proposed_action.value)
                if f.proposed_action
                else "None"
            )
            lines.append(f"    Deferred action: {action_name}")
        lines.append("")

    # 5. Warnings / Findings Detail Section
    lines.append(f"IDLE RESOURCE WARNINGS ({len(items_to_warn)}):")
    if not items_to_warn:
        lines.append("  No new idle resources detected.")
        lines.append("")
    else:
        total_cost_known = 0.0
        unknown_cost_count = 0
        known_cost_count = 0

        for idx, f in enumerate(items_to_warn, start=1):
            lines.append(f"{idx}. [{f.resource_type.value}] {f.resource_id}")
            lines.append(f"   Region: {f.region}")
            lines.append(f"   Reason: {f.reason}")

            # Cost formatting
            if f.est_monthly_cost_usd is not None:
                cost_val = f"${f.est_monthly_cost_usd:.2f}"
                cost_str = f"Approx. {cost_val} / month (confidence: {f.cost_confidence})"
                total_cost_known += f.est_monthly_cost_usd
                known_cost_count += 1
            else:
                cost_str = f"Unknown (confidence: {f.cost_confidence})"
                unknown_cost_count += 1
            lines.append(f"   Cost: {cost_str}")

            # Proposed action & timing
            if f.protected:
                prot_label = f.protection_reason or "protected"
                lines.append(f"   Action: Skipped - Protected ({prot_label})")
                lines.append("   When: No action will be taken")
            elif f.proposed_action:
                desc = ACTION_DESCRIPTIONS.get(f.proposed_action, f.proposed_action.value)
                if dry_run:
                    lines.append(f"   Action: [DRY RUN] Would {desc.lower()}")
                else:
                    lines.append(f"   Action: {desc}")

                # Deadline
                deadline = deadlines_map.get(f.key) or deadlines_map.get(f.resource_id)
                if deadline:
                    deadline_str = format_timestamp(deadline, display_tz)
                    if dry_run:
                        lines.append(f"   When: Would act after {deadline_str} (grace period)")
                    else:
                        lines.append(f"   When: Scheduled after {deadline_str} (grace period)")
                else:
                    lines.append("   When: After grace period expires if still idle")
            else:
                lines.append("   Action: Alert only (no remediation action configured)")
                lines.append("   When: Informational only")

            # Exemption command
            cmd = get_exemption_command(f.resource_type, f.resource_id, f.region, tag_key=tag_key)
            lines.append(f"   Exemption command: {cmd}")
            lines.append(
                "   (Temporary exemption until date: replace Value=true with Value=YYYY-MM-DD)"
            )
            lines.append("")

    # 6. Summary Footer
    lines.append("=" * banner_width)
    lines.append("SUMMARY:")

    # Calculate overall totals across all warnings
    all_findings: list[Finding] = list(items_to_warn)
    total_cost = 0.0
    known_count = 0
    unknown_count = 0
    for item in all_findings:
        if item.est_monthly_cost_usd is not None:
            total_cost += item.est_monthly_cost_usd
            known_count += 1
        else:
            unknown_count += 1

    lines.append(f"- Total idle resources flagged: {len(all_findings)}")
    if known_count > 0 and unknown_count > 0:
        lines.append(
            f"- Total estimated monthly cost at risk: approx. ${total_cost:.2f} USD "
            f"(estimate, plus {unknown_count} resource(s) with unknown cost)"
        )
    elif known_count > 0:
        lines.append(
            f"- Total estimated monthly cost at risk: approx. ${total_cost:.2f} USD (estimate)"
        )
    elif unknown_count > 0:
        msg = f"- Total estimated monthly cost at risk: unknown ({unknown_count} unknown)"
        lines.append(msg)
    else:
        lines.append("- Total estimated monthly cost at risk: $0.00 USD")

    lines.append(f"- Price table date: {pt_date} (approximate rates)")
    dry_run_label = (
        "ENABLED (no changes made)" if dry_run else "DISABLED (mutating actions enabled)"
    )
    lines.append(f"- Dry run: {dry_run_label}")
    lines.append("=" * banner_width)

    return "\n".join(lines)
