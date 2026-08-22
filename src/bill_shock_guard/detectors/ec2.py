"""EC2 detector, recheck, and stop action."""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from botocore.exceptions import ClientError

from bill_shock_guard.aws import mutation_outcome_unknown, paginate
from bill_shock_guard.config import Config
from bill_shock_guard.interfaces import Action, Detector, ScanContext
from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    RecheckResult,
    ResourceType,
)
from bill_shock_guard.pricing import monthly_cost
from bill_shock_guard.protection import is_protected


def is_instance_old_enough(launch_time: datetime, now: datetime, min_hours: int) -> bool:
    """Check if the instance has been running continuously for at least min_hours."""
    if launch_time.tzinfo is None:
        launch_time = launch_time.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - launch_time).total_seconds() >= min_hours * 3600


def is_ec2_idle(
    cpu_values: list[float],
    net_in_values: list[float],
    net_out_values: list[float],
    window_seconds: float,
    cpu_threshold: float,
    net_threshold: float,
) -> tuple[bool | None, float | None, float | None, str]:
    """Pure decision function evaluating whether metric datapoints indicate an idle EC2 instance.

    Returns:
        (is_idle, avg_cpu, avg_net_bytes_per_sec, reason)
        is_idle is None if metrics are missing (Invariant I9).
    """
    if not cpu_values or not net_in_values or not net_out_values:
        return None, None, None, "Missing metric datapoints (Invariant I9: unknown is not idle)"

    if window_seconds <= 0:
        return None, None, None, "Invalid window duration"

    avg_cpu = sum(cpu_values) / len(cpu_values)
    total_net_bytes = sum(net_in_values) + sum(net_out_values)
    avg_net_bytes_per_sec = total_net_bytes / window_seconds

    is_cpu_idle = avg_cpu < cpu_threshold
    is_net_idle = avg_net_bytes_per_sec < net_threshold
    idle = is_cpu_idle and is_net_idle

    if idle:
        window_hours = int(window_seconds // 3600)
        reason = (
            f"avg CPU {avg_cpu:.1f}% < {cpu_threshold:.1f}%, "
            f"avg net {avg_net_bytes_per_sec:.1f} B/s < {net_threshold:.1f} B/s "
            f"over {window_hours}h"
        )
    else:
        reason = (
            f"not idle: avg CPU {avg_cpu:.1f}% (threshold {cpu_threshold:.1f}%), "
            f"avg net {avg_net_bytes_per_sec:.1f} B/s (threshold {net_threshold:.1f} B/s)"
        )

    return idle, avg_cpu, avg_net_bytes_per_sec, reason


def check_ec2_protection(
    instance_id: str,
    tags: Mapping[str, str],
    lifecycle: str | None,
    config: Config,
    now: datetime,
) -> tuple[bool, str | None]:
    """Pure function checking if an EC2 instance is protected or excluded.

    Returns:
        (is_protected, protection_reason)
    """
    prot, reason = is_protected(tags, instance_id, config, now)
    if prot:
        return True, reason

    if lifecycle == "spot":
        return True, "Excluded: Spot instance (lifecycle=spot)"

    return False, None


def fetch_ec2_metrics(
    cw_client: Any,
    instance_id: str,
    start_time: datetime,
    end_time: datetime,
    period: int = 3600,
) -> tuple[list[float], list[float], list[float]]:
    """Fetch CPUUtilization, NetworkIn, NetworkOut metrics via CloudWatch get_metric_data.

    Returns:
        (cpu_values, net_in_values, net_out_values)
    """
    queries = [
        {
            "Id": "cpu",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                },
                "Period": period,
                "Stat": "Average",
            },
            "ReturnData": True,
        },
        {
            "Id": "net_in",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "NetworkIn",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                },
                "Period": period,
                "Stat": "Sum",
            },
            "ReturnData": True,
        },
        {
            "Id": "net_out",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "NetworkOut",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                },
                "Period": period,
                "Stat": "Sum",
            },
            "ReturnData": True,
        },
    ]

    results: dict[str, list[float]] = {"cpu": [], "net_in": [], "net_out": []}

    if hasattr(cw_client, "can_paginate") and cw_client.can_paginate("get_metric_data"):
        paginator = cw_client.get_paginator("get_metric_data")
        for page in paginator.paginate(
            MetricDataQueries=queries,
            StartTime=start_time,
            EndTime=end_time,
        ):
            for item in page.get("MetricDataResults", []):
                qid = item.get("Id")
                if qid in results:
                    results[qid].extend(item.get("Values", []))
    else:
        resp = cw_client.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start_time,
            EndTime=end_time,
        )
        for item in resp.get("MetricDataResults", []):
            qid = item.get("Id")
            if qid in results:
                results[qid].extend(item.get("Values", []))

    return results["cpu"], results["net_in"], results["net_out"]


MetricsFetcher = Callable[
    [Any, str, datetime, datetime, int],
    tuple[list[float], list[float], list[float]],
]


class EC2Detector:
    """Detector for idle running EC2 instances."""

    resource_type = ResourceType.EC2_INSTANCE

    def __init__(self, metrics_fetcher: MetricsFetcher | None = None) -> None:
        self._metrics_fetcher: MetricsFetcher = metrics_fetcher or fetch_ec2_metrics

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan EC2 instances in region and flag idle running instances."""
        ec2 = ctx.client("ec2", region)
        cw = ctx.client("cloudwatch", region)
        findings: list[Finding] = []

        now = ctx.clock.now()
        window_hours = ctx.config.thresholds.ec2_idle_window_hours
        window_seconds = float(window_hours * 3600)
        start_time = now - timedelta(hours=window_hours)
        period = min(3600, max(60, int(window_seconds)))

        try:
            for reservation in paginate(ec2, "describe_instances", "Reservations"):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    state = instance.get("State", {}).get("Name", "")

                    # State must be 'running'
                    if state != "running":
                        continue

                    launch_time = instance.get("LaunchTime")
                    if not launch_time or not is_instance_old_enough(
                        launch_time, now, window_hours
                    ):
                        # Too young to judge: not flagged at all
                        continue

                    raw_tags = instance.get("Tags", [])
                    tags = {t["Key"]: t.get("Value", "") for t in raw_tags if "Key" in t}
                    lifecycle = instance.get("InstanceLifecycle")

                    is_prot, prot_reason = check_ec2_protection(
                        instance_id, tags, lifecycle, ctx.config, now
                    )

                    try:
                        cpu_vals, net_in_vals, net_out_vals = self._metrics_fetcher(
                            cw, instance_id, start_time, now, period
                        )
                    except Exception as e:
                        ctx.report_scan_error(f"CloudWatch metrics for {instance_id}: {e}")
                        ctx.logger.error(
                            f"Failed to fetch CloudWatch metrics for {instance_id}: {e}",
                            extra={"resource_key": f"{region}#ec2_instance#{instance_id}"},
                        )
                        # Invariant I9: unknown is not idle
                        continue

                    idle, avg_cpu, avg_net, idle_reason = is_ec2_idle(
                        cpu_vals,
                        net_in_vals,
                        net_out_vals,
                        window_seconds,
                        ctx.config.thresholds.ec2_idle_cpu_avg_pct,
                        float(ctx.config.thresholds.ec2_idle_network_avg_bytes_per_sec),
                    )

                    if idle is not True:
                        # Missing metrics or not idle
                        continue

                    instance_type = instance.get("InstanceType", "unknown")
                    cost, confidence = monthly_cost(
                        ResourceType.EC2_INSTANCE, region, instance_type=instance_type
                    )

                    finding = Finding(
                        resource_type=ResourceType.EC2_INSTANCE,
                        resource_id=instance_id,
                        region=region,
                        reason=(
                            f"EC2 instance {instance_id} ({instance_type}) is idle: {idle_reason}"
                        ),
                        evidence={
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "launch_time": launch_time.isoformat(),
                            "state": state,
                            "cpu_avg_pct": avg_cpu,
                            "net_avg_bytes_per_sec": avg_net,
                            "lifecycle": lifecycle,
                        },
                        est_monthly_cost_usd=cost,
                        cost_confidence=confidence,
                        proposed_action=ActionKind.EC2_STOP,
                        protected=is_prot,
                        protection_reason=prot_reason,
                        detected_at=now,
                    )
                    findings.append(finding)
        except Exception as e:
            ctx.report_scan_error(f"EC2 inventory: {e}")
            ctx.logger.error(
                f"Failed to describe EC2 instances in {region}: {e}",
                extra={"region": region, "error": str(e)},
            )
            return findings

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify single instance state, tags, and metrics before mutating action."""
        ec2 = ctx.client("ec2", finding.region)
        cw = ctx.client("cloudwatch", finding.region)
        now = ctx.clock.now()

        try:
            resp = ec2.describe_instances(InstanceIds=[finding.resource_id])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"Instance {finding.resource_id} not found",
                )
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe instance {finding.resource_id}: {e}",
            )
        except Exception as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe instance {finding.resource_id}: {e}",
            )

        reservations = resp.get("Reservations", [])
        instances = [i for r in reservations for i in r.get("Instances", [])]
        if not instances:
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"Instance {finding.resource_id} not found in reservations",
            )

        inst = instances[0]
        state = inst.get("State", {}).get("Name", "")
        if state != "running":
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"Instance {finding.resource_id} is in state {state} (not running)",
            )

        raw_tags = inst.get("Tags", [])
        tags = {t["Key"]: t.get("Value", "") for t in raw_tags if "Key" in t}
        lifecycle = inst.get("InstanceLifecycle")

        is_prot, prot_reason = check_ec2_protection(
            finding.resource_id, tags, lifecycle, ctx.config, now
        )

        if is_prot:
            return RecheckResult(
                still_idle=True,
                protected=True,
                reason=prot_reason or "Protected",
            )

        window_hours = ctx.config.thresholds.ec2_idle_window_hours
        window_seconds = float(window_hours * 3600)
        start_time = now - timedelta(hours=window_hours)
        period = min(3600, max(60, int(window_seconds)))

        try:
            cpu_vals, net_in_vals, net_out_vals = self._metrics_fetcher(
                cw, finding.resource_id, start_time, now, period
            )
        except Exception as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to query metrics during recheck: {e}",
            )

        idle, avg_cpu, avg_net, idle_reason = is_ec2_idle(
            cpu_vals,
            net_in_vals,
            net_out_vals,
            window_seconds,
            ctx.config.thresholds.ec2_idle_cpu_avg_pct,
            float(ctx.config.thresholds.ec2_idle_network_avg_bytes_per_sec),
        )

        if idle is None:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason="Metrics unavailable or missing during recheck (Invariant I9)",
            )

        if not idle:
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"Instance {finding.resource_id} is no longer idle ({idle_reason})",
            )

        return RecheckResult(
            still_idle=True,
            protected=False,
            reason=f"Instance {finding.resource_id} is still idle ({idle_reason})",
        )


class EC2StopAction:
    """Action to stop an idle EC2 instance."""

    kind = ActionKind.EC2_STOP

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Stop the instance unless dry_run is active."""
        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=f"DRY RUN: would stop instance {finding.resource_id}",
            )

        ec2 = ctx.client("ec2", finding.region)
        try:
            ec2.stop_instances(InstanceIds=[finding.resource_id])
            return ActionResult(
                ok=True,
                performed=True,
                detail=f"Stopped EC2 instance {finding.resource_id}",
            )
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to stop EC2 instance {finding.resource_id}: {e}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )


DETECTORS: list[Detector] = [EC2Detector()]
ACTIONS: dict[ActionKind, Action] = {ActionKind.EC2_STOP: EC2StopAction()}
