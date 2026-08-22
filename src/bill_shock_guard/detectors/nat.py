"""NAT Gateway detector, recheck, and deletion action."""

from datetime import timedelta
from typing import Any, Callable

import botocore.exceptions

from bill_shock_guard.aws import mutation_outcome_unknown, paginate
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


def evaluate_nat_gateway_idle(
    state: str,
    bytes_out_datapoints: list[float] | None,
) -> tuple[bool | None, str]:
    """Pure decision function for NAT Gateway idleness.

    Args:
        state: State of the NAT gateway (e.g. 'available', 'deleted', 'deleting').
        bytes_out_datapoints: List of metric values for BytesOutToDestination over the window.
            None or empty list represents missing metrics.

    Returns:
        (is_idle, reason):
            is_idle is True if idle, False if active/not available, None if unknown (I9).
    """
    if state != "available":
        return False, f"NAT gateway state is {state!r} (expected 'available')"

    if bytes_out_datapoints is None or len(bytes_out_datapoints) == 0:
        # Invariant I9: Unknown is not idle. Missing metric data means status is unknown.
        return None, "No CloudWatch BytesOutToDestination metric datapoints found (unknown status)"

    if any(b < 0 for b in bytes_out_datapoints):
        return None, "Invalid negative byte count in CloudWatch metric datapoints"

    total_bytes = sum(bytes_out_datapoints)
    if total_bytes == 0.0:
        return True, "Zero bytes sent to destination over idle window"

    return False, f"Active traffic detected ({int(total_bytes)} bytes out to destination)"


def _fetch_nat_metrics(
    cw_client: Any,
    nat_gateway_id: str,
    window_hours: int,
    now_dt: Any,
) -> list[float] | None:
    """Fetch BytesOutToDestination metric datapoints from CloudWatch.

    Returns None if the query fails or raises an exception.
    """
    start_time = now_dt - timedelta(hours=window_hours)
    end_time = now_dt
    period = max(60, min(86400, window_hours * 3600))

    try:
        response = cw_client.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/NATGateway",
                            "MetricName": "BytesOutToDestination",
                            "Dimensions": [{"Name": "NatGatewayId", "Value": nat_gateway_id}],
                        },
                        "Period": period,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
        )
        results = response.get("MetricDataResults", [])
        if not results:
            return None
        values = results[0].get("Values", [])
        return [float(v) for v in values]
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError):
        return None


class NatGatewayDetector(Detector):
    """Detector for idle AWS NAT Gateways."""

    resource_type: ResourceType = ResourceType.NAT_GATEWAY

    def __init__(
        self,
        metrics_fetcher: Callable[[Any, str, int, Any], list[float] | None] | None = None,
    ) -> None:
        self._metrics_fetcher = metrics_fetcher or _fetch_nat_metrics

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan region for idle NAT gateways."""
        ec2 = ctx.client("ec2", region)
        cw = ctx.client("cloudwatch", region)
        now = ctx.clock.now()
        window_hours = ctx.config.thresholds.nat_idle_window_hours

        try:
            nat_gateways = list(paginate(ec2, "describe_nat_gateways", "NatGateways"))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            ctx.report_scan_error(f"NAT gateway inventory: {e}")
            ctx.logger.warning(
                "Failed to describe NAT gateways in region",
                region=region,
                error=str(e),
            )
            return []

        findings: list[Finding] = []
        for nat in nat_gateways:
            nat_id = nat.get("NatGatewayId", "")
            state = nat.get("State", "")
            if state != "available":
                continue

            datapoints = self._metrics_fetcher(cw, nat_id, window_hours, now)
            if datapoints is None:
                ctx.report_scan_error(f"NAT gateway metrics unavailable for {nat_id}")
            is_idle, reason = evaluate_nat_gateway_idle(state, datapoints)

            # Invariant I9: Unknown is not idle. Only proceed if definitely idle (True).
            if is_idle is not True:
                continue

            tags = {t["Key"]: t.get("Value", "") for t in nat.get("Tags", []) if "Key" in t}
            protected, prot_reason = is_protected(
                tags=tags,
                resource_id=nat_id,
                config=ctx.config,
                now=now,
            )

            cost_est, confidence = monthly_cost(ResourceType.NAT_GATEWAY, region)

            evidence = {
                "state": state,
                "nat_gateway_id": nat_id,
                "idle_window_hours": window_hours,
                "bytes_out_sum": sum(datapoints) if datapoints else 0.0,
                "datapoint_count": len(datapoints) if datapoints else 0,
            }

            finding = Finding(
                resource_type=ResourceType.NAT_GATEWAY,
                resource_id=nat_id,
                region=region,
                reason=reason,
                evidence=evidence,
                est_monthly_cost_usd=cost_est,
                cost_confidence=confidence,
                proposed_action=ActionKind.NAT_DELETE,
                protected=protected,
                protection_reason=prot_reason,
                detected_at=now,
            )
            findings.append(finding)

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify live NAT gateway state and metrics before acting (Invariant I4)."""
        ec2 = ctx.client("ec2", finding.region)
        cw = ctx.client("cloudwatch", finding.region)
        now = ctx.clock.now()
        window_hours = ctx.config.thresholds.nat_idle_window_hours

        try:
            resp = ec2.describe_nat_gateways(NatGatewayIds=[finding.resource_id])
            nats = resp.get("NatGateways", [])
            if not nats:
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"NAT gateway {finding.resource_id} no longer exists",
                )
            nat = nats[0]
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NatGatewayNotFound", "InvalidNatGatewayID.NotFound"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"NAT gateway {finding.resource_id} not found",
                )
            # Invariant I9: Unknown on API error
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe NAT gateway: {e}",
            )
        except botocore.exceptions.BotoCoreError as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"AWS connection error during NAT gateway recheck: {e}",
            )

        state = nat.get("State", "")
        if state != "available":
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"NAT gateway state is {state!r} (expected 'available')",
            )

        # Check protection fresh at action time (Invariant I3, I10)
        tags = {t["Key"]: t.get("Value", "") for t in nat.get("Tags", []) if "Key" in t}
        protected, prot_reason = is_protected(
            tags=tags,
            resource_id=finding.resource_id,
            config=ctx.config,
            now=now,
        )
        if protected:
            return RecheckResult(
                still_idle=True,
                protected=True,
                reason=prot_reason or "Protected by tag or configuration",
            )

        # Re-check live metrics (Invariant I4, I9)
        datapoints = self._metrics_fetcher(cw, finding.resource_id, window_hours, now)
        is_idle, reason = evaluate_nat_gateway_idle(state, datapoints)
        return RecheckResult(
            still_idle=is_idle,
            protected=False,
            reason=reason,
        )


class NatDeleteAction(Action):
    """Mutating action to delete an idle NAT Gateway."""

    kind: ActionKind = ActionKind.NAT_DELETE

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Execute deletion of a NAT gateway.

        Respects Invariant I1 (dry_run check) and handles errors cleanly.
        """
        if finding.resource_type != ResourceType.NAT_GATEWAY:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Resource type {finding.resource_type} does not match nat_delete action",
                error="ResourceTypeMismatch",
            )

        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=f"DRY RUN: would delete NAT gateway {finding.resource_id}",
            )

        ec2 = ctx.client("ec2", finding.region)
        try:
            ec2.delete_nat_gateway(NatGatewayId=finding.resource_id)
            ctx.logger.info(
                "Deleted NAT gateway",
                region=finding.region,
                resource_key=finding.key,
            )
            return ActionResult(
                ok=True,
                performed=True,
                detail=f"Deleted NAT gateway {finding.resource_id}",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            ctx.logger.error(
                "Failed to delete NAT gateway",
                region=finding.region,
                resource_key=finding.key,
                error=str(e),
            )
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to delete NAT gateway {finding.resource_id}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )


DETECTORS = [NatGatewayDetector()]
ACTIONS = {ActionKind.NAT_DELETE: NatDeleteAction()}
