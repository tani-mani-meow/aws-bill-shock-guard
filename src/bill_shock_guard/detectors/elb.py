"""Load Balancer detector (ALB and NLB), recheck, and deletion action."""

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


def extract_lb_dimension(load_balancer_arn: str) -> str:
    """Extract dimension value for AWS/ApplicationELB or AWS/NetworkELB.

    CloudWatch expects the ARN suffix starting after 'loadbalancer/'.
    Example: 'app/my-alb/50dc6c495c0c9188' or 'net/my-nlb/50dc6c495c0c9188'.
    """
    marker = "loadbalancer/"
    idx = load_balancer_arn.find(marker)
    if idx != -1:
        return load_balancer_arn[idx + len(marker) :]
    return load_balancer_arn


def evaluate_load_balancer_idle(
    lb_type: str,
    lb_state: str,
    registered_target_count: int,
    target_group_count: int,
    metric_datapoints: list[float] | None,
    metric_name: str,
) -> tuple[bool | None, str]:
    """Pure decision function for Load Balancer idleness.

    Args:
        lb_type: 'application' or 'network'.
        lb_state: State code of the load balancer (e.g. 'active', 'provisioning').
        registered_target_count: Total registered targets across all associated target groups.
        target_group_count: Number of associated target groups.
        metric_datapoints: Metric values for RequestCount (ALB) or NewFlowCount (NLB).
        metric_name: Name of the metric used ('RequestCount' or 'NewFlowCount').

    Returns:
        (is_idle, reason):
            is_idle is True if idle, False if active/not in active state, None if unknown (I9).
    """
    if lb_state != "active":
        return False, f"Load balancer state is {lb_state!r} (expected 'active')"

    # If the load balancer has zero registered targets across all its target groups, it is idle.
    if registered_target_count == 0:
        return (
            True,
            f"Load balancer has 0 registered targets across {target_group_count} target group(s)",
        )

    # When targets exist, we must evaluate traffic metrics
    if metric_datapoints is None or len(metric_datapoints) == 0:
        # Invariant I9: Unknown is not idle. Missing metric data means status is unknown.
        return (
            None,
            f"No CloudWatch {metric_name} metric datapoints found (unknown status)",
        )

    if any(m < 0 for m in metric_datapoints):
        return None, f"Invalid negative metric value in {metric_name} datapoints"

    total_traffic = sum(metric_datapoints)
    traffic_label = "requests" if lb_type == "application" else "new flows"

    if total_traffic == 0.0:
        return (
            True,
            f"Zero {traffic_label} ({metric_name}=0) over idle window with "
            f"{registered_target_count} registered target(s)",
        )

    return (
        False,
        f"Active traffic detected ({int(total_traffic)} {traffic_label})",
    )


def _fetch_elb_metrics(
    cw_client: Any,
    metric_namespace: str,
    metric_name: str,
    dimension_value: str,
    window_hours: int,
    now_dt: Any,
) -> list[float] | None:
    """Fetch RequestCount (ALB) or NewFlowCount (NLB) metric datapoints from CloudWatch."""
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
                            "Namespace": metric_namespace,
                            "MetricName": metric_name,
                            "Dimensions": [{"Name": "LoadBalancer", "Value": dimension_value}],
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


class LoadBalancerDetector(Detector):
    """Detector for idle AWS Application and Network Load Balancers."""

    resource_type: ResourceType = ResourceType.LOAD_BALANCER

    def __init__(
        self,
        metrics_fetcher: Callable[[Any, str, str, str, int, Any], list[float] | None] | None = None,
    ) -> None:
        self._metrics_fetcher = metrics_fetcher or _fetch_elb_metrics

    def _get_target_counts(
        self,
        elbv2: Any,
        lb_arn: str,
        region: str,
        ctx: ScanContext,
    ) -> tuple[int, int] | None:
        """Return (target_group_count, total_registered_targets).

        Returns None if an unexpected API error occurs (triggering Invariant I9).
        """
        try:
            target_groups = list(
                paginate(elbv2, "describe_target_groups", "TargetGroups", LoadBalancerArn=lb_arn)
            )
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("TargetGroupNotFound", "TargetGroupNotFoundException"):
                target_groups = []
            else:
                ctx.logger.warning(
                    "Failed to describe target groups for load balancer",
                    region=region,
                    resource_key=lb_arn,
                    error=str(e),
                )
                return None
        except botocore.exceptions.BotoCoreError as e:
            ctx.logger.warning(
                "AWS error describing target groups",
                region=region,
                resource_key=lb_arn,
                error=str(e),
            )
            return None

        total_registered = 0
        for tg in target_groups:
            tg_arn = tg.get("TargetGroupArn")
            if not tg_arn:
                continue
            try:
                descriptions = list(
                    paginate(
                        elbv2,
                        "describe_target_health",
                        "TargetHealthDescriptions",
                        TargetGroupArn=tg_arn,
                    )
                )
                total_registered += len(descriptions)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                ctx.logger.warning(
                    "Failed to describe target health for target group",
                    region=region,
                    resource_key=tg_arn,
                    error=str(e),
                )
                return None

        return len(target_groups), total_registered

    def _get_tags(
        self, elbv2: Any, lb_arn: str, region: str, ctx: ScanContext
    ) -> dict[str, str] | None:
        """Fetch tags for a single load balancer ARN.

        Returns None if an unexpected API error occurs to enable fail-closed protection.
        """
        try:
            resp = elbv2.describe_tags(ResourceArns=[lb_arn])
            tag_descriptions = resp.get("TagDescriptions", [])
            for desc in tag_descriptions:
                if desc.get("ResourceArn") == lb_arn:
                    return {
                        t["Key"]: t.get("Value", "") for t in desc.get("Tags", []) if "Key" in t
                    }
            return {}
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            ctx.logger.warning(
                "Failed to describe tags for load balancer",
                region=region,
                resource_key=lb_arn,
                error=str(e),
            )
            return None

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan region for idle Application and Network Load Balancers."""
        elbv2 = ctx.client("elbv2", region)
        cw = ctx.client("cloudwatch", region)
        now = ctx.clock.now()
        window_hours = ctx.config.thresholds.elb_idle_window_hours

        try:
            load_balancers = list(paginate(elbv2, "describe_load_balancers", "LoadBalancers"))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            ctx.logger.warning(
                "Failed to describe load balancers in region",
                region=region,
                error=str(e),
            )
            ctx.report_scan_error(f"Load balancer inventory: {e}")
            return []

        findings: list[Finding] = []
        for lb in load_balancers:
            lb_arn = lb.get("LoadBalancerArn", "")
            lb_name = lb.get("LoadBalancerName", "")
            lb_type = lb.get("Type", "")
            lb_state = lb.get("State", {}).get("Code", "")

            if lb_type not in ("application", "network"):
                continue

            if lb_state != "active":
                continue

            counts = self._get_target_counts(elbv2, lb_arn, region, ctx)
            if counts is None:
                # Invariant I9: Unknown is not idle
                ctx.report_scan_error(f"Load balancer target data unavailable for {lb_arn}")
                continue
            tg_count, registered_targets = counts

            # Determine CloudWatch metric namespace and name
            if lb_type == "application":
                metric_namespace = "AWS/ApplicationELB"
                metric_name = "RequestCount"
            else:
                metric_namespace = "AWS/NetworkELB"
                metric_name = "NewFlowCount"

            datapoints: list[float] | None = None
            if registered_targets > 0:
                dim_val = extract_lb_dimension(lb_arn)
                datapoints = self._metrics_fetcher(
                    cw, metric_namespace, metric_name, dim_val, window_hours, now
                )
                if datapoints is None:
                    ctx.report_scan_error(f"Load balancer metrics unavailable for {lb_arn}")

            is_idle, reason = evaluate_load_balancer_idle(
                lb_type=lb_type,
                lb_state=lb_state,
                registered_target_count=registered_targets,
                target_group_count=tg_count,
                metric_datapoints=datapoints,
                metric_name=metric_name,
            )

            # Invariant I9: Unknown is not idle
            if is_idle is not True:
                continue

            tags = self._get_tags(elbv2, lb_arn, region, ctx)
            protected: bool
            prot_reason: str | None
            if tags is None:
                ctx.report_scan_error(f"Load balancer tags unavailable for {lb_arn}")
                protected = True
                prot_reason = "Failed to fetch tags; failing closed as protected"
            else:
                protected, prot_reason = is_protected(
                    tags=tags,
                    resource_id=lb_arn,
                    config=ctx.config,
                    now=now,
                )
            # Also support matching by load balancer name in ignore_resource_ids
            if not protected and lb_name in ctx.config.ignore_resource_ids:
                protected = True
                prot_reason = f"Load balancer name {lb_name} is in ignore_resource_ids"

            cost_est, confidence = monthly_cost(
                ResourceType.LOAD_BALANCER,
                region,
                lb_type=lb_type,
            )

            evidence = {
                "type": lb_type,
                "name": lb_name,
                "load_balancer_arn": lb_arn,
                "target_group_count": tg_count,
                "registered_target_count": registered_targets,
                "metric_name": metric_name if registered_targets > 0 else None,
                "metric_datapoints_sum": sum(datapoints) if datapoints else 0.0,
                "zero_targets": (registered_targets == 0),
                "idle_window_hours": window_hours,
            }

            finding = Finding(
                resource_type=ResourceType.LOAD_BALANCER,
                resource_id=lb_arn,
                region=region,
                reason=reason,
                evidence=evidence,
                est_monthly_cost_usd=cost_est,
                cost_confidence=confidence,
                proposed_action=ActionKind.ELB_DELETE,
                protected=protected,
                protection_reason=prot_reason,
                detected_at=now,
            )
            findings.append(finding)

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify live load balancer state, targets, and metrics before acting (Invariant I4)."""
        elbv2 = ctx.client("elbv2", finding.region)
        cw = ctx.client("cloudwatch", finding.region)
        now = ctx.clock.now()
        window_hours = ctx.config.thresholds.elb_idle_window_hours

        try:
            resp = elbv2.describe_load_balancers(LoadBalancerArns=[finding.resource_id])
            lbs = resp.get("LoadBalancers", [])
            if not lbs:
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"Load balancer {finding.resource_id} no longer exists",
                )
            lb = lbs[0]
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("LoadBalancerNotFound", "LoadBalancerNotFoundException"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"Load balancer {finding.resource_id} not found",
                )
            # Invariant I9: Unknown on API error
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe load balancer: {e}",
            )
        except botocore.exceptions.BotoCoreError as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"AWS connection error during load balancer recheck: {e}",
            )

        lb_state = lb.get("State", {}).get("Code", "")
        if lb_state != "active":
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"Load balancer state is {lb_state!r} (expected 'active')",
            )

        lb_name = lb.get("LoadBalancerName", "")
        lb_type = lb.get("Type", "")

        # Check protection fresh at action time (Invariant I3, I10)
        tags = self._get_tags(elbv2, finding.resource_id, finding.region, ctx)
        if tags is None:
            return RecheckResult(
                still_idle=None,
                protected=True,
                reason="Failed to describe load balancer tags during recheck (fail closed)",
            )
        protected, prot_reason = is_protected(
            tags=tags,
            resource_id=finding.resource_id,
            config=ctx.config,
            now=now,
        )
        if not protected and lb_name in ctx.config.ignore_resource_ids:
            protected = True
            prot_reason = f"Load balancer name {lb_name} is in ignore_resource_ids"

        if protected:
            return RecheckResult(
                still_idle=True,
                protected=True,
                reason=prot_reason or "Protected by tag or configuration",
            )

        counts = self._get_target_counts(elbv2, finding.resource_id, finding.region, ctx)
        if counts is None:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason="Failed to inspect load balancer target groups or targets (unknown status)",
            )
        tg_count, registered_targets = counts

        if lb_type == "application":
            metric_namespace = "AWS/ApplicationELB"
            metric_name = "RequestCount"
        else:
            metric_namespace = "AWS/NetworkELB"
            metric_name = "NewFlowCount"

        datapoints: list[float] | None = None
        if registered_targets > 0:
            dim_val = extract_lb_dimension(finding.resource_id)
            datapoints = self._metrics_fetcher(
                cw, metric_namespace, metric_name, dim_val, window_hours, now
            )

        is_idle, reason = evaluate_load_balancer_idle(
            lb_type=lb_type,
            lb_state=lb_state,
            registered_target_count=registered_targets,
            target_group_count=tg_count,
            metric_datapoints=datapoints,
            metric_name=metric_name,
        )

        return RecheckResult(
            still_idle=is_idle,
            protected=False,
            reason=reason,
        )


class ElbDeleteAction(Action):
    """Mutating action to delete an idle Load Balancer."""

    kind: ActionKind = ActionKind.ELB_DELETE

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Execute deletion of a load balancer.

        Respects Invariant I1 (dry_run check) and handles errors cleanly.
        """
        if finding.resource_type != ResourceType.LOAD_BALANCER:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Resource type {finding.resource_type} does not match elb_delete action",
                error="ResourceTypeMismatch",
            )

        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=f"DRY RUN: would delete load balancer {finding.resource_id}",
            )

        elbv2 = ctx.client("elbv2", finding.region)
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=finding.resource_id)
            ctx.logger.info(
                "Deleted load balancer",
                region=finding.region,
                resource_key=finding.key,
            )
            return ActionResult(
                ok=True,
                performed=True,
                detail=f"Deleted load balancer {finding.resource_id}",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            ctx.logger.error(
                "Failed to delete load balancer",
                region=finding.region,
                resource_key=finding.key,
                error=str(e),
            )
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to delete load balancer {finding.resource_id}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )


DETECTORS = [LoadBalancerDetector()]
ACTIONS = {ActionKind.ELB_DELETE: ElbDeleteAction()}
