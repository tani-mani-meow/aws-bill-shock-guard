"""SageMaker notebook instance detector and stop action (EXPERIMENTAL).

Detects Amazon SageMaker notebook instances in 'InService' status that are idle based
on CloudWatch CPUUtilization metrics over the idle window.

AWS SageMaker Notebook Instances do not publish OS hardware metrics (such as
CPUUtilization) out-of-the-box to CloudWatch without custom lifecycle configuration
scripts (such as the official AWS publish-instance-metrics sample).

When enabled, this detector checks for Notebook Instances in 'InService' status. If
custom CloudWatch metric data is available and idle, it flags the instance. If metrics
are missing or unavailable, per Invariant I9 ('Unknown is not idle'), the resource
is NOT flagged as idle.

Action: sm_notebook_stop stops the notebook instance.
"""

from datetime import timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

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

SAGEMAKER_CW_NAMESPACES = [
    "/aws/sagemaker/NotebookInstances",
    "AWS/SageMaker",
]


def is_sagemaker_notebook_idle(
    notebook: dict[str, Any],
    avg_cpu: float | None,
    cpu_threshold: float = 5.0,
) -> tuple[bool, str, dict[str, Any]]:
    """Determine whether a SageMaker notebook instance is idle.

    Pure function separating SageMaker idle evaluation logic from AWS I/O.

    Returns:
        (is_idle, reason, evidence)
    """
    name = notebook.get("NotebookInstanceName", "unknown")
    status = notebook.get("NotebookInstanceStatus", "")
    instance_type = notebook.get("InstanceType", "unknown")

    evidence: dict[str, Any] = {
        "notebook_name": name,
        "status": status,
        "instance_type": instance_type,
        "avg_cpu_pct": avg_cpu,
        "cpu_threshold_pct": cpu_threshold,
    }

    # 1. Status must be InService
    if status != "InService":
        return False, f"Notebook {name} status is '{status}' (not InService)", evidence

    # 2. Invariant I9: Unknown is not idle
    if avg_cpu is None:
        return (
            False,
            f"Notebook {name} has no CloudWatch CPUUtilization metrics (unknown is not idle)",
            evidence,
        )

    # 3. Check CPU threshold
    if avg_cpu > cpu_threshold:
        return (
            False,
            f"Notebook {name} average CPU was {avg_cpu:.1f}% (exceeds threshold {cpu_threshold}%)",
            evidence,
        )

    return (
        True,
        f"Notebook {name} average CPU was {avg_cpu:.1f}% <= {cpu_threshold}% over idle window",
        evidence,
    )


class SageMakerNotebookDetector(Detector):
    """Detector for idle Amazon SageMaker notebook instances (EXPERIMENTAL)."""

    resource_type: ResourceType = ResourceType.SAGEMAKER_NOTEBOOK

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan a region for idle SageMaker notebook instances."""
        findings: list[Finding] = []
        try:
            sm = ctx.client("sagemaker", region)
            cw = ctx.client("cloudwatch", region)
        except Exception as e:
            ctx.report_scan_error(f"SageMaker/CloudWatch client: {e}")
            ctx.logger.warning("Failed to obtain SageMaker client", extra={"error": str(e)})
            return []

        now = ctx.clock.now()
        # Default window is 24 hours for notebooks
        start_time = now - timedelta(hours=24)

        try:
            notebooks_iter = paginate(sm, "list_notebook_instances", "NotebookInstances")
            for nb in notebooks_iter:
                name = nb.get("NotebookInstanceName", "")
                if not name:
                    continue

                try:
                    desc = sm.describe_notebook_instance(NotebookInstanceName=name)
                except Exception as desc_err:
                    ctx.report_scan_error(f"SageMaker notebook details for {name}: {desc_err}")
                    ctx.logger.warning(
                        "Failed to describe notebook instance",
                        extra={"name": name, "error": str(desc_err)},
                    )
                    continue

                if desc.get("NotebookInstanceStatus") != "InService":
                    continue

                # Query CloudWatch CPUUtilization across candidate namespaces
                avg_cpu: float | None = None
                metrics_error: Exception | None = None
                for ns in SAGEMAKER_CW_NAMESPACES:
                    try:
                        stats = cw.get_metric_statistics(
                            Namespace=ns,
                            MetricName="CPUUtilization",
                            Dimensions=[{"Name": "NotebookInstanceName", "Value": name}],
                            StartTime=start_time,
                            EndTime=now,
                            Period=3600,
                            Statistics=["Average"],
                        )
                        datapoints = stats.get("Datapoints", [])
                        if datapoints:
                            avg_cpu = sum(dp["Average"] for dp in datapoints) / len(datapoints)
                            break
                    except Exception as exc:
                        metrics_error = exc
                if avg_cpu is None and metrics_error is not None:
                    ctx.report_scan_error(f"CloudWatch metrics for {name}: {metrics_error}")

                is_idle, reason, evidence = is_sagemaker_notebook_idle(desc, avg_cpu)
                if not is_idle:
                    continue

                # Get tags for protection check
                tags_dict: dict[str, str] = {}
                arn = desc.get("NotebookInstanceArn")
                if arn:
                    evidence["resource_arn"] = arn
                    try:
                        tags_resp = sm.list_tags(ResourceArn=arn)
                        tags_dict = {
                            t["Key"]: t.get("Value", "")
                            for t in tags_resp.get("Tags", [])
                            if "Key" in t
                        }
                    except Exception as exc:
                        ctx.report_scan_error(f"SageMaker notebook tags for {name}: {exc}")
                        continue

                protected, prot_reason = is_protected(
                    tags=tags_dict,
                    resource_id=name,
                    config=ctx.config,
                    now=now,
                )

                cost, confidence = monthly_cost(
                    resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
                    region=region,
                    instance_type=desc.get("InstanceType"),
                )

                findings.append(
                    Finding(
                        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
                        resource_id=name,
                        region=region,
                        reason=reason,
                        evidence=evidence,
                        est_monthly_cost_usd=cost,
                        cost_confidence=confidence,
                        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
                        protected=protected,
                        protection_reason=prot_reason,
                        detected_at=now,
                    )
                )
        except (ClientError, BotoCoreError) as e:
            ctx.report_scan_error(f"SageMaker inventory: {e}")
            # Invariant I9: One failing region never aborts others
            ctx.logger.warning(
                "SageMaker detection failed in region",
                extra={"region": region, "error": str(e)},
            )
            return findings

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify the live SageMaker notebook instance state (Invariant I4)."""
        now = ctx.clock.now()
        try:
            sm = ctx.client("sagemaker", finding.region)
            desc = sm.describe_notebook_instance(NotebookInstanceName=finding.resource_id)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ValidationException", "ResourceNotFound"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"Notebook {finding.resource_id} no longer exists",
                )
            # Invariant I9: Unknown is not idle
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe notebook {finding.resource_id}: {e}",
            )
        except Exception as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Unexpected error describing notebook {finding.resource_id}: {e}",
            )

        status = desc.get("NotebookInstanceStatus", "")
        if status != "InService":
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"Notebook {finding.resource_id} status is now '{status}'",
            )

        # Check protection
        tags_dict: dict[str, str] = {}
        arn = desc.get("NotebookInstanceArn")
        if arn:
            try:
                tags_resp = sm.list_tags(ResourceArn=arn)
                tags_dict = {
                    t["Key"]: t.get("Value", "") for t in tags_resp.get("Tags", []) if "Key" in t
                }
            except Exception as tag_err:
                ctx.logger.warning(
                    "recheck_tag_fetch_failed",
                    resource_id=finding.resource_id,
                    error=str(tag_err),
                )
                return RecheckResult(
                    still_idle=None,
                    protected=True,
                    reason=f"Failed to fetch tags for notebook {finding.resource_id}: {tag_err}",
                )

        protected, prot_reason = is_protected(
            tags=tags_dict,
            resource_id=finding.resource_id,
            config=ctx.config,
            now=now,
        )
        if protected:
            return RecheckResult(
                still_idle=True,
                protected=True,
                reason=prot_reason or "Resource is protected",
            )

        # Check CloudWatch CPU metric fresh at action time (Invariant I4)
        cw = ctx.client("cloudwatch", finding.region)
        start_time = now - timedelta(hours=24)
        avg_cpu: float | None = None
        for ns in SAGEMAKER_CW_NAMESPACES:
            try:
                stats = cw.get_metric_statistics(
                    Namespace=ns,
                    MetricName="CPUUtilization",
                    Dimensions=[{"Name": "NotebookInstanceName", "Value": finding.resource_id}],
                    StartTime=start_time,
                    EndTime=now,
                    Period=3600,
                    Statistics=["Average"],
                )
                datapoints = stats.get("Datapoints", [])
                if datapoints:
                    avg_cpu = sum(dp["Average"] for dp in datapoints) / len(datapoints)
                    break
            except Exception as cw_err:
                ctx.logger.warning(
                    "recheck_cw_fetch_failed",
                    resource_id=finding.resource_id,
                    error=str(cw_err),
                )

        if avg_cpu is None:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=(
                    f"Notebook {finding.resource_id} has no CloudWatch CPU metrics "
                    "(unknown is not idle)"
                ),
            )

        is_idle, idle_reason, _ = is_sagemaker_notebook_idle(desc, avg_cpu)
        if not is_idle:
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=idle_reason or f"Notebook {finding.resource_id} is active (CPU: {avg_cpu}%)",
            )

        return RecheckResult(
            still_idle=True,
            protected=False,
            reason=f"Notebook {finding.resource_id} is still InService and idle (CPU: {avg_cpu}%)",
        )


class SageMakerNotebookStopAction(Action):
    """Stop an idle Amazon SageMaker notebook instance."""

    kind: ActionKind = ActionKind.SM_NOTEBOOK_STOP

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Stop the SageMaker notebook instance."""
        # Invariant I1: Never mutate when dry_run is true
        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=(
                    f"DRY RUN: would stop SageMaker notebook instance {finding.resource_id} "
                    f"in {finding.region}"
                ),
            )

        try:
            sm = ctx.client("sagemaker", finding.region)
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to obtain SageMaker client in {finding.region}",
                error=str(e),
            )

        try:
            sm.stop_notebook_instance(NotebookInstanceName=finding.resource_id)
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to stop SageMaker notebook {finding.resource_id}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )

        return ActionResult(
            ok=True,
            performed=True,
            detail=f"Successfully stopped SageMaker notebook instance {finding.resource_id}",
        )


DETECTORS = [SageMakerNotebookDetector()]
ACTIONS = {ActionKind.SM_NOTEBOOK_STOP: SageMakerNotebookStopAction()}
