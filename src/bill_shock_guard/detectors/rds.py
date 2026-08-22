"""RDS database instance detector and stop action (EXPERIMENTAL).

Detects standalone Amazon RDS database instances that have been in 'available' state
with 0 database connections over rds_idle_window_hours (default 168 hours / 7 days).

Skips:
- Read replicas (cannot be stopped independently without primary consideration)
- Instances with read replicas (AWS prevents stopping instances that have active read replicas)
- Aurora cluster members (Aurora instances belong to a DB cluster, not stopped individually)
- SQL Server Multi-AZ instances (unsupported by AWS for stop/start)

Action: rds_stop stops the DB instance.
NOTE: AWS automatically restarts stopped RDS instances after 7 days.
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


def is_rds_instance_idle(
    instance: dict[str, Any],
    max_connections: float | None,
) -> tuple[bool, str, dict[str, Any]]:
    """Determine whether an RDS instance is idle based on configuration and metrics.

    Pure function separating RDS idle evaluation logic from AWS I/O.

    Returns:
        (is_idle, reason, evidence)
    """
    db_id = instance.get("DBInstanceIdentifier", "unknown")
    status = instance.get("DBInstanceStatus", "")
    engine = instance.get("Engine", "")
    is_multi_az = instance.get("MultiAZ", False)
    read_replica_source = instance.get("ReadReplicaSourceDBInstanceIdentifier")
    read_replica_ids = instance.get("ReadReplicaDBInstanceIdentifiers", [])
    cluster_id = instance.get("DBClusterIdentifier")
    instance_class = instance.get("DBInstanceClass", "unknown")

    evidence: dict[str, Any] = {
        "db_instance_id": db_id,
        "status": status,
        "engine": engine,
        "multi_az": is_multi_az,
        "instance_class": instance_class,
        "max_connections": max_connections,
    }

    # 1. State must be 'available'
    if status != "available":
        return False, f"RDS instance {db_id} status is '{status}' (not available)", evidence

    # 2. Skip read replicas
    if read_replica_source:
        return (
            False,
            f"RDS instance {db_id} is a read replica of {read_replica_source}",
            evidence,
        )

    # 3. Skip instances with read replicas
    if read_replica_ids:
        return (
            False,
            f"RDS instance {db_id} has {len(read_replica_ids)} active read replica(s)",
            evidence,
        )

    # 4. Skip Aurora cluster members
    if cluster_id:
        return (
            False,
            f"RDS instance {db_id} belongs to DB cluster '{cluster_id}'",
            evidence,
        )

    # 5. Skip SQL Server Multi-AZ
    if engine.lower().startswith("sqlserver") and is_multi_az:
        return (
            False,
            f"RDS instance {db_id} uses SQL Server in Multi-AZ mode (stop unsupported by AWS)",
            evidence,
        )

    # 6. Check metrics (Invariant I9: Unknown is not idle)
    if max_connections is None:
        return (
            False,
            f"RDS instance {db_id} has no DatabaseConnections metrics (unknown is not idle)",
            evidence,
        )

    if max_connections > 0:
        return (
            False,
            (
                f"RDS instance {db_id} had maximum {max_connections:.0f} connection(s) "
                f"over idle window"
            ),
            evidence,
        )

    return (
        True,
        f"RDS instance {db_id} ({engine}) had 0 database connections over idle window",
        evidence,
    )


class RDSDetector(Detector):
    """Detector for idle Amazon RDS database instances."""

    resource_type: ResourceType = ResourceType.RDS_INSTANCE

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan a region for idle Amazon RDS instances."""
        findings: list[Finding] = []
        try:
            rds = ctx.client("rds", region)
            cw = ctx.client("cloudwatch", region)
        except Exception as e:
            ctx.report_scan_error(f"RDS/CloudWatch client: {e}")
            ctx.logger.warning("Failed to obtain RDS/CloudWatch client", extra={"error": str(e)})
            return []

        now = ctx.clock.now()
        window_hours = ctx.config.thresholds.rds_idle_window_hours
        start_time = now - timedelta(hours=window_hours)

        try:
            instances_iter = paginate(rds, "describe_db_instances", "DBInstances")
            for inst in instances_iter:
                db_id = inst.get("DBInstanceIdentifier", "")
                if not db_id:
                    continue

                # Query CloudWatch DatabaseConnections metric
                max_connections: float | None = None
                try:
                    stats_resp = cw.get_metric_statistics(
                        Namespace="AWS/RDS",
                        MetricName="DatabaseConnections",
                        Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                        StartTime=start_time,
                        EndTime=now,
                        Period=3600,
                        Statistics=["Maximum"],
                    )
                    datapoints = stats_resp.get("Datapoints", [])
                    if datapoints:
                        max_connections = max(dp["Maximum"] for dp in datapoints)
                except Exception as cw_err:
                    ctx.report_scan_error(f"CloudWatch metrics for {db_id}: {cw_err}")
                    ctx.logger.warning(
                        "CloudWatch error for RDS instance",
                        extra={"db_id": db_id, "error": str(cw_err)},
                    )
                    max_connections = None

                is_idle, reason, evidence = is_rds_instance_idle(inst, max_connections)
                if not is_idle:
                    continue
                if inst.get("DBInstanceArn"):
                    evidence["resource_arn"] = inst["DBInstanceArn"]

                tags_list = inst.get("TagList", [])
                tags_dict = {t["Key"]: t.get("Value", "") for t in tags_list if "Key" in t}
                protected, prot_reason = is_protected(
                    tags=tags_dict,
                    resource_id=db_id,
                    config=ctx.config,
                    now=now,
                )

                cost, confidence = monthly_cost(
                    resource_type=ResourceType.RDS_INSTANCE,
                    region=region,
                    instance_class=inst.get("DBInstanceClass"),
                    engine=inst.get("Engine"),
                )

                findings.append(
                    Finding(
                        resource_type=ResourceType.RDS_INSTANCE,
                        resource_id=db_id,
                        region=region,
                        reason=reason,
                        evidence=evidence,
                        est_monthly_cost_usd=cost,
                        cost_confidence=confidence,
                        proposed_action=ActionKind.RDS_STOP,
                        protected=protected,
                        protection_reason=prot_reason,
                        detected_at=now,
                    )
                )
        except (ClientError, BotoCoreError) as e:
            ctx.report_scan_error(f"RDS inventory: {e}")
            # Invariant I9: One failing region never aborts others
            ctx.logger.warning(
                "RDS detection failed in region",
                extra={"region": region, "error": str(e)},
            )
            return findings

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify the live RDS instance state before taking action (Invariant I4)."""
        now = ctx.clock.now()
        try:
            rds = ctx.client("rds", finding.region)
            cw = ctx.client("cloudwatch", finding.region)
            resp = rds.describe_db_instances(DBInstanceIdentifier=finding.resource_id)
            instances = resp.get("DBInstances", [])
            if not instances:
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"RDS instance {finding.resource_id} no longer exists",
                )
            inst = instances[0]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"RDS instance {finding.resource_id} not found",
                )
            # Invariant I9: Unknown is not idle
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe RDS instance {finding.resource_id}: {e}",
            )
        except Exception as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Unexpected error describing RDS instance {finding.resource_id}: {e}",
            )

        # Check live status
        status = inst.get("DBInstanceStatus", "")
        if status != "available":
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"RDS instance {finding.resource_id} status is now '{status}'",
            )

        # Check protection
        tags_list = inst.get("TagList", [])
        tags_dict = {t["Key"]: t.get("Value", "") for t in tags_list if "Key" in t}
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

        # Re-check metric
        window_hours = ctx.config.thresholds.rds_idle_window_hours
        start_time = now - timedelta(hours=window_hours)
        try:
            stats_resp = cw.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName="DatabaseConnections",
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": finding.resource_id}],
                StartTime=start_time,
                EndTime=now,
                Period=3600,
                Statistics=["Maximum"],
            )
            datapoints = stats_resp.get("Datapoints", [])
            if not datapoints:
                # Invariant I9: Unknown is not idle
                return RecheckResult(
                    still_idle=None,
                    protected=False,
                    reason="Missing DatabaseConnections metric data during recheck",
                )
            max_connections = max(dp["Maximum"] for dp in datapoints)
            if max_connections > 0:
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"Active database connections detected ({max_connections:.0f})",
                )
        except Exception as cw_err:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to recheck CloudWatch metrics: {cw_err}",
            )

        return RecheckResult(
            still_idle=True,
            protected=False,
            reason="RDS instance still has 0 connections and is unprotected",
        )


class RDSStopAction(Action):
    """Stop an idle Amazon RDS database instance."""

    kind: ActionKind = ActionKind.RDS_STOP

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Stop the RDS DB instance. Note that AWS auto-restarts after 7 days."""
        # Invariant I1: Never mutate when dry_run is true
        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=(
                    f"DRY RUN: would stop RDS instance {finding.resource_id} in {finding.region}. "
                    f"Note: AWS will automatically restart stopped instances after 7 days."
                ),
            )

        try:
            rds = ctx.client("rds", finding.region)
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to obtain RDS client in {finding.region}",
                error=str(e),
            )

        try:
            rds.stop_db_instance(DBInstanceIdentifier=finding.resource_id)
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to stop RDS instance {finding.resource_id}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )

        return ActionResult(
            ok=True,
            performed=True,
            detail=(
                f"Successfully stopped RDS DB instance {finding.resource_id}. "
                f"Note: AWS will automatically restart it after 7 days."
            ),
        )


DETECTORS = [RDSDetector()]
ACTIONS = {ActionKind.RDS_STOP: RDSStopAction()}
