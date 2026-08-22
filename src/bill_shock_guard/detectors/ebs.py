"""EBS volume idle detector and snapshot-before-delete action.

Detects unattached EBS volumes in 'available' state that have been idle
for longer than ebs_unattached_days (default 7 days).

Action: ebs_delete_after_snapshot creates a tagged snapshot, waits for it
to reach 'completed' state, and only then deletes the volume (Invariant I6).
"""

import time
from collections.abc import Callable
from datetime import datetime, timezone
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

BSG_CREATED_BY_TAG = "bsg:created-by"
BSG_CREATED_BY_VALUE = "bill-shock-guard"
BSG_SOURCE_VOLUME_TAG = "bsg:source-volume-id"


def is_ebs_volume_idle(
    volume: dict[str, Any],
    now: datetime,
    unattached_days: int = 7,
    first_seen: datetime | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Determine whether an EBS volume is idle based on state and unattached duration.

    Pure function separating idle evaluation logic from AWS I/O.

    Returns:
        (is_idle, reason, evidence)
    """
    state = volume.get("State", "")
    attachments = volume.get("Attachments", [])
    volume_id = volume.get("VolumeId", "unknown")
    size_gib = volume.get("Size", 0)
    volume_type = volume.get("VolumeType", "unknown")
    create_time = volume.get("CreateTime")

    evidence: dict[str, Any] = {
        "volume_id": volume_id,
        "state": state,
        "size_gib": size_gib,
        "volume_type": volume_type,
        "attachments_count": len(attachments),
    }
    if create_time is not None:
        if isinstance(create_time, datetime):
            evidence["create_time"] = create_time.isoformat()
        else:
            evidence["create_time"] = str(create_time)

    # 1. State must be available (unattached)
    if state != "available":
        return False, f"Volume {volume_id} is in state '{state}' (not available)", evidence

    # 2. Attachments must be empty
    if attachments:
        return (
            False,
            f"Volume {volume_id} has {len(attachments)} active attachment(s)",
            evidence,
        )

    # Ensure now is UTC-aware
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # 3. Check first_seen if provided (from finding state tracking)
    if first_seen is not None:
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        evidence["first_seen"] = first_seen.isoformat()
        unattached_seconds = (now - first_seen).total_seconds()
        unattached_duration_days = unattached_seconds / 86400.0
        evidence["unattached_days_observed"] = round(unattached_duration_days, 2)
        if unattached_duration_days < float(unattached_days):
            return (
                False,
                (
                    f"Volume {volume_id} unattached for {unattached_duration_days:.1f} days, "
                    f"below threshold of {unattached_days} days"
                ),
                evidence,
            )
        return (
            True,
            (
                f"Volume {volume_id} ({size_gib} GiB {volume_type}) unattached for "
                f"{unattached_duration_days:.1f} days (threshold: {unattached_days} days)"
            ),
            evidence,
        )

    # 4. Fallback if first_seen is not yet tracked: check CreateTime
    if isinstance(create_time, datetime):
        if create_time.tzinfo is None:
            create_time = create_time.replace(tzinfo=timezone.utc)
        creation_age_days = (now - create_time).total_seconds() / 86400.0
        evidence["creation_age_days"] = round(creation_age_days, 2)
        if creation_age_days < float(unattached_days):
            return (
                False,
                (
                    f"Volume {volume_id} created {creation_age_days:.1f} days ago, "
                    f"below threshold of {unattached_days} days"
                ),
                evidence,
            )
        return (
            True,
            (
                f"Volume {volume_id} ({size_gib} GiB {volume_type}) is unattached and created "
                f"{creation_age_days:.1f} days ago (threshold: {unattached_days} days)"
            ),
            evidence,
        )

    # If neither first_seen nor CreateTime is available, available volume is considered idle
    return (
        True,
        f"Volume {volume_id} ({size_gib} GiB {volume_type}) is unattached (available)",
        evidence,
    )


class EBSDetector(Detector):
    """Detector for unattached EBS volumes."""

    resource_type: ResourceType = ResourceType.EBS_VOLUME

    def __init__(
        self,
        first_seen_lookup: Callable[[str], datetime | None] | None = None,
    ) -> None:
        self._first_seen_lookup = first_seen_lookup

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan a region for unattached EBS volumes."""
        findings: list[Finding] = []
        try:
            ec2 = ctx.client("ec2", region)
        except Exception as e:
            ctx.report_scan_error(f"EBS client: {e}")
            ctx.logger.warning("Failed to obtain EC2 client for region", extra={"error": str(e)})
            return []

        now = ctx.clock.now()
        unattached_threshold_days = ctx.config.thresholds.ebs_unattached_days

        try:
            volumes_iter = paginate(ec2, "describe_volumes", "Volumes")
            for volume in volumes_iter:
                volume_id = volume.get("VolumeId", "")
                if not volume_id:
                    continue

                first_seen = self._first_seen_lookup(volume_id) if self._first_seen_lookup else None
                is_idle, reason, evidence = is_ebs_volume_idle(
                    volume=volume,
                    now=now,
                    unattached_days=unattached_threshold_days,
                    first_seen=first_seen,
                )

                if not is_idle:
                    continue

                tags_dict = {
                    t["Key"]: t.get("Value", "") for t in volume.get("Tags", []) if "Key" in t
                }
                protected, prot_reason = is_protected(
                    tags=tags_dict,
                    resource_id=volume_id,
                    config=ctx.config,
                    now=now,
                )

                size_gib = volume.get("Size", 0)
                volume_type = volume.get("VolumeType", "gp3")
                cost, confidence = monthly_cost(
                    resource_type=ResourceType.EBS_VOLUME,
                    region=region,
                    size_gib=size_gib,
                    size_gb=size_gib,
                    volume_type=volume_type,
                )

                findings.append(
                    Finding(
                        resource_type=ResourceType.EBS_VOLUME,
                        resource_id=volume_id,
                        region=region,
                        reason=reason,
                        evidence=evidence,
                        est_monthly_cost_usd=cost,
                        cost_confidence=confidence,
                        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
                        protected=protected,
                        protection_reason=prot_reason,
                        detected_at=now,
                    )
                )
        except (ClientError, BotoCoreError) as e:
            ctx.report_scan_error(f"EBS inventory: {e}")
            # Invariant I9: One failing region/detector never aborts others
            ctx.logger.warning(
                "EBS detection failed in region",
                extra={"region": region, "error": str(e)},
            )
            return findings

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify the live EBS volume state immediately before any action (Invariant I4)."""
        now = ctx.clock.now()
        try:
            ec2 = ctx.client("ec2", finding.region)
            resp = ec2.describe_volumes(VolumeIds=[finding.resource_id])
            volumes = resp.get("Volumes", [])
            if not volumes:
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"EBS volume {finding.resource_id} no longer exists",
                )
            vol = volumes[0]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("InvalidVolume.NotFound", "InvalidParameterValue"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"EBS volume {finding.resource_id} not found",
                )
            # Invariant I9: Unknown is not idle
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe EBS volume {finding.resource_id}: {e}",
            )
        except Exception as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Unexpected error describing EBS volume {finding.resource_id}: {e}",
            )

        # Check live state
        state = vol.get("State", "")
        attachments = vol.get("Attachments", [])
        if state != "available" or attachments:
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=(
                    f"EBS volume {finding.resource_id} is no longer idle (state='{state}', "
                    f"attachments={len(attachments)})"
                ),
            )

        # Check protection fresh
        tags_dict = {t["Key"]: t.get("Value", "") for t in vol.get("Tags", []) if "Key" in t}
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

        return RecheckResult(
            still_idle=True,
            protected=False,
            reason=f"EBS volume {finding.resource_id} is still available and unprotected",
        )


class EBSDeleteAfterSnapshotAction(Action):
    """Safely delete unattached volume only after snapshot reaches completed (Invariant I6)."""

    kind: ActionKind = ActionKind.EBS_DELETE_AFTER_SNAPSHOT

    def __init__(
        self,
        sleeper: Callable[[float], None] = time.sleep,
        poll_interval_sec: float = 2.0,
        max_polls: int = 30,
    ) -> None:
        self.sleeper = sleeper
        self.poll_interval_sec = poll_interval_sec
        self.max_polls = max_polls

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Create snapshot, wait for 'completed', and only then delete the volume."""
        # Invariant I1: Never perform a mutating AWS call when dry_run is true
        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=(
                    f"DRY RUN: would create snapshot and delete unattached volume "
                    f"{finding.resource_id} in {finding.region}"
                ),
            )

        try:
            ec2 = ctx.client("ec2", finding.region)
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to obtain EC2 client in {finding.region}",
                error=str(e),
            )

        # Step 1: Create snapshot with required tags
        snapshot_id: str | None = None
        try:
            snap_resp = ec2.create_snapshot(
                VolumeId=finding.resource_id,
                Description=f"Bill Shock Guard pre-deletion snapshot for {finding.resource_id}",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": BSG_CREATED_BY_TAG, "Value": BSG_CREATED_BY_VALUE},
                            {"Key": BSG_SOURCE_VOLUME_TAG, "Value": finding.resource_id},
                        ],
                    }
                ],
            )
            snapshot_id = snap_resp.get("SnapshotId")
        except Exception as e:
            # Invariant I6: Any snapshot creation failure prevents volume deletion
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to create snapshot for volume {finding.resource_id}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )

        if not snapshot_id:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"create_snapshot did not return a SnapshotId for {finding.resource_id}",
                error="Missing SnapshotId",
                needs_reconciliation=True,
            )

        # Step 2: Bounded polling for snapshot to reach 'completed'
        snap_state: str = snap_resp.get("State", "pending")
        attempts = 0
        while snap_state != "completed" and attempts < self.max_polls:
            self.sleeper(self.poll_interval_sec)
            attempts += 1
            try:
                desc_resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
                snaps = desc_resp.get("Snapshots", [])
                if not snaps:
                    snap_state = "unknown"
                    break
                snap_state = snaps[0].get("State", "unknown")
                if snap_state == "error":
                    break
            except Exception as e:
                # Invariant I6: Error polling snapshot means no delete
                return ActionResult(
                    ok=False,
                    performed=False,
                    detail=(
                        f"Error polling snapshot {snapshot_id} for volume {finding.resource_id}. "
                        f"Volume was NOT deleted."
                    ),
                    error=str(e),
                    needs_reconciliation=True,
                )

        if snap_state != "completed":
            # Invariant I6: Any snapshot failure or non-completed status means NO delete
            return ActionResult(
                ok=False,
                performed=False,
                detail=(
                    f"Snapshot {snapshot_id} did not reach 'completed' state "
                    f"(current state: '{snap_state}'). "
                    f"Volume {finding.resource_id} was NOT deleted."
                ),
                error=f"Snapshot state '{snap_state}' != 'completed'",
                needs_reconciliation=True,
            )

        # Step 3: Snapshot reached 'completed', proceed to delete volume
        try:
            ec2.delete_volume(VolumeId=finding.resource_id)
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=(
                    f"Snapshot {snapshot_id} completed successfully, but delete_volume failed "
                    f"on {finding.resource_id}"
                ),
                error=str(e),
                needs_reconciliation=True,
            )

        return ActionResult(
            ok=True,
            performed=True,
            detail=(
                f"Successfully created snapshot {snapshot_id} and deleted unattached volume "
                f"{finding.resource_id}"
            ),
        )


DETECTORS = [EBSDetector()]
ACTIONS = {ActionKind.EBS_DELETE_AFTER_SNAPSHOT: EBSDeleteAfterSnapshotAction()}
