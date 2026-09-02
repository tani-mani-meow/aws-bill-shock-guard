"""Tests for EBS volume detector and snapshot-before-delete action."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

from bill_shock_guard.config import Config, Thresholds
from bill_shock_guard.detectors.ebs import (
    BSG_CREATED_BY_TAG,
    BSG_CREATED_BY_VALUE,
    BSG_SOURCE_VOLUME_TAG,
    EBSDeleteAfterSnapshotAction,
    EBSDetector,
    is_ebs_volume_idle,
)
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Finding,
    ResourceType,
)
from tests.fakes.fake_clock import FakeClock


@pytest.fixture
def fake_clock() -> FakeClock:
    # Set fake clock 14 days ahead of system date to simulate aged volumes in moto
    return FakeClock(datetime.now(timezone.utc) + timedelta(days=14))


@pytest.fixture
def scan_context(fake_clock: FakeClock) -> ScanContext:
    cfg = Config(
        dry_run=False,
        thresholds=Thresholds(ebs_unattached_days=7),
    )
    logger = JsonLogger(run_id="test-run", region="us-east-1")
    return ScanContext(
        config=cfg,
        clock=fake_clock,
        account_id="123456789012",
        run_id="test-run-1",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )


# =========================================================================
# Pure Idle Detection Logic Tests
# =========================================================================


def test_is_ebs_volume_idle_unattached_older_than_threshold():
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    vol = {
        "VolumeId": "vol-12345",
        "State": "available",
        "Size": 100,
        "VolumeType": "gp3",
        "Attachments": [],
        "CreateTime": now - timedelta(days=10),
    }
    is_idle, reason, evidence = is_ebs_volume_idle(vol, now=now, unattached_days=7)
    assert is_idle is True
    assert "vol-12345" in reason
    assert evidence["state"] == "available"
    assert evidence["creation_age_days"] == 10.0


def test_is_ebs_volume_idle_unattached_younger_than_threshold():
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    vol = {
        "VolumeId": "vol-too-young",
        "State": "available",
        "Size": 20,
        "VolumeType": "gp2",
        "Attachments": [],
        "CreateTime": now - timedelta(days=3),
    }
    is_idle, reason, evidence = is_ebs_volume_idle(vol, now=now, unattached_days=7)
    assert is_idle is False
    assert "below threshold" in reason


def test_is_ebs_volume_idle_in_use_state():
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    vol = {
        "VolumeId": "vol-in-use",
        "State": "in-use",
        "Size": 50,
        "Attachments": [{"InstanceId": "i-11111"}],
        "CreateTime": now - timedelta(days=20),
    }
    is_idle, reason, evidence = is_ebs_volume_idle(vol, now=now, unattached_days=7)
    assert is_idle is False
    assert "in state 'in-use'" in reason


def test_is_ebs_volume_idle_attachments_present():
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    vol = {
        "VolumeId": "vol-attached",
        "State": "available",  # odd edge case: state available but attachment listed
        "Size": 50,
        "Attachments": [{"InstanceId": "i-22222"}],
        "CreateTime": now - timedelta(days=20),
    }
    is_idle, reason, evidence = is_ebs_volume_idle(vol, now=now, unattached_days=7)
    assert is_idle is False
    assert "active attachment" in reason


def test_is_ebs_volume_idle_with_first_seen_override():
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    vol = {
        "VolumeId": "vol-first-seen",
        "State": "available",
        "Size": 50,
        "Attachments": [],
        "CreateTime": now - timedelta(days=100),  # created long ago
    }
    # First seen only 2 days ago -> should not be idle yet
    is_idle, reason, _ = is_ebs_volume_idle(
        vol, now=now, unattached_days=7, first_seen=now - timedelta(days=2)
    )
    assert is_idle is False
    assert "below threshold of 7 days" in reason

    # First seen 8 days ago -> should be idle
    is_idle, reason, _ = is_ebs_volume_idle(
        vol, now=now, unattached_days=7, first_seen=now - timedelta(days=8)
    )
    assert is_idle is True
    assert "unattached for 8.0 days" in reason


def test_is_ebs_volume_idle_naive_and_string_datetimes():
    now = datetime(2026, 6, 15, 12, 0, 0)  # naive datetime
    vol = {
        "VolumeId": "vol-naive",
        "State": "available",
        "Size": 30,
        "Attachments": [],
        "CreateTime": "2026-06-01T00:00:00Z",  # string create_time
    }
    # With naive first_seen
    is_idle, _, ev = is_ebs_volume_idle(
        vol, now=now, unattached_days=7, first_seen=datetime(2026, 6, 1, 0, 0, 0)
    )
    assert is_idle is True
    assert ev["create_time"] == "2026-06-01T00:00:00Z"

    # With naive CreateTime and no first_seen
    vol2 = {
        "VolumeId": "vol-naive-dt",
        "State": "available",
        "Attachments": [],
        "CreateTime": datetime(2026, 6, 1, 0, 0, 0),
    }
    is_idle2, _, _ = is_ebs_volume_idle(vol2, now=now, unattached_days=7)
    assert is_idle2 is True

    # With neither first_seen nor CreateTime
    vol3 = {
        "VolumeId": "vol-no-time",
        "State": "available",
        "Attachments": [],
    }
    is_idle3, _, _ = is_ebs_volume_idle(vol3, now=now, unattached_days=7)
    assert is_idle3 is True


# =========================================================================
# Detector Integration Tests with Moto
# =========================================================================


@mock_aws
def test_ebs_detector_detects_unattached_volumes(scan_context: ScanContext):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=50,
        VolumeType="gp3",
    )
    vol_id = vol["VolumeId"]

    detector = EBSDetector()
    findings = detector.detect(scan_context, region="us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == vol_id
    assert f.resource_type == ResourceType.EBS_VOLUME
    assert f.proposed_action == ActionKind.EBS_DELETE_AFTER_SNAPSHOT
    assert f.protected is False
    assert f.protection_reason is None


@mock_aws
def test_ebs_detector_ignores_in_use_volumes(scan_context: ScanContext):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=20,
    )
    vol_id = vol["VolumeId"]

    # Launch instance and attach volume
    inst = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
    )
    inst_id = inst["Instances"][0]["InstanceId"]
    ec2.attach_volume(
        VolumeId=vol_id,
        InstanceId=inst_id,
        Device="/dev/sdf",
    )

    detector = EBSDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 0


@mock_aws
def test_I3_ebs_protected_resource(scan_context: ScanContext):
    """Invariant I3: Protected resources are flagged as protected and never acted on."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=10,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "bsg:keep", "Value": "true"}],
            }
        ],
    )
    detector = EBSDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == vol["VolumeId"]
    assert findings[0].protected is True
    assert "bsg:keep=true" in (findings[0].protection_reason or "")


@mock_aws
def test_I3_ebs_fail_closed_on_invalid_tag_date(scan_context: ScanContext):
    """Invariant I3: Malformed keep tag date fails closed (treats resource as protected)."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=10,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "bsg:keep", "Value": "not-a-date"}],
            }
        ],
    )
    detector = EBSDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == vol["VolumeId"]
    assert findings[0].protected is True
    assert "fail closed" in (findings[0].protection_reason or "").lower()


@mock_aws
def test_ebs_detector_first_seen_lookup_override(scan_context: ScanContext):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)
    vol_id = vol["VolumeId"]

    # First seen is 2 days ago (younger than 7 days)
    detector = EBSDetector(
        first_seen_lookup=lambda vid: scan_context.clock.now() - timedelta(days=2)
    )
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 0

    # First seen is 10 days ago (older than 7 days)
    detector_old = EBSDetector(
        first_seen_lookup=lambda vid: scan_context.clock.now() - timedelta(days=10)
    )
    findings_old = detector_old.detect(scan_context, region="us-east-1")
    assert len(findings_old) == 1
    assert findings_old[0].resource_id == vol_id


def test_ebs_detector_client_exception(scan_context: ScanContext):
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=MagicMock(side_effect=RuntimeError("Client initialization failed")),
    )
    detector = EBSDetector()
    findings = detector.detect(ctx, region="us-east-1")
    assert findings == []


def test_ebs_detector_describe_volumes_client_error(scan_context: ScanContext):
    mock_client = MagicMock()
    mock_client.can_paginate.return_value = False
    mock_client.describe_volumes.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
        "DescribeVolumes",
    )
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )
    detector = EBSDetector()
    findings = detector.detect(ctx, region="us-east-1")
    assert findings == []


@mock_aws
def test_I4_ebs_recheck_detects_state_change(scan_context: ScanContext):
    """Invariant I4: Recheck right before action detects if volume became attached or deleted."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=15)
    vol_id = vol["VolumeId"]

    detector = EBSDetector()
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id=vol_id,
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    # 1. Volume is available
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is True
    assert res.protected is False

    # 2. Add protect tag in between warn and action
    ec2.create_tags(
        Resources=[vol_id],
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )
    res_protected = detector.recheck(scan_context, finding)
    assert res_protected.still_idle is True
    assert res_protected.protected is True

    # 3. Delete volume in between
    ec2.delete_volume(VolumeId=vol_id)
    res_deleted = detector.recheck(scan_context, finding)
    assert res_deleted.still_idle is False
    assert "not found" in res_deleted.reason or "no longer exists" in res_deleted.reason


def test_ebs_recheck_empty_volumes_and_unexpected_exception(scan_context: ScanContext):
    mock_client = MagicMock()
    mock_client.describe_volumes.return_value = {"Volumes": []}
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )
    detector = EBSDetector()
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-none",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "no longer exists" in res.reason

    # Unexpected exception
    mock_client.describe_volumes.side_effect = RuntimeError("Crash")
    res_err = detector.recheck(ctx, finding)
    assert res_err.still_idle is None
    assert "Unexpected error" in res_err.reason


def test_ebs_recheck_volume_attached(scan_context: ScanContext):
    mock_client = MagicMock()
    mock_client.describe_volumes.return_value = {
        "Volumes": [
            {
                "VolumeId": "vol-attached",
                "State": "in-use",
                "Attachments": [{"InstanceId": "i-12345"}],
                "Tags": [],
            }
        ]
    }
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )
    detector = EBSDetector()
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-attached",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "no longer idle" in res.reason


@mock_aws
def test_I9_ebs_api_failure_returns_unknown(scan_context: ScanContext):
    """Invariant I9: Unknown is not idle. Client error returns still_idle=None."""
    detector = EBSDetector()
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-fake",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    mock_client = MagicMock()
    mock_client.describe_volumes.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AuthFailure", "Message": "AWS was not able to validate credentials"}},
        "DescribeVolumes",
    )
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )

    res = detector.recheck(ctx, finding)
    assert res.still_idle is None  # Unknown blocks action per I9


# =========================================================================
# Action Tests: EBSDeleteAfterSnapshotAction
# =========================================================================


@mock_aws
def test_I1_ebs_dry_run_never_mutates(scan_context: ScanContext):
    """Invariant I1: Never perform a mutating AWS call when dry_run is true."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)
    vol_id = vol["VolumeId"]

    dry_ctx = ScanContext(
        config=Config(dry_run=True),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=scan_context.client_factory,
    )

    action = EBSDeleteAfterSnapshotAction(sleeper=lambda s: None)
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id=vol_id,
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    result = action.apply(dry_ctx, finding)
    assert result.ok is True
    assert result.performed is False
    assert "DRY RUN" in result.detail

    vols = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"]
    assert len(vols) == 1
    snaps = ec2.describe_snapshots(
        Filters=[{"Name": f"tag:{BSG_CREATED_BY_TAG}", "Values": [BSG_CREATED_BY_VALUE]}]
    )["Snapshots"]
    assert len(snaps) == 0


@mock_aws
def test_I6_ebs_delete_requires_completed_snapshot(scan_context: ScanContext):
    """Invariant I6: Creates tagged snapshot, waits for completed, then deletes volume."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=25)
    vol_id = vol["VolumeId"]

    sleeps: list[float] = []
    action = EBSDeleteAfterSnapshotAction(sleeper=sleeps.append, poll_interval_sec=0.1)

    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id=vol_id,
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    result = action.apply(scan_context, finding)
    assert result.ok is True
    assert result.performed is True
    assert "Successfully created snapshot" in result.detail

    snaps = ec2.describe_snapshots(
        Filters=[{"Name": f"tag:{BSG_CREATED_BY_TAG}", "Values": [BSG_CREATED_BY_VALUE]}]
    )["Snapshots"]
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap["State"] == "completed"
    tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
    assert tags.get(BSG_CREATED_BY_TAG) == BSG_CREATED_BY_VALUE
    assert tags.get(BSG_SOURCE_VOLUME_TAG) == vol_id

    with pytest.raises(botocore.exceptions.ClientError) as exc:
        ec2.describe_volumes(VolumeIds=[vol_id])
    assert "InvalidVolume.NotFound" in str(exc.value)


@mock_aws
def test_I6_snapshot_failure_prevents_volume_deletion(scan_context: ScanContext):
    """Invariant I6: Any snapshot creation failure means volume is NOT deleted."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)
    vol_id = vol["VolumeId"]

    real_client = boto3.client("ec2", region_name="us-east-1")
    mock_client = MagicMock(wraps=real_client)
    mock_client.create_snapshot.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "SnapshotLimitExceeded", "Message": "Limit exceeded"}},
        "CreateSnapshot",
    )

    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )

    action = EBSDeleteAfterSnapshotAction(sleeper=lambda s: None)
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id=vol_id,
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is False
    assert result.performed is False
    assert "Failed to create snapshot" in result.detail

    vols = real_client.describe_volumes(VolumeIds=[vol_id])["Volumes"]
    assert len(vols) == 1


@mock_aws
def test_I6_snapshot_error_prevents_volume_deletion(scan_context: ScanContext):
    """Invariant I6: If snapshot enters 'error' state during polling, volume is NOT deleted."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)
    vol_id = vol["VolumeId"]

    real_client = boto3.client("ec2", region_name="us-east-1")
    mock_client = MagicMock(wraps=real_client)
    mock_client.create_snapshot.return_value = {
        "SnapshotId": "snap-error-test",
        "State": "pending",
    }
    mock_client.describe_snapshots.return_value = {
        "Snapshots": [{"SnapshotId": "snap-error-test", "State": "error"}]
    }

    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )

    sleeps: list[float] = []
    action = EBSDeleteAfterSnapshotAction(sleeper=sleeps.append, max_polls=5)
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id=vol_id,
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is False
    assert result.performed is False
    assert "Volume vol-" in result.detail and "was NOT deleted" in result.detail
    mock_client.delete_volume.assert_not_called()
    vols = real_client.describe_volumes(VolumeIds=[vol_id])["Volumes"]
    assert len(vols) == 1


@mock_aws
def test_I6_snapshot_timeout_prevents_volume_deletion(scan_context: ScanContext):
    """Invariant I6: Bounded polling timeout stops action and never deletes volume."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)
    vol_id = vol["VolumeId"]

    real_client = boto3.client("ec2", region_name="us-east-1")
    mock_client = MagicMock(wraps=real_client)
    mock_client.create_snapshot.return_value = {
        "SnapshotId": "snap-slow-test",
        "State": "pending",
    }
    mock_client.describe_snapshots.return_value = {
        "Snapshots": [{"SnapshotId": "snap-slow-test", "State": "pending"}]
    }

    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )

    sleeps: list[float] = []
    action = EBSDeleteAfterSnapshotAction(sleeper=sleeps.append, max_polls=3)
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id=vol_id,
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is False
    assert result.performed is False
    assert "did not reach 'completed'" in result.detail
    assert len(sleeps) == 3
    mock_client.delete_volume.assert_not_called()
    vols = real_client.describe_volumes(VolumeIds=[vol_id])["Volumes"]
    assert len(vols) == 1


def test_ebs_action_client_factory_error(scan_context: ScanContext):
    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=MagicMock(side_effect=RuntimeError("EC2 connection failure")),
    )
    action = EBSDeleteAfterSnapshotAction()
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-test",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert "Failed to obtain EC2 client" in res.detail


def test_ebs_action_missing_snapshot_id(scan_context: ScanContext):
    mock_client = MagicMock()
    mock_client.create_snapshot.return_value = {"State": "pending"}  # no SnapshotId
    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )
    action = EBSDeleteAfterSnapshotAction()
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-test",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert "did not return a SnapshotId" in res.detail


def test_ebs_action_polling_empty_snapshots_and_polling_exception(
    scan_context: ScanContext,
):
    mock_client = MagicMock()
    mock_client.create_snapshot.return_value = {
        "SnapshotId": "snap-poll-empty",
        "State": "pending",
    }
    mock_client.describe_snapshots.return_value = {"Snapshots": []}
    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )
    action = EBSDeleteAfterSnapshotAction(sleeper=lambda s: None, max_polls=2)
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-test",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert "did not reach 'completed'" in res.detail

    # Polling exception
    mock_client.describe_snapshots.side_effect = RuntimeError("Network error")
    res_err = action.apply(ctx, finding)
    assert res_err.ok is False
    assert "Error polling snapshot" in res_err.detail


def test_ebs_action_delete_volume_fails_after_snapshot(scan_context: ScanContext):
    mock_client = MagicMock()
    mock_client.create_snapshot.return_value = {
        "SnapshotId": "snap-ok",
        "State": "completed",
    }
    mock_client.delete_volume.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "VolumeInUse", "Message": "Volume is attached"}},
        "DeleteVolume",
    )
    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_client,
    )
    action = EBSDeleteAfterSnapshotAction(sleeper=lambda s: None)
    finding = Finding(
        resource_type=ResourceType.EBS_VOLUME,
        resource_id="vol-fail-del",
        region="us-east-1",
        reason="Unattached",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.EBS_DELETE_AFTER_SNAPSHOT,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert "delete_volume failed" in res.detail
