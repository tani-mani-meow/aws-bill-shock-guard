"""Unit and integration tests for Elastic IP detector, recheck, and release action."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import boto3
import moto
import pytest
from botocore.exceptions import ClientError

from bill_shock_guard.config import Config
from bill_shock_guard.detectors.eip import (
    EIPDetector,
    EIPReleaseAction,
    check_eip_protection,
    is_eip_idle,
    is_eip_unassociated,
)
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Finding,
    ResourceType,
)
from tests.conftest import MOTO_ACCOUNT_ID
from tests.fakes.fake_clock import FakeClock


def _make_context(
    config: Config | None = None,
    clock: FakeClock | None = None,
    region: str = "us-east-1",
) -> ScanContext:
    cfg = config or Config()
    clk = clock or FakeClock()

    def client_factory(service_name: str, region_name: str) -> Any:
        return boto3.client(service_name, region_name=region_name)

    return ScanContext(
        config=cfg,
        clock=clk,
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run-eip",
        logger=JsonLogger(run_id="test-run-eip", region=region),
        client_factory=client_factory,
    )


# ---------------------------------------------------------------------------
# Pure function tests (without moto or AWS I/O)
# ---------------------------------------------------------------------------


def test_is_eip_unassociated_when_unattached() -> None:
    addr: dict[str, Any] = {
        "AllocationId": "eipalloc-12345",
        "PublicIp": "1.2.3.4",
        "AssociationId": None,
        "InstanceId": None,
        "NetworkInterfaceId": None,
    }
    assert is_eip_unassociated(addr) is True


def test_is_eip_unassociated_false_when_associated() -> None:
    addr = {"AllocationId": "eipalloc-1", "AssociationId": "eipassoc-1"}
    assert is_eip_unassociated(addr) is False


def test_is_eip_unassociated_false_when_instance_attached() -> None:
    addr = {"AllocationId": "eipalloc-1", "InstanceId": "i-12345"}
    assert is_eip_unassociated(addr) is False


def test_is_eip_unassociated_false_when_eni_attached() -> None:
    addr = {"AllocationId": "eipalloc-1", "NetworkInterfaceId": "eni-12345"}
    assert is_eip_unassociated(addr) is False


def test_is_eip_idle_first_seen_under_grace() -> None:
    """EIP first_seen logic: if unattached for less than grace_hours, idle check fails."""
    now = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    first_seen = now - timedelta(hours=10)
    addr: dict[str, Any] = {"AllocationId": "eipalloc-1"}

    assert is_eip_idle(addr, first_seen=first_seen, now=now, min_age_hours=24) is False


def test_is_eip_idle_first_seen_over_grace() -> None:
    """EIP first_seen logic: if unattached for at least grace_hours, idle check succeeds."""
    now = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    first_seen = now - timedelta(hours=25)
    addr: dict[str, Any] = {"AllocationId": "eipalloc-1"}

    assert is_eip_idle(addr, first_seen=first_seen, now=now, min_age_hours=24) is True


def test_is_eip_idle_without_first_seen() -> None:
    addr: dict[str, Any] = {"AllocationId": "eipalloc-1"}
    assert is_eip_idle(addr) is True

    addr_associated = {"AllocationId": "eipalloc-1", "AssociationId": "eipassoc-1"}
    assert is_eip_idle(addr_associated) is False


def test_check_eip_protection_tag_true() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()
    tags = {"bsg:keep": "true"}
    prot, reason = check_eip_protection("eipalloc-123", tags, "1.2.3.4", config, now)
    assert prot is True
    assert reason is not None
    assert "bsg:keep=true" in reason


def test_check_eip_protection_ignore_id() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Ignored by AllocationId
    config_alloc = Config(ignore_resource_ids=["eipalloc-123"])
    prot, reason = check_eip_protection("eipalloc-123", {}, "1.2.3.4", config_alloc, now)
    assert prot is True
    assert reason is not None
    assert "ignore_resource_ids" in reason

    # Ignored by PublicIp
    config_ip = Config(ignore_resource_ids=["1.2.3.4"])
    prot, reason = check_eip_protection("eipalloc-123", {}, "1.2.3.4", config_ip, now)
    assert prot is True
    assert reason is not None
    assert "1.2.3.4" in reason


def test_check_eip_protection_invalid_tag_date_fail_closed() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()
    tags = {"bsg:keep": "invalid-date"}
    prot, reason = check_eip_protection("eipalloc-123", tags, "1.2.3.4", config, now)
    assert prot is True
    assert reason is not None
    assert "fail closed" in reason


# ---------------------------------------------------------------------------
# Integration tests with moto: EIP detection, recheck, and release action
# ---------------------------------------------------------------------------


@moto.mock_aws
def test_eip_detect_unassociated_address() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]

    detector = EIPDetector()
    findings = detector.detect(ctx, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == alloc_id
    assert f.resource_type == ResourceType.ELASTIC_IP
    assert f.proposed_action == ActionKind.EIP_RELEASE
    assert f.protected is False
    assert f.protection_reason is None
    assert "unassociated" in f.reason


@moto.mock_aws
def test_eip_detect_associated_address_ignored() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    # Launch instance and associate EIP
    run_resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
    instance_id = run_resp["Instances"][0]["InstanceId"]

    alloc = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=alloc["AllocationId"], InstanceId=instance_id)

    detector = EIPDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 0


@moto.mock_aws
def test_I3_eip_detect_protected_by_tag() -> None:
    """EIP tagged bsg:keep=true is flagged as protected."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {
                "ResourceType": "elastic-ip",
                "Tags": [{"Key": "bsg:keep", "Value": "true"}],
            }
        ],
    )

    detector = EIPDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "bsg:keep=true" in (findings[0].protection_reason or "")


@moto.mock_aws
def test_I3_eip_detect_protected_by_ignore_id() -> None:
    clock = FakeClock()
    ec2 = boto3.client("ec2", region_name="us-east-1")
    alloc = ec2.allocate_address(Domain="vpc")

    config = Config(ignore_resource_ids=[alloc["AllocationId"]])
    ctx = _make_context(config=config, clock=clock)

    detector = EIPDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "ignore_resource_ids" in (findings[0].protection_reason or "")


@moto.mock_aws
def test_eip_detect_invalid_tag_date_fail_closed() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {
                "ResourceType": "elastic-ip",
                "Tags": [{"Key": "bsg:keep", "Value": "2026-99-99"}],
            }
        ],
    )

    detector = EIPDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "fail closed" in (findings[0].protection_reason or "")


# ---------------------------------------------------------------------------
# Recheck tests
# ---------------------------------------------------------------------------


@moto.mock_aws
def test_eip_recheck_still_unassociated() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=alloc_id,
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is True
    assert recheck.protected is False
    assert "still unassociated" in recheck.reason


@moto.mock_aws
def test_I4_eip_recheck_detects_association_and_blocks_action() -> None:
    """Invariant I4: if EIP is associated between warning and action, recheck detects it."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    run_resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
    instance_id = run_resp["Instances"][0]["InstanceId"]

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]

    # EIP is associated before recheck
    ec2.associate_address(AllocationId=alloc_id, InstanceId=instance_id)

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=alloc_id,
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert recheck.protected is False
    assert "now associated" in recheck.reason


@moto.mock_aws
def test_eip_recheck_released_in_meantime() -> None:
    """If address was already released, recheck returns still_idle=False."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]
    ec2.release_address(AllocationId=alloc_id)

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=alloc_id,
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert "not found" in recheck.reason


@moto.mock_aws
def test_I10_eip_recheck_race_tag_added_after_warning() -> None:
    """Invariant I10: adding keep tag between warning and action blocks release."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]

    # User adds keep tag before action
    ec2.create_tags(
        Resources=[alloc_id],
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=alloc_id,
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.protected is True
    assert "bsg:keep=true" in recheck.reason


def test_I9_eip_recheck_api_error_returns_none() -> None:
    """Invariant I9: API error during recheck returns still_idle=None (unknown is not idle)."""
    clock = FakeClock()
    mock_ec2 = MagicMock()
    mock_ec2.describe_addresses.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Access Denied"}},
        "DescribeAddresses",
    )

    def client_factory(service: str, reg: str) -> Any:
        return mock_ec2

    ctx = ScanContext(
        config=Config(),
        clock=clock,
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=client_factory,
    )

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id="eipalloc-12345",
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is None
    assert "Failed to describe" in recheck.reason


# ---------------------------------------------------------------------------
# Release action tests
# ---------------------------------------------------------------------------


@moto.mock_aws
def test_I1_eip_release_dry_run_does_not_mutate() -> None:
    """Invariant I1: Never perform a mutating AWS call when dry_run is true."""
    clock = FakeClock()
    config = Config(dry_run=True)
    ctx = _make_context(config=config, clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]

    action = EIPReleaseAction()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=alloc_id,
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is True
    assert result.performed is False
    assert "DRY RUN" in result.detail

    # Verify address is still allocated
    addrs = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"]
    assert len(addrs) == 1


@moto.mock_aws
def test_eip_release_mutates_when_dry_run_false() -> None:
    """When dry_run is false, unassociated address is released."""
    clock = FakeClock()
    config = Config(dry_run=False)
    ctx = _make_context(config=config, clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]

    action = EIPReleaseAction()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=alloc_id,
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is True
    assert result.performed is True
    assert "Released Elastic IP" in result.detail

    # Verify address is released
    with pytest.raises(ClientError) as exc_info:
        ec2.describe_addresses(AllocationIds=[alloc_id])
    assert exc_info.value.response["Error"]["Code"] == "InvalidAllocationID.NotFound"


@moto.mock_aws
def test_eip_release_api_error_returns_failure() -> None:
    clock = FakeClock()
    config = Config(dry_run=False)
    ctx = _make_context(config=config, clock=clock)

    action = EIPReleaseAction()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id="eipalloc-nonexistent999",
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is False
    assert result.performed is False
    assert result.error is not None


def test_is_eip_idle_naive_datetimes() -> None:
    now = datetime(2026, 1, 2, 12, 0, 0)
    first_seen = datetime(2026, 1, 1, 10, 0, 0)
    addr: dict[str, Any] = {"AllocationId": "eipalloc-1"}
    assert is_eip_idle(addr, first_seen=first_seen, now=now, min_age_hours=24) is True


def test_eip_detect_describe_addresses_error_returns_empty() -> None:
    mock_ec2 = MagicMock()
    mock_ec2.can_paginate.return_value = False
    mock_ec2.describe_addresses.side_effect = RuntimeError("EC2 network error")

    ctx = ScanContext(
        config=Config(),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    detector = EIPDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []


def test_eip_recheck_public_ip_legacy() -> None:
    mock_ec2 = MagicMock()
    mock_ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "PublicIp": "198.51.100.1",
                "AssociationId": None,
                "InstanceId": None,
                "NetworkInterfaceId": None,
                "Tags": [],
            }
        ]
    }

    ctx = ScanContext(
        config=Config(),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id="198.51.100.1",
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=FakeClock().now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is True
    assert recheck.protected is False
    mock_ec2.describe_addresses.assert_called_once_with(PublicIps=["198.51.100.1"])


def test_eip_recheck_empty_addresses_returns_not_found() -> None:
    mock_ec2 = MagicMock()
    mock_ec2.describe_addresses.return_value = {"Addresses": []}

    ctx = ScanContext(
        config=Config(),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    detector = EIPDetector()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id="eipalloc-empty",
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=FakeClock().now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert "not found" in recheck.reason


def test_eip_release_public_ip_legacy() -> None:
    mock_ec2 = MagicMock()

    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    action = EIPReleaseAction()
    finding = Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id="198.51.100.2",
        region="us-east-1",
        reason="unassociated",
        evidence={},
        est_monthly_cost_usd=3.65,
        cost_confidence="estimate",
        proposed_action=ActionKind.EIP_RELEASE,
        protected=False,
        protection_reason=None,
        detected_at=FakeClock().now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is True
    assert result.performed is True
    mock_ec2.release_address.assert_called_once_with(PublicIp="198.51.100.2")
