"""Tests for NAT Gateway detector, pure idle logic, recheck, and deletion action."""

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import botocore.exceptions
import moto

from bill_shock_guard.config import Config
from bill_shock_guard.detectors.nat import (
    NatDeleteAction,
    NatGatewayDetector,
    evaluate_nat_gateway_idle,
)
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Finding,
    ResourceType,
)
from tests.fakes.fake_clock import FakeClock

# =====================================================================
# Pure Decision Logic Tests
# =====================================================================


def test_evaluate_nat_gateway_idle_zero_bytes() -> None:
    """Zero BytesOutToDestination over window indicates an idle NAT gateway."""
    is_idle, reason = evaluate_nat_gateway_idle("available", [0.0, 0.0, 0.0])
    assert is_idle is True
    assert "Zero bytes" in reason


def test_evaluate_nat_gateway_idle_nonzero_bytes() -> None:
    """Non-zero traffic indicates an active (not idle) NAT gateway."""
    is_idle, reason = evaluate_nat_gateway_idle("available", [0.0, 1024.0, 0.0])
    assert is_idle is False
    assert "Active traffic detected" in reason
    assert "1024 bytes" in reason


def test_evaluate_nat_gateway_idle_no_datapoints_I9() -> None:
    """Invariant I9: No metric datapoints means status is unknown (None), not idle."""
    is_idle, reason = evaluate_nat_gateway_idle("available", [])
    assert is_idle is None
    assert "No CloudWatch" in reason

    is_idle_none, reason_none = evaluate_nat_gateway_idle("available", None)
    assert is_idle_none is None
    assert "No CloudWatch" in reason_none


def test_evaluate_nat_gateway_idle_non_available_state() -> None:
    """NAT gateways not in 'available' state are not treated as idle."""
    for state in ["pending", "deleting", "deleted"]:
        is_idle, reason = evaluate_nat_gateway_idle(state, [0.0])
        assert is_idle is False
        assert "expected 'available'" in reason


def test_evaluate_nat_gateway_idle_negative_values() -> None:
    """Malformed negative byte counts are treated as unknown (None)."""
    is_idle, reason = evaluate_nat_gateway_idle("available", [-100.0])
    assert is_idle is None
    assert "negative" in reason.lower()


# =====================================================================
# Moto Helpers & Test Context Setup
# =====================================================================


def _make_context(
    clock: FakeClock,
    config: Config | None = None,
    client_factory: Any = None,
) -> ScanContext:
    cfg = config or Config()
    cf = client_factory or (lambda svc, reg: boto3.client(svc, region_name=reg))
    return ScanContext(
        config=cfg,
        clock=clock,
        account_id="123456789012",
        run_id="test-nat-run",
        logger=JsonLogger(run_id="test-nat-run", region="us-east-1"),
        client_factory=cf,
    )


def _setup_vpc_and_nat(ec2: Any) -> tuple[str, str, str]:
    """Helper to provision VPC, Subnet, EIP, and NAT Gateway in moto."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    eip = ec2.allocate_address(Domain="vpc")
    nat = ec2.create_nat_gateway(
        SubnetId=subnet["SubnetId"],
        AllocationId=eip["AllocationId"],
    )["NatGateway"]
    return nat["NatGatewayId"], eip["AllocationId"], subnet["SubnetId"]


# =====================================================================
# Detector Moto Tests
# =====================================================================


def test_nat_detector_idle_detected(fake_clock: FakeClock) -> None:
    """NAT gateway with 0 bytes traffic over the idle window is detected."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NATGateway",
            MetricData=[
                {
                    "MetricName": "BytesOutToDestination",
                    "Dimensions": [{"Name": "NatGatewayId", "Value": nat_id}],
                    "Timestamp": now - timedelta(hours=2),
                    "Value": 0.0,
                    "Unit": "Bytes",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        finding = findings[0]
        assert finding.resource_type == ResourceType.NAT_GATEWAY
        assert finding.resource_id == nat_id
        assert finding.region == "us-east-1"
        assert finding.proposed_action == ActionKind.NAT_DELETE
        assert finding.protected is False
        assert finding.evidence["bytes_out_sum"] == 0.0


def test_nat_detector_active_traffic_ignored(fake_clock: FakeClock) -> None:
    """NAT gateway with active traffic (> 0 bytes) is not flagged as idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NATGateway",
            MetricData=[
                {
                    "MetricName": "BytesOutToDestination",
                    "Dimensions": [{"Name": "NatGatewayId", "Value": nat_id}],
                    "Timestamp": now - timedelta(hours=2),
                    "Value": 50000.0,
                    "Unit": "Bytes",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        findings = detector.detect(ctx, "us-east-1")
        assert len(findings) == 0


def test_I9_nat_detector_no_metrics_ignored(fake_clock: FakeClock) -> None:
    """Invariant I9: NAT gateway with missing metrics is unknown, so not flagged."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)
        # Note: No CloudWatch metrics put for this NAT gateway

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        findings = detector.detect(ctx, "us-east-1")
        assert len(findings) == 0


def test_I3_nat_detector_protect_tag(fake_clock: FakeClock) -> None:
    """Protected NAT gateway is still detected as a finding, marked protected=True."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        ec2.create_tags(
            Resources=[nat_id],
            Tags=[{"Key": "bsg:keep", "Value": "true"}],
        )

        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NATGateway",
            MetricData=[
                {
                    "MetricName": "BytesOutToDestination",
                    "Dimensions": [{"Name": "NatGatewayId", "Value": nat_id}],
                    "Timestamp": now - timedelta(hours=2),
                    "Value": 0.0,
                    "Unit": "Bytes",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        finding = findings[0]
        assert finding.protected is True
        assert "bsg:keep=true" in (finding.protection_reason or "")


def test_I3_nat_detector_ignored_by_config(fake_clock: FakeClock) -> None:
    """NAT gateway listed in ignore_resource_ids is marked protected."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NATGateway",
            MetricData=[
                {
                    "MetricName": "BytesOutToDestination",
                    "Dimensions": [{"Name": "NatGatewayId", "Value": nat_id}],
                    "Timestamp": now - timedelta(hours=2),
                    "Value": 0.0,
                    "Unit": "Bytes",
                }
            ],
        )

        config = Config(ignore_resource_ids=[nat_id])
        ctx = _make_context(fake_clock, config=config)
        detector = NatGatewayDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        assert findings[0].protected is True
        assert "ignore_resource_ids" in (findings[0].protection_reason or "")


# =====================================================================
# Recheck Tests (Invariant I4, I3, I9, I10)
# =====================================================================


def _make_sample_nat_finding(nat_id: str, region: str = "us-east-1") -> Finding:
    return Finding(
        resource_type=ResourceType.NAT_GATEWAY,
        resource_id=nat_id,
        region=region,
        reason="Zero bytes sent to destination over idle window",
        evidence={"bytes_out_sum": 0.0},
        est_monthly_cost_usd=32.85,
        cost_confidence="estimate",
        proposed_action=ActionKind.NAT_DELETE,
        protected=False,
        protection_reason=None,
        detected_at=datetime.now(timezone.utc),
    )


def test_I4_nat_recheck_still_idle(fake_clock: FakeClock) -> None:
    """Invariant I4: Recheck confirms resource is still idle and unprotected."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NATGateway",
            MetricData=[
                {
                    "MetricName": "BytesOutToDestination",
                    "Dimensions": [{"Name": "NatGatewayId", "Value": nat_id}],
                    "Timestamp": now - timedelta(hours=1),
                    "Value": 0.0,
                    "Unit": "Bytes",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        finding = _make_sample_nat_finding(nat_id)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is True
        assert res.protected is False


def test_I4_nat_recheck_traffic_arrived_not_idle(fake_clock: FakeClock) -> None:
    """Invariant I4: Recheck detects newly arrived traffic and aborts action."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NATGateway",
            MetricData=[
                {
                    "MetricName": "BytesOutToDestination",
                    "Dimensions": [{"Name": "NatGatewayId", "Value": nat_id}],
                    "Timestamp": now - timedelta(hours=1),
                    "Value": 99999.0,
                    "Unit": "Bytes",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        finding = _make_sample_nat_finding(nat_id)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is False
        assert "Active traffic detected" in res.reason


def test_I3_I10_nat_recheck_protected_tag_added(fake_clock: FakeClock) -> None:
    """Invariant I3 & I10: Adding protect tag cancels pending action on recheck."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        # Protect tag added between warn and action
        ec2.create_tags(
            Resources=[nat_id],
            Tags=[{"Key": "bsg:keep", "Value": "true"}],
        )

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        finding = _make_sample_nat_finding(nat_id)

        res = detector.recheck(ctx, finding)
        assert res.protected is True
        assert "bsg:keep=true" in res.reason


def test_I4_nat_recheck_deleted_resource(fake_clock: FakeClock) -> None:
    """Invariant I4: Already deleted NAT gateway returns still_idle=False."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)
        ec2.delete_nat_gateway(NatGatewayId=nat_id)

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        finding = _make_sample_nat_finding(nat_id)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is False
        assert "state is 'deleted'" in res.reason or "no longer exists" in res.reason


def test_I9_nat_recheck_missing_metrics_returns_unknown(fake_clock: FakeClock) -> None:
    """Invariant I9: Missing metrics during recheck returns still_idle=None (unknown)."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)
        # No CloudWatch data

        ctx = _make_context(fake_clock)
        detector = NatGatewayDetector()
        finding = _make_sample_nat_finding(nat_id)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is None
        assert "No CloudWatch" in res.reason


# =====================================================================
# Action Tests (NatDeleteAction)
# =====================================================================


def test_I1_nat_delete_dry_run_no_mutation(fake_clock: FakeClock) -> None:
    """Invariant I1: In dry_run mode, nat_delete must not perform deletion."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        config = Config(dry_run=True)
        ctx = _make_context(fake_clock, config=config)
        action = NatDeleteAction()
        finding = _make_sample_nat_finding(nat_id)

        result = action.apply(ctx, finding)
        assert result.ok is True
        assert result.performed is False
        assert "DRY RUN" in result.detail

        # Verify NAT gateway is still available
        resp = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])
        assert resp["NatGateways"][0]["State"] == "available"


def test_nat_delete_live_success(fake_clock: FakeClock) -> None:
    """When dry_run=False, nat_delete deletes the NAT gateway."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, _, _ = _setup_vpc_and_nat(ec2)

        config = Config(dry_run=False)
        ctx = _make_context(fake_clock, config=config)
        action = NatDeleteAction()
        finding = _make_sample_nat_finding(nat_id)

        result = action.apply(ctx, finding)
        assert result.ok is True
        assert result.performed is True
        assert f"Deleted NAT gateway {nat_id}" in result.detail

        # Verify NAT gateway state transitioned to deleted
        resp = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])
        assert resp["NatGateways"][0]["State"] == "deleted"


def test_nat_delete_mismatched_resource_type(fake_clock: FakeClock) -> None:
    """Action returns error if resource_type does not match NAT_GATEWAY."""
    ctx = _make_context(fake_clock, config=Config(dry_run=False))
    action = NatDeleteAction()
    bad_finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-12345678",
        region="us-east-1",
        reason="Wrong type",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.NAT_DELETE,
        protected=False,
        protection_reason=None,
        detected_at=datetime.now(timezone.utc),
    )
    res = action.apply(ctx, bad_finding)
    assert res.ok is False
    assert res.performed is False
    assert res.error == "ResourceTypeMismatch"


def test_nat_delete_api_error(fake_clock: FakeClock) -> None:
    """Action handles AWS ClientError cleanly without unhandled exceptions."""

    class FailingEC2:
        def delete_nat_gateway(self, **kwargs: Any) -> None:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "Access denied"}},
                "DeleteNatGateway",
            )

    ctx = _make_context(
        fake_clock,
        config=Config(dry_run=False),
        client_factory=lambda svc, reg: FailingEC2(),
    )
    action = NatDeleteAction()
    finding = _make_sample_nat_finding("nat-123")
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert res.performed is False
    assert "Access denied" in (res.error or "")


def test_nat_detect_api_error(fake_clock: FakeClock) -> None:
    """Detect returns empty list and logs error when describe_nat_gateways fails (I9)."""

    class FailingEC2:
        def can_paginate(self, op: str) -> bool:
            return False

        def describe_nat_gateways(self, **kwargs: Any) -> None:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AuthFailure", "Message": "Invalid credentials"}},
                "DescribeNatGateways",
            )

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: FailingEC2(),
    )
    detector = NatGatewayDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []


def test_nat_recheck_api_error(fake_clock: FakeClock) -> None:
    """Recheck returns still_idle=None on ClientError or BotoCoreError (I9)."""

    class FailingEC2:
        def describe_nat_gateways(self, **kwargs: Any) -> None:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ServiceUnavailable", "Message": "Outage"}},
                "DescribeNatGateways",
            )

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: FailingEC2(),
    )
    detector = NatGatewayDetector()
    finding = _make_sample_nat_finding("nat-123")
    res = detector.recheck(ctx, finding)
    assert res.still_idle is None
    assert "Failed to describe NAT gateway" in res.reason


def test_nat_recheck_not_found(fake_clock: FakeClock) -> None:
    """Recheck returns still_idle=False when NAT gateway does not exist."""

    class EmptyEC2:
        def describe_nat_gateways(self, **kwargs: Any) -> dict[str, Any]:
            return {"NatGateways": []}

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: EmptyEC2(),
    )
    detector = NatGatewayDetector()
    finding = _make_sample_nat_finding("nat-nonexistent")
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "no longer exists" in res.reason


# =====================================================================
# Lifecycle Documentation: NAT Deletion Leaves Unassociated EIP
# =====================================================================


def test_nat_deletion_leaves_unassociated_eip(fake_clock: FakeClock) -> None:
    """Document that deleting a NAT gateway leaves its allocated Elastic IP in the account.

    In AWS EC2:
    1. A NAT Gateway requires an Elastic IP allocation at creation time.
    2. When the NAT Gateway is deleted (via nat_delete or console), AWS deletes
       the NAT gateway and its network interface, dissociating the Elastic IP.
    3. The Elastic IP remains allocated in the AWS account, now UNASSOCIATED.
    4. AWS charges $0.005/hour for each unassociated public IPv4 address.
    5. Therefore, deleting a NAT Gateway creates an unassociated EIP bill shock risk
       unless caught by the EIP detector (or cleaned up by the user).

    This test verifies the complete lifecycle sequence:
    - NAT Gateway is deleted.
    - The Elastic IP remains allocated in the account.
    - When disassociated, the Elastic IP has no AssociationId and will be
      flagged by the EIP detector on subsequent runs.
    """
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        nat_id, alloc_id, _ = _setup_vpc_and_nat(ec2)

        # Apply deletion action
        config = Config(dry_run=False)
        ctx = _make_context(fake_clock, config=config)
        action = NatDeleteAction()
        finding = _make_sample_nat_finding(nat_id)

        res = action.apply(ctx, finding)
        assert res.ok is True
        assert res.performed is True

        # In real AWS, deleting a NAT Gateway disassociates the EIP.
        # Moto leaves the EIP allocated; we disassociate it to simulate the AWS lifecycle:
        eip_desc = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
        if eip_desc.get("AssociationId"):
            ec2.disassociate_address(AssociationId=eip_desc["AssociationId"])

        # Assert the Elastic IP is still allocated in the account and unassociated
        post_del_addrs = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"]
        assert len(post_del_addrs) == 1
        addr = post_del_addrs[0]
        assert addr["AllocationId"] == alloc_id
        assert addr.get("AssociationId") is None
        assert not addr.get("NetworkInterfaceId")
        # This unassociated EIP is now eligible for detection by the EIP detector!
