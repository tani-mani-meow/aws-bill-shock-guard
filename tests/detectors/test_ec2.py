"""Unit and integration tests for EC2 detector, recheck, and stop action."""

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import moto
from botocore.exceptions import ClientError

from bill_shock_guard.config import Config
from bill_shock_guard.detectors.ec2 import (
    EC2Detector,
    EC2StopAction,
    check_ec2_protection,
    is_ec2_idle,
    is_instance_old_enough,
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
        run_id="test-run-ec2",
        logger=JsonLogger(run_id="test-run-ec2", region=region),
        client_factory=client_factory,
    )


# ---------------------------------------------------------------------------
# Pure function tests (without moto or AWS I/O)
# ---------------------------------------------------------------------------


def test_is_instance_old_enough() -> None:
    now = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    launched_25h_ago = now - timedelta(hours=25)
    launched_10h_ago = now - timedelta(hours=10)

    assert is_instance_old_enough(launched_25h_ago, now, min_hours=24) is True
    assert is_instance_old_enough(launched_10h_ago, now, min_hours=24) is False


def test_is_instance_old_enough_naive_datetime() -> None:
    now = datetime(2026, 1, 2, 12, 0, 0)
    launched_25h_ago = datetime(2026, 1, 1, 11, 0, 0)
    assert is_instance_old_enough(launched_25h_ago, now, min_hours=24) is True


def test_is_ec2_idle_synthetic_datapoints_idle() -> None:
    cpu_values = [1.2, 2.5, 3.1]
    net_in_values = [50000.0, 50000.0]  # total 100k bytes
    net_out_values = [50000.0, 50000.0]  # total 100k bytes
    window_seconds = 86400.0  # 24 hours

    idle, avg_cpu, avg_net, reason = is_ec2_idle(
        cpu_values=cpu_values,
        net_in_values=net_in_values,
        net_out_values=net_out_values,
        window_seconds=window_seconds,
        cpu_threshold=5.0,
        net_threshold=10000.0,
    )

    assert idle is True
    assert avg_cpu is not None and avg_cpu < 5.0
    assert avg_net is not None and avg_net < 10000.0
    assert "avg CPU" in reason


def test_is_ec2_idle_synthetic_datapoints_high_cpu() -> None:
    cpu_values = [8.5, 12.0]
    net_in_values = [1000.0]
    net_out_values = [1000.0]
    window_seconds = 86400.0

    idle, avg_cpu, avg_net, reason = is_ec2_idle(
        cpu_values=cpu_values,
        net_in_values=net_in_values,
        net_out_values=net_out_values,
        window_seconds=window_seconds,
        cpu_threshold=5.0,
        net_threshold=10000.0,
    )

    assert idle is False
    assert avg_cpu is not None and avg_cpu > 5.0
    assert "not idle" in reason


def test_is_ec2_idle_synthetic_datapoints_high_network() -> None:
    cpu_values = [1.0, 2.0]
    # 24 hours = 86400 seconds. 10000 B/s threshold = 864,000,000 bytes
    net_in_values = [500_000_000.0]
    net_out_values = [500_000_000.0]
    window_seconds = 86400.0

    idle, avg_cpu, avg_net, reason = is_ec2_idle(
        cpu_values=cpu_values,
        net_in_values=net_in_values,
        net_out_values=net_out_values,
        window_seconds=window_seconds,
        cpu_threshold=5.0,
        net_threshold=10000.0,
    )

    assert idle is False
    assert avg_net is not None and avg_net > 10000.0
    assert "not idle" in reason


def test_I9_ec2_missing_metrics_synthetic() -> None:
    """Missing metric datapoints must return None (unknown is not idle)."""
    window_seconds = 86400.0
    # Empty CPU
    idle, avg_cpu, avg_net, reason = is_ec2_idle(
        cpu_values=[],
        net_in_values=[100.0],
        net_out_values=[100.0],
        window_seconds=window_seconds,
        cpu_threshold=5.0,
        net_threshold=10000.0,
    )
    assert idle is None
    assert "Invariant I9" in reason

    # Empty Network
    idle, _, _, reason = is_ec2_idle(
        cpu_values=[1.0],
        net_in_values=[],
        net_out_values=[100.0],
        window_seconds=window_seconds,
        cpu_threshold=5.0,
        net_threshold=10000.0,
    )
    assert idle is None
    assert "Invariant I9" in reason


def test_is_ec2_idle_invalid_window() -> None:
    idle, _, _, reason = is_ec2_idle([1.0], [1.0], [1.0], 0.0, 5.0, 10000.0)
    assert idle is None
    assert "Invalid window duration" in reason


def test_check_ec2_protection_spot() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()
    prot, reason = check_ec2_protection("i-123", {}, "spot", config, now)
    assert prot is True
    assert reason is not None
    assert "Spot instance" in reason


def test_check_ec2_protection_asg() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()
    tags = {"aws:autoscaling:groupName": "production-asg"}
    prot, reason = check_ec2_protection("i-123", tags, None, config, now)
    assert prot is True
    assert reason is not None
    assert "aws:autoscaling:groupName" in reason


def test_check_ec2_protection_eks() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()
    tags = {"eks:cluster-name": "eks-production"}
    prot, reason = check_ec2_protection("i-123", tags, None, config, now)
    assert prot is True
    assert reason is not None
    assert "eks:cluster-name" in reason


def test_check_ec2_protection_invalid_tag_date_fail_closed() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()
    # Invalid calendar date
    tags = {"bsg:keep": "2026-02-30"}
    prot, reason = check_ec2_protection("i-123", tags, None, config, now)
    assert prot is True
    assert reason is not None
    assert "fail closed" in reason


def test_check_ec2_protection_unexpired_and_expired() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    config = Config()

    # Unexpired date
    tags_valid = {"bsg:keep": "2026-01-05"}
    prot, reason = check_ec2_protection("i-123", tags_valid, None, config, now)
    assert prot is True
    assert reason is not None
    assert "until 2026-01-05" in reason

    # Expired date
    tags_expired = {"bsg:keep": "2025-12-31"}
    prot, reason = check_ec2_protection("i-123", tags_expired, None, config, now)
    assert prot is False


# ---------------------------------------------------------------------------
# Integration tests with moto: EC2 detection, recheck, and stop action
# ---------------------------------------------------------------------------


def _setup_moto_instance(
    ec2_client: Any,
    tags: dict[str, str] | None = None,
    is_spot: bool = False,
) -> tuple[str, datetime]:
    """Helper to launch an EC2 instance in moto and return (instance_id, launch_time)."""
    kwargs: dict[str, Any] = {
        "ImageId": "ami-12345678",
        "InstanceType": "t3.micro",
        "MinCount": 1,
        "MaxCount": 1,
    }
    if tags:
        kwargs["TagSpecifications"] = [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
    if is_spot:
        kwargs["InstanceMarketOptions"] = {"MarketType": "spot"}

    resp = ec2_client.run_instances(**kwargs)
    inst = resp["Instances"][0]
    return str(inst["InstanceId"]), inst["LaunchTime"]


def _put_moto_metrics(
    cw_client: Any,
    instance_id: str,
    timestamp: datetime,
    cpu: float = 1.0,
    net_in: float = 100.0,
    net_out: float = 100.0,
) -> None:
    """Helper to populate CloudWatch metric datapoints in moto."""
    cw_client.put_metric_data(
        Namespace="AWS/EC2",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                "Timestamp": timestamp,
                "Value": cpu,
            },
            {
                "MetricName": "NetworkIn",
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                "Timestamp": timestamp,
                "Value": net_in,
            },
            {
                "MetricName": "NetworkOut",
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                "Timestamp": timestamp,
                "Value": net_out,
            },
        ],
    )


@moto.mock_aws
def test_ec2_detect_idle_instance_with_moto_cloudwatch() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    # Advance clock past 24 hours window
    clock.set(launch_time + timedelta(hours=25))

    # Put idle metric datapoints
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=2.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == instance_id
    assert f.resource_type == ResourceType.EC2_INSTANCE
    assert f.proposed_action == ActionKind.EC2_STOP
    assert f.protected is False
    assert f.protection_reason is None
    assert "avg CPU" in f.reason


@moto.mock_aws
def test_ec2_detect_too_young_instance_not_flagged() -> None:
    """An instance launched less than the idle window is not flagged at all."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    # Set clock to only 10 hours after launch (window is 24 hours)
    clock.set(launch_time + timedelta(hours=10))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 0


@moto.mock_aws
def test_ec2_detect_stopped_instance_ignored() -> None:
    """Non-running instances are ignored."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    ec2.stop_instances(InstanceIds=[instance_id])
    clock.set(launch_time + timedelta(hours=25))

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 0


@moto.mock_aws
def test_I9_ec2_detect_missing_metrics_not_flagged() -> None:
    """Invariant I9: if metrics are missing, resource is NOT flagged as idle."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    _, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))
    # No CloudWatch metrics posted at all

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 0


@moto.mock_aws
def test_ec2_detect_high_cpu_not_flagged() -> None:
    """Active instance with high CPU is not idle and not flagged."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=45.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 0


@moto.mock_aws
def test_I3_ec2_detect_asg_excluded_returns_protected_finding() -> None:
    """ASG managed instances are flagged as protected and never acted upon."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(
        ec2, tags={"aws:autoscaling:groupName": "web-asg"}
    )
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert findings[0].protection_reason is not None
    assert "aws:autoscaling:groupName" in findings[0].protection_reason


@moto.mock_aws
def test_I3_ec2_detect_eks_excluded_returns_protected_finding() -> None:
    """EKS worker nodes are flagged as protected."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2, tags={"eks:cluster-name": "cluster-prod"})
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "eks:cluster-name" in (findings[0].protection_reason or "")


@moto.mock_aws
def test_I3_ec2_detect_spot_excluded_returns_protected_finding() -> None:
    """Spot instances are flagged as protected and never acted upon."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2, is_spot=True)
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "Spot instance" in (findings[0].protection_reason or "")


@moto.mock_aws
def test_I3_ec2_detect_protect_tag_returns_protected_finding() -> None:
    """Instances with bsg:keep=true are flagged as protected."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2, tags={"bsg:keep": "true"})
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "bsg:keep=true" in (findings[0].protection_reason or "")


@moto.mock_aws
def test_ec2_detect_invalid_protect_tag_date_fail_closed() -> None:
    """Invalid keep tag date fails closed: marked protected."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2, tags={"bsg:keep": "not-a-date"})
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].protected is True
    assert "fail closed" in (findings[0].protection_reason or "")


@moto.mock_aws
def test_ec2_detect_synthetic_seam_injection() -> None:
    """Test detector using an injected metrics fetcher seam."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))

    def synthetic_fetcher(
        cw: Any, i_id: str, start: datetime, end: datetime, period: int
    ) -> tuple[list[float], list[float], list[float]]:
        return [2.0], [1000.0], [1000.0]

    detector = EC2Detector(metrics_fetcher=synthetic_fetcher)
    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == instance_id


# ---------------------------------------------------------------------------
# Recheck tests
# ---------------------------------------------------------------------------


@moto.mock_aws
def test_ec2_recheck_still_idle() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.5)

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is True
    assert recheck.protected is False


@moto.mock_aws
def test_I4_ec2_recheck_detects_activity_and_blocks_action() -> None:
    """Invariant I4: if metrics spike between warning and action, recheck detects it."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))
    # CPU spiked to 60%
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=60.0)

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert recheck.protected is False
    assert "no longer idle" in recheck.reason


@moto.mock_aws
def test_I10_ec2_recheck_race_tag_added_after_warning() -> None:
    """Invariant I10: adding protect tag between warning and action blocks action at recheck."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")
    cw = ctx.client("cloudwatch", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))
    _put_moto_metrics(cw, instance_id, clock.now() - timedelta(hours=1), cpu=1.0)

    # User adds keep tag to instance
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.protected is True
    assert "bsg:keep=true" in recheck.reason


@moto.mock_aws
def test_ec2_recheck_instance_stopped() -> None:
    """If instance was already stopped, recheck returns still_idle=False."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, _ = _setup_moto_instance(ec2)
    ec2.stop_instances(InstanceIds=[instance_id])

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert "not running" in recheck.reason


@moto.mock_aws
def test_ec2_recheck_instance_terminated_not_found() -> None:
    """Terminated or non-existent instance returns still_idle=False."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-nonexistent123",
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert "not found" in recheck.reason


@moto.mock_aws
def test_I9_ec2_recheck_missing_metrics_returns_none() -> None:
    """Invariant I9: if metrics are missing during recheck, still_idle is None."""
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))
    # No metrics in CloudWatch

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is None
    assert "Invariant I9" in recheck.reason


# ---------------------------------------------------------------------------
# Stop action tests
# ---------------------------------------------------------------------------


@moto.mock_aws
def test_I1_ec2_stop_dry_run_does_not_mutate() -> None:
    """Invariant I1: Never perform a mutating AWS call when dry_run is true."""
    clock = FakeClock()
    config = Config(dry_run=True)
    ctx = _make_context(config=config, clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, _ = _setup_moto_instance(ec2)

    action = EC2StopAction()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is True
    assert result.performed is False
    assert "DRY RUN" in result.detail

    # Verify instance is still running
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state == "running"


@moto.mock_aws
def test_ec2_stop_mutates_when_dry_run_false() -> None:
    """When dry_run is false, instance is stopped."""
    clock = FakeClock()
    config = Config(dry_run=False)
    ctx = _make_context(config=config, clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, _ = _setup_moto_instance(ec2)

    action = EC2StopAction()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is True
    assert result.performed is True
    assert "Stopped EC2 instance" in result.detail

    # Verify instance is stopped
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state in ("stopped", "stopping")


@moto.mock_aws
def test_ec2_stop_api_error_returns_failure() -> None:
    """Stop call failure returns ActionResult with ok=False and error string."""
    clock = FakeClock()
    config = Config(dry_run=False)
    ctx = _make_context(config=config, clock=clock)

    action = EC2StopAction()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-nonexistent999",
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    result = action.apply(ctx, finding)
    assert result.ok is False
    assert result.performed is False
    assert result.error is not None


def test_ec2_detect_describe_instances_exception_handled() -> None:
    from unittest.mock import MagicMock

    mock_ec2 = MagicMock()
    mock_ec2.can_paginate.return_value = False
    mock_ec2.describe_instances.side_effect = RuntimeError("AWS EC2 unavailable")

    ctx = ScanContext(
        config=Config(),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    detector = EC2Detector()
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []


@moto.mock_aws
def test_ec2_detect_metrics_fetcher_exception_skipped() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))

    def failing_fetcher(cw: Any, i_id: str, s: datetime, e: datetime, p: int) -> Any:
        raise RuntimeError("CloudWatch connection timeout")

    detector = EC2Detector(metrics_fetcher=failing_fetcher)
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []


def test_ec2_recheck_describe_instances_unexpected_api_error() -> None:
    from unittest.mock import MagicMock

    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Access Denied"}},
        "DescribeInstances",
    )

    ctx = ScanContext(
        config=Config(),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-12345678",
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=FakeClock().now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is None
    assert "Failed to describe instance" in recheck.reason


@moto.mock_aws
def test_ec2_recheck_metrics_fetcher_exception_returns_none() -> None:
    clock = FakeClock()
    ctx = _make_context(clock=clock)
    ec2 = ctx.client("ec2", "us-east-1")

    instance_id, launch_time = _setup_moto_instance(ec2)
    clock.set(launch_time + timedelta(hours=25))

    def failing_fetcher(cw: Any, i_id: str, s: datetime, e: datetime, p: int) -> Any:
        raise RuntimeError("CloudWatch error during recheck")

    detector = EC2Detector(metrics_fetcher=failing_fetcher)
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance_id,
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is None
    assert "Failed to query metrics during recheck" in recheck.reason


def test_ec2_recheck_empty_reservations_returns_not_found() -> None:
    from unittest.mock import MagicMock

    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": [{"Instances": []}]}

    ctx = ScanContext(
        config=Config(),
        clock=FakeClock(),
        account_id=MOTO_ACCOUNT_ID,
        run_id="test-run",
        logger=JsonLogger("test-run", "us-east-1"),
        client_factory=lambda svc, reg: mock_ec2,
    )

    detector = EC2Detector()
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-12345678",
        region="us-east-1",
        reason="idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=FakeClock().now(),
    )

    recheck = detector.recheck(ctx, finding)
    assert recheck.still_idle is False
    assert "not found in reservations" in recheck.reason
