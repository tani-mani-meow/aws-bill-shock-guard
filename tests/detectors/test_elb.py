"""Tests for Load Balancer detector (ALB & NLB), pure idle logic, recheck, and deletion."""

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import botocore.exceptions
import moto
import pytest

from bill_shock_guard.config import Config
from bill_shock_guard.detectors.elb import (
    ElbDeleteAction,
    LoadBalancerDetector,
    evaluate_load_balancer_idle,
    extract_lb_dimension,
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


def test_extract_lb_dimension() -> None:
    """Extracts ARN suffix starting after 'loadbalancer/' for CloudWatch dimensions."""
    alb_arn = (
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
        "loadbalancer/app/my-alb/50dc6c495c0c9188"
    )
    assert extract_lb_dimension(alb_arn) == "app/my-alb/50dc6c495c0c9188"

    nlb_arn = (
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
        "loadbalancer/net/my-nlb/1234567890abcdef"
    )
    assert extract_lb_dimension(nlb_arn) == "net/my-nlb/1234567890abcdef"

    fallback = "my-custom-lb"
    assert extract_lb_dimension(fallback) == "my-custom-lb"


def test_evaluate_load_balancer_idle_zero_targets() -> None:
    """Load balancer with zero registered targets across target groups is idle."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="application",
        lb_state="active",
        registered_target_count=0,
        target_group_count=1,
        metric_datapoints=None,
        metric_name="RequestCount",
    )
    assert is_idle is True
    assert "0 registered targets" in reason
    assert "1 target group(s)" in reason


def test_evaluate_load_balancer_idle_zero_target_groups() -> None:
    """Load balancer with no target groups at all is idle."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="network",
        lb_state="active",
        registered_target_count=0,
        target_group_count=0,
        metric_datapoints=None,
        metric_name="NewFlowCount",
    )
    assert is_idle is True
    assert "0 registered targets" in reason


def test_evaluate_load_balancer_idle_alb_zero_requests() -> None:
    """ALB with targets but zero RequestCount over window is idle."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="application",
        lb_state="active",
        registered_target_count=2,
        target_group_count=1,
        metric_datapoints=[0.0, 0.0],
        metric_name="RequestCount",
    )
    assert is_idle is True
    assert "Zero requests" in reason
    assert "RequestCount=0" in reason


def test_evaluate_load_balancer_idle_alb_active_requests() -> None:
    """ALB with traffic (> 0 RequestCount) is not idle."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="application",
        lb_state="active",
        registered_target_count=2,
        target_group_count=1,
        metric_datapoints=[100.0, 50.0],
        metric_name="RequestCount",
    )
    assert is_idle is False
    assert "Active traffic detected" in reason
    assert "150 requests" in reason


def test_evaluate_load_balancer_idle_nlb_zero_flows() -> None:
    """NLB with targets but zero NewFlowCount over window is idle."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="network",
        lb_state="active",
        registered_target_count=1,
        target_group_count=1,
        metric_datapoints=[0.0],
        metric_name="NewFlowCount",
    )
    assert is_idle is True
    assert "Zero new flows" in reason
    assert "NewFlowCount=0" in reason


def test_evaluate_load_balancer_idle_nlb_active_flows() -> None:
    """NLB with active flows (> 0 NewFlowCount) is not idle."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="network",
        lb_state="active",
        registered_target_count=1,
        target_group_count=1,
        metric_datapoints=[42.0],
        metric_name="NewFlowCount",
    )
    assert is_idle is False
    assert "Active traffic detected" in reason
    assert "42 new flows" in reason


def test_evaluate_load_balancer_idle_missing_metrics_I9() -> None:
    """Invariant I9: Load balancer with targets and missing metrics is unknown (None)."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="application",
        lb_state="active",
        registered_target_count=2,
        target_group_count=1,
        metric_datapoints=[],
        metric_name="RequestCount",
    )
    assert is_idle is None
    assert "No CloudWatch" in reason

    is_idle_none, _ = evaluate_load_balancer_idle(
        lb_type="application",
        lb_state="active",
        registered_target_count=2,
        target_group_count=1,
        metric_datapoints=None,
        metric_name="RequestCount",
    )
    assert is_idle_none is None


def test_evaluate_load_balancer_idle_non_active_state() -> None:
    """Load balancers not in 'active' state are not treated as idle."""
    for state in ["provisioning", "failed"]:
        is_idle, reason = evaluate_load_balancer_idle(
            lb_type="application",
            lb_state=state,
            registered_target_count=0,
            target_group_count=0,
            metric_datapoints=None,
            metric_name="RequestCount",
        )
        assert is_idle is False
        assert "expected 'active'" in reason


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
        run_id="test-elb-run",
        logger=JsonLogger(run_id="test-elb-run", region="us-east-1"),
        client_factory=cf,
    )


def _setup_subnets(ec2: Any) -> tuple[str, str, str]:
    """Create VPC and two subnets in different availability zones."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sub1 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]
    sub2 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
    )["Subnet"]
    return vpc["VpcId"], sub1["SubnetId"], sub2["SubnetId"]


# =====================================================================
# Detector Moto Tests
# =====================================================================


def test_alb_zero_targets_detected(fake_clock: FakeClock) -> None:
    """ALB with 0 registered targets is detected as idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-empty-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_type == ResourceType.LOAD_BALANCER
        assert f.resource_id == alb["LoadBalancerArn"]
        assert f.proposed_action == ActionKind.ELB_DELETE
        assert f.evidence["zero_targets"] is True
        assert f.evidence["registered_target_count"] == 0
        assert f.protected is False


def test_nlb_zero_targets_detected(fake_clock: FakeClock) -> None:
    """NLB with 0 registered targets is detected as idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        elbv2.create_load_balancer(
            Name="my-empty-nlb",
            Subnets=[sub1, sub2],
            Type="network",
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        assert findings[0].evidence["type"] == "network"
        assert findings[0].evidence["zero_targets"] is True


def test_alb_with_targets_zero_requests_detected(fake_clock: FakeClock) -> None:
    """ALB with registered targets and 0 RequestCount is detected as idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        vpc_id, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-alb-targets",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        tg = elbv2.create_target_group(
            Name="my-tg",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
            TargetType="instance",
        )["TargetGroups"][0]

        elbv2.create_listener(
            LoadBalancerArn=alb_arn,
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )

        # Register a target
        inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
        elbv2.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": inst["InstanceId"]}],
        )

        # CloudWatch metric with zero requests
        dim_val = extract_lb_dimension(alb_arn)
        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/ApplicationELB",
            MetricData=[
                {
                    "MetricName": "RequestCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": dim_val}],
                    "Timestamp": now - timedelta(hours=10),
                    "Value": 0.0,
                    "Unit": "Count",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.evidence["registered_target_count"] == 1
        assert f.evidence["metric_name"] == "RequestCount"
        assert f.evidence["metric_datapoints_sum"] == 0.0
        assert "Zero requests" in f.reason


def test_alb_with_targets_active_traffic_ignored(fake_clock: FakeClock) -> None:
    """ALB with registered targets and active requests is not idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        vpc_id, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-active-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        tg = elbv2.create_target_group(
            Name="my-active-tg",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
        )["TargetGroups"][0]

        elbv2.create_listener(
            LoadBalancerArn=alb_arn,
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )

        inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
        elbv2.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": inst["InstanceId"]}],
        )

        dim_val = extract_lb_dimension(alb_arn)
        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/ApplicationELB",
            MetricData=[
                {
                    "MetricName": "RequestCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": dim_val}],
                    "Timestamp": now - timedelta(hours=5),
                    "Value": 2500.0,
                    "Unit": "Count",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")
        assert len(findings) == 0


def test_nlb_with_targets_zero_flows_detected(fake_clock: FakeClock) -> None:
    """NLB with registered targets and 0 NewFlowCount is detected as idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        vpc_id, sub1, sub2 = _setup_subnets(ec2)

        nlb = elbv2.create_load_balancer(
            Name="my-nlb-targets",
            Subnets=[sub1, sub2],
            Type="network",
        )["LoadBalancers"][0]
        nlb_arn = nlb["LoadBalancerArn"]

        tg = elbv2.create_target_group(
            Name="my-nlb-tg",
            Protocol="TCP",
            Port=443,
            VpcId=vpc_id,
        )["TargetGroups"][0]

        elbv2.create_listener(
            LoadBalancerArn=nlb_arn,
            Protocol="TCP",
            Port=443,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )

        inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
        elbv2.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": inst["InstanceId"]}],
        )

        dim_val = extract_lb_dimension(nlb_arn)
        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NetworkELB",
            MetricData=[
                {
                    "MetricName": "NewFlowCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": dim_val}],
                    "Timestamp": now - timedelta(hours=10),
                    "Value": 0.0,
                    "Unit": "Count",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        assert findings[0].evidence["metric_name"] == "NewFlowCount"
        assert "Zero new flows" in findings[0].reason


def test_I9_elb_missing_metrics_ignored(fake_clock: FakeClock) -> None:
    """Invariant I9: Load balancer with targets and no metrics is unknown, so not flagged."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        vpc_id, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-alb-no-metrics",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]

        tg = elbv2.create_target_group(
            Name="my-tg-no-metrics",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
        )["TargetGroups"][0]

        elbv2.create_listener(
            LoadBalancerArn=alb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )

        inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
        elbv2.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": inst["InstanceId"]}],
        )
        # Note: No CloudWatch metrics put

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")
        assert len(findings) == 0


def test_I3_elb_protect_tag(fake_clock: FakeClock) -> None:
    """Load balancer with bsg:keep=true is detected with protected=True."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        elbv2.create_load_balancer(
            Name="my-protected-alb",
            Subnets=[sub1, sub2],
            Type="application",
            Tags=[{"Key": "bsg:keep", "Value": "true"}],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        assert findings[0].protected is True
        assert "bsg:keep=true" in (findings[0].protection_reason or "")


def test_I3_elb_ignored_by_name_or_arn(fake_clock: FakeClock) -> None:
    """Load balancer ignored by name or ARN in config is marked protected."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        elbv2.create_load_balancer(
            Name="my-ignored-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )

        # Ignore by LB Name
        config = Config(ignore_resource_ids=["my-ignored-alb"])
        ctx = _make_context(fake_clock, config=config)
        detector = LoadBalancerDetector()
        findings = detector.detect(ctx, "us-east-1")

        assert len(findings) == 1
        assert findings[0].protected is True
        assert "ignore_resource_ids" in (findings[0].protection_reason or "")


# =====================================================================
# Recheck Tests (Invariant I4, I3, I9, I10)
# =====================================================================


def _make_sample_elb_finding(arn: str, region: str = "us-east-1") -> Finding:
    return Finding(
        resource_type=ResourceType.LOAD_BALANCER,
        resource_id=arn,
        region=region,
        reason="Load balancer has 0 registered targets across 0 target group(s)",
        evidence={"zero_targets": True, "registered_target_count": 0},
        est_monthly_cost_usd=16.42,
        cost_confidence="estimate",
        proposed_action=ActionKind.ELB_DELETE,
        protected=False,
        protection_reason=None,
        detected_at=datetime.now(timezone.utc),
    )


def test_I4_elb_recheck_still_idle(fake_clock: FakeClock) -> None:
    """Invariant I4: Recheck confirms load balancer is still idle and unprotected."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-recheck-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        finding = _make_sample_elb_finding(alb["LoadBalancerArn"])

        res = detector.recheck(ctx, finding)
        assert res.still_idle is True
        assert res.protected is False


def test_I3_I10_elb_recheck_protected_tag_added(fake_clock: FakeClock) -> None:
    """Invariant I3 & I10: Adding protect tag cancels pending action on recheck."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-recheck-tag-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        elbv2.add_tags(
            ResourceArns=[alb_arn],
            Tags=[{"Key": "bsg:keep", "Value": "true"}],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        finding = _make_sample_elb_finding(alb_arn)

        res = detector.recheck(ctx, finding)
        assert res.protected is True
        assert "bsg:keep=true" in res.reason


def test_I4_elb_recheck_deleted_resource(fake_clock: FakeClock) -> None:
    """Invariant I4: Deleted load balancer returns still_idle=False."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-to-delete-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        elbv2.delete_load_balancer(LoadBalancerArn=alb_arn)

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        finding = _make_sample_elb_finding(alb_arn)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is False
        assert "no longer exists" in res.reason or "not found" in res.reason


def test_I9_elb_recheck_missing_metrics_returns_unknown(fake_clock: FakeClock) -> None:
    """Invariant I9: Target exists but missing metrics on recheck returns still_idle=None."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        vpc_id, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-recheck-alb-targets",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        tg = elbv2.create_target_group(
            Name="my-recheck-tg",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
        )["TargetGroups"][0]

        elbv2.create_listener(
            LoadBalancerArn=alb_arn,
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )

        inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
        elbv2.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": inst["InstanceId"]}],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        finding = _make_sample_elb_finding(alb_arn)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is None
        assert "No CloudWatch" in res.reason


# =====================================================================
# Action Tests (ElbDeleteAction)
# =====================================================================


def test_I1_elb_delete_dry_run_no_mutation(fake_clock: FakeClock) -> None:
    """Invariant I1: In dry_run mode, elb_delete must not delete the load balancer."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-dry-run-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        config = Config(dry_run=True)
        ctx = _make_context(fake_clock, config=config)
        action = ElbDeleteAction()
        finding = _make_sample_elb_finding(alb_arn)

        result = action.apply(ctx, finding)
        assert result.ok is True
        assert result.performed is False
        assert "DRY RUN" in result.detail

        # Assert LB still exists
        remaining = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"]
        assert len(remaining) == 1


def test_elb_delete_live_success(fake_clock: FakeClock) -> None:
    """When dry_run=False, elb_delete deletes the load balancer."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        _, sub1, sub2 = _setup_subnets(ec2)

        alb = elbv2.create_load_balancer(
            Name="my-live-del-alb",
            Subnets=[sub1, sub2],
            Type="application",
        )["LoadBalancers"][0]
        alb_arn = alb["LoadBalancerArn"]

        config = Config(dry_run=False)
        ctx = _make_context(fake_clock, config=config)
        action = ElbDeleteAction()
        finding = _make_sample_elb_finding(alb_arn)

        result = action.apply(ctx, finding)
        assert result.ok is True
        assert result.performed is True
        assert f"Deleted load balancer {alb_arn}" in result.detail

        # Assert LB is deleted
        with pytest.raises(botocore.exceptions.ClientError):
            elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])


def test_elb_delete_mismatched_resource_type(fake_clock: FakeClock) -> None:
    """Action returns error if resource_type is not LOAD_BALANCER."""
    ctx = _make_context(fake_clock, config=Config(dry_run=False))
    action = ElbDeleteAction()
    bad_finding = Finding(
        resource_type=ResourceType.NAT_GATEWAY,
        resource_id="nat-12345",
        region="us-east-1",
        reason="Wrong type",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.ELB_DELETE,
        protected=False,
        protection_reason=None,
        detected_at=datetime.now(timezone.utc),
    )
    res = action.apply(ctx, bad_finding)
    assert res.ok is False
    assert res.performed is False
    assert res.error == "ResourceTypeMismatch"


_SAMPLE_ARN = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/x/1"


def test_elb_delete_api_error(fake_clock: FakeClock) -> None:
    """Action handles delete_load_balancer ClientError cleanly."""

    class FailingELB:
        def delete_load_balancer(self, **kwargs: Any) -> None:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
                "DeleteLoadBalancer",
            )

    ctx = _make_context(
        fake_clock,
        config=Config(dry_run=False),
        client_factory=lambda svc, reg: FailingELB(),
    )
    action = ElbDeleteAction()
    finding = _make_sample_elb_finding(_SAMPLE_ARN)
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert res.performed is False
    assert "Not authorized" in (res.error or "")


def test_elb_detect_api_error(fake_clock: FakeClock) -> None:
    """Detect returns empty list and logs error when describe_load_balancers fails (I9)."""

    class FailingELB:
        def can_paginate(self, op: str) -> bool:
            return False

        def describe_load_balancers(self, **kwargs: Any) -> None:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AuthFailure", "Message": "Invalid credentials"}},
                "DescribeLoadBalancers",
            )

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: FailingELB(),
    )
    detector = LoadBalancerDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []


def test_elb_recheck_api_error(fake_clock: FakeClock) -> None:
    """Recheck returns still_idle=None on ClientError or BotoCoreError (I9)."""

    class FailingELB:
        def describe_load_balancers(self, **kwargs: Any) -> None:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "AWS error"}},
                "DescribeLoadBalancers",
            )

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: FailingELB(),
    )
    detector = LoadBalancerDetector()
    finding = _make_sample_elb_finding(_SAMPLE_ARN)
    res = detector.recheck(ctx, finding)
    assert res.still_idle is None
    assert "Failed to describe load balancer" in res.reason


def test_elb_recheck_not_found(fake_clock: FakeClock) -> None:
    """Recheck returns still_idle=False when load balancer no longer exists."""

    class EmptyELB:
        def describe_load_balancers(self, **kwargs: Any) -> dict[str, Any]:
            return {"LoadBalancers": []}

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: EmptyELB(),
    )
    detector = LoadBalancerDetector()
    finding = _make_sample_elb_finding(_SAMPLE_ARN)
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "no longer exists" in res.reason


def test_elb_recheck_state_not_active(fake_clock: FakeClock) -> None:
    """Recheck returns still_idle=False if state is not active."""

    class NonActiveELB:
        def describe_load_balancers(self, **kwargs: Any) -> dict[str, Any]:
            return {"LoadBalancers": [{"State": {"Code": "provisioning"}}]}

    ctx = _make_context(
        fake_clock,
        client_factory=lambda svc, reg: NonActiveELB(),
    )
    detector = LoadBalancerDetector()
    finding = _make_sample_elb_finding(_SAMPLE_ARN)
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "expected 'active'" in res.reason


def test_evaluate_load_balancer_idle_negative_values() -> None:
    """Negative metric values return unknown (None)."""
    is_idle, reason = evaluate_load_balancer_idle(
        lb_type="application",
        lb_state="active",
        registered_target_count=1,
        target_group_count=1,
        metric_datapoints=[-5.0],
        metric_name="RequestCount",
    )
    assert is_idle is None
    assert "negative" in reason.lower()


def test_nlb_recheck_with_targets(fake_clock: FakeClock) -> None:
    """Recheck on NLB with targets fetches NewFlowCount metrics and confirms idle."""
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        vpc_id, sub1, sub2 = _setup_subnets(ec2)

        nlb = elbv2.create_load_balancer(
            Name="my-nlb-recheck",
            Subnets=[sub1, sub2],
            Type="network",
        )["LoadBalancers"][0]
        nlb_arn = nlb["LoadBalancerArn"]

        tg = elbv2.create_target_group(
            Name="my-nlb-tg-rc",
            Protocol="TCP",
            Port=443,
            VpcId=vpc_id,
        )["TargetGroups"][0]

        elbv2.create_listener(
            LoadBalancerArn=nlb_arn,
            Protocol="TCP",
            Port=443,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )

        inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
        elbv2.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": inst["InstanceId"]}],
        )

        dim_val = extract_lb_dimension(nlb_arn)
        now = fake_clock.now()
        cw.put_metric_data(
            Namespace="AWS/NetworkELB",
            MetricData=[
                {
                    "MetricName": "NewFlowCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": dim_val}],
                    "Timestamp": now - timedelta(hours=2),
                    "Value": 0.0,
                    "Unit": "Count",
                }
            ],
        )

        ctx = _make_context(fake_clock)
        detector = LoadBalancerDetector()
        finding = _make_sample_elb_finding(nlb_arn)

        res = detector.recheck(ctx, finding)
        assert res.still_idle is True
        assert res.protected is False
        assert "NewFlowCount=0" in res.reason


def test_elb_detect_skips_unsupported_type_and_non_active(fake_clock: FakeClock) -> None:
    """Detect skips gateway load balancers and non-active load balancers."""

    class FakeELB:
        def can_paginate(self, op: str) -> bool:
            return False

        def describe_load_balancers(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "LoadBalancers": [
                    {
                        "LoadBalancerArn": "arn:aws:elb:us-east-1:1:lb/gw/1",
                        "Type": "gateway",
                        "State": {"Code": "active"},
                    },
                    {
                        "LoadBalancerArn": "arn:aws:elb:us-east-1:1:lb/app/prov/1",
                        "Type": "application",
                        "State": {"Code": "provisioning"},
                    },
                ]
            }

    ctx = _make_context(fake_clock, client_factory=lambda svc, reg: FakeELB())
    detector = LoadBalancerDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []


def test_elb_target_groups_error_ignored_I9(fake_clock: FakeClock) -> None:
    """When target groups query fails, detector ignores LB (I9: unknown is not idle)."""

    class TargetGroupErrorELB:
        def can_paginate(self, op: str) -> bool:
            return False

        def describe_load_balancers(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "LoadBalancers": [
                    {
                        "LoadBalancerArn": "arn:aws:elb:us-east-1:1:lb/app/test/1",
                        "Type": "application",
                        "State": {"Code": "active"},
                    }
                ]
            }

        def describe_target_groups(self, **kwargs: Any) -> dict[str, Any]:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalError", "Message": "Target group lookup failed"}},
                "DescribeTargetGroups",
            )

    ctx = _make_context(fake_clock, client_factory=lambda svc, reg: TargetGroupErrorELB())
    detector = LoadBalancerDetector()
    findings = detector.detect(ctx, "us-east-1")
    assert findings == []
