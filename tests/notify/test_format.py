"""Tests for digest plain-text formatting, timestamp localization, and exemption hints."""

from datetime import datetime, timezone

from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    ResourceType,
)
from bill_shock_guard.notify.format import (
    format_digest,
    format_subject,
    format_timestamp,
    get_exemption_command,
)


def _make_finding(
    resource_type: ResourceType = ResourceType.EC2_INSTANCE,
    resource_id: str = "i-0123456789abcdef0",
    region: str = "us-east-1",
    reason: str = "CPU avg 1.2% and network 120 B/s over 24h",
    cost: float | None = 15.50,
    confidence: str = "estimate",
    action: ActionKind | None = ActionKind.EC2_STOP,
    protected: bool = False,
    protection_reason: str | None = None,
    detected_at: datetime | None = None,
) -> Finding:
    return Finding(
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        reason=reason,
        evidence={"cpu_pct": 1.2},
        est_monthly_cost_usd=cost,
        cost_confidence="estimate" if confidence == "estimate" else "unknown",
        proposed_action=action,
        protected=protected,
        protection_reason=protection_reason,
        detected_at=detected_at or datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc),
    )


def test_format_timestamp_utc_and_local() -> None:
    dt = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
    # With Asia/Kolkata (+5:30)
    ts = format_timestamp(dt, display_tz="Asia/Kolkata")
    assert "2026-11-12 12:00:00 UTC" in ts
    assert "2026-11-12 17:30:00 Asia/Kolkata" in ts

    # With UTC
    ts_utc = format_timestamp(dt, display_tz="UTC")
    assert ts_utc == "2026-11-12 12:00:00 UTC"

    # With empty display_tz
    ts_empty = format_timestamp(dt, display_tz="")
    assert ts_empty == "2026-11-12 12:00:00 UTC"

    # With invalid timezone - falls back gracefully to UTC without crashing
    ts_invalid = format_timestamp(dt, display_tz="NonExistent/Zone")
    assert ts_invalid == "2026-11-12 12:00:00 UTC"


def test_get_exemption_command_all_types() -> None:
    # EC2
    cmd_ec2 = get_exemption_command(ResourceType.EC2_INSTANCE, "i-abc123", "us-east-1")
    assert cmd_ec2 == (
        "aws ec2 create-tags --region us-east-1 --resources i-abc123 --tags Key=bsg:keep,Value=true"
    )

    # Elastic IP
    cmd_eip = get_exemption_command(ResourceType.ELASTIC_IP, "eipalloc-12345", "us-west-2")
    assert cmd_eip == (
        "aws ec2 create-tags --region us-west-2 "
        "--resources eipalloc-12345 --tags Key=bsg:keep,Value=true"
    )

    # NAT Gateway
    cmd_nat = get_exemption_command(ResourceType.NAT_GATEWAY, "nat-09876", "eu-west-1")
    assert cmd_nat == (
        "aws ec2 create-tags --region eu-west-1 "
        "--resources nat-09876 --tags Key=bsg:keep,Value=true"
    )

    # EBS Volume
    cmd_ebs = get_exemption_command(ResourceType.EBS_VOLUME, "vol-54321", "ap-south-1")
    assert cmd_ebs == (
        "aws ec2 create-tags --region ap-south-1 "
        "--resources vol-54321 --tags Key=bsg:keep,Value=true"
    )

    # Load Balancer
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c49"
    cmd_elb = get_exemption_command(ResourceType.LOAD_BALANCER, lb_arn, "us-east-1")
    assert cmd_elb == (
        f"aws elbv2 add-tags --region us-east-1 "
        f"--resource-arns {lb_arn} --tags Key=bsg:keep,Value=true"
    )

    # RDS Instance
    cmd_rds = get_exemption_command(ResourceType.RDS_INSTANCE, "my-db", "us-east-1")
    assert cmd_rds == (
        "aws rds add-tags-to-resource --region us-east-1 "
        "--resource-name my-db --tags Key=bsg:keep,Value=true"
    )

    # SageMaker Notebook
    sm_arn = "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/my-notebook"
    cmd_sm = get_exemption_command(ResourceType.SAGEMAKER_NOTEBOOK, sm_arn, "us-east-1")
    assert cmd_sm == (
        f"aws sagemaker add-tags --region us-east-1 "
        f"--resource-arn {sm_arn} --tags Key=bsg:keep,Value=true"
    )


def test_format_subject() -> None:
    # Dry run subject
    subj_dry = format_subject(2, total_cost=18.5, dry_run=True)
    assert subj_dry == "[DRY RUN] Bill Shock Guard: 2 resource(s) at risk (~$18.50/mo)"
    assert len(subj_dry) <= 100

    # Active subject
    subj_active = format_subject(1, total_cost=32.0, dry_run=False)
    assert subj_active == "Bill Shock Guard: 1 resource(s) at risk (~$32.00/mo)"

    # Actions taken
    subj_actions = format_subject(2, total_cost=10.0, dry_run=False, actions_count=1)
    assert "1 action(s) taken" in subj_actions

    # All quiet
    subj_quiet = format_subject(0, total_cost=0.0, dry_run=True)
    assert subj_quiet == "[DRY RUN] Bill Shock Guard: All quiet (0 idle resources)"

    # Findings with total_cost = None
    subj_no_cost = format_subject(3, total_cost=None, dry_run=False)
    assert subj_no_cost == "Bill Shock Guard: 3 resource(s) at risk"

    # Subject truncation under 100 chars
    long_subj = format_subject(99999999, total_cost=123456789.99, actions_count=88888888)
    assert len(long_subj) <= 100


def test_snapshot_sample_digest() -> None:
    """Snapshot test verifying exact structure, banners, and plain text content."""
    run_dt = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
    deadline_dt = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

    f1 = _make_finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-0123456789abcdef0",
        region="us-east-1",
        reason="CPU avg 1.2% and network 120 B/s over 24h",
        cost=15.50,
        confidence="estimate",
        action=ActionKind.EC2_STOP,
    )
    f2 = _make_finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id="eipalloc-0123456789abcdef0",
        region="us-east-1",
        reason="Unassociated Elastic IP incurring hourly charge",
        cost=3.65,
        confidence="estimate",
        action=ActionKind.EIP_RELEASE,
    )

    digest = format_digest(
        [f1, f2],
        dry_run=True,
        display_tz="Asia/Kolkata",
        deadlines={f1.key: deadline_dt, f2.key: deadline_dt},
        price_table_date="2026-11-12",
        now=run_dt,
    )

    # Assertions on critical components:
    # 1. DRY RUN banner is prominently at top
    assert "DRY RUN: nothing will be changed." in digest
    assert "In dry run mode, no AWS resources are modified." in digest

    # 2. Dual timestamps (UTC + display_tz)
    assert "2026-11-12 12:00:00 UTC (2026-11-12 17:30:00 Asia/Kolkata)" in digest
    assert "2026-11-13 12:00:00 UTC (2026-11-13 17:30:00 Asia/Kolkata)" in digest

    # 3. Per-finding details
    assert "1. [ec2_instance] i-0123456789abcdef0" in digest
    assert "Region: us-east-1" in digest
    assert "Reason: CPU avg 1.2% and network 120 B/s over 24h" in digest
    assert "Cost: Approx. $15.50 / month (confidence: estimate)" in digest
    assert "Action: [DRY RUN] Would stop ec2 instance" in digest
    assert "aws ec2 create-tags --region us-east-1 --resources i-0123456789abcdef0" in digest

    assert "2. [elastic_ip] eipalloc-0123456789abcdef0" in digest
    assert "Cost: Approx. $3.65 / month (confidence: estimate)" in digest
    assert "Action: [DRY RUN] Would release unassociated elastic ip" in digest
    assert "aws ec2 create-tags --region us-east-1 --resources eipalloc-0123456789abcdef0" in digest

    # 4. Exemption hint
    assert "replace Value=true with Value=YYYY-MM-DD" in digest

    # 5. Footer totals & price table date
    assert "Total idle resources flagged: 2" in digest
    assert "Total estimated monthly cost at risk: approx. $19.15 USD (estimate)" in digest
    assert "Price table date: 2026-11-12 (approximate rates)" in digest
    assert "Dry run: ENABLED (no changes made)" in digest


def test_digest_active_run_banner() -> None:
    f = _make_finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-test",
        cost=10.0,
        action=ActionKind.EC2_STOP,
    )
    digest = format_digest([f], dry_run=False, display_tz="UTC")

    assert "NOTICE: ACTIVE RUN - Mutating actions are enabled." in digest
    assert "Action: Stop EC2 instance" in digest
    assert "Dry run: DISABLED (mutating actions enabled)" in digest


def test_digest_unknown_costs_mixed() -> None:
    f_known = _make_finding(resource_id="i-known", cost=20.0, confidence="estimate")
    f_unknown = _make_finding(resource_id="i-unknown", cost=None, confidence="unknown")

    digest = format_digest([f_known, f_unknown], dry_run=True)

    assert "Cost: Approx. $20.00 / month (confidence: estimate)" in digest
    assert "Cost: Unknown (confidence: unknown)" in digest
    assert "approx. $20.00 USD (estimate, plus 1 resource(s) with unknown cost)" in digest


def test_digest_all_unknown_costs() -> None:
    f1 = _make_finding(resource_id="i-1", cost=None, confidence="unknown")
    f2 = _make_finding(resource_id="i-2", cost=None, confidence="unknown")

    digest = format_digest([f1, f2], dry_run=True)
    assert "Total estimated monthly cost at risk: unknown (2 unknown)" in digest


def test_digest_empty_findings() -> None:
    digest = format_digest([], dry_run=True)
    assert "IDLE RESOURCE WARNINGS (0):" in digest
    assert "No new idle resources detected." in digest
    assert "Total idle resources flagged: 0" in digest
    assert "Total estimated monthly cost at risk: $0.00 USD" in digest


def test_digest_protected_resource() -> None:
    f = _make_finding(
        resource_id="i-keep",
        protected=True,
        protection_reason="Tagged bsg:keep=true",
        cost=50.0,
    )
    digest = format_digest([f], dry_run=True)

    assert "Action: Skipped - Protected (Tagged bsg:keep=true)" in digest
    assert "When: No action will be taken" in digest


def test_digest_actions_taken_and_failed() -> None:
    f_ok = _make_finding(resource_id="i-stopped")
    res_ok = ActionResult(ok=True, performed=True, detail="Stopped instance i-stopped")

    f_fail = _make_finding(resource_id="i-failed")

    f_def = _make_finding(resource_id="i-def")

    digest = format_digest(
        findings=[],
        actions_taken=[(f_ok, res_ok)],
        actions_failed=[(f_fail, "UnauthorizedOperation: client not permitted")],
        actions_deferred=[f_def],
        notification_failures=["Failed to publish to SNS topic arn:..."],
        dry_run=False,
    )

    assert "ACTIONS TAKEN IN THIS RUN:" in digest
    assert "Action: Stopped instance i-stopped [SUCCESS]" in digest

    assert "ACTIONS FAILED IN THIS RUN:" in digest
    assert "Error: UnauthorizedOperation: client not permitted" in digest

    assert "ACTIONS DEFERRED (Circuit breaker limit reached):" in digest
    assert "Deferred action: Stop EC2 instance" in digest

    assert "ATTENTION: Previous notification delivery failures:" in digest
    assert "Failed to publish to SNS topic arn:..." in digest


def test_digest_finding_without_proposed_action_or_deadline() -> None:
    f_no_action = _make_finding(
        resource_id="nat-0123",
        resource_type=ResourceType.NAT_GATEWAY,
        action=None,
    )
    digest = format_digest([f_no_action], dry_run=True)
    assert "Action: Alert only (no remediation action configured)" in digest
    assert "When: Informational only" in digest

    # Active run without deadline provided
    f_action = _make_finding(
        resource_id="i-nodeadline",
        action=ActionKind.EC2_STOP,
    )
    digest_active = format_digest([f_action], dry_run=False)
    assert "When: After grace period expires if still idle" in digest_active


def test_digest_actions_taken_with_plain_findings() -> None:
    f_with_act = _make_finding(resource_id="i-1", action=ActionKind.EC2_STOP)
    f_no_act = _make_finding(resource_id="i-2", action=None)

    digest = format_digest(
        findings=[],
        actions_taken=[f_with_act, f_no_act],
        dry_run=False,
    )
    assert "Action: Stop EC2 instance" in digest
    assert "Action: None" in digest
