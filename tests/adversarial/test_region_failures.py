"""Adversarial tests for Invariant I9: region listing failures and per-region error containment."""

from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import botocore.exceptions
import moto

from bill_shock_guard.aws import get_enabled_regions
from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    FindingState,
    FindingStatus,
    RecheckResult,
    ResourceType,
)
from tests.fakes.fake_clock import FakeClock


def _make_context(
    clock: FakeClock,
    config: Config,
    logger: JsonLogger,
    client_factory: Any = None,
) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-region-failure",
        logger=logger,
        client_factory=client_factory or (lambda svc, reg=None: MagicMock()),
    )


class RegionFailureDetector:
    def __init__(
        self,
        failing_regions: set[str] | None = None,
        failing_recheck_regions: set[str] | None = None,
        resource_type: ResourceType = ResourceType.EC2_INSTANCE,
    ) -> None:
        self.resource_type = resource_type
        self.failing_regions = failing_regions or set()
        self.failing_recheck_regions = failing_recheck_regions or set()
        self.scanned_regions: list[str] = []

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        self.scanned_regions.append(region)
        if region in self.failing_regions:
            error_response = {
                "Error": {
                    "Code": "UnauthorizedOperation",
                    "Message": f"You are not authorized to perform this operation in {region}.",
                }
            }
            raise botocore.exceptions.ClientError(error_response, "DescribeInstances")

        return [
            Finding(
                resource_type=self.resource_type,
                resource_id=f"i-{region}-01",
                region=region,
                reason="Idle test instance",
                evidence={"cpu": 0.1},
                est_monthly_cost_usd=10.0,
                cost_confidence="estimate",
                proposed_action=ActionKind.EC2_STOP,
                protected=False,
                protection_reason=None,
                detected_at=ctx.clock.now(),
            )
        ]

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        if finding.region in self.failing_recheck_regions or finding.region in self.failing_regions:
            error_response = {
                "Error": {
                    "Code": "RequestTimeout",
                    "Message": f"Connection timed out to {finding.region}",
                }
            }
            raise botocore.exceptions.ClientError(error_response, "DescribeInstances")
        return RecheckResult(still_idle=True, protected=False, reason="Still idle")


class RecordingAction:
    def __init__(self) -> None:
        self.applied: list[Finding] = []

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        self.applied.append(finding)
        return ActionResult(ok=True, performed=True, detail=f"Stopped {finding.resource_id}")


def test_I9_describe_regions_client_error_fallback() -> None:
    """When describe_regions raises ClientError, get_enabled_regions falls back to us-east-1."""
    mock_ec2 = MagicMock()
    error_response = {
        "Error": {
            "Code": "UnauthorizedOperation",
            "Message": "You are not authorized to describe regions.",
        }
    }
    mock_ec2.describe_regions.side_effect = botocore.exceptions.ClientError(
        error_response, "DescribeRegions"
    )

    with patch("bill_shock_guard.aws.get_boto_client", return_value=mock_ec2):
        regions = get_enabled_regions()
        assert regions == ["us-east-1"]


def test_I9_describe_regions_endpoint_connection_error_fallback() -> None:
    """When describe_regions raises EndpointConnectionError, falls back to us-east-1."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.side_effect = botocore.exceptions.EndpointConnectionError(
        endpoint_url="https://ec2.us-east-1.amazonaws.com"
    )

    with patch("bill_shock_guard.aws.get_boto_client", return_value=mock_ec2):
        regions = get_enabled_regions(target_regions=["*"])
        assert regions == ["us-east-1"]


def test_I9_runner_region_discovery_error_retains_explicit_config_regions(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    """When get_enabled_regions fails, runner retains explicit config regions."""
    cfg = Config(regions=["us-west-2", "eu-central-1"])
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    with patch(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        side_effect=RuntimeError("STS/EC2 totally down"),
    ):
        detector = RegionFailureDetector(failing_regions=set())
        runner = EngineRunner(detectors=[detector], actions={})
        summary = runner.run(ctx, store)

        # Runner resolved the explicit config regions despite region discovery exception
        assert "us-west-2" in detector.scanned_regions
        assert "eu-central-1" in detector.scanned_regions
        assert len(summary.errors) >= 1
        assert "Region discovery failed" in summary.errors[0]


@moto.mock_aws
def test_I9_one_region_fails_does_not_abort_other_regions(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    """Invariant I9: One failing region never aborts scanning of other regions."""
    cfg = Config(
        dry_run=True,
        regions=["us-east-1", "eu-west-1", "us-west-2"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    # eu-west-1 fails, but us-east-1 and us-west-2 succeed
    detector = RegionFailureDetector(failing_regions={"eu-west-1"})
    mock_notifier = MagicMock()
    mock_notifier.send.return_value = True

    with patch(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        return_value=["us-east-1", "eu-west-1", "us-west-2"],
    ):
        runner = EngineRunner(detectors=[detector], actions={})
        summary = runner.run(ctx, store, notifier=mock_notifier)

    # Findings from us-east-1 and us-west-2 were found
    assert summary.findings_detected == 2
    found_regions = {f.region for f in summary.findings}
    assert found_regions == {"us-east-1", "us-west-2"}

    # Warning digest delivered for the 2 healthy regions
    assert summary.warnings_sent == 2

    # Exactly 1 error recorded for the failing region
    assert len(summary.errors) == 1
    assert "Detector RegionFailureDetector failed in region eu-west-1" in summary.errors[0]


def test_I9_recheck_api_error_skips_action(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    """Invariant I9: Live recheck API error skips mutating action and leaves resource untouched."""
    now = fake_clock.now()
    cfg = Config(
        dry_run=False,
        regions=["eu-west-1"],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-eu-west-1-01",
        region="eu-west-1",
        reason="Idle EC2",
        evidence={},
        est_monthly_cost_usd=25.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    # State is WARNED and grace period has expired
    past_deadline = now
    warned_at = past_deadline - timedelta(hours=cfg.grace_hours)
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=past_deadline,
        last_seen=past_deadline,
        warned_at=warned_at,
        action_deadline=past_deadline,
        version=1,
    )
    store.put(state)

    # Advance clock past deadline
    fake_clock.advance(hours=2)

    detector = RegionFailureDetector(failing_recheck_regions={"eu-west-1"})
    action = RecordingAction()

    with patch(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        return_value=["eu-west-1"],
    ):
        runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
        summary = runner.run(ctx, store, notifier=MagicMock())

    # Invariant I9: Action was SKIPPED due to recheck API error
    assert summary.actions_attempted == 0
    assert summary.actions_performed == 0
    assert len(action.applied) == 0

    # Error recorded
    recheck_errors = [e for e in summary.errors if "Recheck failed" in e]
    assert len(recheck_errors) == 1

    # State must NOT be transitioned to ACTED
    saved_state = store.get(finding.key)
    assert saved_state is not None
    assert saved_state.status == FindingStatus.WARNED


def test_I9_describe_regions_failure_with_non_us_east_target_yields_empty() -> None:
    """Adversarial edge case: if describe_regions fails, fallback available is ['us-east-1'].

    If target_regions does not include 'us-east-1', get_enabled_regions returns an empty list.
    """
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AuthFailure", "Message": "AWS auth failed"}},
        "DescribeRegions",
    )
    with patch("bill_shock_guard.aws.get_boto_client", return_value=mock_ec2):
        regions = get_enabled_regions(target_regions=["ap-south-1", "eu-west-1"])
        assert regions == []


def test_I9_detector_failure_preserves_existing_warning(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    """Missing findings during an outage preserve the previous warning."""
    now = fake_clock.now()
    cfg = Config(dry_run=True, regions=["eu-west-1"])
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    key = "eu-west-1#ec2_instance#i-outage-01"
    prior_state = FindingState(
        key=key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=now,
        last_seen=now,
        warned_at=now,
        action_deadline=now,
        version=1,
    )
    store.put(prior_state)

    # Detector fails in eu-west-1
    detector = RegionFailureDetector(failing_regions={"eu-west-1"})

    with patch(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        return_value=["eu-west-1"],
    ):
        runner = EngineRunner(detectors=[detector], actions={})
        summary = runner.run(ctx, store)

    assert store.get(key) == prior_state
    assert summary.findings_resolved == 0
    assert len(summary.errors) == 1


def test_I9_recheck_unknown_idle_status_skips_action(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    now = fake_clock.now()
    cfg = Config(
        dry_run=False,
        regions=["us-east-1"],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-missing-metrics",
        region="us-east-1",
        reason="Idle EC2",
        evidence={},
        est_monthly_cost_usd=25.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=now,
        last_seen=now,
        warned_at=now,
        action_deadline=now,
        version=1,
    )
    store.put(state)
    fake_clock.advance(hours=2)

    mock_detector = MagicMock()
    mock_detector.resource_type = ResourceType.EC2_INSTANCE
    mock_detector.detect.return_value = [finding]
    # Recheck reports unknown (None) due to missing metrics
    mock_detector.recheck.return_value = RecheckResult(
        still_idle=None,
        protected=False,
        reason="CloudWatch metric data missing or returned empty values",
    )

    action = RecordingAction()
    runner = EngineRunner(detectors=[mock_detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=MagicMock())

    # Invariant I9: Unknown is NOT idle! Action skipped.
    assert summary.actions_attempted == 0
    assert summary.actions_performed == 0
    assert len(action.applied) == 0

    # Resource stays WARNED
    saved_state = store.get(finding.key)
    assert saved_state is not None
    assert saved_state.status == FindingStatus.WARNED
