"""Tests for the execution runner and safety invariants I1 to I10."""

from datetime import timedelta

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


class FakeDetector:
    def __init__(
        self,
        resource_type: ResourceType = ResourceType.EC2_INSTANCE,
        findings: list[Finding] | None = None,
        recheck_result: RecheckResult | None = None,
        raise_on_detect: bool = False,
        raise_on_recheck: bool = False,
    ) -> None:
        self.resource_type = resource_type
        self.findings = findings or []
        self.recheck_result = (
            recheck_result
            if recheck_result is not None
            else RecheckResult(still_idle=True, protected=False, reason="Still idle")
        )
        self.raise_on_detect = raise_on_detect
        self.raise_on_recheck = raise_on_recheck
        self.detect_calls = 0
        self.recheck_calls = 0

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        self.detect_calls += 1
        if self.raise_on_detect:
            raise RuntimeError(f"Detector error in {region}")
        return [f for f in self.findings if f.region == region or region == "us-east-1"]

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        self.recheck_calls += 1
        if self.raise_on_recheck:
            raise RuntimeError("API error during live recheck")
        return self.recheck_result


class FakeAction:
    def __init__(
        self,
        kind: ActionKind = ActionKind.EC2_STOP,
        should_succeed: bool = True,
        raise_exception: bool = False,
    ) -> None:
        self.kind = kind
        self.should_succeed = should_succeed
        self.raise_exception = raise_exception
        self.applied_findings: list[Finding] = []

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        self.applied_findings.append(finding)
        if self.raise_exception:
            raise RuntimeError("Action exploded")
        if self.should_succeed:
            return ActionResult(ok=True, performed=True, detail=f"Stopped {finding.resource_id}")
        return ActionResult(
            ok=False,
            performed=False,
            detail=f"Failed to stop {finding.resource_id}",
            error="ClientError: Unauthorized",
        )


class FakeNotifier:
    def __init__(self, name: str = "sns", succeed: bool = True) -> None:
        self.name = name
        self.succeed = succeed
        self.sent_messages: list[tuple[str, str]] = []

    def send(self, subject: str, body: str) -> bool:
        self.sent_messages.append((subject, body))
        return self.succeed


def _make_context(
    clock: FakeClock,
    config: Config,
    logger: JsonLogger,
) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-run",
        logger=logger,
        client_factory=lambda svc, reg: None,
    )


def test_I1_dry_run_never_mutates(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """I1: Never perform a mutating AWS call when dry_run is true."""
    cfg = Config(
        dry_run=True,
        grace_hours=24,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-12345",
        region="us-east-1",
        reason="Idle EC2",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=fake_clock.now(),
    )
    detector = FakeDetector(findings=[finding])
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})

    # Run 1: Detects finding and delivers warning
    summary1 = runner.run(ctx, store, notifier=notifier)
    assert summary1.warnings_sent == 1
    assert len(action.applied_findings) == 0

    # Advance clock past grace period
    fake_clock.advance(hours=25)

    # Run 2: Grace expired, but dry_run is True
    summary2 = runner.run(ctx, store, notifier=notifier)
    assert summary2.actions_performed == 0
    assert summary2.findings_would_act == 1
    # Assert zero mutating action calls made
    assert len(action.applied_findings) == 0

    state = store.get(finding.key)
    assert state is not None
    assert state.status == FindingStatus.WOULD_ACT


def test_I2_warning_delivery_required_for_action(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """I2: Never act unless warning was successfully delivered and recorded."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-test-i2",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=fake_clock.now(),
    )
    detector = FakeDetector(findings=[finding])
    action = FakeAction()
    # Notifier fails delivery!
    failing_notifier = FakeNotifier(succeed=False)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})

    # Run 1: Delivery fails
    summary1 = runner.run(ctx, store, notifier=failing_notifier)
    assert summary1.warnings_sent == 0
    st1 = store.get(finding.key)
    assert st1 is not None
    assert st1.status == FindingStatus.DETECTED
    assert st1.warned_at is None

    # Advance clock past grace period
    fake_clock.advance(hours=50)

    # Run 2: Even though time passed, warning was never recorded as delivered -> no action!
    summary2 = runner.run(ctx, store, notifier=failing_notifier)
    assert summary2.actions_performed == 0
    assert len(action.applied_findings) == 0


def test_I3_protected_resource_never_acted_on(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """I3: Protected resource is never acted on, re-evaluated fresh at action time."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    # Pre-populate state as WARNED with expired grace period
    t0 = fake_clock.now() - timedelta(hours=30)
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-protected",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,  # Unprotected during detection
        protection_reason=None,
        detected_at=t0,
    )
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=t0,
        last_seen=t0,
        warned_at=t0,
        action_deadline=t0 + timedelta(hours=24),
    )
    store.put(state)

    # BUT live recheck right before action detects a protect tag!
    recheck_res = RecheckResult(
        still_idle=True,
        protected=True,
        reason="Tag bsg:keep=true added after warning",
    )
    detector = FakeDetector(findings=[finding], recheck_result=recheck_res)
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=notifier)

    assert summary.actions_performed == 0
    assert len(action.applied_findings) == 0
    assert summary.findings_exempt == 1

    st = store.get(finding.key)
    assert st is not None
    assert st.status == FindingStatus.EXEMPT


def test_I4_recheck_before_action_aborts_if_not_idle(
    fake_clock: FakeClock, logger: JsonLogger
) -> None:
    """I4: Immediately before action, re-check live resource. If not idle, abort and resolve."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    t0 = fake_clock.now() - timedelta(hours=30)
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-busy-now",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=t0,
    )
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=t0,
        last_seen=t0,
        warned_at=t0,
        action_deadline=t0 + timedelta(hours=24),
    )
    store.put(state)

    # Live recheck shows resource is NO LONGER IDLE (e.g. CPU spiked)
    recheck_res = RecheckResult(still_idle=False, protected=False, reason="CPU avg is 45%")
    detector = FakeDetector(findings=[finding], recheck_result=recheck_res)
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=notifier)

    assert summary.actions_performed == 0
    assert len(action.applied_findings) == 0
    assert summary.findings_resolved == 1

    st = store.get(finding.key)
    assert st is not None
    assert st.status == FindingStatus.RESOLVED


def test_I5_disabled_action_not_performed(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """I5: Only perform actions listed in enabled_actions."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        enabled_actions=[ActionKind.EIP_RELEASE],  # ec2_stop is disabled!
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    t0 = fake_clock.now() - timedelta(hours=30)
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-disabled-act",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=t0,
    )
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=t0,
        last_seen=t0,
        warned_at=t0,
        action_deadline=t0 + timedelta(hours=24),
    )
    store.put(state)

    detector = FakeDetector(findings=[finding])
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=notifier)

    assert summary.actions_performed == 0
    assert len(action.applied_findings) == 0


def test_I7_circuit_breaker_max_actions(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """I7: Circuit breaker caps mutating actions per run at max_actions_per_run."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        max_actions_per_run=2,
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    t0 = fake_clock.now() - timedelta(hours=30)
    findings: list[Finding] = []
    for i in range(5):
        f = Finding(
            resource_type=ResourceType.EC2_INSTANCE,
            resource_id=f"i-cb-{i}",
            region="us-east-1",
            reason="Idle",
            evidence={},
            est_monthly_cost_usd=10.0,
            cost_confidence="estimate",
            proposed_action=ActionKind.EC2_STOP,
            protected=False,
            protection_reason=None,
            detected_at=t0,
        )
        findings.append(f)
        state = FindingState(
            key=f.key,
            status=FindingStatus.WARNED,
            metadata={
                "warning_action": ActionKind.EC2_STOP.value,
                "warning_topic_arn": cfg.notify.sns_topic_arn,
            },
            first_seen=t0,
            last_seen=t0,
            warned_at=t0,
            action_deadline=t0 + timedelta(hours=24),
        )
        store.put(state)

    detector = FakeDetector(findings=findings)
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=notifier)

    # Exactly 2 actions performed (limit is 2)
    assert summary.actions_performed == 2
    assert summary.actions_deferred == 3
    assert len(action.applied_findings) == 2


def test_I8_idempotent_no_duplicate_warning_or_action(
    fake_clock: FakeClock, logger: JsonLogger
) -> None:
    """I8: Running engine twice on the same state produces no duplicate warnings/actions."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-idem",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=fake_clock.now(),
    )
    detector = FakeDetector(findings=[finding])
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})

    # Run 1: 1 warning sent
    s1 = runner.run(ctx, store, notifier=notifier)
    assert s1.warnings_sent == 1
    assert len(notifier.sent_messages) == 1

    # Run 2 immediately at same time: 0 warnings, 0 actions
    s2 = runner.run(ctx, store, notifier=notifier)
    assert s2.warnings_sent == 0
    assert s2.actions_performed == 0
    assert len(notifier.sent_messages) == 1  # No duplicate message!


def test_I9_unknown_is_not_idle_and_per_detector_isolation(
    fake_clock: FakeClock, logger: JsonLogger
) -> None:
    """I9: Unknown metrics/API errors do not act; failing detector in one region isolates."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1", "us-west-2"],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    t0 = fake_clock.now() - timedelta(hours=30)
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-unknown-metrics",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=t0,
    )
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=t0,
        last_seen=t0,
        warned_at=t0,
        action_deadline=t0 + timedelta(hours=24),
    )
    store.put(state)

    # Recheck returns None for still_idle (unknown metrics)
    recheck_res = RecheckResult(still_idle=None, protected=False, reason="Metrics missing")
    detector = FakeDetector(findings=[finding], recheck_result=recheck_res)
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=notifier)

    # Unknown is NOT idle -> no action taken!
    assert summary.actions_performed == 0
    assert len(action.applied_findings) == 0

    # Also test detector exception isolation:
    failing_detector = FakeDetector(raise_on_detect=True)
    working_detector = FakeDetector(findings=[finding])
    runner2 = EngineRunner(
        detectors=[failing_detector, working_detector],
        actions={ActionKind.EC2_STOP: action},
    )
    summary2 = runner2.run(ctx, store, notifier=notifier)
    # The run finished despite detector failure in failing_detector
    assert len(summary2.errors) > 0
    assert summary2.findings_detected > 0


def test_I10_protect_tag_cancels_pending_action(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """I10: Adding protect tag cancels pending action by next run."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    t0 = fake_clock.now() - timedelta(hours=30)
    # Initial state is WARNED
    state = FindingState(
        key="us-east-1#ec2_instance#i-tag-later",
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=t0,
        last_seen=t0,
        warned_at=t0,
        action_deadline=t0 + timedelta(hours=24),
    )
    store.put(state)

    # Finding detected in next run now has protected=True!
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-tag-later",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=True,
        protection_reason="Tagged bsg:keep=true",
        detected_at=fake_clock.now(),
    )
    detector = FakeDetector(findings=[finding])
    action = FakeAction()
    notifier = FakeNotifier(succeed=True)

    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})
    summary = runner.run(ctx, store, notifier=notifier)

    assert summary.actions_performed == 0
    assert summary.findings_exempt == 1
    st = store.get(finding.key)
    assert st is not None
    assert st.status == FindingStatus.EXEMPT


def test_cap_of_3_retries_for_failed(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """Cap of 3 retries for FAILED resources."""
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    t0 = fake_clock.now() - timedelta(hours=30)
    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-fails",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=t0,
    )
    # Initial state is WARNED
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        metadata={
            "warning_action": ActionKind.EC2_STOP.value,
            "warning_topic_arn": cfg.notify.sns_topic_arn,
        },
        first_seen=t0,
        last_seen=t0,
        warned_at=t0,
        action_deadline=t0 + timedelta(hours=24),
    )
    store.put(state)

    detector = FakeDetector(findings=[finding])
    failing_action = FakeAction(should_succeed=False)
    notifier = FakeNotifier(succeed=True)
    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: failing_action})

    # Attempt 1: Fails
    s1 = runner.run(ctx, store, notifier=notifier)
    assert s1.actions_failed == 1
    assert store.get(finding.key).attempts == 1  # type: ignore
    assert store.get(finding.key).status == FindingStatus.FAILED  # type: ignore

    # Attempt 2: Fails (retry 1)
    s2 = runner.run(ctx, store, notifier=notifier)
    assert s2.actions_failed == 1
    assert store.get(finding.key).attempts == 2  # type: ignore

    # Attempt 3: Fails (retry 2)
    s3 = runner.run(ctx, store, notifier=notifier)
    assert s3.actions_failed == 1
    assert store.get(finding.key).attempts == 3  # type: ignore

    # Attempt 4: Attempts reached 3 -> capped! No more action attempts!
    s4 = runner.run(ctx, store, notifier=notifier)
    assert s4.actions_attempted == 0
    assert s4.actions_failed == 0
    assert store.get(finding.key).attempts == 3  # type: ignore
