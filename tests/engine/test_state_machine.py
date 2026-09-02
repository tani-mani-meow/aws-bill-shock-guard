"""Tests for pure state machine transition logic in state_machine.py."""

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from bill_shock_guard.config import Config
from bill_shock_guard.engine.state_machine import decide
from bill_shock_guard.models import (
    ActionKind,
    Effect,
    Finding,
    FindingState,
    FindingStatus,
    ResourceType,
)


def _make_finding(
    resource_type: ResourceType = ResourceType.EC2_INSTANCE,
    resource_id: str = "i-1234567890abcdef0",
    region: str = "us-east-1",
    proposed_action: ActionKind | None = ActionKind.EC2_STOP,
    protected: bool = False,
    protection_reason: str | None = None,
    detected_at: datetime | None = None,
) -> Finding:
    now = detected_at or datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return Finding(
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        reason="Idle EC2 instance",
        evidence={"cpu_avg": 0.5},
        est_monthly_cost_usd=15.0,
        cost_confidence="estimate",
        proposed_action=proposed_action,
        protected=protected,
        protection_reason=protection_reason,
        detected_at=now,
    )


def test_no_finding_no_state() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config()
    dec = decide(None, None, now, cfg)
    assert dec.next_status == FindingStatus.RESOLVED
    assert dec.effect == Effect.NONE


def test_finding_disappeared_resolves() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config()
    state = FindingState(
        key="us-east-1#ec2_instance#i-123",
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=5),
        last_seen=now - timedelta(hours=1),
        warned_at=now - timedelta(hours=4),
    )
    dec = decide(None, state, now, cfg)
    assert dec.next_status == FindingStatus.RESOLVED
    assert dec.effect == Effect.NONE


def test_new_finding_queues_warning() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config()
    finding = _make_finding(detected_at=now)
    dec = decide(finding, None, now, cfg)
    assert dec.next_status == FindingStatus.DETECTED
    assert dec.effect == Effect.SEND_WARNING


def test_protected_finding_becomes_exempt() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config()
    finding = _make_finding(protected=True, protection_reason="Tag bsg:keep=true")
    dec = decide(finding, None, now, cfg)
    assert dec.next_status == FindingStatus.EXEMPT
    assert dec.effect == Effect.NONE


def test_warned_resource_active_grace_period() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config(grace_hours=24)
    finding = _make_finding(detected_at=now)
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=10),
        last_seen=now,
        warned_at=now - timedelta(hours=10),
        action_deadline=now - timedelta(hours=10) + timedelta(hours=24),
    )
    dec = decide(finding, state, now, cfg)
    assert dec.next_status == FindingStatus.WARNED
    assert dec.effect == Effect.NONE


def test_warned_resource_grace_elapsed_dry_run() -> None:
    now = datetime(2026, 1, 2, 13, 0, tzinfo=timezone.utc)
    cfg = Config(dry_run=True, grace_hours=24)
    finding = _make_finding()
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=25),
        last_seen=now,
        warned_at=now - timedelta(hours=25),
        action_deadline=now - timedelta(hours=1),
    )
    dec = decide(finding, state, now, cfg)
    assert dec.next_status == FindingStatus.WOULD_ACT
    assert dec.effect == Effect.NONE


def test_warned_resource_grace_elapsed_action_applied() -> None:
    now = datetime(2026, 1, 2, 13, 0, tzinfo=timezone.utc)
    cfg = Config(dry_run=False, grace_hours=24, enabled_actions=[ActionKind.EC2_STOP])
    finding = _make_finding(proposed_action=ActionKind.EC2_STOP)
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=25),
        last_seen=now,
        warned_at=now - timedelta(hours=25),
        action_deadline=now - timedelta(hours=1),
    )
    dec = decide(finding, state, now, cfg)
    assert dec.next_status == FindingStatus.ACTED
    assert dec.effect == Effect.ATTEMPT_ACTION


def test_disabled_action_not_attempted() -> None:
    now = datetime(2026, 1, 2, 13, 0, tzinfo=timezone.utc)
    cfg = Config(dry_run=False, grace_hours=24, enabled_actions=[ActionKind.EIP_RELEASE])
    finding = _make_finding(proposed_action=ActionKind.EC2_STOP)
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=25),
        last_seen=now,
        warned_at=now - timedelta(hours=25),
        action_deadline=now - timedelta(hours=1),
    )
    dec = decide(finding, state, now, cfg)
    assert dec.next_status == FindingStatus.WARNED
    assert dec.effect == Effect.NONE


def test_circuit_breaker_defers_action() -> None:
    now = datetime(2026, 1, 2, 13, 0, tzinfo=timezone.utc)
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        max_actions_per_run=5,
        enabled_actions=[ActionKind.EC2_STOP],
    )
    finding = _make_finding(proposed_action=ActionKind.EC2_STOP)
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=25),
        last_seen=now,
        warned_at=now - timedelta(hours=25),
        action_deadline=now - timedelta(hours=1),
    )
    # actions_taken == max_actions_per_run -> deferred!
    dec = decide(finding, state, now, cfg, actions_taken=5)
    assert dec.next_status == FindingStatus.WARNED
    assert dec.effect == Effect.NONE
    assert "Circuit breaker" in dec.reason


def test_failed_retry_cap_at_three() -> None:
    now = datetime(2026, 1, 2, 13, 0, tzinfo=timezone.utc)
    cfg = Config(dry_run=False, enabled_actions=[ActionKind.EC2_STOP])
    finding = _make_finding(proposed_action=ActionKind.EC2_STOP)

    # 1st retry (attempts = 1) -> can attempt
    state1 = FindingState(
        key=finding.key,
        status=FindingStatus.FAILED,
        first_seen=now - timedelta(days=2),
        last_seen=now,
        attempts=1,
        last_error="ClientError: throttle",
    )
    dec1 = decide(finding, state1, now, cfg)
    assert dec1.effect == Effect.ATTEMPT_ACTION

    # 2nd retry (attempts = 2) -> can attempt
    state2 = FindingState(
        key=finding.key,
        status=FindingStatus.FAILED,
        first_seen=now - timedelta(days=2),
        last_seen=now,
        attempts=2,
        last_error="ClientError: throttle",
    )
    dec2 = decide(finding, state2, now, cfg)
    assert dec2.effect == Effect.ATTEMPT_ACTION

    # 3 attempts already performed -> stop retrying!
    state3 = FindingState(
        key=finding.key,
        status=FindingStatus.FAILED,
        first_seen=now - timedelta(days=2),
        last_seen=now,
        attempts=3,
        last_error="ClientError: throttle",
    )
    dec3 = decide(finding, state3, now, cfg)
    assert dec3.next_status == FindingStatus.FAILED
    assert dec3.effect == Effect.NONE
    assert "stopped retrying" in dec3.reason


# ---------------------------------------------------------------------------
# Hypothesis Property-Based Tests for Invariants I1, I2, I7, I8
# ---------------------------------------------------------------------------


@st.composite
def finding_strategy(draw: st.DrawFn) -> Finding:
    res_type = draw(st.sampled_from(list(ResourceType)))
    res_id = draw(st.text(min_size=3, max_size=20, alphabet="abcdef0123456789-"))
    region = draw(st.sampled_from(["us-east-1", "us-west-2", "eu-west-1"]))
    action = draw(st.one_of(st.none(), st.sampled_from(list(ActionKind))))
    protected = draw(st.booleans())
    reason = draw(st.text(max_size=30)) if protected else None
    dt = draw(
        st.datetimes(
            min_value=datetime(2025, 1, 1),
            max_value=datetime(2027, 1, 1),
            timezones=st.just(timezone.utc),
        )
    )
    return Finding(
        resource_type=res_type,
        resource_id=res_id,
        region=region,
        reason="Property test finding",
        evidence={},
        est_monthly_cost_usd=draw(st.one_of(st.none(), st.floats(min_value=0.0, max_value=1000.0))),
        cost_confidence="estimate",
        proposed_action=action,
        protected=protected,
        protection_reason=reason,
        detected_at=dt,
    )


@st.composite
def finding_state_strategy(draw: st.DrawFn, finding: Finding) -> FindingState:
    status = draw(st.sampled_from(list(FindingStatus)))
    t0 = finding.detected_at
    first_seen = t0 - timedelta(hours=draw(st.integers(min_value=0, max_value=100)))
    last_seen = t0
    has_warned = draw(st.booleans())
    warned_at = (
        first_seen + timedelta(hours=draw(st.integers(min_value=0, max_value=50)))
        if has_warned
        else None
    )
    deadline = (
        warned_at + timedelta(hours=draw(st.integers(min_value=1, max_value=72)))
        if warned_at
        else None
    )
    attempts = draw(st.integers(min_value=0, max_value=5))
    version = draw(st.integers(min_value=1, max_value=10))

    return FindingState(
        key=finding.key,
        status=status,
        first_seen=first_seen,
        last_seen=last_seen,
        warned_at=warned_at,
        action_deadline=deadline,
        attempts=attempts,
        version=version,
    )


@given(
    finding=finding_strategy(),
    state_opt=st.one_of(st.none(), st.booleans()),
    grace_hours=st.integers(min_value=1, max_value=72),
    advance_hours=st.integers(min_value=0, max_value=200),
)
@settings(max_examples=100)
def test_I1_dry_run_never_acts_property(
    finding: Finding,
    state_opt: bool | None,
    grace_hours: int,
    advance_hours: int,
) -> None:
    """Invariant I1: When dry_run is True, state_machine NEVER outputs Effect.ATTEMPT_ACTION."""
    cfg = Config(dry_run=True, grace_hours=grace_hours)
    now = finding.detected_at + timedelta(hours=advance_hours)

    state: FindingState | None = None
    if state_opt is not None:
        state = FindingState(
            key=finding.key,
            status=FindingStatus.WARNED if state_opt else FindingStatus.DETECTED,
            first_seen=finding.detected_at,
            last_seen=finding.detected_at,
            warned_at=finding.detected_at if state_opt else None,
            action_deadline=(
                finding.detected_at + timedelta(hours=grace_hours) if state_opt else None
            ),
        )

    decision = decide(finding, state, now, cfg)
    assert decision.effect != Effect.ATTEMPT_ACTION
    assert decision.next_status != FindingStatus.ACTED


@given(
    finding=finding_strategy(),
    warned_offset_hours=st.integers(min_value=-50, max_value=50),
    grace_hours=st.integers(min_value=1, max_value=48),
)
@settings(max_examples=100)
def test_I2_grace_and_warning_required_property(
    finding: Finding,
    warned_offset_hours: int,
    grace_hours: int,
) -> None:
    """Invariant I2: Never act unless warning was delivered and grace period has elapsed."""
    cfg = Config(
        dry_run=False,
        grace_hours=grace_hours,
        enabled_actions=list(ActionKind),
    )
    now = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    warned_at = now + timedelta(hours=warned_offset_hours)

    # State with warning
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=warned_at - timedelta(hours=5),
        last_seen=now,
        warned_at=warned_at,
        action_deadline=warned_at + timedelta(hours=grace_hours),
    )

    decision = decide(finding, state, now, cfg)

    # If now < deadline, effect CANNOT be ATTEMPT_ACTION
    deadline = state.action_deadline
    assert deadline is not None
    if now < deadline:
        assert decision.effect != Effect.ATTEMPT_ACTION
        assert decision.next_status != FindingStatus.ACTED

    # If state has no warned_at, effect CANNOT be ATTEMPT_ACTION
    unwarned_state = FindingState(
        key=finding.key,
        status=FindingStatus.DETECTED,
        first_seen=now,
        last_seen=now,
        warned_at=None,
    )
    decision_unwarned = decide(finding, unwarned_state, now, cfg)
    assert decision_unwarned.effect != Effect.ATTEMPT_ACTION


@given(
    max_actions=st.integers(min_value=0, max_value=10),
    actions_taken=st.integers(min_value=0, max_value=20),
)
@settings(max_examples=50)
def test_I7_circuit_breaker_property(max_actions: int, actions_taken: int) -> None:
    """Invariant I7: At most max_actions_per_run mutating actions allowed per run."""
    now = datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        max_actions_per_run=max_actions,
        enabled_actions=[ActionKind.EC2_STOP],
    )
    finding = _make_finding(
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        detected_at=now - timedelta(hours=48),
    )
    state = FindingState(
        key=finding.key,
        status=FindingStatus.WARNED,
        first_seen=now - timedelta(hours=48),
        last_seen=now,
        warned_at=now - timedelta(hours=48),
        action_deadline=now - timedelta(hours=24),
    )

    dec = decide(finding, state, now, cfg, actions_taken=actions_taken)
    if actions_taken >= max_actions:
        assert dec.effect != Effect.ATTEMPT_ACTION
        assert dec.next_status != FindingStatus.ACTED
    else:
        assert dec.effect == Effect.ATTEMPT_ACTION
        assert dec.next_status == FindingStatus.ACTED


@given(
    finding=finding_strategy(),
    dry_run=st.booleans(),
)
@settings(max_examples=50)
def test_I8_idempotence_property(finding: Finding, dry_run: bool) -> None:
    """Invariant I8: Running twice on the same state produces no duplicate warnings/actions."""
    now = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    cfg = Config(
        dry_run=dry_run,
        grace_hours=24,
        enabled_actions=list(ActionKind),
    )

    # First run on new finding:
    dec1 = decide(finding, None, now, cfg)

    # If first run resulted in SEND_WARNING, suppose state becomes WARNED
    if dec1.effect == Effect.SEND_WARNING:
        state = FindingState(
            key=finding.key,
            status=FindingStatus.WARNED,
            first_seen=now,
            last_seen=now,
            warned_at=now,
            action_deadline=now + timedelta(hours=24),
        )
        # Running immediately again at the same time:
        dec2 = decide(finding, state, now, cfg)
        # MUST NOT re-send warning and MUST NOT act!
        assert dec2.effect == Effect.NONE
        assert dec2.next_status == FindingStatus.WARNED

    # If state is ACTED:
    acted_state = FindingState(
        key=finding.key,
        status=FindingStatus.ACTED,
        first_seen=now - timedelta(days=2),
        last_seen=now,
        warned_at=now - timedelta(days=2),
    )
    dec_acted = decide(finding, acted_state, now, cfg)
    assert dec_acted.effect == Effect.NONE
    assert dec_acted.next_status == FindingStatus.ACTED
