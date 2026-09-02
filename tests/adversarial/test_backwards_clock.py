"""Adversarial tests for clock anomalies, NTP jumps, and time moving backwards."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.state_machine import decide
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Effect,
    Finding,
    FindingState,
    FindingStatus,
    ResourceType,
)
from bill_shock_guard.protection import is_protected
from tests.fakes.fake_clock import FakeClock


def _make_context(clock: FakeClock, config: Config, logger: JsonLogger) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-backwards-clock",
        logger=logger,
        client_factory=lambda svc, reg=None: MagicMock(),
    )


def test_clock_moves_backwards_before_warned_at(base_config: Config) -> None:
    """If clock jumps backward before warned_at, resource stays in WARNED and does not act."""
    warned_at = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    deadline = warned_at + timedelta(hours=24)

    state = FindingState(
        key="us-east-1#ec2_instance#i-time-traveler",
        status=FindingStatus.WARNED,
        first_seen=warned_at,
        last_seen=warned_at,
        warned_at=warned_at,
        action_deadline=deadline,
        version=1,
    )

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-time-traveler",
        region="us-east-1",
        reason="Idle EC2",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=warned_at,
    )

    # Clock moves backwards by 4 hours before warned_at (e.g. 08:00 UTC)
    time_in_past = warned_at - timedelta(hours=4)
    dec = decide(finding=finding, state=state, now=time_in_past, config=base_config)

    assert dec.next_status == FindingStatus.WARNED
    assert dec.effect == Effect.NONE
    assert "Grace period active" in dec.reason


def test_clock_moves_backwards_from_expired_to_unexpired_deadline(base_config: Config) -> None:
    """If clock steps backwards from past deadline to before deadline, action is deferred."""
    warned_at = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    deadline = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)

    state = FindingState(
        key="us-east-1#ec2_instance#i-time-traveler-2",
        status=FindingStatus.WARNED,
        first_seen=warned_at,
        last_seen=warned_at,
        warned_at=warned_at,
        action_deadline=deadline,
        version=1,
    )

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-time-traveler-2",
        region="us-east-1",
        reason="Idle EC2",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=warned_at,
    )

    # In active run mode (dry_run=False)
    active_config = Config(dry_run=False, enabled_actions=[ActionKind.EC2_STOP])

    # Case A: At 13:00 (past deadline), action would be attempted
    dec_ready = decide(
        finding=finding,
        state=state,
        now=datetime(2026, 6, 2, 13, 0, 0, tzinfo=timezone.utc),
        config=active_config,
    )
    assert dec_ready.effect == Effect.ATTEMPT_ACTION

    # Case B: Clock suddenly jumps backwards to 11:45 (15 min before deadline)
    jumped_back_now = datetime(2026, 6, 2, 11, 45, 0, tzinfo=timezone.utc)
    dec_deferred = decide(finding=finding, state=state, now=jumped_back_now, config=active_config)

    assert dec_deferred.next_status == FindingStatus.WARNED
    assert dec_deferred.effect == Effect.NONE
    assert "Grace period active" in dec_deferred.reason


def test_clock_moves_backwards_with_date_protection_tag(base_config: Config) -> None:
    """Clock moving backwards revives an expired keep tag back into protected status."""
    tags = {"bsg:keep": "2026-06-15"}
    resource_id = "i-date-tagged"

    # Future: 2026-06-16 (tag expired)
    now_future = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
    prot_future, reason_future = is_protected(tags, resource_id, base_config, now_future)
    assert prot_future is False
    assert "expired" in (reason_future or "")

    # Clock moves backwards to 2026-06-14 10:00:00 (before expiration)
    now_past = datetime(2026, 6, 14, 10, 0, 0, tzinfo=timezone.utc)
    prot_past, reason_past = is_protected(tags, resource_id, base_config, now_past)
    assert prot_past is True
    assert "until 2026-06-15" in (reason_past or "")


def test_runner_multi_cycle_with_backwards_clock(
    fake_clock: FakeClock,
    logger: JsonLogger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EngineRunner execution across cycles where clock goes backwards preserves safety."""
    start_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    fake_clock.set(start_time)
    monkeypatch.setattr(
        "bill_shock_guard.engine.runner.get_enabled_regions", lambda **kwargs: ["us-east-1"]
    )

    cfg = Config(
        dry_run=True,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    finding = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-backwards-cycle",
        region="us-east-1",
        reason="Idle EC2 instance",
        evidence={},
        est_monthly_cost_usd=15.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=start_time,
    )

    mock_detector = MagicMock()
    mock_detector.resource_type = ResourceType.EC2_INSTANCE
    mock_detector.detect.return_value = [finding]

    mock_notifier = MagicMock()
    mock_notifier.send.return_value = True

    runner = EngineRunner(detectors=[mock_detector], actions={})

    # Cycle 1: Normal initial warning
    summary1 = runner.run(ctx, store, notifier=mock_notifier)
    assert summary1.warnings_sent == 1
    assert summary1.actions_performed == 0

    state1 = store.get(finding.key)
    assert state1 is not None
    assert state1.status == FindingStatus.WARNED
    assert state1.warned_at == start_time

    # Cycle 2: Clock steps backward 3 hours (NTP backward adjustment)
    backwards_time = start_time - timedelta(hours=3)
    fake_clock.set(backwards_time)

    summary2 = runner.run(ctx, store, notifier=mock_notifier)
    # Invariant I8: No duplicate warning sent
    assert summary2.warnings_sent == 0
    assert summary2.actions_performed == 0
    assert summary2.actions_attempted == 0
    assert summary2.errors == []

    # Invariant: During active grace period with Effect.NONE, no unnecessary store writes occur
    state2 = store.get(finding.key)
    assert state2 is not None
    assert state2.status == FindingStatus.WARNED
    assert state2.warned_at == start_time
    # last_seen in store retains previous cycle's timestamp because no mutation occurred
    assert state2.last_seen == start_time
