"""Targeted tests to ensure full test coverage across engine modules."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.engine.runner import EngineRunner, run_engine
from bill_shock_guard.engine.state_machine import decide
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore, OptimisticLockError
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Decision,
    Effect,
    Finding,
    FindingState,
    FindingStatus,
    RecheckResult,
    ResourceType,
)
from tests.fakes.fake_clock import FakeClock


def _make_context(clock: FakeClock, config: Config) -> ScanContext:
    logger = JsonLogger(run_id="cov-run", region="us-east-1")
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="cov-run",
        logger=logger,
        client_factory=lambda svc, reg: None,
    )


def test_state_machine_uncovered_branches() -> None:
    now = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
    cfg_live = Config(dry_run=False, grace_hours=24, enabled_actions=[ActionKind.EC2_STOP])
    cfg_dry = Config(dry_run=True, grace_hours=24, enabled_actions=[ActionKind.EC2_STOP])

    # 1. finding is None, state is RESOLVED -> remains RESOLVED
    st_res = FindingState(key="k1", status=FindingStatus.RESOLVED, first_seen=now, last_seen=now)
    d1 = decide(None, st_res, now, cfg_live)
    assert d1.next_status == FindingStatus.RESOLVED

    # 2. finding is None, state is ACTED -> RESOLVED
    st_acted = FindingState(key="k2", status=FindingStatus.ACTED, first_seen=now, last_seen=now)
    d2 = decide(None, st_acted, now, cfg_live)
    assert d2.next_status == FindingStatus.RESOLVED

    # 3. finding present, state is RESOLVED -> DETECTED
    f_ec2 = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-res",
        region="us-east-1",
        reason="Idle again",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )
    d3 = decide(f_ec2, st_res, now, cfg_live)
    assert d3.next_status == FindingStatus.DETECTED
    assert d3.effect == Effect.SEND_WARNING

    # 4. state is WARNED but warned_at is None -> reverts to DETECTED
    st_unwarned = FindingState(
        key="k3", status=FindingStatus.WARNED, first_seen=now, last_seen=now, warned_at=None
    )
    d4 = decide(f_ec2, st_unwarned, now, cfg_live)
    assert d4.next_status == FindingStatus.DETECTED

    # 5. state is WOULD_ACT in dry_run
    st_would_act = FindingState(
        key="k4",
        status=FindingStatus.WOULD_ACT,
        first_seen=now - timedelta(days=2),
        last_seen=now,
        warned_at=now - timedelta(days=2),
    )
    d5 = decide(f_ec2, st_would_act, now, cfg_dry)
    assert d5.next_status == FindingStatus.WOULD_ACT
    assert d5.effect == Effect.NONE

    # 6. state is WOULD_ACT, dry_run=False, but action not enabled
    cfg_disabled = Config(dry_run=False, enabled_actions=[ActionKind.EIP_RELEASE])
    d6 = decide(f_ec2, st_would_act, now, cfg_disabled)
    assert d6.next_status == FindingStatus.WARNED
    assert d6.effect == Effect.NONE

    # 7. state is WOULD_ACT, dry_run=False, circuit breaker hit
    d7 = decide(f_ec2, st_would_act, now, cfg_live, actions_taken=5)
    assert d7.next_status == FindingStatus.WOULD_ACT
    assert d7.effect == Effect.NONE

    # 8. state is WOULD_ACT, dry_run=False, all pass -> ACTED
    d8 = decide(f_ec2, st_would_act, now, cfg_live, actions_taken=0)
    assert d8.next_status == FindingStatus.ACTED
    assert d8.effect == Effect.ATTEMPT_ACTION

    # 9. state is FAILED, dry_run=True -> WOULD_ACT
    st_failed = FindingState(
        key="k5",
        status=FindingStatus.FAILED,
        first_seen=now - timedelta(days=2),
        last_seen=now,
        attempts=1,
    )
    d9 = decide(f_ec2, st_failed, now, cfg_dry)
    assert d9.next_status == FindingStatus.WOULD_ACT

    # 10. state is FAILED, dry_run=False, action not enabled -> FAILED
    d10 = decide(f_ec2, st_failed, now, cfg_disabled)
    assert d10.next_status == FindingStatus.FAILED

    # 11. state is FAILED, dry_run=False, circuit breaker hit -> FAILED
    d11 = decide(f_ec2, st_failed, now, cfg_live, actions_taken=5)
    assert d11.next_status == FindingStatus.FAILED


def test_runner_error_and_edge_branches() -> None:
    clock = FakeClock()
    cfg = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:topic"),
    )
    ctx = _make_context(clock, cfg)

    # 1. Store list_open raising exception
    bad_store = MagicMock()
    bad_store.list_open.side_effect = RuntimeError("DB connection dropped")
    runner = EngineRunner(detectors=[], actions={})
    sum1 = runner.run(ctx, bad_store)
    assert len(sum1.errors) > 0

    # 2. Store get raising exception
    bad_store2 = MagicMock()
    bad_store2.list_open.return_value = []
    bad_store2.get.side_effect = RuntimeError("DB error on get")
    f = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-test",
        region="us-east-1",
        reason="Idle",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )
    det = MagicMock()
    det.resource_type = ResourceType.EC2_INSTANCE
    det.detect.return_value = [f]
    runner2 = EngineRunner(detectors=[det], actions={})
    sum2 = runner2.run(ctx, bad_store2)
    assert any("Store get failed" in e for e in sum2.errors)

    # 3. Safe put raising generic error
    bad_store_put = MagicMock()
    bad_store_put.list_open.return_value = []
    bad_store_put.get.return_value = None
    bad_store_put.put.side_effect = RuntimeError("Disk full")
    sum3 = runner2.run(ctx, bad_store_put)
    assert any("Store put failed" in e for e in sum3.errors)

    # 4. Safe put raising OptimisticLockError
    bad_store_lock = MagicMock()
    bad_store_lock.list_open.return_value = []
    bad_store_lock.get.return_value = None
    bad_store_lock.put.side_effect = OptimisticLockError("Conflict")
    sum4 = runner2.run(ctx, bad_store_lock)
    assert any("Optimistic concurrency conflict" in e for e in sum4.errors)

    # 5. Missing detector for recheck in Phase 3
    # Detector resource_type is ELASTIC_IP, but returns an EC2_INSTANCE finding
    det_mismatch = MagicMock()
    det_mismatch.resource_type = ResourceType.ELASTIC_IP
    det_mismatch.detect.return_value = [f]

    store_ok = MemoryStateStore()
    t0 = clock.now() - timedelta(hours=30)
    st_warned = FindingState(
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
    store_ok.put(st_warned)

    runner_mismatch = EngineRunner(detectors=[det_mismatch], actions={})
    sum5 = runner_mismatch.run(ctx, store_ok)
    assert any("No detector for resource type" in e for e in sum5.errors)

    # 6. Detector recheck raising exception
    det_err = MagicMock()
    det_err.resource_type = ResourceType.EC2_INSTANCE
    det_err.detect.return_value = [f]
    det_err.recheck.side_effect = RuntimeError("Recheck network timeout")
    runner_recheck_err = EngineRunner(detectors=[det_err], actions={})
    sum6 = runner_recheck_err.run(ctx, store_ok)
    assert any("Recheck failed" in e for e in sum6.errors)

    # 7. Action handler missing
    det_ok = MagicMock()
    det_ok.resource_type = ResourceType.EC2_INSTANCE
    det_ok.detect.return_value = [f]
    det_ok.recheck.return_value = RecheckResult(still_idle=True, protected=False, reason="idle")
    runner_no_act = EngineRunner(detectors=[det_ok], actions={})
    sum7 = runner_no_act.run(ctx, store_ok)
    assert any("Action handler missing" in e for e in sum7.errors)

    # 8. Action apply raising exception
    act_err = MagicMock()
    act_err.kind = ActionKind.EC2_STOP
    act_err.apply.side_effect = RuntimeError("Crash in apply")
    runner_act_err = EngineRunner(detectors=[det_ok], actions={ActionKind.EC2_STOP: act_err})
    sum8 = runner_act_err.run(ctx, store_ok)
    assert sum8.actions_failed == 1

    # 9. Notifier send raising exception
    notif_err = MagicMock()
    notif_err.send.side_effect = RuntimeError("SNS unreachable")
    store_new = MemoryStateStore()
    sum9 = runner_act_err.run(ctx, store_new, notifier=notif_err)
    assert any("Notifier exception" in e for e in sum9.errors)

    # 10. Region discovery failure
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(
            "bill_shock_guard.engine.runner.get_enabled_regions",
            MagicMock(side_effect=RuntimeError("Auth failure")),
        )
        sum10 = runner_act_err.run(ctx, store_new)
        assert any("Region discovery failed" in e for e in sum10.errors)

    # 11. Report-only mode when SNS topic is None and notifier is None
    cfg_no_sns = Config(
        dry_run=False,
        grace_hours=24,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn=None),
    )
    ctx_no_sns = _make_context(clock, cfg_no_sns)
    store_report = MemoryStateStore()
    store_report.put(st_warned)
    sum11 = runner_act_err.run(ctx_no_sns, store_report, notifier=None)
    assert sum11.actions_performed == 0

    # 12. Auto-discovery initialization and run_engine helper
    r_def = EngineRunner()
    assert r_def is not None
    sum_hlp = run_engine(ctx, store_new)
    assert sum_hlp is not None


def test_dynamodb_store_error_and_edge_branches() -> None:
    client_mock = MagicMock()
    store = DynamoDbStateStore(table_name="test-tab", client=client_mock)

    # 1. get_item ClientError
    client_mock.get_item.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
        "GetItem",
    )
    with pytest.raises(RuntimeError):
        store.get("k1")

    # 2. put_item ClientError other than ConditionalCheckFailedException
    client_mock.put_item.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}},
        "PutItem",
    )
    st = FindingState(
        key="k1",
        status=FindingStatus.DETECTED,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    with pytest.raises(RuntimeError):
        store.put(st)

    # 3. Manual scan fallback when get_paginator raises AttributeError
    client_mock.get_paginator.side_effect = AttributeError("No paginator")
    client_mock.scan.side_effect = [
        {
            "Items": [
                {
                    "key": {"S": "k1"},
                    "status": {"S": "WARNED"},
                    "first_seen": {"S": "2026-01-01T12:00:00"},
                    "last_seen": {"S": "2026-01-01T12:00:00"},
                    "warned_at": {"S": "2026-01-01T12:00:00"},
                    "action_deadline": {"S": "2026-01-02T12:00:00"},
                    "attempts": {"N": "0"},
                    "version": {"N": "1"},
                    "last_error": {"S": "sample error"},
                    "ttl": {"N": "123456789"},
                    "metadata": {"S": "invalid-json"},
                },
                {
                    "key": {"S": "k-failed-max"},
                    "status": {"S": "FAILED"},
                    "first_seen": {"S": "2026-01-01T12:00:00"},
                    "last_seen": {"S": "2026-01-01T12:00:00"},
                    "attempts": {"N": "3"},
                    "version": {"N": "3"},
                },
            ],
            "LastEvaluatedKey": {"key": {"S": "k-failed-max"}},
        },
        {
            "Items": [
                {
                    "key": {"S": "k2"},
                    "status": {"S": "DETECTED"},
                    "first_seen": {"S": "2026-01-01T12:00:00+00:00"},
                    "last_seen": {"S": "2026-01-01T12:00:00+00:00"},
                    "attempts": {"N": "0"},
                    "version": {"N": "1"},
                }
            ]
        },
    ]
    open_items = store.list_open()
    assert len(open_items) == 2
    assert open_items[0].key == "k1"
    assert open_items[0].first_seen.tzinfo is not None
    assert open_items[0].last_seen.tzinfo is not None
    assert open_items[0].warned_at is not None and open_items[0].warned_at.tzinfo is not None
    assert (
        open_items[0].action_deadline is not None
        and open_items[0].action_deadline.tzinfo is not None
    )
    assert open_items[0].last_error == "sample error"
    assert open_items[0].ttl == 123456789
    assert open_items[0].metadata == {}

    # 4. Serialization with last_error and ttl
    serialized = store._serialize(open_items[0])
    assert "last_error" in serialized
    assert "ttl" in serialized

    # 5. Non-ClientError ConditionalCheckFailedException in put
    class MockConditionalCheckFailedException(Exception):
        pass

    client_mock.put_item.side_effect = MockConditionalCheckFailedException("version conflict")
    st_conflict = FindingState(
        key="k1",
        status=FindingStatus.DETECTED,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        version=2,
    )
    with pytest.raises(OptimisticLockError):
        store.put(st_conflict)


def test_runner_unseen_protected_and_unseen_would_act() -> None:
    clock = FakeClock()
    cfg = Config(dry_run=True, grace_hours=24, regions=["us-east-1"])
    ctx = _make_context(clock, cfg)

    # 1. Unseen protected finding creates EXEMPT state with state is None
    f_prot = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-unseen-prot",
        region="us-east-1",
        reason="Protected",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=True,
        protection_reason="Tag bsg:keep=true",
        detected_at=clock.now(),
    )
    det = MagicMock()
    det.resource_type = ResourceType.EC2_INSTANCE
    det.detect.return_value = [f_prot]
    store = MemoryStateStore()
    runner = EngineRunner(detectors=[det], actions={})
    sum1 = runner.run(ctx, store)
    assert sum1.findings_exempt == 1
    st = store.get(f_prot.key)
    assert st is not None
    assert st.status == FindingStatus.EXEMPT

    # 2. Unseen finding returning WOULD_ACT directly with state is None
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(
            "bill_shock_guard.engine.runner.decide",
            MagicMock(
                return_value=Decision(
                    next_status=FindingStatus.WOULD_ACT,
                    effect=Effect.NONE,
                    reason="Would act directly",
                )
            ),
        )
        f_norm = Finding(
            resource_type=ResourceType.EC2_INSTANCE,
            resource_id="i-would-act-new",
            region="us-east-1",
            reason="Idle",
            evidence={},
            est_monthly_cost_usd=10.0,
            cost_confidence="estimate",
            proposed_action=ActionKind.EC2_STOP,
            protected=False,
            protection_reason=None,
            detected_at=clock.now(),
        )
        det.detect.return_value = [f_norm]
        store2 = MemoryStateStore()
        sum2 = runner.run(ctx, store2)
        assert sum2.findings_would_act == 1
        st2 = store2.get(f_norm.key)
        assert st2 is not None
        assert st2.status == FindingStatus.WOULD_ACT


def test_memory_store_invalid_version_on_new() -> None:
    store = MemoryStateStore()
    st = FindingState(
        key="k-bad",
        status=FindingStatus.DETECTED,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        version=5,  # Non-existent item with version > 1
    )
    with pytest.raises(OptimisticLockError):
        store.put(st)
