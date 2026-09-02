"""Adversarial tests verifying system behavior on completely empty AWS accounts."""

from unittest.mock import MagicMock

import boto3
import moto
import pytest

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.detectors.registry import discover
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.state_machine import decide
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.handler import scan_handler
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import Effect, FindingStatus
from bill_shock_guard.notify.format import format_digest, format_subject
from tests.fakes.fake_clock import FakeClock


def _make_context(clock: FakeClock, config: Config, logger: JsonLogger) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-empty-run",
        logger=logger,
        client_factory=boto3.client,
    )


def test_state_machine_empty_inputs(fake_clock: FakeClock, base_config: Config) -> None:
    """State machine given finding=None and state=None resolves safely with no side-effects."""
    dec = decide(
        finding=None,
        state=None,
        now=fake_clock.now(),
        config=base_config,
    )
    assert dec.next_status == FindingStatus.RESOLVED
    assert dec.effect == Effect.NONE
    assert "No finding and no prior state" in dec.reason


@moto.mock_aws
def test_empty_account_dynamodb_store() -> None:
    """DynamoDbStateStore operations on empty table return empty results without crashing."""
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    table_name = "bsg-empty-test"
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    store = DynamoDbStateStore(table_name=table_name, client=ddb)
    assert store.list_open() == []
    assert store.get("us-east-1#ec2_instance#i-nonexistent") is None


def test_empty_account_memory_store() -> None:
    """MemoryStateStore operations on brand new store return empty results."""
    store = MemoryStateStore()
    assert store.list_open() == []
    assert store.get("us-east-1#ec2_instance#i-nonexistent") is None


def test_empty_account_engine_runner_all_quiet(
    fake_clock: FakeClock,
    logger: JsonLogger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EngineRunner on completely empty account sends no notifications and takes no actions."""
    cfg = Config(
        dry_run=True,
        regions=["us-east-1", "us-west-2"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    mock_notifier = MagicMock()
    mock_notifier.send.return_value = True
    monkeypatch.setattr(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        lambda **kwargs: ["us-east-1", "us-west-2"],
    )

    # Empty detector list
    runner = EngineRunner(detectors=[], actions={})
    summary = runner.run(ctx, store, notifier=mock_notifier)

    assert summary.findings_detected == 0
    assert summary.warnings_sent == 0
    assert summary.actions_attempted == 0
    assert summary.actions_performed == 0
    assert summary.actions_failed == 0
    assert summary.actions_deferred == 0
    assert summary.findings_resolved == 0
    assert summary.findings_exempt == 0
    assert summary.errors == []
    assert len(summary.findings) == 0

    # Invariant: All-quiet run sends no notifications
    mock_notifier.send.assert_not_called()


@moto.mock_aws
def test_empty_account_with_all_registered_detectors(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    """Running all registered detectors against an empty AWS account produces 0 findings."""
    detectors, actions = discover()
    cfg = Config(dry_run=True, regions=["us-east-1"])
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    runner = EngineRunner(detectors=detectors, actions=actions)
    summary = runner.run(ctx, store, notifier=None)

    assert summary.findings_detected == 0
    assert summary.warnings_sent == 0
    assert summary.actions_performed == 0
    assert summary.errors == []


@moto.mock_aws
def test_empty_account_lambda_scan_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lambda scan_handler executes cleanly on an empty AWS account."""
    monkeypatch.setenv("BSG_CONFIG", '{"regions": ["us-east-1"], "dry_run": true}')
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    res = scan_handler({}, None)
    assert res["status"] == "success"
    assert res["counts"]["findings_detected"] == 0
    assert res["counts"]["warnings_sent"] == 0
    assert res["counts"]["actions_performed"] == 0
    assert res["counts"]["actions_attempted"] == 0
    assert res["counts"]["actions_failed"] == 0
    assert res["counts"]["actions_deferred"] == 0
    assert res["counts"]["findings_resolved"] == 0
    assert res["counts"]["errors"] == 0


def test_empty_account_notification_formatting() -> None:
    """Digest and subject formatting for an empty findings list."""
    digest = format_digest([], dry_run=True)
    assert "No new idle resources detected." in digest
    assert "Total estimated monthly cost at risk: $0.00 USD" in digest
    assert "Total idle resources flagged: 0" in digest

    subject_dry = format_subject(findings_count=0, dry_run=True)
    assert subject_dry == "[DRY RUN] Bill Shock Guard: All quiet (0 idle resources)"

    subject_active = format_subject(findings_count=0, dry_run=False)
    assert subject_active == "Bill Shock Guard: All quiet (0 idle resources)"
