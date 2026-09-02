"""Adversarial tests for duplicate resource IDs across different AWS regions."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import boto3
import moto

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Finding,
    FindingState,
    FindingStatus,
    RecheckResult,
    ResourceType,
)
from bill_shock_guard.notify.format import format_digest
from bill_shock_guard.protection import is_protected
from tests.fakes.fake_clock import FakeClock


def _make_context(clock: FakeClock, config: Config, logger: JsonLogger) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-dup-ids",
        logger=logger,
        client_factory=boto3.client,
    )


def test_duplicate_resource_id_keys_are_region_scoped() -> None:
    """Findings with identical resource IDs in different regions produce distinct composite keys."""
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    f_east = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-duplicate999",
        region="us-east-1",
        reason="Idle instance in us-east-1",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    f_west = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-duplicate999",
        region="us-west-2",
        reason="Idle instance in us-west-2",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    assert f_east.key == "us-east-1#ec2_instance#i-duplicate999"
    assert f_west.key == "us-west-2#ec2_instance#i-duplicate999"
    assert f_east.key != f_west.key


@moto.mock_aws
def test_duplicate_resource_ids_stored_independently_in_dynamodb() -> None:
    """DynamoDbStateStore stores duplicate resource IDs from different regions without collision."""
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    table_name = "bsg-dup-test"
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    store = DynamoDbStateStore(table_name=table_name, client=ddb)
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    state_east = FindingState(
        key="us-east-1#ec2_instance#i-duplicate999",
        status=FindingStatus.WARNED,
        first_seen=now,
        last_seen=now,
        warned_at=now,
        version=1,
    )
    state_west = FindingState(
        key="us-west-2#ec2_instance#i-duplicate999",
        status=FindingStatus.DETECTED,
        first_seen=now,
        last_seen=now,
        version=1,
    )

    store.put(state_east)
    store.put(state_west)

    retrieved_east = store.get("us-east-1#ec2_instance#i-duplicate999")
    retrieved_west = store.get("us-west-2#ec2_instance#i-duplicate999")

    assert retrieved_east is not None
    assert retrieved_west is not None
    assert retrieved_east.status == FindingStatus.WARNED
    assert retrieved_west.status == FindingStatus.DETECTED

    # Modifying state_east does not mutate state_west
    state_east.status = FindingStatus.ACTED
    state_east.version = 2
    store.put(state_east)

    assert store.get("us-east-1#ec2_instance#i-duplicate999").status == FindingStatus.ACTED  # type: ignore[union-attr]
    assert store.get("us-west-2#ec2_instance#i-duplicate999").status == FindingStatus.DETECTED  # type: ignore[union-attr]


def test_duplicate_resource_ids_runner_isolation(
    fake_clock: FakeClock,
    logger: JsonLogger,
) -> None:
    """Exempting a duplicate resource in one region does NOT exempt the other region."""
    now = fake_clock.now()
    cfg = Config(
        dry_run=True,
        regions=["us-east-1", "us-west-2"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()

    # In us-east-1: protected
    f_east = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-duplicate-shared",
        region="us-east-1",
        reason="Idle instance in us-east-1",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=True,
        protection_reason="Protected by keep tag",
        detected_at=now,
    )

    # In us-west-2: unprotected idle
    f_west = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-duplicate-shared",
        region="us-west-2",
        reason="Idle instance in us-west-2",
        evidence={},
        est_monthly_cost_usd=10.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    class MultiRegionDetector:
        resource_type = ResourceType.EC2_INSTANCE

        def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
            if region == "us-east-1":
                return [f_east]
            if region == "us-west-2":
                return [f_west]
            return []

        def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
            return RecheckResult(still_idle=True, protected=finding.protected, reason="Rechecked")

    mock_notifier = MagicMock()
    mock_notifier.send.return_value = True

    with patch(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        return_value=["us-east-1", "us-west-2"],
    ):
        runner = EngineRunner(detectors=[MultiRegionDetector()], actions={})
        summary = runner.run(ctx, store, notifier=mock_notifier)

    assert summary.findings_detected == 2
    assert summary.findings_exempt == 1  # us-east-1 is exempt
    assert summary.warnings_sent == 1  # us-west-2 is warned

    st_east = store.get(f_east.key)
    st_west = store.get(f_west.key)

    assert st_east is not None and st_east.status == FindingStatus.EXEMPT
    assert st_west is not None and st_west.status == FindingStatus.WARNED


def test_ignore_resource_ids_applies_globally_to_duplicate_ids(
    fake_clock: FakeClock,
) -> None:
    """ignore_resource_ids is evaluated by resource ID, protecting matches across all regions."""
    cfg = Config(ignore_resource_ids=["i-dup-global"])
    now = fake_clock.now()

    # Check both regions
    prot_east, reason_east = is_protected({}, "i-dup-global", cfg, now)
    prot_west, reason_west = is_protected({}, "i-dup-global", cfg, now)

    assert prot_east is True
    assert prot_west is True
    assert "ignore_resource_ids" in (reason_east or "")
    assert "ignore_resource_ids" in (reason_west or "")


def test_duplicate_resource_ids_in_notification_digest(fake_clock: FakeClock) -> None:
    """Notification digest renders duplicate resource IDs clearly with respective regions."""
    now = fake_clock.now()
    deadline_east = now + datetime.resolution * 3600
    deadline_west = now + datetime.resolution * 7200

    f_east = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-dup-visual",
        region="us-east-1",
        reason="Idle in us-east-1",
        evidence={},
        est_monthly_cost_usd=12.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )
    f_west = Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-dup-visual",
        region="us-west-2",
        reason="Idle in us-west-2",
        evidence={},
        est_monthly_cost_usd=12.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    deadlines = {
        f_east.key: deadline_east,
        f_west.key: deadline_west,
    }

    digest = format_digest(
        [f_east, f_west],
        dry_run=True,
        deadlines=deadlines,
        now=now,
    )

    # Both regions explicitly documented in warnings
    assert "i-dup-visual" in digest
    assert "Region: us-east-1" in digest
    assert "Region: us-west-2" in digest
    assert "Total idle resources flagged: 2" in digest
    assert "approx. $24.00 USD" in digest
