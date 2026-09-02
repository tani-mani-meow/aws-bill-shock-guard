"""Regression coverage for remediation and incomplete scans."""

from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.detectors.eip import EIPDetector
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import ActionKind, Finding, FindingState, FindingStatus, ResourceType
from bill_shock_guard.notify.sns import SNSNotifier
from tests.engine.test_runner import FakeAction, FakeDetector, FakeNotifier, _make_context
from tests.fakes.fake_clock import FakeClock

REGION = "us-east-1"


def _idle_instance(clock: FakeClock) -> Finding:
    return Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-idle",
        region=REGION,
        reason="Idle instance",
        evidence={},
        est_monthly_cost_usd=5.0,
        cost_confidence="estimate",
        proposed_action=ActionKind.EC2_STOP,
        protected=False,
        protection_reason=None,
        detected_at=clock.now(),
    )


@mock_aws
def test_empty_sns_topic_cannot_start_active_grace_period(
    fake_clock: FakeClock, logger: JsonLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    sns = boto3.client("sns", region_name=REGION)
    arn = sns.create_topic(Name="warnings")["TopicArn"]
    ctx = _make_context(
        fake_clock,
        Config(dry_run=False, regions=[REGION], notify=NotifyConfig(sns_topic_arn=arn)),
        logger,
    )
    finding = _idle_instance(fake_clock)
    action = FakeAction()
    runner = EngineRunner([FakeDetector(findings=[finding])], {ActionKind.EC2_STOP: action})
    store = MemoryStateStore()
    notifier = SNSNotifier(topic_arn=arn, client=sns)

    for _ in range(2):
        result = runner.run(ctx, store, notifier)
        assert result.warnings_sent == 0
        assert result.errors
        state = store.get(finding.key)
        assert state is not None and state.status == FindingStatus.DETECTED
        assert state.warned_at is None
        fake_clock.advance(hours=25)
    assert action.applied_findings == []

    sns.subscribe(TopicArn=arn, Protocol="email", Endpoint="operator@example.com")
    publish = sns.publish

    def delayed_publish(**kwargs):
        fake_clock.advance(hours=1)
        return publish(**kwargs)

    monkeypatch.setattr(sns, "publish", delayed_publish)
    assert runner.run(ctx, store, notifier).warnings_sent == 1
    state = store.get(finding.key)
    assert state is not None and state.warned_at == fake_clock.now()
    fake_clock.advance(hours=23)
    assert runner.run(ctx, store, notifier).actions_attempted == 0
    fake_clock.advance(hours=1)
    assert runner.run(ctx, store, notifier).actions_performed == 1


@mock_aws
@pytest.mark.parametrize("failed_status", [FindingStatus.ACTION_PENDING, FindingStatus.ACTED])
def test_state_write_failure_guards_action_and_replay(
    failed_status: FindingStatus,
    fake_clock: FakeClock,
    logger: JsonLogger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName="guard-state",
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    store = DynamoDbStateStore("guard-state", ddb)
    ctx = _make_context(
        fake_clock,
        Config(
            dry_run=False,
            regions=[REGION],
            notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:alerts"),
        ),
        logger,
    )
    finding = _idle_instance(fake_clock)
    action = FakeAction()
    detector = FakeDetector(findings=[finding])
    runner = EngineRunner([detector], {ActionKind.EC2_STOP: action})
    notifier = FakeNotifier()
    assert runner.run(ctx, store, notifier).warnings_sent == 1
    fake_clock.advance(hours=25)
    put_item = ddb.put_item

    def fail_selected_write(**kwargs):
        if kwargs["Item"]["status"]["S"] == failed_status:
            raise ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException"}}, "PutItem"
            )
        return put_item(**kwargs)

    monkeypatch.setattr(ddb, "put_item", fail_selected_write)
    run = runner.run(ctx, store, notifier)
    assert any("Store put failed" in error for error in run.errors)
    expected_actions = 0 if failed_status == FindingStatus.ACTION_PENDING else 1
    assert len(action.applied_findings) == expected_actions
    state = store.get(finding.key)
    assert state is not None
    monkeypatch.setattr(ddb, "put_item", put_item)
    fake_clock.advance(hours=6)
    restarted = EngineRunner([detector], {ActionKind.EC2_STOP: action})
    reopened_store = DynamoDbStateStore("guard-state", ddb)
    if failed_status == FindingStatus.ACTION_PENDING:
        assert state.status == FindingStatus.WARNED
        assert restarted.run(ctx, reopened_store, notifier).actions_performed == 1
        return

    assert state.status == FindingStatus.ACTION_PENDING
    assert state.attempts == 1
    retry = restarted.run(ctx, reopened_store, notifier)
    assert retry.actions_attempted == 0
    assert any("needs reconciliation" in error for error in retry.errors)
    assert len(action.applied_findings) == 1


def test_discovery_failure_preserves_unsurveyed_finding(
    fake_clock: FakeClock, logger: JsonLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    denied = ClientError({"Error": {"Code": "UnauthorizedOperation"}}, "DescribeRegions")
    client = Mock()
    client.describe_regions.side_effect = denied
    monkeypatch.setattr("bill_shock_guard.aws.get_boto_client", Mock(return_value=client))
    detector = FakeDetector()
    ctx = _make_context(fake_clock, Config(regions=["*"]), logger)
    store = MemoryStateStore()
    prior = FindingState(
        key="eu-west-1#ec2_instance#i-prior",
        status=FindingStatus.WARNED,
        first_seen=fake_clock.now(),
        last_seen=fake_clock.now(),
        warned_at=fake_clock.now(),
        action_deadline=fake_clock.now() + timedelta(hours=24),
    )
    store.put(prior)

    result = EngineRunner([detector], {}).run(ctx, store)

    assert store.get(prior.key) == prior
    assert result.findings_resolved == 0
    assert detector.detect_calls == 0
    assert any("Region discovery failed" in error for error in result.errors)


def test_incomplete_detector_preserves_only_its_own_missing_findings(
    fake_clock: FakeClock, logger: JsonLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed_region = "eu-west-1"
    monkeypatch.setattr(
        "bill_shock_guard.engine.runner.get_enabled_regions",
        Mock(return_value=[REGION, failed_region]),
    )
    unavailable = Mock()
    unavailable.can_paginate.return_value = False
    unavailable.describe_addresses.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation"}}, "DescribeAddresses"
    )
    healthy = Mock()
    healthy.can_paginate.return_value = False
    healthy.describe_addresses.return_value = {"Addresses": []}
    ctx = replace(
        _make_context(fake_clock, Config(), logger),
        client_factory=lambda service, region: unavailable if region == failed_region else healthy,
    )
    store = MemoryStateStore()
    prior = FindingState(
        key=f"{failed_region}#elastic_ip#eipalloc-1",
        status=FindingStatus.WARNED,
        first_seen=fake_clock.now(),
        last_seen=fake_clock.now(),
        warned_at=fake_clock.now(),
        action_deadline=fake_clock.now() + timedelta(hours=24),
    )
    other = replace(prior, key=f"{REGION}#elastic_ip#eipalloc-2")
    store.put(prior)
    store.put(other)

    result = EngineRunner([EIPDetector()], {}).run(ctx, store)

    assert store.get(prior.key) == prior
    resolved = store.get(other.key)
    assert resolved is not None and resolved.status == FindingStatus.RESOLVED
    assert result.findings_resolved == 1
    assert len(result.errors) == 1 and failed_region in result.errors[0]


def test_rds_warning_uses_resource_arn_and_configured_tag(
    fake_clock: FakeClock, logger: JsonLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "bill_shock_guard.engine.runner.get_enabled_regions", Mock(return_value=[REGION])
    )
    arn = f"arn:aws:rds:{REGION}:123456789012:db:idle-db"
    finding = replace(
        _idle_instance(fake_clock),
        resource_id="idle-db",
        resource_type=ResourceType.RDS_INSTANCE,
        proposed_action=ActionKind.RDS_STOP,
        evidence={"resource_arn": arn},
    )
    ctx = _make_context(fake_clock, Config(protect_tag_key="bsg:skip"), logger)
    notifier = FakeNotifier()
    detector = FakeDetector(resource_type=ResourceType.RDS_INSTANCE, findings=[finding])

    EngineRunner([detector], {}).run(ctx, MemoryStateStore(), notifier)

    _, body = notifier.sent_messages[0]
    assert f"aws rds add-tags-to-resource --region {REGION} --resource-name {arn}" in body
    assert "Key=bsg:skip,Value=true" in body
