"""Unit and integration tests for Lambda scan_handler."""

import json
from dataclasses import dataclass
from unittest.mock import patch

import boto3
import moto
import pytest

from bill_shock_guard.engine.runner import RunSummary
from bill_shock_guard.handler import _build_state_store, _get_account_id, scan_handler


@dataclass
class FakeLambdaContext:
    aws_request_id: str = "req-12345"
    invoked_function_arn: str = "arn:aws:lambda:us-east-1:112233445566:function:bsg-scan"


def test_get_account_id_from_context() -> None:
    ctx = FakeLambdaContext()
    acc = _get_account_id(ctx, "us-east-1")
    assert acc == "112233445566"


@moto.mock_aws
def test_get_account_id_from_sts() -> None:
    # Context without valid ARN
    acc = _get_account_id(None, "us-east-1")
    assert acc == "123456789012"


def test_get_account_id_fallback_on_error() -> None:
    with patch("bill_shock_guard.handler.get_boto_client", side_effect=RuntimeError("no STS")):
        acc = _get_account_id(None, "us-east-1")
        assert acc == "123456789012"


@moto.mock_aws
def test_build_state_store_dynamodb() -> None:
    from bill_shock_guard.config import Config
    from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
    from bill_shock_guard.engine.store_memory import MemoryStateStore

    cfg_mem = Config(state_table=None)
    store_mem = _build_state_store(cfg_mem, "us-east-1")
    assert isinstance(store_mem, MemoryStateStore)

    cfg_ddb = Config(state_table="test-table")
    store_ddb = _build_state_store(cfg_ddb, "us-east-1")
    assert isinstance(store_ddb, DynamoDbStateStore)


@moto.mock_aws
def test_scan_handler_default_empty_account(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BSG_CONFIG", raising=False)
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    with patch("bill_shock_guard.engine.runner.get_enabled_regions", return_value=["us-east-1"]):
        res = scan_handler({}, FakeLambdaContext())
        assert res["status"] == "success"
        assert res["run_id"] == "run-req-12345"
        assert "counts" in res
        assert res["counts"]["findings_detected"] == 0
        assert res["counts"]["warnings_sent"] == 0
        assert res["counts"]["actions_performed"] == 0


@moto.mock_aws
def test_scan_handler_with_custom_config(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_data = {
        "dry_run": True,
        "grace_hours": 12,
        "regions": ["us-east-1"],
        "enabled_actions": ["ec2_stop"],
    }
    monkeypatch.setenv("BSG_CONFIG", json.dumps(cfg_data))
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    res = scan_handler(None, None)
    assert res["status"] == "success"
    assert res["run_id"].startswith("run-")
    assert res["counts"]["findings_detected"] == 0


@moto.mock_aws
def test_scan_handler_with_dynamodb_and_detected_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    # Setup DynamoDB state table
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    table_name = "bsg-state"
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # Setup an unassociated EIP in moto
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.allocate_address(Domain="vpc")

    # Setup SNS topic
    sns = boto3.client("sns", region_name="us-east-1")
    topic = sns.create_topic(Name="bsg-alerts")
    topic_arn = topic["TopicArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint="operator@example.com")

    cfg_data = {
        "dry_run": True,
        "grace_hours": 24,
        "regions": ["us-east-1"],
        "state_table": table_name,
        "notify": {
            "sns_topic_arn": topic_arn,
        },
    }
    monkeypatch.setenv("BSG_CONFIG", json.dumps(cfg_data))
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    res = scan_handler({}, FakeLambdaContext())
    assert res["status"] == "success"
    assert res["counts"]["findings_detected"] == 1
    assert res["counts"]["warnings_sent"] == 1
    assert res["counts"]["actions_performed"] == 0  # In dry run, no actions taken


def test_partial_run_emits_alarm_log_event(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("BSG_CONFIG", raising=False)
    with patch(
        "bill_shock_guard.handler.EngineRunner.run",
        return_value=RunSummary(run_id="test", errors=["Region discovery failed"]),
    ):
        response = scan_handler({}, FakeLambdaContext())

    assert response["status"] == "completed_with_errors"
    assert response["counts"]["errors"] == 1
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    completed = next(record for record in logs if record["event"] == "lambda_scan_completed")
    assert completed["errors_count"] == 1
