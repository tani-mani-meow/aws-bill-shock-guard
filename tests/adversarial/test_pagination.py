"""Adversarial tests for pagination handling across multiple pages."""

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import boto3
import moto

from bill_shock_guard.aws import paginate
from bill_shock_guard.config import Config
from bill_shock_guard.detectors.ebs import EBSDetector
from bill_shock_guard.detectors.ec2 import EC2Detector
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import FindingState, FindingStatus
from tests.fakes.fake_clock import FakeClock


def _make_context(clock: FakeClock, config: Config, logger: JsonLogger) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-pag-run",
        logger=logger,
        client_factory=boto3.client,
    )


def test_paginate_multiple_pages() -> None:
    """Test that paginate() yields all items across multiple paginated pages."""
    mock_client = MagicMock()
    mock_client.can_paginate.return_value = True

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Reservations": [{"ReservationId": "r-1"}, {"ReservationId": "r-2"}]},
        {"Reservations": [{"ReservationId": "r-3"}]},
        {"Reservations": [{"ReservationId": "r-4"}, {"ReservationId": "r-5"}]},
    ]
    mock_client.get_paginator.return_value = mock_paginator

    items = list(paginate(mock_client, "describe_instances", "Reservations"))
    assert len(items) == 5
    assert [item["ReservationId"] for item in items] == ["r-1", "r-2", "r-3", "r-4", "r-5"]
    mock_client.can_paginate.assert_called_once_with("describe_instances")
    mock_client.get_paginator.assert_called_once_with("describe_instances")


def test_paginate_empty_intermediate_pages() -> None:
    """Test paginate() when intermediate pages contain empty lists."""
    mock_client = MagicMock()
    mock_client.can_paginate.return_value = True

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Volumes": []},
        {"Volumes": [{"VolumeId": "vol-1"}]},
        {"Volumes": []},
        {"Volumes": [{"VolumeId": "vol-2"}]},
        {"Volumes": []},
    ]
    mock_client.get_paginator.return_value = mock_paginator

    items = list(paginate(mock_client, "describe_volumes", "Volumes"))
    assert len(items) == 2
    assert [item["VolumeId"] for item in items] == ["vol-1", "vol-2"]


def test_paginate_fallback_when_cannot_paginate() -> None:
    """Test paginate() fallback when client.can_paginate returns False.

    Adversarial note: If an operation returns NextToken but is not in botocore's
    paginator model, the fallback only returns the first page.
    """
    mock_client = MagicMock()
    mock_client.can_paginate.return_value = False
    mock_client.custom_operation.return_value = {
        "Items": [{"id": "1"}, {"id": "2"}],
        "NextToken": "has_more_data",
    }

    items = list(paginate(mock_client, "custom_operation", "Items", Filter="test"))
    assert len(items) == 2
    mock_client.custom_operation.assert_called_once_with(Filter="test")


@moto.mock_aws
def test_dynamodb_store_list_open_multi_page() -> None:
    """Test DynamoDbStateStore.list_open() when results span multiple paginated pages."""
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    table_name = "bsg-pag-test"
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    store = DynamoDbStateStore(table_name=table_name, client=ddb)
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Insert 15 items in WARNED state
    for i in range(15):
        st = FindingState(
            key=f"us-east-1#ec2_instance#i-{i:04d}",
            status=FindingStatus.WARNED,
            first_seen=now,
            last_seen=now,
            warned_at=now,
            version=1,
        )
        store.put(st)

    # Use pagination in list_open: DynamoDB paginator with small page size
    orig_get_paginator = ddb.get_paginator

    def mock_get_paginator(operation_name: str) -> Any:
        paginator = orig_get_paginator(operation_name)
        orig_paginate = paginator.paginate

        def custom_paginate(**kwargs: Any) -> Any:
            kwargs["PaginationConfig"] = {"PageSize": 3}
            return orig_paginate(**kwargs)

        paginator.paginate = custom_paginate  # type: ignore[method-assign]
        return paginator

    ddb.get_paginator = mock_get_paginator  # type: ignore[method-assign]

    open_items = store.list_open()
    assert len(open_items) == 15
    keys = {item.key for item in open_items}
    assert len(keys) == 15


@moto.mock_aws
def test_dynamodb_store_list_open_manual_scan_fallback_pagination() -> None:
    """Test DynamoDbStateStore.list_open() fallback pagination when paginator fails."""
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    table_name = "bsg-fallback-pag-test"
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    store = DynamoDbStateStore(table_name=table_name, client=ddb)
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Insert 6 items
    for i in range(6):
        st = FindingState(
            key=f"us-east-1#ec2_instance#i-fallback-{i:03d}",
            status=FindingStatus.DETECTED,
            first_seen=now,
            last_seen=now,
            version=1,
        )
        store.put(st)

    # Force get_paginator to raise AttributeError to trigger fallback manual scan
    ddb.get_paginator = MagicMock(side_effect=AttributeError("paginator not supported"))

    open_items = store.list_open()
    assert len(open_items) == 6
    keys = {item.key for item in open_items}
    assert len(keys) == 6


def test_ec2_detector_pagination_reservations(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """Test EC2Detector handling multiple pages of Reservations in describe_instances."""
    detector = EC2Detector()
    cfg = Config(regions=["us-east-1"])
    ctx = _make_context(fake_clock, cfg, logger)

    mock_ec2 = MagicMock()
    mock_ec2.can_paginate.return_value = True

    # 3 pages of describe_instances
    mock_paginator = MagicMock()
    launch_time = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    page1 = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-page1-01",
                        "InstanceType": "t3.micro",
                        "State": {"Name": "running"},
                        "LaunchTime": launch_time,
                        "Tags": [],
                    }
                ]
            }
        ]
    }
    page2 = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-page2-02",
                        "InstanceType": "t3.micro",
                        "State": {"Name": "running"},
                        "LaunchTime": launch_time,
                        "Tags": [],
                    }
                ]
            }
        ]
    }
    mock_paginator.paginate.return_value = [page1, page2]
    mock_ec2.get_paginator.return_value = mock_paginator

    # Mock CloudWatch metrics to return idle
    mock_cw = MagicMock()
    mock_cw.can_paginate.return_value = False
    mock_cw.get_metric_data.return_value = {
        "MetricDataResults": [
            {"Id": "cpu", "Values": [0.5, 0.4]},
            {"Id": "net_in", "Values": [10.0, 10.0]},
            {"Id": "net_out", "Values": [10.0, 10.0]},
        ]
    }

    def client_factory(service: str, region_name: str | None = None) -> Any:
        if service == "ec2":
            return mock_ec2
        if service == "cloudwatch":
            return mock_cw
        return MagicMock()

    ctx = ScanContext(
        config=cfg,
        clock=fake_clock,
        account_id="123456789012",
        run_id="test-pag-ec2",
        logger=logger,
        client_factory=client_factory,
    )

    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 2
    found_ids = {f.resource_id for f in findings}
    assert found_ids == {"i-page1-01", "i-page2-02"}


def test_ebs_detector_pagination_volumes(fake_clock: FakeClock, logger: JsonLogger) -> None:
    """Test EBSDetector handling multiple pages of describe_volumes."""
    detector = EBSDetector()
    cfg = Config(regions=["us-east-1"])

    mock_ec2 = MagicMock()
    mock_ec2.can_paginate.return_value = True

    create_time = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    page1 = {
        "Volumes": [
            {
                "VolumeId": "vol-page1-01",
                "State": "available",
                "Size": 20,
                "VolumeType": "gp3",
                "CreateTime": create_time,
                "Attachments": [],
                "Tags": [],
            }
        ]
    }
    page2 = {
        "Volumes": [
            {
                "VolumeId": "vol-page2-02",
                "State": "available",
                "Size": 50,
                "VolumeType": "gp2",
                "CreateTime": create_time,
                "Attachments": [],
                "Tags": [],
            }
        ]
    }

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [page1, page2]
    mock_ec2.get_paginator.return_value = mock_paginator

    ctx = ScanContext(
        config=cfg,
        clock=fake_clock,
        account_id="123456789012",
        run_id="test-pag-ebs",
        logger=logger,
        client_factory=lambda svc, reg=None: mock_ec2,
    )

    findings = detector.detect(ctx, "us-east-1")
    assert len(findings) == 2
    found_ids = {f.resource_id for f in findings}
    assert found_ids == {"vol-page1-01", "vol-page2-02"}
