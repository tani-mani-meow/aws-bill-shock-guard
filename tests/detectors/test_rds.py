"""Tests for RDS database instance detector and stop action."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

from bill_shock_guard.config import Config, Thresholds
from bill_shock_guard.detectors.rds import (
    RDSDetector,
    RDSStopAction,
    is_rds_instance_idle,
)
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    Finding,
    ResourceType,
)
from tests.fakes.fake_clock import FakeClock


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock(datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc))


@pytest.fixture
def scan_context(fake_clock: FakeClock) -> ScanContext:
    cfg = Config(
        dry_run=False,
        thresholds=Thresholds(rds_idle_window_hours=168),
    )
    logger = JsonLogger(run_id="test-run-rds", region="us-east-1")
    return ScanContext(
        config=cfg,
        clock=fake_clock,
        account_id="123456789012",
        run_id="test-run-rds",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )


# =========================================================================
# Pure Idle Detection Logic Tests
# =========================================================================


def test_is_rds_instance_idle_zero_connections():
    inst = {
        "DBInstanceIdentifier": "prod-db-1",
        "DBInstanceStatus": "available",
        "Engine": "postgres",
        "MultiAZ": False,
        "DBInstanceClass": "db.t3.micro",
    }
    is_idle, reason, ev = is_rds_instance_idle(inst, max_connections=0.0)
    assert is_idle is True
    assert "0 database connections" in reason
    assert ev["max_connections"] == 0.0


def test_is_rds_instance_idle_active_connections():
    inst = {
        "DBInstanceIdentifier": "busy-db",
        "DBInstanceStatus": "available",
        "Engine": "mysql",
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=5.0)
    assert is_idle is False
    assert "maximum 5 connection(s)" in reason


def test_is_rds_instance_idle_missing_metrics_not_idle():
    """Invariant I9: Unknown is not idle."""
    inst = {
        "DBInstanceIdentifier": "unknown-db",
        "DBInstanceStatus": "available",
        "Engine": "postgres",
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=None)
    assert is_idle is False
    assert "unknown is not idle" in reason


def test_is_rds_instance_idle_status_not_available():
    inst = {
        "DBInstanceIdentifier": "stopped-db",
        "DBInstanceStatus": "stopped",
        "Engine": "postgres",
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=0.0)
    assert is_idle is False
    assert "status is 'stopped'" in reason


def test_is_rds_instance_idle_skips_read_replica():
    inst = {
        "DBInstanceIdentifier": "replica-db",
        "DBInstanceStatus": "available",
        "Engine": "postgres",
        "ReadReplicaSourceDBInstanceIdentifier": "master-db",
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=0.0)
    assert is_idle is False
    assert "is a read replica" in reason


def test_is_rds_instance_idle_skips_instance_with_replicas():
    inst = {
        "DBInstanceIdentifier": "master-db",
        "DBInstanceStatus": "available",
        "Engine": "postgres",
        "ReadReplicaDBInstanceIdentifiers": ["replica-1", "replica-2"],
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=0.0)
    assert is_idle is False
    assert "active read replica" in reason


def test_is_rds_instance_idle_skips_aurora_member():
    inst = {
        "DBInstanceIdentifier": "aurora-node-1",
        "DBInstanceStatus": "available",
        "Engine": "aurora-postgresql",
        "DBClusterIdentifier": "my-aurora-cluster",
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=0.0)
    assert is_idle is False
    assert "belongs to DB cluster" in reason


def test_is_rds_instance_idle_skips_sqlserver_multi_az():
    inst = {
        "DBInstanceIdentifier": "sqlserver-db",
        "DBInstanceStatus": "available",
        "Engine": "sqlserver-ee",
        "MultiAZ": True,
    }
    is_idle, reason, _ = is_rds_instance_idle(inst, max_connections=0.0)
    assert is_idle is False
    assert "SQL Server in Multi-AZ mode" in reason


# =========================================================================
# Detector Integration Tests with Moto
# =========================================================================


@mock_aws
def test_rds_detector_detects_idle_instance(scan_context: ScanContext):
    rds = boto3.client("rds", region_name="us-east-1")
    cw = boto3.client("cloudwatch", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="idle-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
    )

    now = scan_context.clock.now()
    cw.put_metric_data(
        Namespace="AWS/RDS",
        MetricData=[
            {
                "MetricName": "DatabaseConnections",
                "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "idle-db"}],
                "Timestamp": now - timedelta(hours=1),
                "Value": 0.0,
                "Unit": "Count",
            }
        ],
    )

    detector = RDSDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "idle-db"
    assert f.resource_type == ResourceType.RDS_INSTANCE
    assert f.proposed_action == ActionKind.RDS_STOP
    assert f.protected is False


@mock_aws
def test_I9_rds_missing_metrics_not_idle(scan_context: ScanContext):
    """Invariant I9: When metrics are missing, instance is not flagged."""
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="no-metric-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
    )

    detector = RDSDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 0


@mock_aws
def test_I3_rds_protected_resource(scan_context: ScanContext):
    """Invariant I3: Protected RDS instance is flagged with protected=True."""
    rds = boto3.client("rds", region_name="us-east-1")
    cw = boto3.client("cloudwatch", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="protected-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )
    now = scan_context.clock.now()
    cw.put_metric_data(
        Namespace="AWS/RDS",
        MetricData=[
            {
                "MetricName": "DatabaseConnections",
                "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "protected-db"}],
                "Timestamp": now - timedelta(hours=1),
                "Value": 0.0,
            }
        ],
    )

    detector = RDSDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == "protected-db"
    assert findings[0].protected is True
    assert "bsg:keep=true" in (findings[0].protection_reason or "")


def test_rds_detector_client_exception(scan_context: ScanContext):
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=MagicMock(side_effect=RuntimeError("RDS failure")),
    )
    detector = RDSDetector()
    assert detector.detect(ctx, region="us-east-1") == []


def test_rds_detector_describe_db_instances_client_error(scan_context: ScanContext):
    mock_rds = MagicMock()
    mock_rds.can_paginate.return_value = False
    mock_rds.describe_db_instances.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
        "DescribeDBInstances",
    )
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_rds,
    )
    detector = RDSDetector()
    assert detector.detect(ctx, region="us-east-1") == []


def test_rds_detector_cw_metric_exception_during_detect(scan_context: ScanContext):
    mock_rds = MagicMock()
    mock_rds.can_paginate.return_value = False
    mock_rds.describe_db_instances.return_value = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "cw-err-db",
                "DBInstanceStatus": "available",
                "Engine": "postgres",
            }
        ]
    }
    mock_cw = MagicMock()
    mock_cw.get_metric_statistics.side_effect = RuntimeError("CloudWatch down")

    def factory(svc, reg):
        return mock_cw if svc == "cloudwatch" else mock_rds

    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=factory,
    )
    detector = RDSDetector()
    # When CW fails, max_connections is None -> unknown is not idle -> 0 findings
    assert detector.detect(ctx, region="us-east-1") == []


# =========================================================================
# Recheck Tests
# =========================================================================


@mock_aws
def test_I4_rds_recheck(scan_context: ScanContext):
    """Invariant I4: Recheck live RDS instance before action."""
    rds = boto3.client("rds", region_name="us-east-1")
    cw = boto3.client("cloudwatch", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="recheck-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
    )
    now = scan_context.clock.now()
    cw.put_metric_data(
        Namespace="AWS/RDS",
        MetricData=[
            {
                "MetricName": "DatabaseConnections",
                "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "recheck-db"}],
                "Timestamp": now - timedelta(hours=1),
                "Value": 0.0,
            }
        ],
    )

    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="recheck-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=now,
    )

    detector = RDSDetector()
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is True
    assert res.protected is False

    # Stop DB instance
    rds.stop_db_instance(DBInstanceIdentifier="recheck-db")
    res_stopped = detector.recheck(scan_context, finding)
    assert res_stopped.still_idle is False
    assert "status is now 'stopped'" in res_stopped.reason


@mock_aws
def test_rds_recheck_protected_tag_fresh(scan_context: ScanContext):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="tag-recheck-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )
    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="tag-recheck-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    detector = RDSDetector()
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is True
    assert res.protected is True


def test_rds_recheck_missing_or_errors(scan_context: ScanContext):
    mock_rds = MagicMock()
    mock_rds.describe_db_instances.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "DBInstanceNotFound", "Message": "Not found"}},
        "DescribeDBInstances",
    )
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_rds,
    )
    detector = RDSDetector()
    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="missing-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "not found" in res.reason

    # Empty DBInstances list
    mock_rds.describe_db_instances.side_effect = None
    mock_rds.describe_db_instances.return_value = {"DBInstances": []}
    res_empty = detector.recheck(ctx, finding)
    assert res_empty.still_idle is False
    assert "no longer exists" in res_empty.reason

    # Unexpected exception
    mock_rds.describe_db_instances.side_effect = RuntimeError("Crash")
    res_crash = detector.recheck(ctx, finding)
    assert res_crash.still_idle is None


def test_rds_recheck_cw_active_or_failure(scan_context: ScanContext):
    mock_rds = MagicMock()
    mock_rds.describe_db_instances.return_value = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "active-cw-db",
                "DBInstanceStatus": "available",
                "Engine": "postgres",
                "TagList": [],
            }
        ]
    }
    mock_cw = MagicMock()
    # Active connections (max 4.0)
    mock_cw.get_metric_statistics.return_value = {"Datapoints": [{"Maximum": 4.0}]}

    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_cw if svc == "cloudwatch" else mock_rds,
    )
    detector = RDSDetector()
    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="active-cw-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "Active database connections" in res.reason

    # CW exception
    mock_cw.get_metric_statistics.side_effect = RuntimeError("CW query failed")
    res_err = detector.recheck(ctx, finding)
    assert res_err.still_idle is None
    assert "Failed to recheck CloudWatch" in res_err.reason


# =========================================================================
# Action Tests: RDSStopAction
# =========================================================================


@mock_aws
def test_I1_rds_dry_run_never_mutates(scan_context: ScanContext):
    """Invariant I1: Never mutate when dry_run is true; detail mentions 7-day auto-restart."""
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="dry-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
    )

    dry_ctx = ScanContext(
        config=Config(dry_run=True),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=scan_context.client_factory,
    )

    action = RDSStopAction()
    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="dry-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    res = action.apply(dry_ctx, finding)
    assert res.ok is True
    assert res.performed is False
    assert "DRY RUN" in res.detail
    assert "7 days" in res.detail

    desc = rds.describe_db_instances(DBInstanceIdentifier="dry-db")
    assert desc["DBInstances"][0]["DBInstanceStatus"] == "available"


@mock_aws
def test_rds_stop_action_stops_instance(scan_context: ScanContext):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="action-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
    )

    action = RDSStopAction()
    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="action-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    res = action.apply(scan_context, finding)
    assert res.ok is True
    assert res.performed is True
    assert "7 days" in res.detail

    desc = rds.describe_db_instances(DBInstanceIdentifier="action-db")
    assert desc["DBInstances"][0]["DBInstanceStatus"] == "stopped"


def test_rds_stop_action_error_handling(scan_context: ScanContext):
    mock_rds = MagicMock()
    mock_rds.stop_db_instance.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "InvalidDBInstanceState", "Message": "Cannot stop"}},
        "StopDBInstance",
    )
    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_rds,
    )
    action = RDSStopAction()
    finding = Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="error-db",
        region="us-east-1",
        reason="Idle DB",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.RDS_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert res.performed is False
    assert "Failed to stop RDS instance" in res.detail

    # Client factory error
    ctx_bad_client = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=MagicMock(side_effect=RuntimeError("Client error")),
    )
    res_bad = action.apply(ctx_bad_client, finding)
    assert res_bad.ok is False
    assert "Failed to obtain RDS client" in res_bad.detail
