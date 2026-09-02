"""Tests for SageMaker notebook instance detector and stop action."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

from bill_shock_guard.config import Config
from bill_shock_guard.detectors.sagemaker import (
    SageMakerNotebookDetector,
    SageMakerNotebookStopAction,
    is_sagemaker_notebook_idle,
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
    cfg = Config(dry_run=False)
    logger = JsonLogger(run_id="test-run-sm", region="us-east-1")
    return ScanContext(
        config=cfg,
        clock=fake_clock,
        account_id="123456789012",
        run_id="test-run-sm",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )


# =========================================================================
# Pure Idle Detection Logic Tests
# =========================================================================


def test_is_sagemaker_notebook_idle_under_threshold():
    nb = {
        "NotebookInstanceName": "idle-nb",
        "NotebookInstanceStatus": "InService",
        "InstanceType": "ml.t3.medium",
    }
    is_idle, reason, ev = is_sagemaker_notebook_idle(nb, avg_cpu=2.5, cpu_threshold=5.0)
    assert is_idle is True
    assert "2.5% <= 5.0%" in reason
    assert ev["avg_cpu_pct"] == 2.5


def test_is_sagemaker_notebook_idle_above_threshold():
    nb = {
        "NotebookInstanceName": "busy-nb",
        "NotebookInstanceStatus": "InService",
        "InstanceType": "ml.t3.medium",
    }
    is_idle, reason, _ = is_sagemaker_notebook_idle(nb, avg_cpu=15.0, cpu_threshold=5.0)
    assert is_idle is False
    assert "exceeds threshold 5.0%" in reason


def test_is_sagemaker_notebook_idle_status_not_inservice():
    nb = {
        "NotebookInstanceName": "stopped-nb",
        "NotebookInstanceStatus": "Stopped",
        "InstanceType": "ml.t3.medium",
    }
    is_idle, reason, _ = is_sagemaker_notebook_idle(nb, avg_cpu=0.0)
    assert is_idle is False
    assert "status is 'Stopped'" in reason


def test_is_sagemaker_notebook_idle_missing_metrics_not_idle():
    """Invariant I9: Unknown is not idle."""
    nb = {
        "NotebookInstanceName": "no-metric-nb",
        "NotebookInstanceStatus": "InService",
        "InstanceType": "ml.t3.medium",
    }
    is_idle, reason, _ = is_sagemaker_notebook_idle(nb, avg_cpu=None)
    assert is_idle is False
    assert "unknown is not idle" in reason


# =========================================================================
# Detector Integration Tests with Moto
# =========================================================================


@mock_aws
def test_I9_sagemaker_notebook_missing_metrics_not_detected(scan_context: ScanContext):
    """Invariant I9: Notebook without CloudWatch metrics is not flagged as idle."""
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="default-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )

    detector = SageMakerNotebookDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    # Per AWS docs, no metrics exist natively, so detector must return 0 findings
    assert len(findings) == 0


@mock_aws
def test_sagemaker_notebook_with_custom_metrics_detected(scan_context: ScanContext):
    sm = boto3.client("sagemaker", region_name="us-east-1")
    cw = boto3.client("cloudwatch", region_name="us-east-1")

    sm.create_notebook_instance(
        NotebookInstanceName="custom-metric-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )

    now = scan_context.clock.now()
    cw.put_metric_data(
        Namespace="/aws/sagemaker/NotebookInstances",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "NotebookInstanceName", "Value": "custom-metric-nb"}],
                "Timestamp": now - timedelta(hours=1),
                "Value": 1.2,
                "Unit": "Percent",
            }
        ],
    )

    detector = SageMakerNotebookDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "custom-metric-nb"
    assert f.resource_type == ResourceType.SAGEMAKER_NOTEBOOK
    assert f.proposed_action == ActionKind.SM_NOTEBOOK_STOP
    assert f.protected is False


@mock_aws
def test_I3_sagemaker_protected_notebook(scan_context: ScanContext):
    """Invariant I3: Protected notebook has protected=True."""
    sm = boto3.client("sagemaker", region_name="us-east-1")
    cw = boto3.client("cloudwatch", region_name="us-east-1")

    sm.create_notebook_instance(
        NotebookInstanceName="keep-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )

    now = scan_context.clock.now()
    cw.put_metric_data(
        Namespace="/aws/sagemaker/NotebookInstances",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "NotebookInstanceName", "Value": "keep-nb"}],
                "Timestamp": now - timedelta(hours=1),
                "Value": 1.0,
            }
        ],
    )

    detector = SageMakerNotebookDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == "keep-nb"
    assert findings[0].protected is True
    assert "bsg:keep=true" in (findings[0].protection_reason or "")


@mock_aws
def test_sagemaker_detector_ignores_stopped_notebooks(scan_context: ScanContext):
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="stopped-detect-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )
    sm.stop_notebook_instance(NotebookInstanceName="stopped-detect-nb")

    detector = SageMakerNotebookDetector()
    findings = detector.detect(scan_context, region="us-east-1")
    assert len(findings) == 0


def test_sagemaker_detector_describe_failure_resilience(scan_context: ScanContext):
    mock_sm = MagicMock()
    mock_sm.can_paginate.return_value = False
    mock_sm.list_notebook_instances.return_value = {
        "NotebookInstances": [{"NotebookInstanceName": "fail-desc-nb"}]
    }
    mock_sm.describe_notebook_instance.side_effect = RuntimeError("Describe failed")
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_sm,
    )
    detector = SageMakerNotebookDetector()
    assert detector.detect(ctx, region="us-east-1") == []


def test_sagemaker_detector_client_exception(scan_context: ScanContext):
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=MagicMock(side_effect=RuntimeError("SageMaker connection failed")),
    )
    detector = SageMakerNotebookDetector()
    assert detector.detect(ctx, region="us-east-1") == []


def test_sagemaker_detector_list_notebooks_client_error(scan_context: ScanContext):
    mock_sm = MagicMock()
    mock_sm.can_paginate.return_value = False
    mock_sm.list_notebook_instances.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
        "ListNotebookInstances",
    )
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_sm,
    )
    detector = SageMakerNotebookDetector()
    assert detector.detect(ctx, region="us-east-1") == []


# =========================================================================
# Recheck Tests
# =========================================================================


@mock_aws
def test_I4_sagemaker_recheck(scan_context: ScanContext):
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="recheck-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_data(
        Namespace="/aws/sagemaker/NotebookInstances",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "NotebookInstanceName", "Value": "recheck-nb"}],
                "Timestamp": scan_context.clock.now() - timedelta(hours=1),
                "Value": 0.5,
                "Unit": "Percent",
            }
        ],
    )

    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="recheck-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    detector = SageMakerNotebookDetector()
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is True
    assert res.protected is False

    # Stop the notebook
    sm.stop_notebook_instance(NotebookInstanceName="recheck-nb")
    res_stopped = detector.recheck(scan_context, finding)
    assert res_stopped.still_idle is False
    assert "Stopped" in res_stopped.reason


@mock_aws
def test_I4_sagemaker_recheck_active_notebook_blocks_action(scan_context: ScanContext):
    """Invariant I4: active model training at recheck time detects high CPU and blocks action."""
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="active-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_data(
        Namespace="/aws/sagemaker/NotebookInstances",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "NotebookInstanceName", "Value": "active-nb"}],
                "Timestamp": scan_context.clock.now() - timedelta(hours=1),
                "Value": 85.0,
                "Unit": "Percent",
            }
        ],
    )
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="active-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    detector = SageMakerNotebookDetector()
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is False
    assert res.protected is False
    assert "active" in res.reason.lower()


@mock_aws
def test_I9_sagemaker_recheck_missing_metrics_returns_none(scan_context: ScanContext):
    """Invariant I9: missing CloudWatch metrics during recheck returns still_idle=None."""
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="no-metrics-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="no-metrics-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    detector = SageMakerNotebookDetector()
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is None
    assert "unknown is not idle" in res.reason


@mock_aws
def test_sagemaker_recheck_protected(scan_context: ScanContext):
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="recheck-prot-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
        Tags=[{"Key": "bsg:keep", "Value": "true"}],
    )
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="recheck-prot-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    detector = SageMakerNotebookDetector()
    res = detector.recheck(scan_context, finding)
    assert res.still_idle is True
    assert res.protected is True


def test_sagemaker_recheck_errors(scan_context: ScanContext):
    mock_sm = MagicMock()
    mock_sm.describe_notebook_instance.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ResourceNotFound", "Message": "Not found"}},
        "DescribeNotebookInstance",
    )
    ctx = ScanContext(
        config=scan_context.config,
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_sm,
    )
    detector = SageMakerNotebookDetector()
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="ghost-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = detector.recheck(ctx, finding)
    assert res.still_idle is False
    assert "no longer exists" in res.reason

    # Unexpected error
    mock_sm.describe_notebook_instance.side_effect = RuntimeError("Crash")
    res_crash = detector.recheck(ctx, finding)
    assert res_crash.still_idle is None


# =========================================================================
# Action Tests: SageMakerNotebookStopAction
# =========================================================================


@mock_aws
def test_I1_sagemaker_dry_run_never_mutates(scan_context: ScanContext):
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="dry-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )

    dry_ctx = ScanContext(
        config=Config(dry_run=True),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=scan_context.client_factory,
    )

    action = SageMakerNotebookStopAction()
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="dry-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    res = action.apply(dry_ctx, finding)
    assert res.ok is True
    assert res.performed is False
    assert "DRY RUN" in res.detail

    desc = sm.describe_notebook_instance(NotebookInstanceName="dry-nb")
    assert desc["NotebookInstanceStatus"] == "InService"


@mock_aws
def test_sagemaker_stop_action_stops_notebook(scan_context: ScanContext):
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="stop-me-nb",
        InstanceType="ml.t3.medium",
        RoleArn="arn:aws:iam::123456789012:role/service-role",
    )

    action = SageMakerNotebookStopAction()
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="stop-me-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )

    res = action.apply(scan_context, finding)
    assert res.ok is True
    assert res.performed is True

    desc = sm.describe_notebook_instance(NotebookInstanceName="stop-me-nb")
    assert desc["NotebookInstanceStatus"] == "Stopped"


def test_sagemaker_stop_action_error_handling(scan_context: ScanContext):
    mock_sm = MagicMock()
    mock_sm.stop_notebook_instance.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": "Cannot stop"}},
        "StopNotebookInstance",
    )
    ctx = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=lambda svc, reg: mock_sm,
    )
    action = SageMakerNotebookStopAction()
    finding = Finding(
        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
        resource_id="error-nb",
        region="us-east-1",
        reason="Idle notebook",
        evidence={},
        est_monthly_cost_usd=None,
        cost_confidence="unknown",
        proposed_action=ActionKind.SM_NOTEBOOK_STOP,
        protected=False,
        protection_reason=None,
        detected_at=scan_context.clock.now(),
    )
    res = action.apply(ctx, finding)
    assert res.ok is False
    assert res.performed is False
    assert "Failed to stop SageMaker notebook" in res.detail

    # Client error
    ctx_bad = ScanContext(
        config=Config(dry_run=False),
        clock=scan_context.clock,
        account_id=scan_context.account_id,
        run_id=scan_context.run_id,
        logger=scan_context.logger,
        client_factory=MagicMock(side_effect=RuntimeError("Client failed")),
    )
    res_bad = action.apply(ctx_bad, finding)
    assert res_bad.ok is False
    assert "Failed to obtain SageMaker client" in res_bad.detail
