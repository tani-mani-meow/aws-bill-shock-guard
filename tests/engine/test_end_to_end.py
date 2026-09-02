"""End-to-end moto test for the execution engine."""

from datetime import datetime, timezone

import boto3
from moto import mock_aws

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.interfaces import Action, Detector, ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    FindingStatus,
    RecheckResult,
    ResourceType,
)
from tests.fakes.fake_clock import FakeClock


class MotoEc2Detector(Detector):
    """Detector for the moto end-to-end test reading live moto EC2 instances."""

    resource_type = ResourceType.EC2_INSTANCE

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_instances()
        findings: list[Finding] = []
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                state_name = inst["State"]["Name"]
                if state_name == "running":
                    instance_id = inst["InstanceId"]
                    findings.append(
                        Finding(
                            resource_type=ResourceType.EC2_INSTANCE,
                            resource_id=instance_id,
                            region=region,
                            reason="Idle running EC2 instance",
                            evidence={"state": state_name},
                            est_monthly_cost_usd=15.0,
                            cost_confidence="estimate",
                            proposed_action=ActionKind.EC2_STOP,
                            protected=False,
                            protection_reason=None,
                            detected_at=ctx.clock.now(),
                        )
                    )
        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        ec2 = boto3.client("ec2", region_name=finding.region)
        resp = ec2.describe_instances(InstanceIds=[finding.resource_id])
        inst = resp["Reservations"][0]["Instances"][0]
        state_name = inst["State"]["Name"]
        still_running = state_name in ("running", "pending")
        return RecheckResult(
            still_idle=still_running,
            protected=False,
            reason=f"Instance state is {state_name}",
        )


class MotoEc2StopAction(Action):
    """Action for the moto end-to-end test stopping live moto EC2 instances."""

    kind = ActionKind.EC2_STOP

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        ec2 = boto3.client("ec2", region_name=finding.region)
        ec2.stop_instances(InstanceIds=[finding.resource_id])
        return ActionResult(
            ok=True,
            performed=True,
            detail=f"Stopped instance {finding.resource_id}",
        )


class FakeSnsNotifier:
    name: str = "sns"

    def __init__(self) -> None:
        self.sent_messages: list[tuple[str, str]] = []

    def send(self, subject: str, body: str) -> bool:
        self.sent_messages.append((subject, body))
        return True


@mock_aws
def test_end_to_end_ec2_lifecycle() -> None:
    """Require a fresh active-mode warning before stopping an idle EC2 instance."""
    region = "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)

    # 1. Create an EC2 instance in moto (state 'running')
    run_resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]

    # Verify initial state is running
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    assert desc["Reservations"][0]["Instances"][0]["State"]["Name"] == "running"

    clock = FakeClock(initial_time=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc))
    logger = JsonLogger(run_id="e2e-run", region=region)
    store = MemoryStateStore()
    notifier = FakeSnsNotifier()

    detector = MotoEc2Detector()
    action = MotoEc2StopAction()
    runner = EngineRunner(detectors=[detector], actions={ActionKind.EC2_STOP: action})

    # -------------------------------------------------------------------------
    # Run 1: dry_run = True
    # -------------------------------------------------------------------------
    cfg_dry = Config(
        dry_run=True,
        grace_hours=24,
        regions=[region],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx1 = ScanContext(
        config=cfg_dry,
        clock=clock,
        account_id="123456789012",
        run_id="run-1",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )

    summary1 = runner.run(ctx1, store, notifier=notifier)
    # Assert 1 warning sent, 0 mutations
    assert summary1.warnings_sent == 1
    assert summary1.actions_performed == 0
    assert len(notifier.sent_messages) == 1

    desc1 = ec2.describe_instances(InstanceIds=[instance_id])
    assert desc1["Reservations"][0]["Instances"][0]["State"]["Name"] == "running"

    # -------------------------------------------------------------------------
    # Run 2: dry_run = True, running again immediately
    # -------------------------------------------------------------------------
    ctx2 = ScanContext(
        config=cfg_dry,
        clock=clock,
        account_id="123456789012",
        run_id="run-2",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )

    summary2 = runner.run(ctx2, store, notifier=notifier)
    # Assert 0 new warnings (still 1 total message), 0 mutations
    assert summary2.warnings_sent == 0
    assert summary2.actions_performed == 0
    assert len(notifier.sent_messages) == 1

    desc2 = ec2.describe_instances(InstanceIds=[instance_id])
    assert desc2["Reservations"][0]["Instances"][0]["State"]["Name"] == "running"

    # -------------------------------------------------------------------------
    # Flip dry_run off and advance fake clock past grace period (25 hours)
    # -------------------------------------------------------------------------
    clock.advance(hours=25)

    cfg_live = Config(
        dry_run=False,
        grace_hours=24,
        regions=[region],
        enabled_actions=[ActionKind.EC2_STOP],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:bsg-topic"),
    )
    ctx3 = ScanContext(
        config=cfg_live,
        clock=clock,
        account_id="123456789012",
        run_id="run-3",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )

    # -------------------------------------------------------------------------
    # Run 3: Send an active warning and start a new grace period.
    # -------------------------------------------------------------------------
    summary3 = runner.run(ctx3, store, notifier=notifier)
    assert summary3.warnings_sent == 1
    assert summary3.actions_performed == 0
    assert (
        ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
            "State"
        ]["Name"]
        == "running"
    )

    clock.advance(hours=23)
    assert runner.run(ctx3, store, notifier=notifier).actions_performed == 0
    clock.advance(hours=1)
    summary3 = runner.run(ctx3, store, notifier=notifier)
    assert summary3.actions_performed == 1
    assert summary3.actions_failed == 0

    # In moto, verify instance is now stopping or stopped
    desc3 = ec2.describe_instances(InstanceIds=[instance_id])
    assert desc3["Reservations"][0]["Instances"][0]["State"]["Name"] in (
        "stopping",
        "stopped",
    )

    # State in store is ACTED
    key = f"{region}#{ResourceType.EC2_INSTANCE.value}#{instance_id}"
    st = store.get(key)
    assert st is not None
    assert st.status == FindingStatus.ACTED

    # -------------------------------------------------------------------------
    # Run 4: Idempotence check (I8)
    # -------------------------------------------------------------------------
    ctx4 = ScanContext(
        config=cfg_live,
        clock=clock,
        account_id="123456789012",
        run_id="run-4",
        logger=logger,
        client_factory=lambda svc, reg: boto3.client(svc, region_name=reg),
    )
    summary4 = runner.run(ctx4, store, notifier=notifier)
    assert summary4.actions_performed == 0
    assert summary4.warnings_sent == 0
