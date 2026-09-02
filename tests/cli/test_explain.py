"""Unit tests for 'bsg explain' command."""

import pytest

from bill_shock_guard.cli import main, run_explain
from bill_shock_guard.config import Config, Thresholds
from bill_shock_guard.models import ActionKind, ResourceType


def test_explain_ec2_instance(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "ec2_instance"])
    assert code == 0
    out = capsys.readouterr().out
    t = Thresholds()

    assert "Resource Type: ec2_instance" in out
    assert f"ec2_idle_window_hours: {t.ec2_idle_window_hours}" in out
    assert f"ec2_idle_cpu_avg_pct: {t.ec2_idle_cpu_avg_pct}" in out
    assert f"ec2_idle_network_avg_bytes_per_sec: {t.ec2_idle_network_avg_bytes_per_sec}" in out
    assert f"Proposed Action: {ActionKind.EC2_STOP.value}" in out
    assert "Enabled by Default: Yes" in out


def test_explain_elastic_ip(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "elastic_ip"])
    assert code == 0
    out = capsys.readouterr().out

    assert "Resource Type: elastic_ip" in out
    assert "Allocated Elastic IP address with no association" in out
    assert f"Proposed Action: {ActionKind.EIP_RELEASE.value}" in out
    assert "Enabled by Default: Yes" in out


def test_explain_nat_gateway(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "nat_gateway"])
    assert code == 0
    out = capsys.readouterr().out
    t = Thresholds()

    assert "Resource Type: nat_gateway" in out
    assert f"nat_idle_window_hours: {t.nat_idle_window_hours}" in out
    assert f"Proposed Action: {ActionKind.NAT_DELETE.value}" in out
    assert "Enabled by Default: No" in out


def test_explain_ebs_volume(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "ebs_volume"])
    assert code == 0
    out = capsys.readouterr().out
    t = Thresholds()

    assert "Resource Type: ebs_volume" in out
    assert f"ebs_unattached_days: {t.ebs_unattached_days}" in out
    assert f"Proposed Action: {ActionKind.EBS_DELETE_AFTER_SNAPSHOT.value}" in out
    assert "Enabled by Default: No" in out


def test_explain_load_balancer(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "load_balancer"])
    assert code == 0
    out = capsys.readouterr().out
    t = Thresholds()

    assert "Resource Type: load_balancer" in out
    assert f"elb_idle_window_hours: {t.elb_idle_window_hours}" in out
    assert f"Proposed Action: {ActionKind.ELB_DELETE.value}" in out
    assert "Enabled by Default: No" in out


def test_explain_rds_instance(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "rds_instance"])
    assert code == 0
    out = capsys.readouterr().out
    t = Thresholds()

    assert "Resource Type: rds_instance" in out
    assert f"rds_idle_window_hours: {t.rds_idle_window_hours}" in out
    assert f"Proposed Action: {ActionKind.RDS_STOP.value}" in out
    assert "Enabled by Default: No" in out


def test_explain_sagemaker_notebook(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["explain", "sagemaker_notebook"])
    assert code == 0
    out = capsys.readouterr().out

    assert "Resource Type: sagemaker_notebook" in out
    assert f"Proposed Action: {ActionKind.SM_NOTEBOOK_STOP.value}" in out
    assert "Enabled by Default: No" in out


@pytest.mark.parametrize(
    "alias,expected_enum",
    [
        ("ec2", ResourceType.EC2_INSTANCE),
        ("eip", ResourceType.ELASTIC_IP),
        ("nat", ResourceType.NAT_GATEWAY),
        ("ebs", ResourceType.EBS_VOLUME),
        ("elb", ResourceType.LOAD_BALANCER),
        ("rds", ResourceType.RDS_INSTANCE),
        ("sagemaker", ResourceType.SAGEMAKER_NOTEBOOK),
    ],
)
def test_explain_aliases(
    capsys: pytest.CaptureFixture[str], alias: str, expected_enum: ResourceType
) -> None:
    code = main(["explain", alias])
    assert code == 0
    out = capsys.readouterr().out
    assert f"Resource Type: {expected_enum.value}" in out


def test_explain_unknown_resource_type(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_explain("unknown_resource_xyz")
    assert code == 1
    err = capsys.readouterr().err
    assert "Error: Unknown resource type 'unknown_resource_xyz'" in err
    assert "Valid resource types:" in err


def test_explain_matches_code_constants() -> None:
    from bill_shock_guard.cli import get_explanation

    cfg = Config()
    t = Thresholds()

    expl_ec2 = get_explanation(ResourceType.EC2_INSTANCE)
    assert expl_ec2.default_thresholds["ec2_idle_window_hours"] == t.ec2_idle_window_hours
    assert expl_ec2.default_thresholds["ec2_idle_cpu_avg_pct"] == t.ec2_idle_cpu_avg_pct
    assert (
        expl_ec2.default_thresholds["ec2_idle_network_avg_bytes_per_sec"]
        == t.ec2_idle_network_avg_bytes_per_sec
    )
    assert expl_ec2.proposed_action == ActionKind.EC2_STOP
    assert expl_ec2.is_enabled_by_default == (ActionKind.EC2_STOP in cfg.enabled_actions)
