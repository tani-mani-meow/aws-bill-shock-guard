"""Unit tests for 'bsg scan' command."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import botocore.exceptions
import moto
import pytest

from bill_shock_guard.cli import main, run_scan
from bill_shock_guard.interfaces import Detector, ScanContext
from bill_shock_guard.models import ActionKind, Finding, ResourceType
from bill_shock_guard.pricing import PRICE_TABLE_DATE


class MockEC2Detector:
    resource_type = ResourceType.EC2_INSTANCE

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        if region != "us-east-1":
            return []
        return [
            Finding(
                resource_type=ResourceType.EC2_INSTANCE,
                resource_id="i-0123456789abcdef0",
                region="us-east-1",
                reason="CPU avg 1.2% < 5.0%, net 120 B/s < 10000 B/s over 24h",
                evidence={"avg_cpu": 1.2, "avg_net": 120},
                est_monthly_cost_usd=14.60,
                cost_confidence="estimate",
                proposed_action=ActionKind.EC2_STOP,
                protected=False,
                protection_reason=None,
                detected_at=datetime.now(timezone.utc),
            )
        ]

    def recheck(self, ctx: ScanContext, finding: Finding) -> object:
        raise NotImplementedError


class MockProtectedEIPDetector:
    resource_type = ResourceType.ELASTIC_IP

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        if region != "us-east-1":
            return []
        return [
            Finding(
                resource_type=ResourceType.ELASTIC_IP,
                resource_id="eipalloc-01234567",
                region="us-east-1",
                reason="Unassociated Elastic IP address",
                evidence={"public_ip": "54.210.1.2"},
                est_monthly_cost_usd=3.65,
                cost_confidence="estimate",
                proposed_action=ActionKind.EIP_RELEASE,
                protected=True,
                protection_reason="bsg:keep=true",
                detected_at=datetime.now(timezone.utc),
            )
        ]

    def recheck(self, ctx: ScanContext, finding: Finding) -> object:
        raise NotImplementedError


class FailingDetector:
    resource_type = ResourceType.NAT_GATEWAY

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        raise RuntimeError("Simulated CloudWatch query failure")

    def recheck(self, ctx: ScanContext, finding: Finding) -> object:
        raise NotImplementedError


@moto.mock_aws
def test_scan_empty_account_table(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--regions", "us-east-1", "--format", "table"])
    assert code == 0
    out = capsys.readouterr().out

    assert "No idle or unattached resources found. Your account is clean!" in out
    assert "Total idle resources: 0" in out
    assert "Total estimated monthly cost at risk: $0.00" in out
    assert f"Price table date: {PRICE_TABLE_DATE}" in out


@moto.mock_aws
def test_scan_with_findings_table(capsys: pytest.CaptureFixture[str]) -> None:
    detectors: list[Detector] = [MockEC2Detector(), MockProtectedEIPDetector()]  # type: ignore[list-item]

    code = run_scan(
        regions_arg="us-east-1",
        output_format="table",
        detectors=detectors,
    )
    assert code == 0
    out = capsys.readouterr().out

    assert "Region" in out
    assert "Resource Type" in out
    assert "Resource ID" in out
    assert "i-0123456789abcdef0" in out
    assert "ec2_instance" in out
    assert "$14.60 (estimate)" in out
    assert "eipalloc-01234567" in out
    assert "Yes (bsg:keep=true)" in out
    assert "--- Scan Summary ---" in out
    assert "Total idle resources: 2" in out
    assert "Total estimated monthly cost at risk: $18.25 (estimate)" in out
    assert f"Price table date: {PRICE_TABLE_DATE}" in out


@moto.mock_aws
def test_scan_with_findings_json(capsys: pytest.CaptureFixture[str]) -> None:
    detectors: list[Detector] = [MockEC2Detector()]  # type: ignore[list-item]

    code = run_scan(
        regions_arg="us-east-1",
        output_format="json",
        detectors=detectors,
    )
    assert code == 0
    out = capsys.readouterr().out

    data = json.loads(out)
    assert data["findings_count"] == 1
    assert data["total_est_monthly_cost_usd"] == 14.60
    assert data["price_table_date"] == PRICE_TABLE_DATE
    assert data["cost_confidence"] == "estimate"
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["resource_id"] == "i-0123456789abcdef0"
    assert f["resource_type"] == "ec2_instance"
    assert f["proposed_action"] == "ec2_stop"
    assert f["protected"] is False


def test_scan_missing_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = botocore.exceptions.NoCredentialsError()

    with patch("bill_shock_guard.cli.get_boto_client", return_value=mock_sts):
        code = main(["scan"])

    assert code == 1
    err = capsys.readouterr().err
    assert "Error: Unable to locate valid AWS credentials." in err
    assert "Guidance for students:" in err
    assert "aws configure" in err


def test_scan_config_file_not_found(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--config", "nonexistent_config_123.json"])
    assert code == 1
    err = capsys.readouterr().err
    assert "Error: Config file not found: nonexistent_config_123.json" in err


@moto.mock_aws
def test_scan_config_file_valid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_file = tmp_path / "bsg_config.json"
    cfg_file.write_text(
        json.dumps(
            {
                "dry_run": True,
                "regions": ["us-east-1"],
                "grace_hours": 12,
            }
        ),
        encoding="utf-8",
    )

    code = main(["scan", "--config", str(cfg_file)])
    assert code == 0
    out = capsys.readouterr().out
    assert "--- Scan Summary ---" in out


@moto.mock_aws
def test_scan_invariant_I9_resilient_to_detector_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invariant I9: One failing detector/region never crashes or aborts the scan."""
    detectors: list[Detector] = [FailingDetector(), MockEC2Detector()]  # type: ignore[list-item]

    code = run_scan(
        regions_arg="us-east-1",
        output_format="table",
        detectors=detectors,
    )
    assert code == 0
    out = capsys.readouterr().out

    assert "i-0123456789abcdef0" in out
    assert "Total idle resources: 1" in out
    assert "Warnings during scan (Invariant I9: failures skipped without aborting):" in out
    assert "Simulated CloudWatch query failure" in out


@moto.mock_aws
def test_scan_regions_all_argument(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--regions", "all"])
    assert code == 0
    out = capsys.readouterr().out
    assert "--- Scan Summary ---" in out


def test_cli_empty_args_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([])
    assert code == 0
    out = capsys.readouterr().out
    assert "Bill Shock Guard" in out
    assert "usage:" in out


def test_json_serial_fallback() -> None:
    from datetime import date

    from bill_shock_guard.cli import _json_serial_fallback

    dt = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)
    d = date(2026, 11, 12)
    assert _json_serial_fallback(dt) == "2026-11-12T10:00:00+00:00"
    assert _json_serial_fallback(d) == "2026-11-12"
    assert _json_serial_fallback(123) == "123"


def test_scan_invalid_json_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad_cfg = tmp_path / "bad.json"
    bad_cfg.write_text("{invalid json", encoding="utf-8")

    code = main(["scan", "--config", str(bad_cfg)])
    assert code == 1
    err = capsys.readouterr().err
    assert "Error: Failed to load config file:" in err


def test_scan_empty_regions_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--regions", ",,"])
    assert code == 1
    err = capsys.readouterr().err
    assert "Error: --regions must specify at least one region or 'all'." in err


@moto.mock_aws
def test_scan_empty_account_with_warning(capsys: pytest.CaptureFixture[str]) -> None:
    """Scan with zero findings but a detector failure shows warnings in table footer."""
    detectors: list[Detector] = [FailingDetector()]  # type: ignore[list-item]

    code = run_scan(
        regions_arg="us-east-1",
        output_format="table",
        detectors=detectors,
    )
    assert code == 0
    out = capsys.readouterr().out

    assert "No idle or unattached resources found. Your account is clean!" in out
    assert "Warnings during scan (Invariant I9: skipped without aborting):" in out
    assert "Simulated CloudWatch query failure" in out
