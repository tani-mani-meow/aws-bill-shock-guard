"""Unit tests for 'bsg doctor' command."""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import moto
import pytest

from bill_shock_guard.cli import main, run_doctor


@moto.mock_aws
def test_doctor_with_valid_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["doctor", "--regions", "us-east-1"])
    assert code == 0
    captured = capsys.readouterr()
    out = captured.out

    assert "[OK] AWS Credentials verified" in out
    assert "Account ID: 123456789012" in out
    assert "Region: us-east-1" in out
    assert "[OK] ec2:DescribeInstances" in out
    assert "[OK] ec2:DescribeAddresses" in out
    assert "[OK] ec2:DescribeNatGateways" in out
    assert "[OK] ec2:DescribeVolumes" in out
    assert "All required read permissions are permitted across the checked regions." in out


def test_doctor_missing_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = botocore.exceptions.NoCredentialsError()

    with patch("bill_shock_guard.cli.get_boto_client", return_value=mock_sts):
        code = run_doctor()

    assert code == 1
    err = capsys.readouterr().err
    assert "Error: Unable to locate valid AWS credentials." in err
    assert "Guidance for students:" in err
    assert "aws configure" in err
    assert "AWS_ACCESS_KEY_ID" in err


@moto.mock_aws
def test_doctor_access_denied_reports_missing_permissions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Allow STS to succeed, but raise UnauthorizedOperation on ec2 DescribeNatGateways
    from typing import Any

    from bill_shock_guard.aws import get_boto_client as real_get_client

    def selective_boto_client(
        service_name: str, region_name: str | None = None, session: Any = None, **kwargs: Any
    ) -> Any:
        client = real_get_client(service_name, region_name=region_name, session=session, **kwargs)
        if service_name == "ec2":

            def fake_describe_nat(*_args: object, **_kw: object) -> dict[str, Any]:
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "Access Denied"}},
                    "DescribeNatGateways",
                )

            client.describe_nat_gateways = fake_describe_nat
        return client

    with patch("bill_shock_guard.cli.get_boto_client", side_effect=selective_boto_client):
        code = main(["doctor", "--regions", "us-east-1"])

    assert code == 1
    captured = capsys.readouterr()
    out = captured.out

    assert "[DENIED] ec2:DescribeNatGateways (UnauthorizedOperation)" in out
    assert "--- Doctor Finding: Missing Permissions Detected ---" in out
    assert "ec2:DescribeNatGateways" in out
    assert "Tip: Ensure your IAM user or role policy includes the read actions" in out


@moto.mock_aws
def test_doctor_skips_unsupported_service_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from typing import Any

    from bill_shock_guard.aws import get_boto_client as real_get_client

    def selective_boto_client(
        service_name: str, region_name: str | None = None, session: Any = None, **kwargs: Any
    ) -> Any:
        client = real_get_client(service_name, region_name=region_name, session=session, **kwargs)
        if service_name == "rds":

            def fake_describe_rds(*_args: object, **_kw: object) -> dict[str, Any]:
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "InvalidAction", "Message": "Service not supported"}},
                    "DescribeDBInstances",
                )

            client.describe_db_instances = fake_describe_rds
        return client

    with patch("bill_shock_guard.cli.get_boto_client", side_effect=selective_boto_client):
        code = main(["doctor", "--regions", "us-east-1"])

    assert code == 0
    captured = capsys.readouterr()
    out = captured.out
    assert "[SKIPPED] rds:DescribeDBInstances (InvalidAction)" in out
