"""Unit tests for 'bsg version' command."""

import pytest

from bill_shock_guard.cli import VERSION, main, run_version


def test_run_version_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_version()
    assert code == 0
    captured = capsys.readouterr()
    assert f"bill-shock-guard {VERSION}" in captured.out


def test_main_version_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["version"])
    assert code == 0
    captured = capsys.readouterr()
    assert f"bill-shock-guard {VERSION}" in captured.out


def test_main_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert f"bill-shock-guard {VERSION}" in captured.out
