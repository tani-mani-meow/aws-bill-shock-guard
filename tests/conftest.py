"""Pytest fixtures and environment setup for Bill Shock Guard tests."""

import os
from typing import Generator

import pytest

from bill_shock_guard.config import Config
from bill_shock_guard.logging_util import JsonLogger
from tests.fakes.fake_clock import FakeClock

MOTO_ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def aws_credentials() -> Generator[None, None, None]:
    """Mocked AWS Credentials for moto."""
    old_env = os.environ.copy()
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_env)


@pytest.fixture
def account_id() -> str:
    return MOTO_ACCOUNT_ID


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def logger() -> JsonLogger:
    return JsonLogger(run_id="test-run", region="us-east-1")


@pytest.fixture
def base_config() -> Config:
    return Config()
