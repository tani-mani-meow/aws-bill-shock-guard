"""Unit tests for resource protection rules (Invariant I3)."""

from datetime import datetime, timezone

import pytest

from bill_shock_guard.config import Config
from bill_shock_guard.protection import is_protected


@pytest.fixture
def test_now() -> datetime:
    return datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_I3_unprotected_resource(base_config: Config, test_now: datetime):
    prot, reason = is_protected({}, "i-123", base_config, test_now)
    assert prot is False
    assert reason is None


def test_I3_protected_by_ignore_resource_ids(test_now: datetime):
    cfg = Config(ignore_resource_ids=["i-12345"])
    prot, reason = is_protected({}, "i-12345", cfg, test_now)
    assert prot is True
    assert "ignore_resource_ids" in (reason or "")


def test_I3_protected_by_keep_true_tag(base_config: Config, test_now: datetime):
    tags = {"bsg:keep": "true"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is True
    assert "indefinitely" in (reason or "")


def test_I3_unprotected_by_keep_false_tag(base_config: Config, test_now: datetime):
    tags = {"bsg:keep": "false"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is False
    assert reason is None


def test_I3_protected_by_keep_date_future(base_config: Config, test_now: datetime):
    # test_now is 2026-06-15
    tags = {"bsg:keep": "2026-06-20"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is True
    assert "until 2026-06-20" in (reason or "")


def test_I3_protected_by_keep_date_same_day_inclusive(base_config: Config, test_now: datetime):
    # Same day should still be protected (inclusive)
    tags = {"bsg:keep": "2026-06-15"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is True
    assert "until 2026-06-15" in (reason or "")


def test_I3_unprotected_when_keep_date_past(base_config: Config, test_now: datetime):
    # Past date
    tags = {"bsg:keep": "2026-06-10"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is False
    assert "expired" in (reason or "")


def test_I3_fail_closed_on_invalid_date_format(base_config: Config, test_now: datetime):
    # Invalid string that is not a date
    tags = {"bsg:keep": "maybe-keep"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is True
    assert "fail closed" in (reason or "")


def test_I3_fail_closed_on_invalid_calendar_date(base_config: Config, test_now: datetime):
    # Invalid calendar date (e.g. Feb 31)
    tags = {"bsg:keep": "2026-02-31"}
    prot, reason = is_protected(tags, "i-999", base_config, test_now)
    assert prot is True
    assert "fail closed" in (reason or "")


def test_I3_protected_by_managed_tag(base_config: Config, test_now: datetime):
    tags = {"aws:autoscaling:groupName": "my-asg"}
    prot, reason = is_protected(tags, "i-asg-1", base_config, test_now)
    assert prot is True
    assert "aws:autoscaling:groupName" in (reason or "")


def test_managed_tag_with_empty_value_still_protected(
    base_config: Config, test_now: datetime
) -> None:
    """Empty string value for managed service tag must still protect the resource (I3)."""
    tags = {"aws:autoscaling:groupName": ""}
    prot, reason = is_protected(tags, "i-asg-2", base_config, test_now)
    assert prot is True
    assert "aws:autoscaling:groupName" in (reason or "")
