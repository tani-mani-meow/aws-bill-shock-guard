"""Adversarial tests for tag parsing: odd whitespace, case variations, and fail-closed rules."""

from datetime import datetime, timezone

import pytest

from bill_shock_guard.config import Config
from bill_shock_guard.protection import is_protected


@pytest.fixture
def test_now() -> datetime:
    return datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_tag_value_whitespace_and_case_tolerance(base_config: Config, test_now: datetime) -> None:
    """Keep tag value should tolerate leading/trailing whitespace and mixed casing."""
    valid_true_values = [
        "  true  ",
        "TRUE",
        " True ",
        "  TRUE\n",
        "\ttrue\t",
        "TrUe",
    ]
    for val in valid_true_values:
        tags = {"bsg:keep": val}
        prot, reason = is_protected(tags, "i-test", base_config, test_now)
        assert prot is True, f"Failed for val: {val!r}"
        assert "indefinitely" in (reason or "")

    valid_false_values = [
        "  false  ",
        "FALSE",
        " False ",
        "  FALSE\n",
        "\tfalse\t",
    ]
    for val in valid_false_values:
        tags = {"bsg:keep": val}
        prot, reason = is_protected(tags, "i-test", base_config, test_now)
        assert prot is False, f"Expected False for val: {val!r}"
        assert reason is None


def test_tag_value_date_with_whitespace(base_config: Config, test_now: datetime) -> None:
    """Date tag value with surrounding whitespace is stripped and correctly evaluated."""
    # Future date with whitespace
    tags_future = {"bsg:keep": "  2026-06-20  \n"}
    prot, reason = is_protected(tags_future, "i-test", base_config, test_now)
    assert prot is True
    assert "until 2026-06-20" in (reason or "")

    # Past date with whitespace
    tags_past = {"bsg:keep": "\t2026-06-10 "}
    prot, reason = is_protected(tags_past, "i-test", base_config, test_now)
    assert prot is False
    assert "expired on 2026-06-10" in (reason or "")


def test_tag_value_empty_or_whitespace_fails_closed(
    base_config: Config,
    test_now: datetime,
) -> None:
    """Empty or whitespace-only keep tag values must fail closed (treated as protected)."""
    empty_values = [
        "",
        "   ",
        "\t\n",
        " \r\n\t ",
    ]
    for val in empty_values:
        tags = {"bsg:keep": val}
        prot, reason = is_protected(tags, "i-test", base_config, test_now)
        assert prot is True, f"Failed to fail closed for {val!r}"
        assert "fail closed" in (reason or "")


def test_tag_value_invalid_date_or_calendar_fails_closed(
    base_config: Config,
    test_now: datetime,
) -> None:
    """Malformed dates or non-existent calendar dates must fail closed."""
    invalid_dates = [
        "2026-02-30",  # Feb 30 does not exist
        "2026-13-01",  # Month 13
        "2026-00-10",  # Month 0
        "2026-06-31",  # June has 30 days
        "2026/06/20",  # Slashes instead of dashes
        "20-06-2026",  # DD-MM-YYYY
        "tomorrow",
        "forever",
        "yes",
        "1",
        "keep",
    ]
    for val in invalid_dates:
        tags = {"bsg:keep": val}
        prot, reason = is_protected(tags, "i-test", base_config, test_now)
        assert prot is True, f"Failed to fail closed for {val!r}"
        assert "fail closed" in (reason or "")


def test_tag_key_case_sensitivity_aws_behavior(base_config: Config, test_now: datetime) -> None:
    """Adversarial check: AWS tags are case-sensitive strings.

    If user sets 'BSG:KEEP' instead of 'bsg:keep', it is NOT recognized.
    """
    tags_uppercase = {"BSG:KEEP": "true"}
    prot, reason = is_protected(tags_uppercase, "i-test", base_config, test_now)
    # AWS case-sensitivity means it is not matched
    assert prot is False
    assert reason is None

    tags_mixed = {"Bsg:Keep": "true"}
    prot, reason = is_protected(tags_mixed, "i-test", base_config, test_now)
    assert prot is False
    assert reason is None


def test_tag_key_whitespace_aws_behavior(base_config: Config, test_now: datetime) -> None:
    """Adversarial check: Tag keys with leading/trailing spaces do not match exact key."""
    tags_space = {" bsg:keep ": "true"}
    prot, reason = is_protected(tags_space, "i-test", base_config, test_now)
    assert prot is False
    assert reason is None


def test_managed_tag_key_case_sensitivity(base_config: Config, test_now: datetime) -> None:
    """AWS managed service tags are case-sensitive. 'groupname' != 'groupName'."""
    # Incorrect casing in ASG tag
    tags_wrong_case = {"aws:autoscaling:groupname": "my-asg"}
    prot, reason = is_protected(tags_wrong_case, "i-test", base_config, test_now)
    assert prot is False
    assert reason is None

    # Correct casing
    tags_correct_case = {"aws:autoscaling:groupName": "my-asg"}
    prot, reason = is_protected(tags_correct_case, "i-test", base_config, test_now)
    assert prot is True
    assert "aws:autoscaling:groupName" in (reason or "")


def test_tag_value_special_chars_and_unicode_fails_closed(
    base_config: Config,
    test_now: datetime,
) -> None:
    """Values containing emojis, control characters, or unexpected punctuation fail closed."""
    weird_values = [
        "true \U0001f600",
        "keep\x00null",
        "true; rm -rf /",
        "2026-06-20; DROP TABLE",
        "' OR '1'='1",
    ]
    for val in weird_values:
        tags = {"bsg:keep": val}
        prot, reason = is_protected(tags, "i-test", base_config, test_now)
        assert prot is True, f"Failed to fail closed for {val!r}"
        assert "fail closed" in (reason or "")
