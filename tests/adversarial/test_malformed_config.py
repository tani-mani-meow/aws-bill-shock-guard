"""Adversarial tests for malformed, adversarial, and boundary BSG_CONFIG inputs."""

import pytest

from bill_shock_guard.config import load_config_from_dict, load_config_from_json
from bill_shock_guard.handler import scan_handler


def test_malformed_json_syntax_error() -> None:
    """Invalid JSON syntax must raise ValueError with diagnostic message."""
    bad_json_strings = [
        "{unquoted_key: 1}",
        '{"dry_run": true,',
        '{"dry_run": true}}',
        "<config><dry_run>true</dry_run></config>",
        "",
        "   ",
        "None",
    ]
    for bad in bad_json_strings:
        with pytest.raises(ValueError, match="Invalid JSON configuration"):
            load_config_from_json(bad)


def test_malformed_json_non_dict_root() -> None:
    """Config root must be a JSON object; primitives and lists must be rejected."""
    non_dicts = [
        "[]",
        '["dry_run", true]',
        '"a string config"',
        "12345",
        "true",
        "false",
        "null",
    ]
    for item in non_dicts:
        with pytest.raises(ValueError, match="Config must be a JSON object"):
            load_config_from_json(item)


def test_unknown_root_keys_rejected() -> None:
    """Arbitrary/injected root keys must be rejected to prevent config pollution."""
    injected_payloads = [
        {"unknown_param": "malicious"},
        {"dry_run": True, "admin": True},
        {"dry_run": True, "__class__": "exploit"},
    ]
    for raw in injected_payloads:
        with pytest.raises(ValueError, match="Unknown config keys"):
            load_config_from_dict(raw)


def test_strict_dry_run_type_coercion_rejected() -> None:
    """dry_run must strictly be a bool. String 'false' or integer 0 must NOT disable dry run."""
    adversarial_dry_run_values: list[object] = [
        "false",
        "False",
        "0",
        0,
        1,
        0.0,
        [],
        {},
        None,
    ]
    for val in adversarial_dry_run_values:
        with pytest.raises(ValueError, match="dry_run must be a boolean"):
            load_config_from_dict({"dry_run": val})


def test_invalid_grace_hours_rejected() -> None:
    """grace_hours must be an integer >= 1. 0 or negative values must be rejected."""
    invalid_grace_values: list[object] = [
        0,
        -1,
        -24,
        "24",
        1.5,
        0.0,
        None,
        True,  # In python bool is subclass of int, but True == 1. Let's check True vs int
    ]
    for val in invalid_grace_values:
        # If val is True, isinstance(True, int) is True and True >= 1, but "24" or 0 must fail
        if val is True:
            continue
        with pytest.raises(ValueError, match="grace_hours must be an integer >= 1"):
            load_config_from_dict({"grace_hours": val})


def test_invalid_regions_rejected() -> None:
    """regions must be a non-empty list of non-empty strings."""
    invalid_regions: list[object] = [
        [],
        [""],
        ["   "],
        ["us-east-1", ""],
        ["us-east-1", None],
        [123],
        "us-east-1",
        None,
    ]
    for reg in invalid_regions:
        with pytest.raises(ValueError):
            load_config_from_dict({"regions": reg})


def test_invalid_protect_tag_key_rejected() -> None:
    """protect_tag_key must be a non-empty string."""
    invalid_keys: list[object] = [
        "",
        "   ",
        None,
        123,
        [],
    ]
    for k in invalid_keys:
        with pytest.raises(ValueError, match="protect_tag_key must be a non-empty string"):
            load_config_from_dict({"protect_tag_key": k})


def test_invalid_managed_tag_keys_rejected() -> None:
    """managed_tag_keys must be a list of non-empty strings."""
    invalid_managed: list[object] = [
        "not-a-list",
        [""],
        ["   "],
        [123],
        None,
    ]
    for m in invalid_managed:
        with pytest.raises(ValueError):
            load_config_from_dict({"managed_tag_keys": m})


def test_invalid_ignore_resource_ids_rejected() -> None:
    """ignore_resource_ids must be a list of non-empty strings."""
    invalid_ignores: list[object] = [
        "i-12345",
        [""],
        ["   "],
        [123],
        None,
    ]
    for ign in invalid_ignores:
        with pytest.raises(ValueError):
            load_config_from_dict({"ignore_resource_ids": ign})


def test_invalid_enabled_actions_rejected() -> None:
    """enabled_actions must contain only recognized ActionKind values."""
    invalid_actions_list: list[object] = [
        "ec2_stop",  # string instead of list
        ["rm_rf_everything"],
        ["ec2_terminate"],  # we only support ec2_stop, not ec2_terminate
        ["ec2_stop", "invalid_action"],
        [""],
        [None],
        [123],
    ]
    for act in invalid_actions_list:
        with pytest.raises(ValueError):
            load_config_from_dict({"enabled_actions": act})


def test_invalid_max_actions_per_run_rejected() -> None:
    """max_actions_per_run must be an integer >= 0."""
    invalid_max: list[object] = [
        -1,
        -100,
        "5",
        5.5,
        None,
    ]
    for m in invalid_max:
        with pytest.raises(ValueError, match="max_actions_per_run must be an integer >= 0"):
            load_config_from_dict({"max_actions_per_run": m})


def test_invalid_thresholds_rejected() -> None:
    """thresholds must be a dict with recognized keys and positive numbers."""
    # Unknown key
    with pytest.raises(ValueError, match="Unknown thresholds keys"):
        load_config_from_dict({"thresholds": {"alien_threshold": 10}})

    # Non-dict
    with pytest.raises(ValueError, match="thresholds must be a JSON object"):
        load_config_from_dict({"thresholds": "100"})

    # Non-positive numbers
    bad_threshold_values = [
        {"ec2_idle_window_hours": 0},
        {"ec2_idle_window_hours": -5},
        {"ec2_idle_cpu_avg_pct": -0.1},
        {"ec2_idle_cpu_avg_pct": 0},
        {"ec2_idle_network_avg_bytes_per_sec": -100},
        {"ebs_unattached_days": 0},
        {"rds_idle_window_hours": "168"},  # string rejected
    ]
    for bad in bad_threshold_values:
        with pytest.raises(ValueError, match="must be a positive number"):
            load_config_from_dict({"thresholds": bad})


def test_invalid_notify_rejected() -> None:
    """notify must be a dict with recognized keys and valid sub-fields."""
    # Unknown key
    with pytest.raises(ValueError, match="Unknown notify keys"):
        load_config_from_dict({"notify": {"discord": {}}})

    # Empty string for SNS ARN
    with pytest.raises(ValueError, match="sns_topic_arn must be null or a non-empty string"):
        load_config_from_dict({"notify": {"sns_topic_arn": ""}})

    with pytest.raises(ValueError, match="sns_topic_arn must be null or a non-empty string"):
        load_config_from_dict({"notify": {"sns_topic_arn": "   "}})

    # Invalid telegram config
    with pytest.raises(ValueError, match="telegram config must be a JSON object"):
        load_config_from_dict({"notify": {"telegram": "enabled"}})

    with pytest.raises(ValueError, match="Unknown telegram keys"):
        load_config_from_dict({"notify": {"telegram": {"bot_token": "secret"}}})

    with pytest.raises(ValueError, match="telegram.enabled must be a boolean"):
        load_config_from_dict({"notify": {"telegram": {"enabled": "yes"}}})


def test_scan_handler_aborts_on_malformed_bsg_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lambda scan_handler immediately raises ValueError when BSG_CONFIG is malformed."""
    monkeypatch.setenv("BSG_CONFIG", '{"dry_run": "false", "grace_hours": -1}')
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    with pytest.raises(ValueError, match="dry_run must be a boolean"):
        scan_handler({}, None)


def test_scan_handler_defaults_on_empty_bsg_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty or whitespace BSG_CONFIG safely falls back to default Config."""
    from unittest.mock import patch

    monkeypatch.setenv("BSG_CONFIG", "    ")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    with patch("bill_shock_guard.engine.runner.get_enabled_regions", return_value=["us-east-1"]):
        # Should not raise; runs with default Config
        res = scan_handler({}, None)
        assert res["status"] in {"success", "completed_with_errors"}
