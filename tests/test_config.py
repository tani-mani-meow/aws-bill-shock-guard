"""Unit tests for config parsing and validation."""

import pytest

from bill_shock_guard.config import (
    Config,
    load_config_from_dict,
    load_config_from_json,
)
from bill_shock_guard.models import ActionKind


def test_default_config():
    cfg = Config()
    assert cfg.dry_run is True
    assert cfg.grace_hours == 24
    assert cfg.regions == ["*"]
    assert cfg.protect_tag_key == "bsg:keep"
    assert ActionKind.EC2_STOP in cfg.enabled_actions
    assert ActionKind.EIP_RELEASE in cfg.enabled_actions
    assert cfg.max_actions_per_run == 5


def test_load_valid_config_from_dict():
    raw = {
        "dry_run": False,
        "grace_hours": 48,
        "regions": ["us-east-1", "eu-west-1"],
        "protect_tag_key": "custom:keep",
        "managed_tag_keys": ["custom:managed"],
        "ignore_resource_ids": ["i-1234567890abcdef0"],
        "enabled_actions": ["ec2_stop"],
        "max_actions_per_run": 10,
        "display_tz": "UTC",
        "thresholds": {
            "ec2_idle_window_hours": 12,
            "ec2_idle_cpu_avg_pct": 2.5,
            "ec2_idle_network_avg_bytes_per_sec": 5000,
            "nat_idle_window_hours": 12,
            "ebs_unattached_days": 3,
            "elb_idle_window_hours": 72,
            "rds_idle_window_hours": 72,
        },
        "notify": {
            "sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "telegram": {
                "enabled": True,
                "chat_id": "12345678",
                "token_ssm_param": "/bsg/tg_token",
            },
        },
        "state_table": "bsg-state",
    }
    cfg = load_config_from_dict(raw)
    assert cfg.dry_run is False
    assert cfg.grace_hours == 48
    assert cfg.regions == ["us-east-1", "eu-west-1"]
    assert cfg.protect_tag_key == "custom:keep"
    assert cfg.managed_tag_keys == ["custom:managed"]
    assert cfg.ignore_resource_ids == ["i-1234567890abcdef0"]
    assert cfg.enabled_actions == [ActionKind.EC2_STOP]
    assert cfg.max_actions_per_run == 10
    assert cfg.thresholds.ec2_idle_window_hours == 12
    assert cfg.thresholds.ec2_idle_cpu_avg_pct == 2.5
    assert cfg.notify.sns_topic_arn == "arn:aws:sns:us-east-1:123456789012:test-topic"
    assert cfg.notify.telegram.enabled is True
    assert cfg.notify.telegram.chat_id == "12345678"
    assert cfg.state_table == "bsg-state"


def test_reject_string_for_dry_run():
    raw = {"dry_run": "false"}
    with pytest.raises(ValueError, match="dry_run must be a boolean"):
        load_config_from_dict(raw)


def test_reject_unknown_key():
    raw = {"unexpected_key": "val"}
    with pytest.raises(ValueError, match="Unknown config keys"):
        load_config_from_dict(raw)


def test_reject_invalid_grace_hours():
    with pytest.raises(ValueError, match="grace_hours"):
        load_config_from_dict({"grace_hours": 0})
    with pytest.raises(ValueError, match="grace_hours"):
        load_config_from_dict({"grace_hours": -5})


def test_reject_invalid_action():
    with pytest.raises(ValueError, match="Invalid action kind"):
        load_config_from_dict({"enabled_actions": ["non_existent_action"]})


def test_reject_negative_threshold():
    with pytest.raises(
        ValueError, match="Threshold ec2_idle_cpu_avg_pct must be a positive number"
    ):
        load_config_from_dict({"thresholds": {"ec2_idle_cpu_avg_pct": -1.0}})


def test_load_from_json_string():
    json_str = '{"dry_run": true, "grace_hours": 12}'
    cfg = load_config_from_json(json_str)
    assert cfg.dry_run is True
    assert cfg.grace_hours == 12


def test_reject_malformed_json():
    with pytest.raises(ValueError, match="Invalid JSON configuration"):
        load_config_from_json("{not valid json}")
