"""Configuration model, validation, and JSON loading for Bill Shock Guard."""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from bill_shock_guard.models import ActionKind


@dataclass(frozen=True)
class Thresholds:
    ec2_idle_window_hours: int = 24
    ec2_idle_cpu_avg_pct: float = 5.0
    ec2_idle_network_avg_bytes_per_sec: int = 10000
    nat_idle_window_hours: int = 24
    ebs_unattached_days: int = 7
    elb_idle_window_hours: int = 168
    rds_idle_window_hours: int = 168


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool = False
    chat_id: str = ""
    token_ssm_param: str = ""


@dataclass(frozen=True)
class NotifyConfig:
    sns_topic_arn: str | None = None
    telegram: TelegramConfig = field(default_factory=TelegramConfig)


@dataclass(frozen=True)
class Config:
    dry_run: bool = True
    grace_hours: int = 24
    regions: list[str] = field(default_factory=lambda: ["*"])
    protect_tag_key: str = "bsg:keep"
    managed_tag_keys: list[str] = field(
        default_factory=lambda: [
            "aws:autoscaling:groupName",
            "eks:cluster-name",
            "aws:eks:cluster-name",
            "elasticbeanstalk:environment-name",
        ]
    )
    ignore_resource_ids: list[str] = field(default_factory=list)
    enabled_actions: list[ActionKind] = field(
        default_factory=lambda: [ActionKind.EC2_STOP, ActionKind.EIP_RELEASE]
    )
    max_actions_per_run: int = 5
    display_tz: str = "Asia/Kolkata"
    thresholds: Thresholds = field(default_factory=Thresholds)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    state_table: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # convert ActionKind enums to string
        data["enabled_actions"] = [a.value for a in self.enabled_actions]
        return data


_ALLOWED_ROOT_KEYS = {
    "dry_run",
    "grace_hours",
    "regions",
    "protect_tag_key",
    "managed_tag_keys",
    "ignore_resource_ids",
    "enabled_actions",
    "max_actions_per_run",
    "display_tz",
    "thresholds",
    "notify",
    "state_table",
}

_ALLOWED_THRESHOLDS_KEYS = {
    "ec2_idle_window_hours",
    "ec2_idle_cpu_avg_pct",
    "ec2_idle_network_avg_bytes_per_sec",
    "nat_idle_window_hours",
    "ebs_unattached_days",
    "elb_idle_window_hours",
    "rds_idle_window_hours",
}

_ALLOWED_NOTIFY_KEYS = {"sns_topic_arn", "telegram"}
_ALLOWED_TELEGRAM_KEYS = {"enabled", "chat_id", "token_ssm_param"}


def load_config_from_dict(raw: dict[str, Any]) -> Config:
    """Validate and build Config from a raw dictionary."""
    if not isinstance(raw, dict):
        raise ValueError("Config must be a JSON object")

    unknown_keys = set(raw.keys()) - _ALLOWED_ROOT_KEYS
    if unknown_keys:
        raise ValueError(f"Unknown config keys: {sorted(unknown_keys)}")

    # dry_run: must be a strict bool
    dry_run = raw.get("dry_run", True)
    if not isinstance(dry_run, bool):
        raise ValueError(f"dry_run must be a boolean, got {type(dry_run).__name__}: {dry_run!r}")

    # grace_hours: >= 1
    grace_hours = raw.get("grace_hours", 24)
    if not isinstance(grace_hours, int) or grace_hours < 1:
        raise ValueError(f"grace_hours must be an integer >= 1, got {grace_hours!r}")

    # regions: ["*"] or list of non-empty strings
    regions = raw.get("regions", ["*"])
    if not isinstance(regions, list) or not regions:
        raise ValueError("regions must be a non-empty list of region names or ['*']")
    for r in regions:
        if not isinstance(r, str) or not r.strip():
            raise ValueError(f"Invalid region entry: {r!r}")

    # protect_tag_key
    protect_tag_key = raw.get("protect_tag_key", "bsg:keep")
    if not isinstance(protect_tag_key, str) or not protect_tag_key.strip():
        raise ValueError("protect_tag_key must be a non-empty string")

    # managed_tag_keys
    managed_tag_keys = raw.get(
        "managed_tag_keys",
        [
            "aws:autoscaling:groupName",
            "eks:cluster-name",
            "aws:eks:cluster-name",
            "elasticbeanstalk:environment-name",
        ],
    )
    if not isinstance(managed_tag_keys, list):
        raise ValueError("managed_tag_keys must be a list of string tag keys")
    for k in managed_tag_keys:
        if not isinstance(k, str) or not k.strip():
            raise ValueError(f"Invalid managed_tag_key entry: {k!r}")

    # ignore_resource_ids
    ignore_resource_ids = raw.get("ignore_resource_ids", [])
    if not isinstance(ignore_resource_ids, list):
        raise ValueError("ignore_resource_ids must be a list of string resource IDs")
    for rid in ignore_resource_ids:
        if not isinstance(rid, str) or not rid.strip():
            raise ValueError(f"Invalid ignore_resource_ids entry: {rid!r}")

    # enabled_actions: list of valid ActionKind
    raw_actions = raw.get("enabled_actions", ["ec2_stop", "eip_release"])
    if not isinstance(raw_actions, list):
        raise ValueError("enabled_actions must be a list of action kind strings")
    valid_actions = {a.value for a in ActionKind}
    enabled_actions: list[ActionKind] = []
    for a in raw_actions:
        if a not in valid_actions:
            raise ValueError(
                f"Invalid action kind {a!r} in enabled_actions. Valid: {sorted(valid_actions)}"
            )
        enabled_actions.append(ActionKind(a))

    # max_actions_per_run: >= 0
    max_actions = raw.get("max_actions_per_run", 5)
    if not isinstance(max_actions, int) or max_actions < 0:
        raise ValueError(f"max_actions_per_run must be an integer >= 0, got {max_actions!r}")

    # display_tz
    display_tz = raw.get("display_tz", "Asia/Kolkata")
    if not isinstance(display_tz, str) or not display_tz.strip():
        raise ValueError("display_tz must be a non-empty string")

    # thresholds
    raw_thresh = raw.get("thresholds", {})
    if not isinstance(raw_thresh, dict):
        raise ValueError("thresholds must be a JSON object")
    unknown_thresh = set(raw_thresh.keys()) - _ALLOWED_THRESHOLDS_KEYS
    if unknown_thresh:
        raise ValueError(f"Unknown thresholds keys: {sorted(unknown_thresh)}")

    ec2_idle_window_hours = raw_thresh.get("ec2_idle_window_hours", 24)
    ec2_idle_cpu_avg_pct = raw_thresh.get("ec2_idle_cpu_avg_pct", 5.0)
    ec2_idle_network_avg_bytes_per_sec = raw_thresh.get("ec2_idle_network_avg_bytes_per_sec", 10000)
    nat_idle_window_hours = raw_thresh.get("nat_idle_window_hours", 24)
    ebs_unattached_days = raw_thresh.get("ebs_unattached_days", 7)
    elb_idle_window_hours = raw_thresh.get("elb_idle_window_hours", 168)
    rds_idle_window_hours = raw_thresh.get("rds_idle_window_hours", 168)

    for name, val in [
        ("ec2_idle_window_hours", ec2_idle_window_hours),
        ("ec2_idle_cpu_avg_pct", ec2_idle_cpu_avg_pct),
        ("ec2_idle_network_avg_bytes_per_sec", ec2_idle_network_avg_bytes_per_sec),
        ("nat_idle_window_hours", nat_idle_window_hours),
        ("ebs_unattached_days", ebs_unattached_days),
        ("elb_idle_window_hours", elb_idle_window_hours),
        ("rds_idle_window_hours", rds_idle_window_hours),
    ]:
        if not isinstance(val, (int, float)) or val <= 0:
            raise ValueError(f"Threshold {name} must be a positive number, got {val!r}")

    thresholds = Thresholds(
        ec2_idle_window_hours=int(ec2_idle_window_hours),
        ec2_idle_cpu_avg_pct=float(ec2_idle_cpu_avg_pct),
        ec2_idle_network_avg_bytes_per_sec=int(ec2_idle_network_avg_bytes_per_sec),
        nat_idle_window_hours=int(nat_idle_window_hours),
        ebs_unattached_days=int(ebs_unattached_days),
        elb_idle_window_hours=int(elb_idle_window_hours),
        rds_idle_window_hours=int(rds_idle_window_hours),
    )

    # notify
    raw_notify = raw.get("notify", {})
    if not isinstance(raw_notify, dict):
        raise ValueError("notify must be a JSON object")
    unknown_notify = set(raw_notify.keys()) - _ALLOWED_NOTIFY_KEYS
    if unknown_notify:
        raise ValueError(f"Unknown notify keys: {sorted(unknown_notify)}")

    sns_arn = raw_notify.get("sns_topic_arn")
    if sns_arn is not None and not (isinstance(sns_arn, str) and sns_arn.strip()):
        raise ValueError(f"sns_topic_arn must be null or a non-empty string, got {sns_arn!r}")

    raw_tg = raw_notify.get("telegram", {})
    if not isinstance(raw_tg, dict):
        raise ValueError("telegram config must be a JSON object")
    unknown_tg = set(raw_tg.keys()) - _ALLOWED_TELEGRAM_KEYS
    if unknown_tg:
        raise ValueError(f"Unknown telegram keys: {sorted(unknown_tg)}")

    tg_enabled = raw_tg.get("enabled", False)
    if not isinstance(tg_enabled, bool):
        raise ValueError(f"telegram.enabled must be a boolean, got {tg_enabled!r}")
    tg_chat_id = str(raw_tg.get("chat_id", ""))
    tg_param = str(raw_tg.get("token_ssm_param", ""))

    telegram = TelegramConfig(
        enabled=tg_enabled,
        chat_id=tg_chat_id,
        token_ssm_param=tg_param,
    )
    notify = NotifyConfig(sns_topic_arn=sns_arn, telegram=telegram)

    # state_table
    state_table = raw.get("state_table")
    if state_table is not None and not (isinstance(state_table, str) and state_table.strip()):
        raise ValueError(f"state_table must be null or a non-empty string, got {state_table!r}")

    return Config(
        dry_run=dry_run,
        grace_hours=grace_hours,
        regions=regions,
        protect_tag_key=protect_tag_key,
        managed_tag_keys=managed_tag_keys,
        ignore_resource_ids=ignore_resource_ids,
        enabled_actions=enabled_actions,
        max_actions_per_run=max_actions,
        display_tz=display_tz,
        thresholds=thresholds,
        notify=notify,
        state_table=state_table,
    )


def load_config_from_json(json_str: str) -> Config:
    """Parse JSON string and return validated Config."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON configuration: {exc}") from exc
    return load_config_from_dict(data)


def load_config_from_file(path: Path | str) -> Config:
    """Read a JSON file from disk and return validated Config."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Config file not found: {p}")
    content = p.read_text(encoding="utf-8")
    return load_config_from_json(content)
