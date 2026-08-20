"""Protection logic to safeguard resources against accidental modification or deletion."""

import re
from datetime import date, datetime, timezone
from typing import Mapping

from bill_shock_guard.config import Config

_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def is_protected(
    tags: Mapping[str, str] | None,
    resource_id: str,
    config: Config,
    now: datetime,
) -> tuple[bool, str | None]:
    """Determine whether a resource is protected from any action.

    Returns:
        (is_protected, reason_if_protected)
    """
    # Invariant I3: explicit ignore ID list
    if resource_id in config.ignore_resource_ids:
        return True, f"Resource ID {resource_id} is in ignore_resource_ids"

    if tags is None:
        tags = {}

    # Managed tags (e.g. ASG, EKS, Elastic Beanstalk)
    for managed_key in config.managed_tag_keys:
        if managed_key in tags and tags[managed_key] is not None:
            return True, f"Managed by external service via tag {managed_key}={tags[managed_key]}"

    # Protect tag check
    protect_key = config.protect_tag_key
    if protect_key in tags:
        raw_val = tags[protect_key].strip()
        lower_val = raw_val.lower()

        if lower_val == "true":
            return True, f"Protected indefinitely by tag {protect_key}=true"

        if lower_val == "false":
            return False, None

        # Check date format YYYY-MM-DD
        if _DATE_PATTERN.match(raw_val):
            try:
                exp_date = date.fromisoformat(raw_val)
                # UTC date of 'now'
                now_utc_date = now.astimezone(timezone.utc).date()
                if now_utc_date <= exp_date:
                    return (
                        True,
                        f"Protected by tag {protect_key}={raw_val} until {raw_val} (inclusive)",
                    )
                else:
                    return (
                        False,
                        f"Protection tag {protect_key}={raw_val} expired on {raw_val}",
                    )
            except ValueError:
                # Malformed calendar date like 2026-02-30 -> Fail closed!
                return (
                    True,
                    f"Invalid keep tag date value {raw_val!r} (fail closed: protected)",
                )

        # Unrecognized value (not true, not false, not YYYY-MM-DD) -> Fail closed!
        return (
            True,
            f"Invalid keep tag format {raw_val!r} (fail closed: protected)",
        )

    return False, None
