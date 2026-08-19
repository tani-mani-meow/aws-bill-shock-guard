"""Structured JSON logger writing single-line JSON records to stdout."""

import json
import sys
from datetime import datetime, timezone
from typing import Any


class JsonLogger:
    """JSON event logger with mandatory standardized fields."""

    def __init__(self, run_id: str = "default", region: str = "global"):
        self.run_id = run_id
        self.region = region

    def bind(self, run_id: str | None = None, region: str | None = None) -> "JsonLogger":
        return JsonLogger(
            run_id=run_id if run_id is not None else self.run_id,
            region=region if region is not None else self.region,
        )

    def _log(
        self,
        level: str,
        event: str,
        region: str | None = None,
        resource_key: str | None = None,
        **extra: Any,
    ) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "event": event,
            "region": region or self.region,
            "resource_key": resource_key or "",
            "run_id": self.run_id,
        }
        # Add extra fields (sanitize tokens or sensitive data)
        for k, v in extra.items():
            if "token" in k.lower() or "secret" in k.lower() or "password" in k.lower():
                continue
            record[k] = v

        try:
            line = json.dumps(record, separators=(",", ":"))
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except Exception:
            # Fallback if serialization fails
            sys.stdout.write(f'{{"event":"logging_error","run_id":"{self.run_id}"}}\n')
            sys.stdout.flush()

    def info(
        self,
        event: str,
        region: str | None = None,
        resource_key: str | None = None,
        **extra: Any,
    ) -> None:
        self._log("INFO", event, region=region, resource_key=resource_key, **extra)

    def warning(
        self,
        event: str,
        region: str | None = None,
        resource_key: str | None = None,
        **extra: Any,
    ) -> None:
        self._log("WARNING", event, region=region, resource_key=resource_key, **extra)

    def error(
        self,
        event: str,
        region: str | None = None,
        resource_key: str | None = None,
        **extra: Any,
    ) -> None:
        self._log("ERROR", event, region=region, resource_key=resource_key, **extra)
