"""Injectable clock protocol and implementations for deterministic time handling."""

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    """Protocol for getting current timezone-aware UTC datetime."""

    def now(self) -> datetime:
        """Return the current timezone-aware datetime in UTC."""
        ...


class SystemClock:
    """Production system clock that returns current UTC time."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)
