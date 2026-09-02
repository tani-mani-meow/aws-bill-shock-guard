"""Fake clock for deterministic testing."""

from datetime import datetime, timedelta, timezone


class FakeClock:
    """Deterministic clock allowing time advances."""

    def __init__(self, initial_time: datetime | None = None):
        if initial_time is None:
            self._current = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        else:
            if initial_time.tzinfo is None:
                self._current = initial_time.replace(tzinfo=timezone.utc)
            else:
                self._current = initial_time.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._current

    def advance(self, seconds: float = 0, hours: float = 0, days: float = 0) -> datetime:
        delta = timedelta(seconds=seconds, hours=hours, days=days)
        self._current += delta
        return self._current

    def set(self, dt: datetime) -> None:
        if dt.tzinfo is None:
            self._current = dt.replace(tzinfo=timezone.utc)
        else:
            self._current = dt.astimezone(timezone.utc)
