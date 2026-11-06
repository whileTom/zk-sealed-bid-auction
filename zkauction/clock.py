"""Injectable clock so phase logic is testable without sleeping."""
from datetime import datetime, timedelta, timezone


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FakeClock:
    """Test clock: starts at a fixed instant and only moves when told to."""

    def __init__(self, start: datetime = None):
        self._now = start or datetime(2030, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)
