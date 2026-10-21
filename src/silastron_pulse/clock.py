"""Injectable clock for deterministic tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol


def format_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_generated_at(value: str) -> datetime:
    parsed = parse_source_timestamp(value)
    if parsed is None:
        raise ValueError(f"Invalid generated_at timestamp: {value!r}")
    return parsed


def parse_source_timestamp(value: str | None) -> datetime | None:
    """Parse official source timestamps, including fractional UTC fetchTime values."""
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class Clock(Protocol):
    def now(self) -> datetime:
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FrozenClock:
    def __init__(self, instant: datetime) -> None:
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        self._instant = instant.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._instant

    def advance(self, seconds: float) -> None:
        self._instant = self._instant + timedelta(seconds=seconds)


class SteppingClock:
    """Advance on each now() call so start and completion timestamps differ."""

    def __init__(self, instant: datetime, *, step_seconds: float = 1.0) -> None:
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        self._instant = instant.astimezone(timezone.utc)
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> datetime:
        current = self._instant
        self._instant = self._instant + self._step
        return current
