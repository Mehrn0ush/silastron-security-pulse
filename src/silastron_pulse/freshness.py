"""Compute snapshot freshness at evaluation time, not at promote time."""

from __future__ import annotations

from datetime import datetime, timezone

from silastron_pulse.clock import parse_generated_at
from silastron_pulse.errors import ValidationError


def freshness(
    *,
    generated_at: str,
    now: datetime,
    stale_after_hours: int,
) -> dict[str, object]:
    try:
        generated = parse_generated_at(generated_at)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    current = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    age_hours = (current - generated).total_seconds() / 3600.0
    if age_hours < 0:
        raise ValidationError("generated_at is in the future")
    stale = age_hours > stale_after_hours
    return {
        "stale": stale,
        "fresh": not stale,
        "age_hours": round(age_hours, 3),
        "stale_after_hours": stale_after_hours,
        "evaluated_at": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
