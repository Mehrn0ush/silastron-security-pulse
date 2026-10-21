"""CVE List V5 official incremental indexes: delta.json and deltaLog.json.

Observed 2026-10-21:
- delta.json is the current change window (~680 bytes).
- deltaLog.json is the official catch-up log (~30 MB) and can exceed the
  bounded KEV/delta byte limit. When the log cannot be retrieved completely,
  the collector falls back to If-None-Match revalidation and still force-fetches
  IDs from the latest delta.json window.
"""

from __future__ import annotations

from dataclasses import dataclass

from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import CVE_DELTA_JSON_URL, CVE_DELTA_LOG_URL
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.http import Fetcher
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.jsonutil import load_bounded_json


@dataclass(frozen=True)
class DeltaIndex:
    changed_ids: frozenset[str]
    latest_fetch_time: str | None
    earliest_fetch_time: str | None
    retrieved_at: str
    content_sha256: str | None
    complete_since: bool


def fetch_delta_index(
    fetcher: Fetcher,
    config: PulseConfig,
    *,
    since: str | None,
) -> DeltaIndex | None:
    changed: set[str] = set()
    times: list[str] = []
    retrieved_at = None
    window_ok = False
    log_complete = False

    try:
        response = fetcher.get(CVE_DELTA_JSON_URL, max_bytes=min(config.max_kev_bytes, 2_000_000))
        payload = load_bounded_json(
            response.body,
            max_bytes=min(config.max_kev_bytes, 2_000_000),
            max_depth=config.max_json_depth,
            source="cvelistV5 delta.json",
        )
        window = parse_delta_window(payload)
        changed |= window
        fetch_time = payload.get("fetchTime") if isinstance(payload, dict) else None
        if isinstance(fetch_time, str):
            times.append(fetch_time)
        retrieved_at = response.retrieved_at
        window_ok = True
    except (FetchError, ValidationError):
        window_ok = False

    try:
        response = fetcher.get(CVE_DELTA_LOG_URL, max_bytes=config.max_kev_bytes)
        payload = load_bounded_json(
            response.body,
            max_bytes=config.max_kev_bytes,
            max_depth=config.max_json_depth,
            source="cvelistV5 deltaLog",
        )
        log = parse_delta_log(payload, since=since, retrieved_at=response.retrieved_at)
        changed |= set(log.changed_ids)
        if log.latest_fetch_time:
            times.append(log.latest_fetch_time)
        if log.earliest_fetch_time:
            times.append(log.earliest_fetch_time)
        retrieved_at = retrieved_at or log.retrieved_at
        log_complete = log.complete_since
    except (FetchError, ValidationError):
        log_complete = False

    if not window_ok and not times and not changed:
        return None
    times.sort()
    return DeltaIndex(
        changed_ids=frozenset(changed),
        latest_fetch_time=times[-1] if times else None,
        earliest_fetch_time=times[0] if times else None,
        retrieved_at=retrieved_at or "",
        content_sha256=None,
        complete_since=log_complete,
    )


def parse_delta_window(payload: object) -> set[str]:
    if not isinstance(payload, dict):
        raise ValidationError("delta.json must be a JSON object")
    return _ids_from_buckets(payload)


def parse_delta_log(payload: object, *, since: str | None, retrieved_at: str) -> DeltaIndex:
    if not isinstance(payload, list):
        raise ValidationError("deltaLog.json must be a JSON array")
    changed: set[str] = set()
    times: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        fetch_time = item.get("fetchTime")
        if isinstance(fetch_time, str):
            times.append(fetch_time)
            if since and fetch_time <= since:
                continue
        changed |= _ids_from_buckets(item)
    times.sort()
    earliest = times[0] if times else None
    latest = times[-1] if times else None
    complete_since = True
    if since:
        if not times or (earliest is not None and earliest > since):
            complete_since = False
    return DeltaIndex(
        changed_ids=frozenset(changed),
        latest_fetch_time=latest,
        earliest_fetch_time=earliest,
        retrieved_at=retrieved_at,
        content_sha256=None,
        complete_since=complete_since,
    )


def _ids_from_buckets(item: dict[str, object]) -> set[str]:
    changed: set[str] = set()
    for bucket in ("new", "updated"):
        rows = item.get(bucket) or []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                changed.add(parse_cve_id(row.get("cveId")))
            except ValidationError:
                continue
    return changed
