"""CVE List V5 official incremental indexes: delta.json and deltaLog.json.

Measured 2026-10-21 against live cvelistV5:

- git clone of the full repository is ~3.02 GB (GitHub size 3,162,116 KB).
- Midnight release zip is 639.61 MB and includes every CVE, not the KEV subset.
- Hourly delta zips are ~0.4–0.5 MB but only cover since midnight and have
  documented race conditions (cvelistV5#40).
- delta.json is the current ~7-minute window (4,123 bytes) and is not a
  historical catch-up log.
- deltaLog.json is the official rolling ~30-day catch-up index
  (~29.88 MB uncompressed). HEAD without gzip reports that uncompressed
  Content-Length so oversized skip stays conservative. GET uses gzip
  (~1.73 MB wire / ~4.2s vs ~228s identity). Parse still covers every
  window after the stored fetchTime. KEV ∩ changed was 7 IDs in 24h and
  160 in 30 days.

HEAD is used to skip GET when uncompressed Content-Length exceeds the
configured bound or when a previous skip recorded the same ETag. The log
body is never stored.
"""

from __future__ import annotations

from dataclasses import dataclass

from datetime import datetime

from silastron_pulse.clock import parse_source_timestamp
from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import CVE_DELTA_JSON_URL, CVE_DELTA_LOG_URL
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.http import Fetcher
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.jsonutil import load_bounded_json, sha256_bytes


@dataclass(frozen=True)
class DeltaIndex:
    changed_ids: frozenset[str]
    latest_fetch_time: str | None
    earliest_fetch_time: str | None
    retrieved_at: str
    content_sha256: str | None
    complete_since: bool
    etag: str | None = None
    content_length: int | None = None
    skipped: bool = False
    reason: str | None = None


def fetch_latest_window(fetcher: Fetcher, config: PulseConfig) -> DeltaIndex | None:
    try:
        response = fetcher.get(
            CVE_DELTA_JSON_URL, max_bytes=min(config.max_cve_bytes, 2_000_000)
        )
        payload = load_bounded_json(
            response.body,
            max_bytes=min(config.max_cve_bytes, 2_000_000),
            max_depth=config.max_json_depth,
            source="cvelistV5 delta.json",
        )
        changed = parse_delta_window(payload)
        fetch_time = payload.get("fetchTime") if isinstance(payload, dict) else None
        if not isinstance(fetch_time, str):
            fetch_time = None
        return DeltaIndex(
            changed_ids=frozenset(changed),
            latest_fetch_time=fetch_time,
            earliest_fetch_time=fetch_time,
            retrieved_at=response.retrieved_at,
            content_sha256=sha256_bytes(response.body),
            complete_since=True,
            etag=response.etag,
            content_length=len(response.body),
        )
    except (FetchError, ValidationError):
        return None


def fetch_delta_log(
    fetcher: Fetcher,
    config: PulseConfig,
    *,
    since: str | None,
    previous_etag: str | None = None,
    previous_bytes: int | None = None,
    previous_skipped: bool = False,
) -> DeltaIndex:
    """Load deltaLog.json only when it fits the configured byte bound."""
    try:
        head = fetcher.head(CVE_DELTA_LOG_URL)
    except FetchError as exc:
        if previous_skipped and previous_bytes and previous_bytes > config.max_delta_bytes:
            return DeltaIndex(
                changed_ids=frozenset(),
                latest_fetch_time=None,
                earliest_fetch_time=None,
                retrieved_at="",
                content_sha256=None,
                complete_since=False,
                etag=previous_etag,
                content_length=previous_bytes,
                skipped=True,
                reason=f"deltaLog HEAD failed after previous oversized skip: {exc}",
            )
        return DeltaIndex(
            changed_ids=frozenset(),
            latest_fetch_time=None,
            earliest_fetch_time=None,
            retrieved_at="",
            content_sha256=None,
            complete_since=False,
            skipped=True,
            reason=f"deltaLog HEAD failed: {exc}",
        )

    length = head.content_length
    if length is None:
        length = previous_bytes
    if length is not None and length > config.max_delta_bytes:
        return DeltaIndex(
            changed_ids=frozenset(),
            latest_fetch_time=None,
            earliest_fetch_time=None,
            retrieved_at=head.retrieved_at,
            content_sha256=None,
            complete_since=False,
            etag=head.etag,
            content_length=length,
            skipped=True,
            reason=(
                f"deltaLog.json is {length} bytes which exceeds max_delta_bytes "
                f"{config.max_delta_bytes}; refusing to download"
            ),
        )
    if (
        previous_skipped
        and previous_etag
        and head.etag
        and previous_etag == head.etag
        and previous_bytes
        and previous_bytes > config.max_delta_bytes
    ):
        return DeltaIndex(
            changed_ids=frozenset(),
            latest_fetch_time=None,
            earliest_fetch_time=None,
            retrieved_at=head.retrieved_at,
            content_sha256=None,
            complete_since=False,
            etag=head.etag,
            content_length=previous_bytes,
            skipped=True,
            reason="deltaLog.json still exceeds max_delta_bytes; not re-downloaded",
        )

    try:
        response = fetcher.get(CVE_DELTA_LOG_URL, max_bytes=config.max_delta_bytes)
    except FetchError as exc:
        return DeltaIndex(
            changed_ids=frozenset(),
            latest_fetch_time=None,
            earliest_fetch_time=None,
            retrieved_at=head.retrieved_at,
            content_sha256=None,
            complete_since=False,
            etag=head.etag,
            content_length=length,
            skipped=True,
            reason=f"deltaLog GET failed: {exc}",
        )
    try:
        payload = load_bounded_json(
            response.body,
            max_bytes=config.max_delta_bytes,
            max_depth=config.max_json_depth,
            source="cvelistV5 deltaLog",
        )
        parsed = parse_delta_log(payload, since=since, retrieved_at=response.retrieved_at)
        return DeltaIndex(
            changed_ids=parsed.changed_ids,
            latest_fetch_time=parsed.latest_fetch_time,
            earliest_fetch_time=parsed.earliest_fetch_time,
            retrieved_at=parsed.retrieved_at,
            content_sha256=sha256_bytes(response.body),
            complete_since=parsed.complete_since,
            etag=response.etag or head.etag,
            content_length=len(response.body),
            skipped=False,
        )
    except ValidationError as exc:
        return DeltaIndex(
            changed_ids=frozenset(),
            latest_fetch_time=None,
            earliest_fetch_time=None,
            retrieved_at=response.retrieved_at,
            content_sha256=None,
            complete_since=False,
            etag=response.etag,
            content_length=len(response.body),
            skipped=True,
            reason=str(exc),
        )


def parse_delta_window(payload: object) -> set[str]:
    if not isinstance(payload, dict):
        raise ValidationError("delta.json must be a JSON object")
    return _ids_from_buckets(payload)


def parse_fetch_time(value: str | None) -> datetime | None:
    return parse_source_timestamp(value)


def compare_fetch_times(current: str | None, stored: str | None) -> str:
    """Order current delta.json fetchTime relative to the stored watermark."""
    current_dt = parse_fetch_time(current)
    stored_dt = parse_fetch_time(stored)
    if current_dt is None or stored_dt is None:
        return "invalid"
    if current_dt == stored_dt:
        return "equal"
    if current_dt > stored_dt:
        return "newer"
    return "older"


def parse_delta_log(payload: object, *, since: str | None, retrieved_at: str) -> DeltaIndex:
    if not isinstance(payload, list):
        raise ValidationError("deltaLog.json must be a JSON array")
    changed: set[str] = set()
    parsed_times: list[tuple[datetime, str]] = []
    since_dt = parse_fetch_time(since)
    for item in payload:
        if not isinstance(item, dict):
            continue
        fetch_time = item.get("fetchTime") if isinstance(item.get("fetchTime"), str) else None
        fetch_dt = parse_fetch_time(fetch_time)
        if fetch_dt is not None and fetch_time is not None:
            parsed_times.append((fetch_dt, fetch_time))
            # The stored watermark is the last fully processed window. Skip it
            # and older windows. Include later windows, including duplicates.
            if since_dt is not None and fetch_dt <= since_dt:
                continue
        changed |= _ids_from_buckets(item)
    parsed_times.sort(key=lambda pair: pair[0])
    earliest = parsed_times[0][1] if parsed_times else None
    latest = parsed_times[-1][1] if parsed_times else None
    complete_since = True
    if since:
        if since_dt is None or not parsed_times or parsed_times[0][0] > since_dt:
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
    for bucket in ("new", "updated", "error"):
        rows = item.get(bucket) or []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, str):
                try:
                    changed.add(parse_cve_id(row))
                except ValidationError:
                    continue
                continue
            if not isinstance(row, dict):
                continue
            try:
                changed.add(parse_cve_id(row.get("cveId")))
            except ValidationError:
                continue
    return changed
