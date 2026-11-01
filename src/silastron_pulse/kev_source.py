"""Collect-time CISA KEV source integrity.

The candidate-to-bundled-catalog check is internal consistency only. This
module independently validates that the collected catalog came from the
documented CISA feed, that the HTTP payload is well-formed, and that the
parsed records match the original downloaded bytes.

CISA does not publish an independent checksum of this feed. The
cisagov/kev-data git mirror is a convenience copy of the same source and is
not used as corroboration. HTTPS transport integrity is not cryptographic
authentication of CISA's content.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from silastron_pulse.constants import KEV_JSON_URL
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.http import FetchResult
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.jsonutil import load_bounded_json, sha256_bytes

KEV_SOURCE_SCHEMA_VERSION = "1.0.0"
KEV_JSON_HOSTS = frozenset({"www.cisa.gov", "cisa.gov"})
KEV_JSON_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ALLOWED_KEV_CONTENT_TYPES = frozenset({"application/json", "text/json"})
# CISA has served the JSON feed as text/plain. Accept only when the body is JSON.
CONDITIONAL_KEV_CONTENT_TYPES = frozenset({"text/plain"})
REJECTED_KEV_CONTENT_TYPES = frozenset(
    {"text/html", "application/xhtml+xml", "text/xml", "application/xml"}
)
KEV_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KEV_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
PUBLISHER_AUTHENTICATION = "not_available"
INDEPENDENT_CHECKSUM = "none_published_by_cisa"
PROVENANCE_NOTE = (
    "HTTPS transport integrity is not cryptographic authentication of CISA "
    "content. CISA does not publish an independent checksum of this feed. "
    "The cisagov/kev-data git mirror is not used as independent verification."
)


def validate_kev_fetch(result: FetchResult, *, max_bytes: int) -> None:
    """Fail closed on a KEV response that is not the documented CISA feed."""
    if result.status_code != 200:
        raise FetchError(
            f"KEV collection failed: HTTP {result.status_code}",
            status_code=result.status_code,
        )
    if result.requested_url != KEV_JSON_URL:
        raise ValidationError(
            f"KEV was not fetched from the authoritative CISA URL {KEV_JSON_URL}"
        )
    _assert_authoritative_url(result.final_url, label="final KEV URL")
    if not result.body:
        raise ValidationError("KEV response body is empty")
    if len(result.body) > max_bytes:
        raise ValidationError(
            f"KEV response exceeds the configured size limit of {max_bytes} bytes"
        )
    content_type = (result.content_type or "").split(";")[0].strip().lower()
    if content_type in REJECTED_KEV_CONTENT_TYPES:
        raise ValidationError(f"KEV content type {content_type!r} is not JSON")
    if content_type in CONDITIONAL_KEV_CONTENT_TYPES:
        if not _looks_like_json_object(result.body):
            raise ValidationError(
                f"KEV content type {content_type!r} is allowed only for a JSON object body"
            )
    elif content_type not in ALLOWED_KEV_CONTENT_TYPES:
        if content_type:
            raise ValidationError(f"KEV content type {content_type!r} is not an allowed JSON type")
        if not _looks_like_json_object(result.body):
            raise ValidationError("KEV response is missing a JSON content type and is not a JSON object")
    if result.body.lstrip().startswith(b"<"):
        raise ValidationError("KEV response looks like HTML or XML, not the CISA JSON catalog")
    declared = result.content_length
    if isinstance(declared, int) and declared > max_bytes:
        raise ValidationError(
            f"KEV Content-Length {declared} exceeds the configured size limit of {max_bytes} bytes"
        )
    if isinstance(declared, int) and declared > 0 and declared <= max_bytes:
        if len(result.body) < declared:
            raise ValidationError(
                f"KEV response was truncated: received {len(result.body)} bytes, "
                f"Content-Length declared {declared}"
            )


def validate_kev_catalog_metadata(payload: dict[str, Any]) -> None:
    """Validate catalog-level fields that parse_kev_catalog also relies on."""
    catalog_version = payload.get("catalogVersion")
    date_released = payload.get("dateReleased")
    if not isinstance(catalog_version, str) or not catalog_version.strip():
        raise ValidationError("KEV catalogVersion is missing or not a string")
    if not isinstance(date_released, str) or not date_released.strip():
        raise ValidationError("KEV dateReleased is missing or not a string")
    require_kev_datetime(date_released, label="dateReleased")


def require_kev_date(value: str, *, label: str) -> str:
    if not KEV_DATE_RE.fullmatch(value):
        raise ValidationError(f"KEV {label} {value!r} is not a YYYY-MM-DD date")
    _assert_calendar_date(value, label=label)
    return value


def require_kev_datetime(value: str, *, label: str) -> str:
    if not KEV_DATETIME_RE.fullmatch(value):
        raise ValidationError(f"KEV {label} {value!r} is not an RFC3339 / ISO-8601 timestamp")
    _assert_calendar_date(value[:10], label=label)
    return value


def assert_catalog_matches_raw(
    catalog: Any,
    *,
    raw: bytes,
    payload: dict[str, Any],
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    """Compare the parsed catalog to a fresh parse of the original bytes."""
    replay = load_bounded_json(
        raw, max_bytes=max_bytes, max_depth=max_depth, source="CISA KEV raw replay"
    )
    if not isinstance(replay, dict):
        raise ValidationError("KEV raw payload is not a JSON object")
    if replay != payload:
        raise ValidationError(
            "Parsed KEV catalog does not match a fresh parse of the original downloaded payload"
        )
    raw_digest = sha256_bytes(raw)
    if catalog.meta.content_sha256 != raw_digest:
        raise ValidationError("KEV catalog content digest does not match the original response bytes")
    replay_version = replay.get("catalogVersion")
    replay_released = replay.get("dateReleased")
    replay_count = replay.get("count")
    replay_items = replay.get("vulnerabilities")
    if replay_version != catalog.meta.source_revision:
        raise ValidationError("KEV catalogVersion changed between download and parse")
    if replay_released != catalog.meta.source_published_at:
        raise ValidationError("KEV dateReleased changed between download and parse")
    if not isinstance(replay_items, list):
        raise ValidationError("KEV raw payload vulnerabilities is not an array")
    if not isinstance(replay_count, int) or isinstance(replay_count, bool):
        raise ValidationError("KEV raw payload count is not an integer")
    if replay_count != len(replay_items):
        raise ValidationError(
            f"KEV raw count {replay_count} does not match vulnerabilities length {len(replay_items)}"
        )
    raw_ids: list[str] = []
    seen: set[str] = set()
    identical_duplicates = 0
    for index, item in enumerate(replay_items):
        if not isinstance(item, dict):
            raise ValidationError(f"KEV raw vulnerabilities[{index}] is not an object")
        try:
            cve_id = parse_cve_id(item.get("cveID"))
        except ValidationError as exc:
            raise ValidationError(f"KEV raw vulnerabilities[{index}] {exc}") from exc
        if cve_id in seen:
            identical_duplicates += 1
            continue
        seen.add(cve_id)
        raw_ids.append(cve_id)
    parsed_ids = [record.cve_id for record in catalog.records]
    if sorted(raw_ids) != sorted(parsed_ids):
        raise ValidationError(
            "Parsed KEV CVE identifiers do not match the original downloaded payload"
        )
    if len(parsed_ids) != len(set(parsed_ids)):
        raise ValidationError("Parsed KEV catalog contains duplicate CVE identifiers")
    return {
        "raw_record_count": len(replay_items),
        "parsed_unique_records": len(parsed_ids),
        "identical_duplicate_records": identical_duplicates,
        "content_sha256": raw_digest,
        "catalog_version": catalog.meta.source_revision,
        "date_released": catalog.meta.source_published_at,
        "declared_count": replay_count,
    }


def build_kev_provenance(
    result: FetchResult,
    *,
    match: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": KEV_SOURCE_SCHEMA_VERSION,
        "source": "cisa-kev",
        "requested_url": result.requested_url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "body_bytes": len(result.body),
        "content_sha256": match["content_sha256"],
        "retrieved_at": result.retrieved_at,
        "catalog_version": match["catalog_version"],
        "date_released": match["date_released"],
        "declared_count": match["declared_count"],
        "raw_record_count": match["raw_record_count"],
        "parsed_unique_records": match["parsed_unique_records"],
        "identical_duplicate_records": match["identical_duplicate_records"],
        "verification": {
            "transport": "https",
            "structural_consistency": True,
            "parsed_matches_raw": True,
            "publisher_authentication": PUBLISHER_AUTHENTICATION,
            "independent_checksum": INDEPENDENT_CHECKSUM,
            "note": PROVENANCE_NOTE,
        },
    }


def validate_kev_provenance(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("KEV provenance must be a JSON object")
    if payload.get("source") != "cisa-kev":
        raise ValidationError("KEV provenance source is not cisa-kev")
    if payload.get("requested_url") != KEV_JSON_URL:
        raise ValidationError("KEV provenance requested_url is not the authoritative CISA URL")
    digest = payload.get("content_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValidationError("KEV provenance content_sha256 is not a SHA-256 hex digest")
    for key in ("retrieved_at", "catalog_version"):
        if not isinstance(payload.get(key), str) or not str(payload.get(key)).strip():
            raise ValidationError(f"KEV provenance {key} is missing")
    for key in ("declared_count", "raw_record_count", "parsed_unique_records"):
        value = payload.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValidationError(f"KEV provenance {key} is not a positive integer")
    verification = payload.get("verification")
    if not isinstance(verification, dict):
        raise ValidationError("KEV provenance verification is missing")
    if verification.get("publisher_authentication") != PUBLISHER_AUTHENTICATION:
        raise ValidationError("KEV provenance must not claim publisher authentication")
    if verification.get("independent_checksum") != INDEPENDENT_CHECKSUM:
        raise ValidationError("KEV provenance must not invent an independent checksum")
    if verification.get("parsed_matches_raw") is not True:
        raise ValidationError("KEV provenance does not record a parsed-vs-raw match")
    return payload


def _looks_like_json_object(body: bytes) -> bool:
    stripped = body.lstrip()
    return bool(stripped) and stripped[:1] == b"{"


def _assert_authoritative_url(url: str, *, label: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValidationError(f"{label} is not HTTPS")
    host = (parsed.hostname or "").lower()
    if host not in KEV_JSON_HOSTS:
        raise ValidationError(f"{label} host {host!r} is not an authoritative CISA host")
    path = parsed.path.rstrip("/")
    if path != KEV_JSON_PATH:
        raise ValidationError(f"{label} path is not the documented KEV JSON feed")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValidationError(f"{label} must not include credentials, query, or fragment")


def _assert_calendar_date(value: str, *, label: str) -> None:
    try:
        datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValidationError(f"KEV {label} {value!r} is not a real calendar date") from exc
