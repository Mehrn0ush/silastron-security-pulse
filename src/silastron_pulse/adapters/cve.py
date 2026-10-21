"""CVE List V5 enrichment for selected KEV identifiers only.

Initial sync fetches the KEV subset from raw GitHub (not the 640 MB midnight
zip or 3 GB git clone). Incremental sync uses official delta.json identity
plus deltaLog.json catch-up. Per-CVE If-None-Match of the full KEV set is not
the scheduled path. Incomplete catch-up fails closed instead of publishing
unverified cache.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any

from silastron_pulse.adapters.delta import (
    compare_fetch_times,
    fetch_delta_log,
    fetch_latest_window,
    parse_fetch_time,
)
from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import CVE_PARSER_VERSION, MITRE_CVE_ATTRIBUTION
from silastron_pulse.errors import CorrelationError, FetchError, ValidationError
from silastron_pulse.http import Fetcher
from silastron_pulse.ids import cvelist_v5_raw_url, parse_cve_id, same_cve_id
from silastron_pulse.jsonutil import load_bounded_json, sha256_bytes
from silastron_pulse.models import CveProduct, CveRecord, CveSeverity, SourceMeta
from silastron_pulse.sanitize import authoritative_cve_url, clean_text_report

MAX_VERSIONS_PER_PRODUCT = 12


@dataclass(frozen=True)
class CveEnrichment:
    meta: SourceMeta
    records: dict[str, CveRecord]
    strategy: str = "full"
    delta_fetch_time: str | None = None
    fetched_ids: tuple[str, ...] = ()
    reused_ids: tuple[str, ...] = ()
    delta_log_etag: str | None = None
    delta_log_bytes: int | None = None
    delta_log_skipped: bool = False
    delta_sha256: str | None = None
    delta_log_sha256: str | None = None


def enrich_cves(
    cve_ids: list[str],
    fetcher: Fetcher,
    config: PulseConfig,
    *,
    cache_index: dict[str, Any] | None = None,
    cached_records: dict[str, dict[str, Any]] | None = None,
) -> CveEnrichment:
    unique_ids = sorted({parse_cve_id(cve_id) for cve_id in cve_ids})
    if len(unique_ids) > config.max_cve_enrichments:
        raise ValidationError(
            f"CVE enrichment requested {len(unique_ids)} IDs; max is {config.max_cve_enrichments}"
        )
    cache_index = cache_index or {}
    cached_records = cached_records or {}
    index_records = cache_index.get("records") if isinstance(cache_index.get("records"), dict) else {}
    since = cache_index.get("delta_fetch_time") if isinstance(cache_index.get("delta_fetch_time"), str) else None
    stored_delta_sha = (
        cache_index.get("delta_sha256") if isinstance(cache_index.get("delta_sha256"), str) else None
    )
    window = fetch_latest_window(fetcher, config)
    log = None
    strategy = "full"
    incomplete_reason: str | None = None
    changed_ids: frozenset[str] = frozenset()

    if index_records:
        if window is None or not window.latest_fetch_time:
            strategy = "failed"
            incomplete_reason = "CVE List V5 delta.json is unavailable; refusing incomplete CVE sync"
        elif not since:
            strategy = "resync"
        else:
            order = compare_fetch_times(window.latest_fetch_time, since)
            if order == "invalid":
                strategy = "failed"
                incomplete_reason = "CVE List V5 fetchTime is unparseable; refusing incomplete CVE sync"
            elif order == "older":
                strategy = "failed"
                incomplete_reason = (
                    "CVE List V5 delta.json fetchTime is older than the stored watermark; "
                    "refusing a stale identity that could hide later CVE changes"
                )
            elif order == "equal":
                if stored_delta_sha and window.content_sha256 == stored_delta_sha:
                    strategy = "unchanged"
                    changed_ids = frozenset()
                else:
                    # Same fetchTime can still list different IDs if the window
                    # was rewritten. Apply this window; do not skip on time alone.
                    strategy = "delta"
                    changed_ids = window.changed_ids
            else:
                log = fetch_delta_log(
                    fetcher,
                    config,
                    since=since,
                    previous_etag=cache_index.get("delta_log_etag")
                    if isinstance(cache_index.get("delta_log_etag"), str)
                    else None,
                    previous_bytes=cache_index.get("delta_log_bytes")
                    if isinstance(cache_index.get("delta_log_bytes"), int)
                    else None,
                    previous_skipped=bool(cache_index.get("delta_log_skipped")),
                )
                if log.skipped:
                    strategy = "failed"
                    incomplete_reason = log.reason or (
                        "CVE List V5 deltaLog.json is incomplete; refusing to treat cached CVE records as current"
                    )
                elif not log.complete_since:
                    earliest_dt = parse_fetch_time(log.earliest_fetch_time)
                    since_dt = parse_fetch_time(since)
                    if earliest_dt is not None and since_dt is not None and earliest_dt > since_dt:
                        strategy = "resync"
                    else:
                        strategy = "failed"
                        incomplete_reason = log.reason or (
                            "CVE List V5 deltaLog.json does not cover the stored fetchTime"
                        )
                else:
                    strategy = "delta"
                    changed_ids = log.changed_ids | window.changed_ids

    if strategy == "failed":
        return _failed_enrichment(
            unique_ids,
            incomplete_reason or "CVE synchronization is incomplete",
            window=window,
            log=log,
        )

    to_fetch: dict[str, str | None] = {}
    reused: dict[str, CveRecord] = {}
    for cve_id in unique_ids:
        cached = cached_records.get(cve_id)
        if strategy in {"full", "resync"} or cached is None or (cached or {}).get("status") != "ok":
            to_fetch[cve_id] = None
            continue
        if strategy == "delta" and cve_id in changed_ids:
            to_fetch[cve_id] = None
            continue
        reused[cve_id] = cve_record_from_dict(cached, cached=True)

    records: dict[str, CveRecord] = dict(reused)
    if to_fetch:
        workers = min(config.cve_workers, len(to_fetch))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                cve_id: pool.submit(
                    _fetch_one,
                    cve_id,
                    fetcher,
                    config,
                    etag=None,
                    cached=cached_records.get(cve_id),
                )
                for cve_id in to_fetch
            }
            for cve_id, future in futures.items():
                records[cve_id] = future.result()

    failures = sum(1 for item in records.values() if item.status != "ok")
    truncated = sum(1 for item in records.values() if item.truncated_fields)
    failure_ratio = (failures / len(unique_ids)) if unique_ids else 0.0
    if failures > config.max_cve_failures_absolute or failure_ratio > config.max_cve_failures_ratio:
        status = "failed"
        error = (
            f"CVE enrichment failure threshold exceeded "
            f"({failures}/{len(unique_ids)})"
        )
    elif failures or truncated:
        status = "degraded"
        parts = []
        if failures:
            parts.append(f"{failures} CVE records could not be enriched")
        if truncated:
            parts.append(f"{truncated} CVE records have truncated fields")
        error = "; ".join(parts)
    else:
        status = "ok"
        error = None

    retrieved_times = [item.retrieved_at for item in records.values() if item.retrieved_at]
    updated_times = [item.date_updated for item in records.values() if item.date_updated]
    digest_material = ":".join(
        f"{cve_id}:{records[cve_id].record_sha256}" for cve_id in sorted(records)
    )
    source_revision = None
    if window and window.latest_fetch_time:
        source_revision = window.latest_fetch_time
    elif log and log.latest_fetch_time:
        source_revision = log.latest_fetch_time
    elif digest_material:
        source_revision = sha256_bytes(digest_material.encode("utf-8"))[:16]
    notes = MITRE_CVE_ATTRIBUTION
    if strategy != "full":
        notes = (
            f"{MITRE_CVE_ATTRIBUTION} Incremental strategy={strategy}; "
            f"fetched={len(to_fetch)}; reused={len(reused)}."
        )
    meta = SourceMeta(
        id="cve-list-v5",
        name="CVE List V5",
        status=status,
        url="https://github.com/CVEProject/cvelistV5",
        retrieved_at=max(retrieved_times) if retrieved_times else None,
        source_published_at=min(updated_times) if updated_times else None,
        source_updated_at=max(updated_times) if updated_times else None,
        source_revision=source_revision,
        parser_version=CVE_PARSER_VERSION,
        schema_version="CVE Record Format 5.x (dataVersion on each record)",
        license="CVE Program Terms of Use",
        content_sha256=sha256_bytes(digest_material.encode("utf-8")) if digest_material else None,
        notes=notes,
        error=error,
    )
    return CveEnrichment(
        meta=meta,
        records=records,
        strategy=strategy,
        delta_fetch_time=(window.latest_fetch_time if window else None),
        fetched_ids=tuple(sorted(to_fetch)),
        reused_ids=tuple(sorted(reused)),
        delta_log_etag=(log.etag if log else None),
        delta_log_bytes=(log.content_length if log else None),
        delta_log_skipped=(log.skipped if log else False),
        delta_sha256=(window.content_sha256 if window else None),
        delta_log_sha256=(log.content_sha256 if log else None),
    )


def _failed_enrichment(
    unique_ids: list[str],
    error: str,
    *,
    window: Any,
    log: Any,
) -> CveEnrichment:
    records = {
        cve_id: _unavailable(cve_id, cvelist_v5_raw_url(cve_id), error) for cve_id in unique_ids
    }
    meta = SourceMeta(
        id="cve-list-v5",
        name="CVE List V5",
        status="failed",
        url="https://github.com/CVEProject/cvelistV5",
        retrieved_at=None,
        source_published_at=None,
        source_updated_at=None,
        source_revision=window.latest_fetch_time if window else None,
        parser_version=CVE_PARSER_VERSION,
        schema_version="CVE Record Format 5.x (dataVersion on each record)",
        license="CVE Program Terms of Use",
        content_sha256=None,
        notes=MITRE_CVE_ATTRIBUTION,
        error=error,
    )
    return CveEnrichment(
        meta=meta,
        records=records,
        strategy="failed",
        delta_fetch_time=window.latest_fetch_time if window else None,
        fetched_ids=(),
        reused_ids=(),
        delta_log_etag=log.etag if log else None,
        delta_log_bytes=log.content_length if log else None,
        delta_log_skipped=True,
        delta_sha256=window.content_sha256 if window else None,
        delta_log_sha256=log.content_sha256 if log else None,
    )


def _unavailable(cve_id: str, url: str, error: str) -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        state="unavailable",
        data_version=None,
        date_published=None,
        date_updated=None,
        assigner_short_name=None,
        title=None,
        description=None,
        severity=None,
        products=[],
        source_url=url,
        record_page_url=authoritative_cve_url(cve_id),
        record_sha256="",
        status="unavailable",
        error=error,
    )


def _fetch_one(
    cve_id: str,
    fetcher: Fetcher,
    config: PulseConfig,
    *,
    etag: str | None,
    cached: dict[str, Any] | None,
) -> CveRecord:
    url = cvelist_v5_raw_url(cve_id)
    try:
        response = fetcher.get(url, max_bytes=config.max_cve_bytes, etag=etag)
        if response.not_modified:
            if cached is None:
                return _unavailable(cve_id, url, "HTTP 304 without a cached record")
            record = cve_record_from_dict(cached, cached=True)
            return replace(record, last_checked_at=response.retrieved_at, etag=etag or record.etag)
        payload = load_bounded_json(
            response.body,
            max_bytes=config.max_cve_bytes,
            max_depth=config.max_json_depth,
            source=cve_id,
        )
        return parse_cve_record(
            payload,
            expected_cve_id=cve_id,
            raw=response.body,
            source_url=url,
            config=config,
            retrieved_at=response.retrieved_at,
            etag=response.etag,
        )
    except (FetchError, ValidationError, CorrelationError) as exc:
        return _unavailable(cve_id, url, str(exc))


def parse_cve_record(
    payload: object,
    *,
    expected_cve_id: str,
    raw: bytes,
    source_url: str,
    config: PulseConfig,
    retrieved_at: str | None = None,
    etag: str | None = None,
) -> CveRecord:
    expected = parse_cve_id(expected_cve_id)
    if not isinstance(payload, dict):
        raise ValidationError("CVE record must be a JSON object")
    data_type = payload.get("dataType")
    if data_type not in {"CVE_RECORD", "CVE_RECORD_REJECTED"} and data_type is not None:
        if data_type != "CVE_RECORD":
            raise ValidationError(f"Unexpected CVE dataType {data_type!r}")
    metadata = payload.get("cveMetadata")
    if not isinstance(metadata, dict):
        raise ValidationError("CVE cveMetadata must be an object")
    actual_id = parse_cve_id(metadata.get("cveId"))
    if not same_cve_id(actual_id, expected):
        raise CorrelationError(
            f"CVE record identifier {actual_id} does not match requested {expected}"
        )
    containers = payload.get("containers")
    if not isinstance(containers, dict):
        raise ValidationError("CVE containers must be an object")
    cna = containers.get("cna")
    if not isinstance(cna, dict):
        cna = {}
    truncated: list[str] = []
    title, t_title = clean_text_report(cna.get("title"), config.max_string_chars)
    if t_title:
        truncated.append("title")
    description, t_desc = _english_description(cna.get("descriptions"), config)
    if t_desc:
        truncated.append("description")
    products, t_products = _products(cna.get("affected"), config)
    truncated.extend(t_products)
    severity = _cna_severity(cna.get("metrics"), config)
    return CveRecord(
        cve_id=expected,
        state=clean_text_report(metadata.get("state"), 32)[0] or "UNKNOWN",
        data_version=clean_text_report(payload.get("dataVersion"), 16)[0],
        date_published=clean_text_report(metadata.get("datePublished"), 64)[0],
        date_updated=clean_text_report(metadata.get("dateUpdated"), 64)[0],
        assigner_short_name=clean_text_report(metadata.get("assignerShortName"), 128)[0],
        title=title,
        description=description,
        severity=severity,
        products=products,
        source_url=source_url,
        record_page_url=authoritative_cve_url(expected),
        record_sha256=sha256_bytes(raw),
        status="ok",
        retrieved_at=retrieved_at,
        last_checked_at=retrieved_at,
        etag=etag,
        truncated_fields=tuple(truncated),
        cached=False,
    )


def cve_record_from_dict(payload: dict[str, Any], *, cached: bool = False) -> CveRecord:
    severity_raw = payload.get("severity")
    severity = None
    if isinstance(severity_raw, dict) and severity_raw.get("base_score") is not None:
        severity = CveSeverity(
            source=severity_raw.get("source") or "cve_cna",
            cvss_version=str(severity_raw.get("cvss_version") or ""),
            base_score=float(severity_raw["base_score"]),
            base_severity=severity_raw.get("base_severity"),
            vector=severity_raw.get("vector"),
        )
    return CveRecord(
        cve_id=parse_cve_id(payload.get("cve_id")),
        state=str(payload.get("state") or "UNKNOWN"),
        data_version=payload.get("data_version"),
        date_published=payload.get("date_published"),
        date_updated=payload.get("date_updated"),
        assigner_short_name=payload.get("assigner_short_name"),
        title=payload.get("title"),
        description=payload.get("description"),
        severity=severity,
        products=[
            CveProduct(
                vendor=prod.get("vendor"),
                product=prod.get("product"),
                status=prod.get("status"),
                versions=list(prod.get("versions") or []),
            )
            for prod in payload.get("products") or []
            if isinstance(prod, dict)
        ],
        source_url=payload.get("source_url") or "",
        record_page_url=payload.get("record_page_url") or "",
        record_sha256=payload.get("record_sha256") or "",
        status=payload.get("status") or "unavailable",
        error=payload.get("error"),
        retrieved_at=payload.get("retrieved_at"),
        last_checked_at=payload.get("last_checked_at"),
        etag=payload.get("etag"),
        truncated_fields=tuple(payload.get("truncated_fields") or ()),
        cached=cached,
    )


def _english_description(value: object, config: PulseConfig) -> tuple[str | None, bool]:
    if not isinstance(value, list):
        return None, False
    english = None
    fallback = None
    truncated = False
    for item in value:
        if not isinstance(item, dict):
            continue
        text, was_truncated = clean_text_report(item.get("value"), config.max_description_chars)
        if not text:
            continue
        lang, _ = clean_text_report(item.get("lang"), 16)
        lang = lang or ""
        if lang.lower().startswith("en"):
            english = text
            truncated = was_truncated
            break
        if fallback is None:
            fallback = text
            truncated = was_truncated
    return english or fallback, truncated


def _products(value: object, config: PulseConfig) -> tuple[list[CveProduct], list[str]]:
    if not isinstance(value, list):
        return [], []
    truncated: list[str] = []
    if len(value) > config.max_products:
        truncated.append("products")
    products: list[CveProduct] = []
    for item in value[: config.max_products]:
        if not isinstance(item, dict):
            continue
        versions_raw = item.get("versions") if isinstance(item.get("versions"), list) else []
        if len(versions_raw) > MAX_VERSIONS_PER_PRODUCT and "versions" not in truncated:
            truncated.append("versions")
        versions: list[str] = []
        for version in versions_raw[:MAX_VERSIONS_PER_PRODUCT]:
            if not isinstance(version, dict):
                continue
            label, _ = clean_text_report(version.get("version"), 128)
            status, _ = clean_text_report(version.get("status"), 32)
            less_than, _ = clean_text_report(version.get("lessThan"), 128)
            parts = [part for part in (status, label, less_than) if part]
            if parts:
                versions.append(" ".join(parts)[:256])
        vendor, t_vendor = clean_text_report(item.get("vendor"), config.max_string_chars)
        product, t_product = clean_text_report(item.get("product"), config.max_string_chars)
        if t_vendor and "product_vendor" not in truncated:
            truncated.append("product_vendor")
        if t_product and "product" not in truncated:
            truncated.append("product")
        products.append(
            CveProduct(
                vendor=vendor,
                product=product,
                status=clean_text_report(item.get("defaultStatus"), 32)[0],
                versions=versions,
            )
        )
    return products, truncated


def _cna_severity(value: object, config: PulseConfig) -> CveSeverity | None:
    """Use CNA metrics only. ADP scores are not silently substituted."""
    del config
    if not isinstance(value, list):
        return None
    preferred_keys = (
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    )
    for version_key, version_label in preferred_keys:
        for item in value:
            if not isinstance(item, dict):
                continue
            block = item.get(version_key)
            if not isinstance(block, dict):
                continue
            score = block.get("baseScore")
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                continue
            return CveSeverity(
                source="cve_cna",
                cvss_version=clean_text_report(block.get("version"), 16)[0] or version_label,
                base_score=float(score),
                base_severity=clean_text_report(block.get("baseSeverity"), 32)[0],
                vector=clean_text_report(block.get("vectorString"), 256)[0],
            )
    return None
