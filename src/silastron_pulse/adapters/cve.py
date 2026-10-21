"""CVE List V5 enrichment for selected KEV identifiers only.

Incremental strategy (evaluated against official cvelistV5 distribution):

- Full git clone / release zips are official but too large to store or fetch
  on every run.
- `cves/deltaLog.json` is the official change index. When the log covers the
  period since the last stored fetchTime, only KEV ∩ (new ∪ updated) plus
  cache misses are fetched.
- If the delta log is missing, gapped, or unusable, each cached KEV CVE is
  revalidated with If-None-Match instead of an unconditional body download.
- A failed refetch is marked unavailable. Cached bytes are never presented as
  a verified current record.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any

from silastron_pulse.adapters.delta import fetch_delta_index
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
    delta = None
    strategy = "full"
    if index_records:
        delta = fetch_delta_index(fetcher, config, since=since)
        if delta is not None and delta.complete_since:
            strategy = "delta"
        else:
            strategy = "etag"

    to_fetch: dict[str, str | None] = {}
    reused: dict[str, CveRecord] = {}
    for cve_id in unique_ids:
        cached = cached_records.get(cve_id)
        index_row = index_records.get(cve_id) if isinstance(index_records.get(cve_id), dict) else {}
        etag = index_row.get("etag") or (cached or {}).get("etag")
        if strategy == "full" or cached is None or (cached or {}).get("status") != "ok":
            to_fetch[cve_id] = None if strategy != "etag" else etag
            continue
        if strategy == "delta":
            if cve_id in delta.changed_ids:  # type: ignore[union-attr]
                to_fetch[cve_id] = None
            else:
                reused[cve_id] = cve_record_from_dict(cached, cached=True)
            continue
        if delta and cve_id in delta.changed_ids:
            to_fetch[cve_id] = None
        else:
            to_fetch[cve_id] = etag

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
                    etag=etag,
                    cached=cached_records.get(cve_id),
                )
                for cve_id, etag in to_fetch.items()
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
    elif failures or truncated or strategy == "etag":
        status = "degraded"
        parts = []
        if failures:
            parts.append(f"{failures} CVE records could not be enriched")
        if truncated:
            parts.append(f"{truncated} CVE records have truncated fields")
        if strategy == "etag" and delta is None:
            parts.append("deltaLog unavailable; used If-None-Match revalidation")
        elif strategy == "etag":
            parts.append("deltaLog incomplete since last fetchTime; used If-None-Match revalidation")
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
    if delta and delta.latest_fetch_time:
        source_revision = delta.latest_fetch_time
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
        delta_fetch_time=(delta.latest_fetch_time if delta else None),
        fetched_ids=tuple(sorted(to_fetch)),
        reused_ids=tuple(sorted(reused)),
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
