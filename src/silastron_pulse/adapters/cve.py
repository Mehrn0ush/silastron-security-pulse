"""CVE List V5 enrichment for selected KEV identifiers only."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import (
    CVE_LIST_V5_BLOB_BASE,
    CVE_PARSER_VERSION,
    MITRE_CVE_ATTRIBUTION,
)
from silastron_pulse.errors import CorrelationError, FetchError, ValidationError
from silastron_pulse.http import Fetcher
from silastron_pulse.ids import cvelist_v5_raw_url, cvelist_v5_relpath, parse_cve_id, same_cve_id
from silastron_pulse.jsonutil import load_bounded_json, sha256_bytes
from silastron_pulse.models import CveProduct, CveRecord, CveSeverity, SourceMeta
from silastron_pulse.sanitize import authoritative_cve_url, clean_text


@dataclass(frozen=True)
class CveEnrichment:
    meta: SourceMeta
    records: dict[str, CveRecord]


def enrich_cves(
    cve_ids: list[str],
    fetcher: Fetcher,
    config: PulseConfig,
) -> CveEnrichment:
    unique_ids = sorted({parse_cve_id(cve_id) for cve_id in cve_ids})
    if len(unique_ids) > config.max_cve_enrichments:
        raise ValidationError(
            f"CVE enrichment requested {len(unique_ids)} IDs; max is {config.max_cve_enrichments}"
        )
    records: dict[str, CveRecord] = {}
    failures = 0
    if unique_ids:
        workers = min(config.cve_workers, len(unique_ids))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_fetch_one, cve_id, fetcher, config) for cve_id in unique_ids
            ]
            for cve_id, future in zip(unique_ids, futures):
                records[cve_id] = future.result()
                if records[cve_id].status != "ok":
                    failures += 1
    failure_ratio = (failures / len(unique_ids)) if unique_ids else 0.0
    if failures > config.max_cve_failures_absolute or failure_ratio > config.max_cve_failures_ratio:
        status = "failed"
        error = (
            f"CVE enrichment failure threshold exceeded "
            f"({failures}/{len(unique_ids)})"
        )
    elif failures:
        status = "degraded"
        error = f"{failures} CVE records could not be enriched"
    else:
        status = "ok"
        error = None
    meta = SourceMeta(
        id="cve-list-v5",
        name="CVE List V5",
        status=status,
        url="https://github.com/CVEProject/cvelistV5",
        retrieved_at=None,
        source_published_at=None,
        source_updated_at=None,
        source_revision=None,
        parser_version=CVE_PARSER_VERSION,
        schema_version="CVE Record Format 5.x (dataVersion on each record)",
        license="CVE Program Terms of Use",
        content_sha256=None,
        notes=MITRE_CVE_ATTRIBUTION,
        error=error,
    )
    return CveEnrichment(meta=meta, records=records)


def _fetch_one(cve_id: str, fetcher: Fetcher, config: PulseConfig) -> CveRecord:
    url = cvelist_v5_raw_url(cve_id)
    try:
        response = fetcher.get(url, max_bytes=config.max_cve_bytes)
        payload = load_bounded_json(
            response.body,
            max_bytes=config.max_cve_bytes,
            max_depth=config.max_json_depth,
            source=cve_id,
        )
        record = parse_cve_record(
            payload,
            expected_cve_id=cve_id,
            raw=response.body,
            source_url=url,
            config=config,
        )
        return record
    except (FetchError, ValidationError, CorrelationError) as exc:
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
            error=str(exc),
        )


def parse_cve_record(
    payload: object,
    *,
    expected_cve_id: str,
    raw: bytes,
    source_url: str,
    config: PulseConfig,
) -> CveRecord:
    expected = parse_cve_id(expected_cve_id)
    if not isinstance(payload, dict):
        raise ValidationError("CVE record must be a JSON object")
    data_type = payload.get("dataType")
    if data_type not in {"CVE_RECORD", "CVE_RECORD_REJECTED"} and data_type is not None:
        # Accept official records; reject unrelated documents.
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
    title = clean_text(cna.get("title"), config.max_string_chars)
    description = _english_description(cna.get("descriptions"), config)
    products = _products(cna.get("affected"), config)
    severity = _cna_severity(cna.get("metrics"), config)
    blob_url = CVE_LIST_V5_BLOB_BASE + cvelist_v5_relpath(expected)
    return CveRecord(
        cve_id=expected,
        state=clean_text(metadata.get("state"), 32) or "UNKNOWN",
        data_version=clean_text(payload.get("dataVersion"), 16),
        date_published=clean_text(metadata.get("datePublished"), 64),
        date_updated=clean_text(metadata.get("dateUpdated"), 64),
        assigner_short_name=clean_text(metadata.get("assignerShortName"), 128),
        title=title,
        description=description,
        severity=severity,
        products=products,
        source_url=source_url,
        record_page_url=authoritative_cve_url(expected),
        record_sha256=sha256_bytes(raw),
        status="ok",
    )


def _english_description(value: object, config: PulseConfig) -> str | None:
    if not isinstance(value, list):
        return None
    english = None
    fallback = None
    for item in value:
        if not isinstance(item, dict):
            continue
        text = clean_text(item.get("value"), config.max_description_chars)
        if not text:
            continue
        lang = clean_text(item.get("lang"), 16) or ""
        if lang.lower().startswith("en"):
            english = text
            break
        if fallback is None:
            fallback = text
    return english or fallback


def _products(value: object, config: PulseConfig) -> list[CveProduct]:
    if not isinstance(value, list):
        return []
    products: list[CveProduct] = []
    for item in value[: config.max_products]:
        if not isinstance(item, dict):
            continue
        versions_raw = item.get("versions") if isinstance(item.get("versions"), list) else []
        versions: list[str] = []
        for version in versions_raw[:12]:
            if not isinstance(version, dict):
                continue
            label = clean_text(version.get("version"), 128)
            status = clean_text(version.get("status"), 32)
            less_than = clean_text(version.get("lessThan"), 128)
            parts = [part for part in (status, label, less_than) if part]
            if parts:
                versions.append(" ".join(parts)[:256])
        products.append(
            CveProduct(
                vendor=clean_text(item.get("vendor"), config.max_string_chars),
                product=clean_text(item.get("product"), config.max_string_chars),
                status=clean_text(item.get("defaultStatus"), 32),
                versions=versions,
            )
        )
    return products


def _cna_severity(value: object, config: PulseConfig) -> CveSeverity | None:
    """Use CNA metrics only. ADP scores are not silently substituted."""
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
                cvss_version=clean_text(block.get("version"), 16) or version_label,
                base_score=float(score),
                base_severity=clean_text(block.get("baseSeverity"), 32),
                vector=clean_text(block.get("vectorString"), 256),
            )
    return None
