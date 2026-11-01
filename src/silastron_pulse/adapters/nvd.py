"""Optional official NVD CVE API 2.0 enrichment.

NVD is never a KEV publication dependency. A missing, delayed, or invalid
NVD record stays explicitly unavailable. HTTP 403 is treated as a transient
NVD condition in this adapter only; it is not added to the global retry set.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import (
    NVD_API_DOCS_URL,
    NVD_ATTRIBUTION,
    NVD_CVE_API_URL,
    NVD_PARSER_VERSION,
)
from silastron_pulse.errors import CorrelationError, FetchError, ValidationError
from silastron_pulse.http import Fetcher
from silastron_pulse.ids import nvd_cve_api_url, parse_cve_id, parse_cwe_id, same_cve_id
from silastron_pulse.jsonutil import dump_canonical, load_bounded_json, sha256_bytes
from silastron_pulse.models import SourceMeta, SourceStatus
from silastron_pulse.sanitize import (
    authoritative_nvd_url,
    clean_text_report,
    sanitize_public_https_url,
)

NVD_LICENSE_ID = "NVD-API-2.0"
MAX_ASSESSMENTS = 16
MAX_CWE_ASSERTIONS = 16
MAX_PRODUCTS = 200
MAX_RANGES_PER_PRODUCT = 32
MAX_REFERENCES = 32
NVD_TRANSIENT_STATUS = {403, 408, 429, 500, 502, 503, 504}

CVSS_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)

V3_METRIC_FIELDS = (
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
)
V2_METRIC_FIELDS = (
    "accessVector",
    "accessComplexity",
    "authentication",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
)
V4_METRIC_FIELDS = (
    "attackVector",
    "attackComplexity",
    "attackRequirements",
    "privilegesRequired",
    "userInteraction",
    "vulnConfidentialityImpact",
    "vulnIntegrityImpact",
    "vulnAvailabilityImpact",
    "subConfidentialityImpact",
    "subIntegrityImpact",
    "subAvailabilityImpact",
)


@dataclass(frozen=True)
class NvdRecord:
    cve_id: str
    status: SourceStatus
    source_url: str
    record_page_url: str
    record_sha256: str
    vuln_status: str | None = None
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None
    assessments: tuple[dict[str, Any], ...] = ()
    cwes: tuple[dict[str, Any], ...] = ()
    products: tuple[dict[str, Any], ...] = ()
    references: tuple[dict[str, Any], ...] = ()
    retrieved_at: str | None = None
    last_checked_at: str | None = None
    source_timestamp: str | None = None
    etag: str | None = None
    error: str | None = None
    cached: bool = False
    availability: dict[str, Any] | None = None
    truncated_fields: tuple[str, ...] = ()

    def comparable(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "status": self.status,
            "vuln_status": self.vuln_status,
            "published": self.published,
            "last_modified": self.last_modified,
            "description": self.description,
            "assessments": [dict(item) for item in self.assessments],
            "cwes": [dict(item) for item in self.cwes],
            "products": [dict(item) for item in self.products],
            "references": [dict(item) for item in self.references],
            "truncated_fields": list(self.truncated_fields),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "status": self.status,
            "vuln_status": self.vuln_status,
            "published": self.published,
            "last_modified": self.last_modified,
            "description": self.description,
            "assessments": [dict(item) for item in self.assessments],
            "cwes": [dict(item) for item in self.cwes],
            "products": [dict(item) for item in self.products],
            "references": [dict(item) for item in self.references],
            "source_url": self.source_url,
            "record_page_url": self.record_page_url,
            "record_sha256": self.record_sha256,
            "retrieved_at": self.retrieved_at,
            "last_checked_at": self.last_checked_at,
            "source_timestamp": self.source_timestamp,
            "etag": self.etag,
            "error": self.error,
            "cached": self.cached,
            "availability": self.availability,
            "truncated_fields": list(self.truncated_fields),
        }


@dataclass(frozen=True)
class NvdEnrichment:
    meta: SourceMeta
    records: dict[str, NvdRecord]
    fetched_ids: tuple[str, ...] = ()
    reused_ids: tuple[str, ...] = ()
    api_key_configured: bool = False


def collect_nvd(
    cve_ids: list[str],
    fetcher: Fetcher,
    config: PulseConfig,
    *,
    cache_index: dict[str, Any] | None = None,
    cached_records: dict[str, dict[str, Any]] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> NvdEnrichment:
    unique_ids = sorted({parse_cve_id(cve_id) for cve_id in cve_ids})
    sleeper = sleep or time.sleep
    interval = max(0, config.nvd_min_interval_ms) / 1000.0
    headers = _api_headers(config.nvd_api_key)
    cached_records = cached_records or {}
    index_records = (
        cache_index.get("records")
        if isinstance(cache_index, dict) and isinstance(cache_index.get("records"), dict)
        else {}
    )
    records: dict[str, NvdRecord] = {}
    fetched: list[str] = []
    reused: list[str] = []
    first_error: str | None = None
    for offset, cve_id in enumerate(unique_ids):
        if offset and interval:
            sleeper(interval)
        cached = cached_records.get(cve_id)
        etag = None
        if isinstance(index_records.get(cve_id), dict):
            etag = index_records[cve_id].get("etag")
        elif isinstance(cached, dict):
            etag = cached.get("etag")
        record = _fetch_one(
            cve_id,
            fetcher,
            config,
            headers=headers,
            cached=cached if isinstance(cached, dict) else None,
            etag=etag if isinstance(etag, str) and etag else None,
        )
        records[cve_id] = record
        if record.cached:
            reused.append(cve_id)
        else:
            fetched.append(cve_id)
        if record.status != "ok" and first_error is None:
            first_error = record.error
    ok = sum(1 for item in records.values() if item.status == "ok")
    unavailable = len(records) - ok
    if not records:
        status: SourceStatus = "unavailable"
        notes = "No KEV identifiers were submitted for NVD enrichment."
    elif ok == 0:
        status = "unavailable"
        notes = (
            "NVD enrichment is unavailable. Verified CISA KEV records remain "
            "eligible for publication."
        )
    elif unavailable:
        status = "degraded"
        notes = (
            f"NVD enrichment available for {ok} of {len(records)} KEV records. "
            "Missing NVD rows stay unavailable and do not invalidate KEV data."
        )
    else:
        status = "ok"
        notes = "NVD CVE API 2.0 enrichment completed for the KEV identifier set."
    comparable = [records[key].comparable() for key in sorted(records)]
    digest = sha256_bytes(dump_canonical(comparable).encode("utf-8"))
    retrieved = next(
        (item.retrieved_at or item.last_checked_at for item in records.values() if item.retrieved_at or item.last_checked_at),
        None,
    )
    meta = SourceMeta(
        id="nvd",
        name="NVD CVE API 2.0",
        status=status,
        url=NVD_CVE_API_URL,
        retrieved_at=retrieved,
        source_published_at=None,
        source_updated_at=None,
        source_revision=digest,
        parser_version=NVD_PARSER_VERSION,
        schema_version="2.0",
        license=NVD_LICENSE_ID,
        content_sha256=digest,
        notes=f"{notes} {NVD_ATTRIBUTION}",
        error=first_error if status != "ok" else None,
    )
    return NvdEnrichment(
        meta=meta,
        records=records,
        fetched_ids=tuple(fetched),
        reused_ids=tuple(reused),
        api_key_configured=config.nvd_api_key is not None,
    )


def nvd_record_from_dict(payload: dict[str, Any], *, cached: bool = False) -> NvdRecord:
    return NvdRecord(
        cve_id=parse_cve_id(payload.get("cve_id")),
        status=payload.get("status") or "unavailable",
        vuln_status=payload.get("vuln_status") if isinstance(payload.get("vuln_status"), str) else None,
        published=payload.get("published") if isinstance(payload.get("published"), str) else None,
        last_modified=payload.get("last_modified") if isinstance(payload.get("last_modified"), str) else None,
        description=payload.get("description") if isinstance(payload.get("description"), str) else None,
        assessments=_dict_tuple(payload.get("assessments")),
        cwes=_dict_tuple(payload.get("cwes")),
        products=_dict_tuple(payload.get("products")),
        references=_dict_tuple(payload.get("references")),
        source_url=str(payload.get("source_url") or ""),
        record_page_url=str(payload.get("record_page_url") or ""),
        record_sha256=str(payload.get("record_sha256") or ""),
        retrieved_at=payload.get("retrieved_at") if isinstance(payload.get("retrieved_at"), str) else None,
        last_checked_at=payload.get("last_checked_at") if isinstance(payload.get("last_checked_at"), str) else None,
        source_timestamp=payload.get("source_timestamp") if isinstance(payload.get("source_timestamp"), str) else None,
        etag=payload.get("etag") if isinstance(payload.get("etag"), str) else None,
        error=payload.get("error") if isinstance(payload.get("error"), str) else None,
        cached=cached,
        availability=payload.get("availability") if isinstance(payload.get("availability"), dict) else None,
        truncated_fields=tuple(
            item for item in (payload.get("truncated_fields") or ()) if isinstance(item, str)
        ),
    )


def _api_headers(api_key: str | None) -> dict[str, str] | None:
    if not api_key:
        return None
    return {"apiKey": api_key}


def _fetch_one(
    cve_id: str,
    fetcher: Fetcher,
    config: PulseConfig,
    *,
    headers: dict[str, str] | None,
    cached: dict[str, Any] | None,
    etag: str | None,
) -> NvdRecord:
    url = nvd_cve_api_url(cve_id)
    try:
        response = fetcher.get(
            url,
            max_bytes=config.max_nvd_bytes,
            etag=etag,
            headers=headers,
        )
    except FetchError as exc:
        return _unavailable_from_error(cve_id, url, exc, cached)
    checked_at = response.retrieved_at
    if response.not_modified:
        if not cached:
            return _unavailable(
                cve_id,
                url,
                "NVD returned 304 without a cached record",
                availability=_availability("invalid_payload", 304, url),
                retrieved_at=checked_at,
            )
        record = nvd_record_from_dict(cached, cached=True)
        return replace(record, last_checked_at=checked_at, cached=True)
    try:
        payload = load_bounded_json(
            response.body,
            max_bytes=config.max_nvd_bytes,
            max_depth=config.max_json_depth,
            source=f"nvd:{cve_id}",
        )
        record = parse_nvd_response(
            payload,
            expected_cve_id=cve_id,
            raw=response.body,
            source_url=url,
            config=config,
            retrieved_at=response.retrieved_at,
            etag=response.etag,
        )
        return record
    except (ValidationError, CorrelationError) as exc:
        return _unavailable(
            cve_id,
            url,
            str(exc),
            availability=_availability("invalid_payload", response.status_code, url),
            retrieved_at=checked_at,
            etag=response.etag,
        )


def parse_nvd_response(
    payload: object,
    *,
    expected_cve_id: str,
    raw: bytes,
    source_url: str,
    config: PulseConfig,
    retrieved_at: str | None,
    etag: str | None,
) -> NvdRecord:
    expected = parse_cve_id(expected_cve_id)
    if not isinstance(payload, dict):
        raise ValidationError("NVD response must be a JSON object")
    total = payload.get("totalResults")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise ValidationError("NVD totalResults is missing or invalid")
    timestamp, _ = clean_text_report(payload.get("timestamp"), 64)
    if total == 0:
        return _unavailable(
            expected,
            source_url,
            "NVD has no CVE record for this identifier",
            availability=_availability("missing_record", 200, source_url),
            retrieved_at=retrieved_at,
            etag=etag,
            source_timestamp=timestamp,
        )
    rows = payload.get("vulnerabilities")
    if not isinstance(rows, list) or not rows:
        raise ValidationError("NVD vulnerabilities array is missing")
    first = rows[0]
    if not isinstance(first, dict):
        raise ValidationError("NVD vulnerability item must be an object")
    cve = first.get("cve")
    if not isinstance(cve, dict):
        raise ValidationError("NVD cve object is missing")
    actual = parse_cve_id(cve.get("id"))
    if not same_cve_id(actual, expected):
        raise CorrelationError(
            f"NVD record identifier {actual} does not match requested {expected}"
        )
    requested = urlparse(source_url)
    query_id = (parse_qs(requested.query).get("cveId") or [None])[0]
    if query_id and not same_cve_id(query_id, expected):
        raise CorrelationError("NVD request identifier does not match response")
    truncated: list[str] = []
    description, desc_truncated = _english_description(cve.get("descriptions"), config)
    if desc_truncated:
        truncated.append("description")
    assessments, a_trunc = _assessments(cve.get("metrics"))
    truncated.extend(a_trunc)
    cwes, c_trunc = _cwes(cve.get("weaknesses"))
    truncated.extend(c_trunc)
    products, p_trunc = _products(cve.get("configurations"), config)
    truncated.extend(p_trunc)
    references, r_trunc = _references(cve.get("references"))
    truncated.extend(r_trunc)
    return NvdRecord(
        cve_id=expected,
        status="ok",
        vuln_status=clean_text_report(cve.get("vulnStatus"), 64)[0],
        published=clean_text_report(cve.get("published"), 64)[0],
        last_modified=clean_text_report(cve.get("lastModified"), 64)[0],
        description=description,
        assessments=tuple(assessments),
        cwes=tuple(cwes),
        products=tuple(products),
        references=tuple(references),
        source_url=source_url,
        record_page_url=authoritative_nvd_url(expected),
        record_sha256=sha256_bytes(raw),
        retrieved_at=retrieved_at,
        last_checked_at=retrieved_at,
        source_timestamp=timestamp,
        etag=etag,
        availability={
            "class": "available",
            "http_status": 200,
            "requested_url": source_url,
            "source_timestamp": timestamp,
        },
        truncated_fields=tuple(truncated),
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
        if (lang or "").lower().startswith("en"):
            return text, was_truncated
        if fallback is None:
            fallback = text
            truncated = was_truncated
    return fallback, truncated


def _assessments(value: object) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(value, dict):
        return [], []
    assessments: list[dict[str, Any]] = []
    truncated: list[str] = []
    for key, version in CVSS_METRIC_KEYS:
        rows = value.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            parsed = _assessment(row, version)
            if parsed is None:
                continue
            assessments.append(parsed)
            if len(assessments) >= MAX_ASSESSMENTS:
                truncated.append("assessments")
                return assessments, truncated
    return assessments, truncated


def _assessment(row: dict[str, Any], version_fallback: str) -> dict[str, Any] | None:
    data = row.get("cvssData")
    if not isinstance(data, dict):
        return None
    score = data.get("baseScore")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return None
    version = clean_text_report(data.get("version"), 16)[0] or version_fallback
    metrics = _version_metrics(data, version)
    source, _ = clean_text_report(row.get("source"), 128)
    return {
        "source": "nvd",
        "nvd_metric_source": source,
        "cvss_version": version,
        "base_score": float(score),
        "severity": clean_text_report(data.get("baseSeverity"), 32)[0],
        "vector": clean_text_report(data.get("vectorString"), 256)[0],
        "metrics": metrics,
        "source_updated_at": None,
    }


def _version_metrics(data: dict[str, Any], version: str) -> dict[str, Any]:
    if version.startswith("4"):
        fields = V4_METRIC_FIELDS
    elif version.startswith("2"):
        fields = V2_METRIC_FIELDS
    else:
        fields = V3_METRIC_FIELDS
    metrics: dict[str, Any] = {}
    for field in fields:
        text, _ = clean_text_report(data.get(field), 64)
        if text:
            metrics[field] = text
    return metrics


def _cwes(value: object) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(value, list):
        return [], []
    assertions: list[dict[str, Any]] = []
    truncated: list[str] = []
    seen: set[tuple[str, str | None]] = set()
    for row in value:
        if not isinstance(row, dict):
            continue
        source, _ = clean_text_report(row.get("source"), 128)
        descriptions = row.get("description")
        if not isinstance(descriptions, list):
            continue
        for item in descriptions:
            if not isinstance(item, dict):
                continue
            raw, _ = clean_text_report(item.get("value"), 256)
            if not raw:
                continue
            cwe_id = parse_cwe_id(raw) or parse_cwe_id(raw.split(":")[0].strip())
            name = None
            if cwe_id and raw.upper().startswith(cwe_id) and ":" in raw:
                name, _ = clean_text_report(raw.split(":", 1)[1], 256)
            elif not cwe_id:
                continue
            key = (cwe_id, source)
            if key in seen:
                continue
            seen.add(key)
            assertions.append(
                {
                    "cwe_id": cwe_id,
                    "name": name,
                    "source": "nvd",
                    "nvd_weakness_source": source,
                }
            )
            if len(assertions) >= MAX_CWE_ASSERTIONS:
                truncated.append("cwes")
                return assertions, truncated
    return assertions, truncated


def _products(value: object, config: PulseConfig) -> tuple[list[dict[str, Any]], list[str]]:
    del config
    if not isinstance(value, list):
        return [], []
    grouped: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    truncated: list[str] = []
    omitted = 0
    for config_row in value:
        if not isinstance(config_row, dict):
            continue
        nodes = config_row.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if not isinstance(match, dict):
                    continue
                parsed = _cpe_range(match)
                if parsed is None:
                    continue
                key = (parsed["vendor"], parsed["product"])
                bucket = grouped.get(key)
                if bucket is None:
                    if len(grouped) >= MAX_PRODUCTS:
                        omitted += 1
                        continue
                    bucket = {
                        "vendor": parsed["vendor"],
                        "product": parsed["product"],
                        "source": "nvd",
                        "package_ecosystem": parsed["package_ecosystem"],
                        "ranges": [],
                    }
                    grouped[key] = bucket
                if len(bucket["ranges"]) >= MAX_RANGES_PER_PRODUCT:
                    omitted += 1
                    continue
                bucket["ranges"].append(parsed["range"])
    if omitted:
        truncated.append("products")
    products = []
    for key in sorted(grouped):
        item = grouped[key]
        item["ranges"] = sorted(
            item["ranges"],
            key=lambda row: (
                str(row.get("status") or ""),
                str(row.get("version") or ""),
                str(row.get("less_than") or ""),
                str(row.get("less_than_or_equal") or ""),
            ),
        )
        products.append(item)
    return products, truncated


def _cpe_range(match: dict[str, Any]) -> dict[str, Any] | None:
    criteria, _ = clean_text_report(match.get("criteria"), 512)
    if not criteria or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    vendor = _unquote_cpe(parts[3])
    product = _unquote_cpe(parts[4])
    version = _unquote_cpe(parts[5])
    ecosystem = _unquote_cpe(parts[10]) if len(parts) > 10 else None
    vulnerable = match.get("vulnerable")
    if vulnerable is True:
        status = "affected"
    elif vulnerable is False:
        status = "unaffected"
    else:
        status = "unknown"
    start_inc, _ = clean_text_report(match.get("versionStartIncluding"), 128)
    start_exc, _ = clean_text_report(match.get("versionStartExcluding"), 128)
    end_inc, _ = clean_text_report(match.get("versionEndIncluding"), 128)
    end_exc, _ = clean_text_report(match.get("versionEndExcluding"), 128)
    return {
        "vendor": vendor,
        "product": product,
        "package_ecosystem": None if ecosystem in {None, "*"} else ecosystem,
        "range": {
            "status": status,
            "version": None if version in {None, "*"} else version,
            "greater_than": start_exc,
            "greater_than_or_equal": start_inc,
            "less_than": end_exc,
            "less_than_or_equal": end_inc,
            "version_type": "cpe",
            "platform": None,
            "fixed_version": None,
            "fixed_evidence": None,
        },
    }


def _unquote_cpe(value: str) -> str | None:
    text, _ = clean_text_report(value.replace("\\", ""), 128)
    if text in {None, "*", "-"}:
        return None
    return text


def _references(value: object) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(value, list):
        return [], []
    refs: list[dict[str, Any]] = []
    truncated: list[str] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict):
            continue
        url = sanitize_public_https_url(row.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        tags = [
            str(tag).lower()
            for tag in (row.get("tags") or [])
            if isinstance(tag, str)
        ]
        classification = "other"
        if "vendor advisory" in tags or "vendor-advisory" in tags:
            classification = "vendor_advisory"
        elif "patch" in tags:
            classification = "patch"
        name, _ = clean_text_report(row.get("source"), 128)
        refs.append(
            {
                "url": url,
                "title": name,
                "classification": classification,
                "source": "nvd",
                "original_tags": tags[:8],
            }
        )
        if len(refs) >= MAX_REFERENCES:
            truncated.append("references")
            break
    return refs, truncated


def _unavailable_from_error(
    cve_id: str,
    url: str,
    exc: FetchError,
    cached: dict[str, Any] | None,
) -> NvdRecord:
    status_code = exc.status_code
    if status_code == 404:
        classification = "missing_record"
    elif status_code in NVD_TRANSIENT_STATUS:
        classification = "transient"
    elif "exceeded max bytes" in str(exc).lower():
        classification = "oversized"
    else:
        classification = "transient" if exc.retryable else "invalid_payload"
    # Cached validated records are not reused across hard validation failures.
    # Transient outages keep the last validated record and mark it stale.
    if classification == "transient" and cached and cached.get("status") == "ok":
        record = nvd_record_from_dict(cached, cached=True)
        availability = _availability(classification, status_code, url)
        availability["cached_reuse"] = True
        return replace(
            record,
            error=str(exc),
            availability=availability,
            cached=True,
        )
    return _unavailable(
        cve_id,
        url,
        str(exc),
        availability=_availability(classification, status_code, url),
    )


def _unavailable(
    cve_id: str,
    url: str,
    error: str,
    *,
    availability: dict[str, Any],
    retrieved_at: str | None = None,
    etag: str | None = None,
    source_timestamp: str | None = None,
) -> NvdRecord:
    return NvdRecord(
        cve_id=parse_cve_id(cve_id),
        status="unavailable",
        source_url=url,
        record_page_url=authoritative_nvd_url(cve_id),
        record_sha256="",
        error=error,
        retrieved_at=retrieved_at,
        last_checked_at=retrieved_at,
        source_timestamp=source_timestamp,
        etag=etag,
        availability=availability,
    )


def _availability(classification: str, status_code: int | None, url: str) -> dict[str, Any]:
    return {
        "class": classification,
        "http_status": status_code,
        "requested_url": url,
        "docs_url": NVD_API_DOCS_URL,
    }


def _dict_tuple(value: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))
