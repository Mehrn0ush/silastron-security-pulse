"""Source-attributed vulnerability intelligence.

Assertions stay attributed to their source. Conflicts are recorded, never
collapsed into a composite score. Collection timestamps are excluded from
comparable() so retrieval-only reruns do not create history noise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from silastron_pulse.adapters.nvd import NvdRecord
from silastron_pulse.config import PulseConfig
from silastron_pulse.ids import parse_cwe_id
from silastron_pulse.models import CveRecord, KevRecord
from silastron_pulse.sanitize import (
    authoritative_cve_url,
    authoritative_kev_url,
    authoritative_nvd_url,
    clean_text_report,
    sanitize_public_https_url,
)

INTELLIGENCE_SCHEMA_VERSION = "1.0.0"
SOURCE_CNA = "cve_cna"
SOURCE_NVD = "nvd"
SOURCE_KEV = "cisa_kev"

# Deterministic display order. This is a UI preference, not objective truth.
CVSS_VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
CVSS_SOURCE_RANK = {SOURCE_CNA: 0, SOURCE_NVD: 1}

CNA_METRIC_KEYS = (
    ("cvssV4_0", "4.0"),
    ("cvssV3_1", "3.1"),
    ("cvssV3_0", "3.0"),
    ("cvssV2_0", "2.0"),
)
V3_FIELDS = (
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
)
V2_FIELDS = (
    "accessVector",
    "accessComplexity",
    "authentication",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
)
V4_FIELDS = (
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
class VulnerabilityIntelligence:
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)

    def comparable(self) -> dict[str, Any]:
        return comparable_intelligence(self.payload)


def comparable_intelligence(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {
        "identity": _without_keys(payload.get("identity"), ()),
        "kev": payload.get("kev"),
        "descriptions": _sorted_dicts(payload.get("descriptions")),
        "cvss": _sorted_dicts((payload.get("cvss") or {}).get("assessments")),
        "cwes": _sorted_dicts((payload.get("cwes") or {}).get("assertions")),
        "affected": _sorted_dicts((payload.get("affected") or {}).get("products")),
        "fixed_versions": _sorted_dicts((payload.get("remediation") or {}).get("fixed_versions")),
        "vendor_advisories": _sorted_dicts((payload.get("remediation") or {}).get("vendor_advisories")),
        "references": _sorted_dicts(payload.get("references")),
        "conflicts": _sorted_dicts(payload.get("conflicts")),
        "coverage": payload.get("coverage"),
        "source_status": {
            name: {
                "status": ((payload.get("sources") or {}).get(name) or {}).get("status"),
                "upstream_modified_at": ((payload.get("sources") or {}).get(name) or {}).get(
                    "upstream_modified_at"
                ),
                "completeness": ((payload.get("sources") or {}).get(name) or {}).get("completeness"),
            }
            for name in ("cisa_kev", "cve_list_v5", "nvd")
        },
    }


def assemble_intelligence(
    *,
    kev: KevRecord,
    cve: CveRecord,
    nvd: NvdRecord | None,
) -> VulnerabilityIntelligence:
    cna = cve.cna_assertions if isinstance(cve.cna_assertions, dict) else {}
    descriptions = _descriptions(cve, nvd)
    assessments = list(cna.get("assessments") or [])
    if nvd and nvd.status == "ok":
        assessments.extend(nvd.assessments)
    cwes = _cwes(kev, cna, nvd)
    products = list(cna.get("products") or [])
    if nvd and nvd.status == "ok":
        products.extend(nvd.products)
    references = list(cna.get("references") or [])
    if nvd and nvd.status == "ok":
        references.extend(nvd.references)
    fixed_versions = list(cna.get("fixed_versions") or [])
    advisories = [item for item in references if item.get("classification") == "vendor_advisory"]
    conflicts = _conflicts(assessments, cwes, products)
    nvd_status = nvd.status if nvd is not None else "unavailable"
    coverage = {
        "has_cvss": bool(assessments),
        "has_cwe": bool(cwes),
        "has_affected_versions": _has_affected_ranges(products),
        "has_fixed_version": bool(fixed_versions),
        "has_vendor_advisory": bool(advisories),
        "nvd_available": nvd_status == "ok",
        "cve_list_available": cve.status == "ok",
    }
    payload = {
        "schema_version": INTELLIGENCE_SCHEMA_VERSION,
        "identity": {
            "cve_id": kev.cve_id,
            "cve_status": cve.state if cve.status == "ok" else None,
            "cna_organization": cve.assigner_short_name if cve.status == "ok" else None,
            "cve_published_at": cve.date_published if cve.status == "ok" else None,
            "cve_updated_at": cve.date_updated if cve.status == "ok" else None,
            "source_identifiers": {
                "cisa_kev": authoritative_kev_url(),
                "cve_list_v5": authoritative_cve_url(kev.cve_id),
                "nvd": authoritative_nvd_url(kev.cve_id),
            },
        },
        "kev": {
            "date_added": kev.date_added,
            "due_date": kev.due_date,
            "required_action": kev.required_action,
            "known_ransomware_campaign_use": kev.known_ransomware_campaign_use,
            "notes": kev.notes,
            "source": SOURCE_KEV,
            "source_url": kev.source_url,
        },
        "descriptions": descriptions,
        "cvss": {
            "assessments": assessments,
            "display_preference": _cvss_preference(assessments),
            "display_preference_note": (
                "Display preference is a deterministic UI order (newest CVSS "
                "version, then CNA before NVD). It is not a judgment that one "
                "assessment is more correct."
            ),
        },
        "cwes": {"assertions": cwes},
        "affected": {
            "products": products,
            "note": (
                "Affected ranges are copied from each source and are not merged. "
                "An upper bound is not a fixed version. Absence is not evidence "
                "that a product is unaffected or patched."
            ),
        },
        "remediation": {
            "fixed_versions": fixed_versions,
            "vendor_advisories": advisories,
            "cisa_required_action": kev.required_action,
            "note": (
                "Fixed versions appear only when a source states an explicit "
                "fixed change. versionEndExcluding / lessThan are affected-range "
                "boundaries, not patches."
            ),
        },
        "references": references,
        "sources": {
            "cisa_kev": {
                "status": "ok",
                "retrieved_at": None,
                "upstream_modified_at": None,
                "completeness": "partial" if kev.truncated_fields or kev.cwes_incomplete else "available",
            },
            "cve_list_v5": {
                "status": cve.status,
                "retrieved_at": cve.retrieved_at,
                "upstream_modified_at": cve.date_updated,
                "completeness": _cve_completeness(cve),
                "error": cve.error,
            },
            "nvd": {
                "status": nvd_status,
                "retrieved_at": nvd.retrieved_at if nvd else None,
                "last_checked_at": nvd.last_checked_at if nvd else None,
                "upstream_modified_at": nvd.last_modified if nvd else None,
                "source_timestamp": nvd.source_timestamp if nvd else None,
                "completeness": _nvd_completeness(nvd),
                "error": nvd.error if nvd else "NVD enrichment was not collected",
            },
        },
        "conflicts": conflicts,
        "coverage": coverage,
    }
    return VulnerabilityIntelligence(payload=payload)


def extract_cna_assertions(cna: dict[str, Any], config: PulseConfig) -> dict[str, Any]:
    assessments = _cna_assessments(cna.get("metrics"))
    products, fixed = _cna_products(cna.get("affected"), config)
    return {
        "assessments": assessments,
        "cwes": _cna_cwes(cna.get("problemTypes")),
        "products": products,
        "fixed_versions": fixed,
        "references": _cna_references(cna.get("references")),
    }


def coverage_metrics(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "records_with_cvss": 0,
        "records_with_cwe": 0,
        "records_with_affected_versions": 0,
        "records_with_fixed_version": 0,
        "records_with_vendor_advisory": 0,
        "records_missing_nvd": 0,
        "records_with_conflicts": 0,
    }
    for record in records:
        intel = record.get("intelligence")
        if not isinstance(intel, dict):
            counts["records_missing_nvd"] += 1
            continue
        coverage = intel.get("coverage") if isinstance(intel.get("coverage"), dict) else {}
        if coverage.get("has_cvss"):
            counts["records_with_cvss"] += 1
        if coverage.get("has_cwe"):
            counts["records_with_cwe"] += 1
        if coverage.get("has_affected_versions"):
            counts["records_with_affected_versions"] += 1
        if coverage.get("has_fixed_version"):
            counts["records_with_fixed_version"] += 1
        if coverage.get("has_vendor_advisory"):
            counts["records_with_vendor_advisory"] += 1
        if not coverage.get("nvd_available"):
            counts["records_missing_nvd"] += 1
        if intel.get("conflicts"):
            counts["records_with_conflicts"] += 1
    return counts


def _descriptions(cve: CveRecord, nvd: NvdRecord | None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if cve.status == "ok" and cve.description:
        items.append(
            {
                "text": cve.description,
                "source": SOURCE_CNA,
                "source_updated_at": cve.date_updated,
            }
        )
    if nvd and nvd.status == "ok" and nvd.description:
        items.append(
            {
                "text": nvd.description,
                "source": SOURCE_NVD,
                "source_updated_at": nvd.last_modified,
            }
        )
    return items


def _cwes(kev: KevRecord, cna: dict[str, Any], nvd: NvdRecord | None) -> list[dict[str, Any]]:
    assertions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for cwe_id in kev.cwes:
        parsed = parse_cwe_id(cwe_id)
        if not parsed:
            continue
        key = (parsed, SOURCE_KEV)
        if key in seen:
            continue
        seen.add(key)
        assertions.append({"cwe_id": parsed, "name": None, "source": SOURCE_KEV})
    for item in cna.get("cwes") or []:
        if not isinstance(item, dict):
            continue
        key = (item.get("cwe_id"), item.get("source"))
        if key in seen or not item.get("cwe_id"):
            continue
        seen.add(key)  # type: ignore[arg-type]
        assertions.append(item)
    if nvd and nvd.status == "ok":
        for item in nvd.cwes:
            key = (item.get("cwe_id"), item.get("source"))
            if key in seen or not item.get("cwe_id"):
                continue
            seen.add(key)  # type: ignore[arg-type]
            assertions.append(item)
    return assertions


def _cna_assessments(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    assessments: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        for key, version in CNA_METRIC_KEYS:
            block = item.get(key)
            if not isinstance(block, dict):
                continue
            score = block.get("baseScore")
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                continue
            fields = V4_FIELDS if version.startswith("4") else V2_FIELDS if version.startswith("2") else V3_FIELDS
            metrics = {}
            for field in fields:
                text, _ = clean_text_report(block.get(field), 64)
                if text:
                    metrics[field] = text
            assessments.append(
                {
                    "source": SOURCE_CNA,
                    "cvss_version": clean_text_report(block.get("version"), 16)[0] or version,
                    "base_score": float(score),
                    "severity": clean_text_report(block.get("baseSeverity"), 32)[0],
                    "vector": clean_text_report(block.get("vectorString"), 256)[0],
                    "metrics": metrics,
                    "source_updated_at": None,
                }
            )
    return assessments


def _cna_cwes(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    assertions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict):
            continue
        descriptions = row.get("descriptions")
        if not isinstance(descriptions, list):
            continue
        for item in descriptions:
            if not isinstance(item, dict):
                continue
            raw = item.get("cweId") or item.get("description")
            cwe_id = parse_cwe_id(raw) if isinstance(raw, str) else None
            if not cwe_id:
                text, _ = clean_text_report(item.get("description"), 256)
                if text:
                    cwe_id = parse_cwe_id(text.split(":")[0].strip())
            if not cwe_id or cwe_id in seen:
                continue
            seen.add(cwe_id)
            name, _ = clean_text_report(item.get("description"), 256)
            if name and name.upper().startswith(cwe_id):
                if ":" in name:
                    name, _ = clean_text_report(name.split(":", 1)[1], 256)
            assertions.append({"cwe_id": cwe_id, "name": name, "source": SOURCE_CNA})
    return assertions


def _cna_products(
    value: object, config: PulseConfig
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(value, list):
        return [], []
    products: list[dict[str, Any]] = []
    fixed: list[dict[str, Any]] = []
    for item in value[: config.max_products]:
        if not isinstance(item, dict):
            continue
        vendor, _ = clean_text_report(item.get("vendor"), config.max_string_chars)
        product, _ = clean_text_report(item.get("product"), config.max_string_chars)
        default_status, _ = clean_text_report(item.get("defaultStatus"), 32)
        ecosystem, _ = clean_text_report(item.get("packageName"), 128)
        platforms = item.get("platforms")
        platform, _ = clean_text_report(
            platforms[0] if isinstance(platforms, list) and platforms else None,
            128,
        )
        ranges: list[dict[str, Any]] = []
        versions = item.get("versions") if isinstance(item.get("versions"), list) else []
        for row in versions[: config.max_versions_per_product]:
            if not isinstance(row, dict):
                continue
            status, _ = clean_text_report(row.get("status"), 32)
            version, _ = clean_text_report(row.get("version"), 128)
            less_than, _ = clean_text_report(row.get("lessThan"), 128)
            less_eq, _ = clean_text_report(row.get("lessThanOrEqual"), 128)
            version_type, _ = clean_text_report(row.get("versionType"), 64)
            ranges.append(
                {
                    "status": status or default_status or "unknown",
                    "version": version,
                    "greater_than": None,
                    "greater_than_or_equal": None,
                    "less_than": less_than,
                    "less_than_or_equal": less_eq,
                    "version_type": version_type,
                    "platform": platform,
                    "fixed_version": None,
                    "fixed_evidence": None,
                }
            )
            for change in row.get("changes") or []:
                if not isinstance(change, dict):
                    continue
                change_status, _ = clean_text_report(change.get("status"), 32)
                at, _ = clean_text_report(change.get("at"), 128)
                if change_status and change_status.lower() == "fixed" and at:
                    fixed.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "version": at,
                            "source": SOURCE_CNA,
                            "evidence": "cna_changes_status_fixed",
                        }
                    )
        products.append(
            {
                "vendor": vendor,
                "product": product,
                "source": SOURCE_CNA,
                "package_ecosystem": ecosystem,
                "ranges": ranges,
            }
        )
    return products, fixed


def _cna_references(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict):
            continue
        url = sanitize_public_https_url(row.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        tags = [str(tag).lower() for tag in (row.get("tags") or []) if isinstance(tag, str)]
        classification = "other"
        if "vendor-advisory" in tags:
            classification = "vendor_advisory"
        title, _ = clean_text_report(row.get("name"), 256)
        refs.append(
            {
                "url": url,
                "title": title,
                "classification": classification,
                "source": SOURCE_CNA,
                "original_tags": tags[:8],
            }
        )
        if len(refs) >= 32:
            break
    return refs


def _conflicts(
    assessments: list[dict[str, Any]],
    cwes: list[dict[str, Any]],
    products: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    by_version: dict[str, list[dict[str, Any]]] = {}
    for item in assessments:
        by_version.setdefault(str(item.get("cvss_version")), []).append(item)
    for version, rows in sorted(by_version.items()):
        sources = {row.get("source") for row in rows}
        scores = {row.get("base_score") for row in rows}
        vectors = {row.get("vector") for row in rows}
        if len(sources) > 1 and (len(scores) > 1 or len(vectors) > 1):
            conflicts.append(
                {
                    "kind": "cvss",
                    "cvss_version": version,
                    "note": "Independent CVSS assessments disagree and were not merged.",
                    "assertions": [
                        {
                            "source": row.get("source"),
                            "base_score": row.get("base_score"),
                            "severity": row.get("severity"),
                            "vector": row.get("vector"),
                        }
                        for row in rows
                    ],
                }
            )
    cwe_by_source: dict[str, set[str]] = {}
    for item in cwes:
        cwe_by_source.setdefault(str(item.get("source")), set()).add(str(item.get("cwe_id")))
    if SOURCE_CNA in cwe_by_source and SOURCE_NVD in cwe_by_source:
        if cwe_by_source[SOURCE_CNA] != cwe_by_source[SOURCE_NVD]:
            conflicts.append(
                {
                    "kind": "cwe",
                    "note": "CNA and NVD CWE classifications differ.",
                    "assertions": [
                        {"source": source, "cwe_ids": sorted(ids)}
                        for source, ids in sorted(cwe_by_source.items())
                    ],
                }
            )
    cna_products = {
        (item.get("vendor"), item.get("product"))
        for item in products
        if item.get("source") == SOURCE_CNA
    }
    nvd_products = {
        (item.get("vendor"), item.get("product"))
        for item in products
        if item.get("source") == SOURCE_NVD
    }
    if cna_products and nvd_products and cna_products != nvd_products:
        conflicts.append(
            {
                "kind": "affected_products",
                "note": (
                    "CNA and NVD product inventories differ. Ranges were not merged."
                ),
                "cna_products": _product_list(cna_products),
                "nvd_products": _product_list(nvd_products),
            }
        )
    return conflicts


def _product_list(pairs: set[tuple[Any, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(pairs, key=lambda pair: (str(pair[0] or ""), str(pair[1] or "")))
    return [{"vendor": vendor, "product": product} for vendor, product in ordered]


def _cvss_preference(assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(
        assessments,
        key=lambda item: (
            CVSS_VERSION_RANK.get(str(item.get("cvss_version")), 99),
            CVSS_SOURCE_RANK.get(str(item.get("source")), 99),
            str(item.get("vector") or ""),
        ),
    )
    return [
        {
            "source": item.get("source"),
            "cvss_version": item.get("cvss_version"),
            "base_score": item.get("base_score"),
        }
        for item in ranked
    ]


def _has_affected_ranges(products: list[dict[str, Any]]) -> bool:
    for product in products:
        ranges = product.get("ranges")
        if not isinstance(ranges, list):
            continue
        for row in ranges:
            if not isinstance(row, dict):
                continue
            if row.get("status") != "affected":
                continue
            if any(
                row.get(key)
                for key in (
                    "version",
                    "less_than",
                    "less_than_or_equal",
                    "greater_than",
                    "greater_than_or_equal",
                )
            ):
                return True
    return False


def _cve_completeness(cve: CveRecord) -> str:
    if cve.status != "ok":
        return "unavailable"
    if cve.truncated_fields or cve.omitted_product_count or cve.omitted_version_count:
        return "partial"
    return "available"


def _nvd_completeness(nvd: NvdRecord | None) -> str:
    if nvd is None or nvd.status != "ok":
        return "unavailable"
    if nvd.truncated_fields:
        return "partial"
    return "available"


def _without_keys(value: object, keys: tuple[str, ...]) -> object:
    if not isinstance(value, dict):
        return value
    return {key: item for key, item in value.items() if key not in keys}


def _sorted_dicts(value: object) -> list[Any]:
    if not isinstance(value, list):
        return []
    return sorted(value, key=lambda item: repr(item))
