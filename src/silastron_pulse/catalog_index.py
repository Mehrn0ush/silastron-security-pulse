"""Split the published snapshot into a small browser index and per-CVE detail.

The full snapshot (latest.json) stays the single full-fidelity source of
truth used for integrity checks, rollback, and CVE history. It is no longer
what the browser downloads. Instead:

- catalog-index.json: one small entry per record with exactly the fields the
  explorer table, its filters, and CSV export use. No full intelligence
  object, no unbounded product/version lists.
- cve/<CVE_ID>.json: the same entry plus the full intelligence object, for
  the CVE detail view, fetched on demand.

This mirrors (and replaces) the client-side `compactRecord` derivation that
used to run after downloading the entire snapshot; the derived fields are
now computed once, here, instead of once per browser.
"""

from __future__ import annotations

from typing import Any

from silastron_pulse.constants import CATALOG_INDEX_SCHEMA_VERSION, CVE_DETAIL_SCHEMA_VERSION

PRODUCT_DETAIL_LIMIT = 8
VERSION_DETAIL_LIMIT = 3


def _assessments(record: dict[str, Any]) -> list[dict[str, Any]]:
    intel = record.get("intelligence")
    if not isinstance(intel, dict):
        return []
    cvss = intel.get("cvss")
    if not isinstance(cvss, dict):
        return []
    assessments = cvss.get("assessments")
    return assessments if isinstance(assessments, list) else []


def _sorted_values(record: dict[str, Any], key: str) -> list[str]:
    seen: set[str] = set()
    for item in _assessments(record):
        if isinstance(item, dict) and item.get(key):
            seen.add(str(item[key]))
    return sorted(seen)


def _sorted_metrics(record: dict[str, Any], key: str) -> list[str]:
    seen: set[str] = set()
    for item in _assessments(record):
        if not isinstance(item, dict):
            continue
        metrics = item.get("metrics")
        metrics = metrics if isinstance(metrics, dict) else {}
        value = metrics.get(key) or (metrics.get("accessVector") if key == "attackVector" else None)
        if value:
            seen.add(str(value))
    return sorted(seen)


def _coverage_flag(record: dict[str, Any], key: str) -> bool | None:
    intel = record.get("intelligence")
    coverage = intel.get("coverage") if isinstance(intel, dict) else None
    if not isinstance(coverage, dict):
        return None
    return coverage.get(key) is True


def _ssvc(record: dict[str, Any]) -> dict[str, str]:
    """CISA ADP SSVC decision points, each 'unavailable' when not present.

    These are source-attributed facts copied from the CVE record, never a
    derived score or priority.
    """
    intel = record.get("intelligence")
    adp = intel.get("cisa_adp") if isinstance(intel, dict) else None
    ssvc = adp.get("ssvc") if isinstance(adp, dict) else None
    ssvc = ssvc if isinstance(ssvc, dict) else {}
    return {
        "ssvc_exploitation": ssvc.get("exploitation") or "unavailable",
        "ssvc_automatable": ssvc.get("automatable") or "unavailable",
        "ssvc_technical_impact": ssvc.get("technical_impact") or "unavailable",
    }


def _nvd_status(record: dict[str, Any]) -> str:
    intel = record.get("intelligence")
    sources = intel.get("sources") if isinstance(intel, dict) else None
    nvd = sources.get("nvd") if isinstance(sources, dict) else None
    if not isinstance(nvd, dict):
        return "unavailable"
    return nvd.get("status") or "unavailable"


def _conflict_kinds(record: dict[str, Any]) -> list[str]:
    intel = record.get("intelligence")
    conflicts = intel.get("conflicts") if isinstance(intel, dict) else None
    if not isinstance(conflicts, list):
        return []
    return [str(item["kind"]) for item in conflicts if isinstance(item, dict) and item.get("kind")]


def _cwe_ids(record: dict[str, Any]) -> list[str]:
    ids: set[str] = set()
    kev = record.get("kev") or {}
    for item in kev.get("cwes") or []:
        if item:
            ids.add(str(item))
    intel = record.get("intelligence")
    cwes = intel.get("cwes") if isinstance(intel, dict) else None
    assertions = cwes.get("assertions") if isinstance(cwes, dict) else None
    for item in assertions or []:
        if isinstance(item, dict) and item.get("cwe_id"):
            ids.add(str(item["cwe_id"]))
    return sorted(ids)


def _remediation_kinds(remediation: dict[str, Any] | None) -> list[str]:
    items = remediation.get("items") if isinstance(remediation, dict) else None
    if not isinstance(items, list):
        return []
    return [str(item["kind"]) for item in items if isinstance(item, dict) and item.get("kind")]


def _fallback_remediation(kev: dict[str, Any]) -> dict[str, Any]:
    items = []
    if kev.get("required_action"):
        items.append(
            {
                "kind": "required_action",
                "source": "cisa_kev",
                "attribution": "CISA KEV requiredAction",
                "text": kev["required_action"],
            }
        )
    if kev.get("notes"):
        items.append(
            {
                "kind": "reference",
                "source": "cisa_kev",
                "attribution": "CISA KEV notes",
                "text": kev["notes"],
            }
        )
    return {"status": "available" if items else "unavailable", "items": items}


def catalog_entry(record: dict[str, Any]) -> dict[str, Any]:
    """The compact fields the explorer table, its filters, and CSV export use.

    This never includes the full `intelligence` object; only derived
    summary fields computed from it.
    """
    cve = record.get("cve") or {}
    kev = record.get("kev") or {}
    epss = record.get("epss") or {}
    links = record.get("links") or {}
    severity = cve.get("severity") if isinstance(cve.get("severity"), dict) else {}
    products = (cve.get("products") or [])[:PRODUCT_DETAIL_LIMIT]
    remediation = record.get("remediation") or _fallback_remediation(kev)
    truncated_fields = list(cve.get("truncated_fields") or []) + list(kev.get("truncated_fields") or [])
    product_strings = []
    for item in products:
        if not isinstance(item, dict):
            continue
        versions = (item.get("versions") or [])[:VERSION_DETAIL_LIMIT]
        label = " / ".join(str(part) for part in (item.get("vendor"), item.get("product"), item.get("status")) if part)
        if versions:
            label += " (" + ", ".join(str(v) for v in versions) + ")"
        if label:
            product_strings.append(label)
    base_score = severity.get("base_score")
    return {
        "cve_id": record.get("cve_id"),
        "vendor_project": kev.get("vendor_project"),
        "product": kev.get("product"),
        "vulnerability_name": kev.get("vulnerability_name"),
        "kev_date_added": kev.get("date_added"),
        "kev_listed": kev.get("listed") is not False,
        "completeness": record.get("completeness"),
        "omitted_product_count": cve.get("omitted_product_count") or 0,
        "omitted_version_count": cve.get("omitted_version_count") or 0,
        "truncated_fields": truncated_fields,
        "partial": bool(cve.get("truncated_fields")) or cve.get("status") != "ok",
        "cvss_base_score": base_score,
        "severity_status": "unavailable" if base_score is None else "available",
        "cvss_vector": severity.get("vector"),
        "epss_status": epss.get("status"),
        "epss_score": epss.get("score"),
        "short_description": kev.get("short_description"),
        "required_action": kev.get("required_action"),
        "due_date": kev.get("due_date"),
        "known_ransomware_campaign_use": kev.get("known_ransomware_campaign_use"),
        "cwes": list(kev.get("cwes") or []),
        "cve_state": cve.get("state"),
        "cve_description": cve.get("description"),
        "products": product_strings,
        "remediation": remediation,
        "remediation_kinds": _remediation_kinds(remediation),
        "links": {
            "cve_record": links.get("cve_record"),
            "kev_catalog": links.get("kev_catalog"),
            "cvelist_v5": links.get("cvelist_v5"),
            "nvd": links.get("nvd"),
        },
        "cwe_ids": _cwe_ids(record),
        "cvss_versions": _sorted_values(record, "cvss_version"),
        "cvss_sources": _sorted_values(record, "source"),
        "attack_vector": _sorted_metrics(record, "attackVector"),
        "privileges_required": _sorted_metrics(record, "privilegesRequired"),
        "user_interaction": _sorted_metrics(record, "userInteraction"),
        "has_fixed_version": _coverage_flag(record, "has_fixed_version"),
        "has_vendor_advisory": _coverage_flag(record, "has_vendor_advisory"),
        "has_affected_versions": _coverage_flag(record, "has_affected_versions"),
        "nvd_status": _nvd_status(record),
        "source_conflicts": _conflict_kinds(record),
        **_ssvc(record),
    }


def build_catalog_index(snapshot: dict[str, Any]) -> dict[str, Any]:
    records = snapshot.get("records") or []
    return {
        "schema_version": CATALOG_INDEX_SCHEMA_VERSION,
        "snapshot_id": snapshot.get("snapshot_id"),
        "generated_at": snapshot.get("generated_at"),
        "record_count": len(records),
        "note": (
            "Compact index for the explorer table, its filters, and CSV "
            "export. Full source-attributed intelligence (CVSS detail, CWE "
            "names, affected ranges, references, conflicts) is not included "
            "here; fetch cve/<CVE_ID>.json for one record's full detail."
        ),
        "records": [catalog_entry(record) for record in records],
    }


def build_cve_detail(record: dict[str, Any]) -> dict[str, Any]:
    """The full per-CVE detail document: the catalog entry plus intelligence."""
    entry = catalog_entry(record)
    entry["schema_version"] = CVE_DETAIL_SCHEMA_VERSION
    entry["intelligence"] = record.get("intelligence")
    return entry
