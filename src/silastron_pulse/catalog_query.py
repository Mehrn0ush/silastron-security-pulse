"""Deterministic catalog filter, sort, and pagination used by explorer tests.

The browser explorer implements the same rules in preview/app.js. Missing
CWE, version, or remediation values are never fabricated.
"""

from __future__ import annotations

from typing import Any, Iterable

UNAVAILABLE = "unavailable"


def row_matches(row: dict[str, Any], filters: dict[str, Any]) -> bool:
    query = str(filters.get("query") or "").strip().lower()
    if query:
        haystack = " ".join(
            str(row.get(key) or "")
            for key in ("cve_id", "vendor_project", "product", "vulnerability_name", "cve_description")
        ).lower()
        if query not in haystack:
            return False
    vendor = filters.get("vendor") or "all"
    if vendor != "all" and (row.get("vendor_project") or UNAVAILABLE) != vendor:
        return False
    product = filters.get("product") or "all"
    if product != "all" and (row.get("product") or UNAVAILABLE) != product:
        return False
    completeness = filters.get("completeness") or "all"
    if completeness != "all" and row.get("completeness") != completeness:
        return False
    if not _cvss_matches(row, filters):
        return False
    if not _date_in_range(row.get("kev_date_added"), filters.get("date_from"), filters.get("date_to")):
        return False
    cwe = filters.get("cwe") or "all"
    cwes = row.get("cwes")
    if cwe == "unavailable":
        if isinstance(cwes, list) and cwes:
            return False
    elif cwe != "all":
        if not isinstance(cwes, list) or cwe not in cwes:
            return False
    truncated = filters.get("truncated") or "all"
    is_truncated = "versions" in (row.get("truncated_fields") or []) or int(row.get("omitted_version_count") or 0) > 0
    if truncated == "truncated" and not is_truncated:
        return False
    remediation = filters.get("remediation") or "all"
    if not _remediation_matches(row, remediation):
        return False
    if not _list_filter(row.get("cvss_versions"), filters.get("cvss_version")):
        return False
    if not _list_filter(row.get("attack_vector"), filters.get("attack_vector")):
        return False
    if not _list_filter(row.get("privileges_required"), filters.get("privileges_required")):
        return False
    if not _list_filter(row.get("user_interaction"), filters.get("user_interaction")):
        return False
    if not _flag_filter(row.get("has_fixed_version"), filters.get("fixed_version")):
        return False
    if not _flag_filter(row.get("has_vendor_advisory"), filters.get("vendor_advisory")):
        return False
    nvd = filters.get("nvd") or "all"
    if nvd == "ok" and row.get("nvd_status") != "ok":
        return False
    if nvd == "unavailable" and row.get("nvd_status") == "ok":
        return False
    if not _ssvc_filter(row.get("ssvc_exploitation"), filters.get("ssvc_exploitation")):
        return False
    if not _ssvc_filter(row.get("ssvc_automatable"), filters.get("ssvc_automatable")):
        return False
    if not _ssvc_filter(row.get("ssvc_technical_impact"), filters.get("ssvc_technical_impact")):
        return False
    return True


def sort_rows(rows: Iterable[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    copy = list(rows)
    if key == "cvss_base_score":
        copy.sort(
            key=lambda row: (
                row.get("cvss_base_score") is None,
                -(row.get("cvss_base_score") or 0),
                str(row.get("cve_id") or ""),
            )
        )
        return copy
    if key == "cve_id":
        copy.sort(key=lambda row: str(row.get("cve_id") or ""))
        return copy
    if key == "vendor_project":
        copy.sort(key=lambda row: (str(row.get("vendor_project") or ""), str(row.get("cve_id") or "")))
        return copy
    copy.sort(key=lambda row: (str(row.get("kev_date_added") or ""), str(row.get("cve_id") or "")), reverse=True)
    # Newest KEV date first; when dates match, higher CVE last like the UI localeCompare reverse on date then cve.
    copy.sort(key=lambda row: str(row.get("cve_id") or ""), reverse=True)
    copy.sort(key=lambda row: str(row.get("kev_date_added") or ""), reverse=True)
    return copy


def paginate(rows: list[dict[str, Any]], *, page: int, page_size: int) -> dict[str, Any]:
    page_size = max(1, page_size)
    max_page = max(0, (len(rows) + page_size - 1) // page_size - 1) if rows else 0
    page = min(max(0, page), max_page)
    start = page * page_size
    page_rows = rows[start : start + page_size]
    return {
        "page": page,
        "page_size": page_size,
        "total": len(rows),
        "rows": page_rows,
        "start": start + 1 if page_rows else 0,
        "end": start + len(page_rows),
    }


def apply_catalog_filters(rows: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
    matched = [row for row in rows if row_matches(row, filters)]
    return sort_rows(matched, str(filters.get("sort") or "kev_date_added"))


def unique_values(rows: Iterable[dict[str, Any]], field: str) -> list[str]:
    values = []
    seen = set()
    for row in rows:
        value = row.get(field)
        if not value or value == UNAVAILABLE:
            continue
        if value in seen:
            continue
        seen.add(value)
        values.append(str(value))
    return sorted(values)


def unique_cwes(rows: Iterable[dict[str, Any]]) -> list[str]:
    values = []
    seen = set()
    for row in rows:
        cwes = row.get("cwes")
        if not isinstance(cwes, list):
            continue
        for cwe in cwes:
            if not cwe or cwe in seen:
                continue
            seen.add(cwe)
            values.append(str(cwe))
    return sorted(values)


def _cvss_matches(row: dict[str, Any], filters: dict[str, Any]) -> bool:
    band = filters.get("cvss") or "all"
    score = row.get("cvss_base_score")
    status = row.get("severity_status")
    available = score is not None and status == "available"
    if band == "unavailable":
        return not available
    if band == "critical":
        return available and float(score) >= 9
    if band == "high":
        return available and 7 <= float(score) < 9
    if band == "medium":
        return available and 4 <= float(score) < 7
    if band == "low":
        return available and 0 < float(score) < 4
    low = filters.get("cvss_min")
    high = filters.get("cvss_max")
    if low in (None, "") and high in (None, "") and band == "all":
        return True
    if not available:
        return False
    numeric = float(score)
    if low not in (None, "") and numeric < float(low):
        return False
    if high not in (None, "") and numeric > float(high):
        return False
    return True


def _date_in_range(value: object, start: object, end: object) -> bool:
    if not start and not end:
        return True
    if not isinstance(value, str) or not value:
        return False
    if start and value < str(start):
        return False
    if end and value > str(end):
        return False
    return True


def _remediation_matches(row: dict[str, Any], wanted: str) -> bool:
    if wanted == "all":
        return True
    remediation = row.get("remediation") if isinstance(row.get("remediation"), dict) else {}
    status = remediation.get("status") or row.get("remediation_status") or UNAVAILABLE
    kinds = row.get("remediation_kinds")
    if not kinds and isinstance(remediation.get("items"), list):
        kinds = [item.get("kind") for item in remediation["items"] if isinstance(item, dict)]
    if wanted == "unavailable":
        return status != "available"
    if wanted == "available":
        return status == "available"
    return isinstance(kinds, list) and wanted in kinds


def _list_filter(values: object, wanted: object) -> bool:
    if not wanted or wanted == "all":
        return True
    items = values if isinstance(values, list) else []
    if wanted == "unavailable":
        return not items
    return wanted in items


def _flag_filter(value: object, wanted: object) -> bool:
    if not wanted or wanted == "all":
        return True
    if wanted == "available":
        return value is True
    return value is not True


def _ssvc_filter(value: object, wanted: object) -> bool:
    if not wanted or wanted == "all":
        return True
    return (value or UNAVAILABLE) == wanted
