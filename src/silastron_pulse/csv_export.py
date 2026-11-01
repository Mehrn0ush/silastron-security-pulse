"""UTF-8 CSV helpers with spreadsheet formula-injection protection.

The explorer exports in the browser using the same quoting and sanitization
rules. Unavailable values stay explicit. EPSS columns are omitted while EPSS
publication remains disabled.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
UNAVAILABLE = "unavailable"

CSV_COLUMNS = (
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "kev_date_added",
    "kev_due_date",
    "known_ransomware_campaign_use",
    "short_description",
    "required_action",
    "cwes",
    "completeness",
    "cvss_base_score",
    "cvss_severity_status",
    "cvss_vector",
    "cve_state",
    "cve_description",
    "remediation_status",
    "remediation_kinds",
    "omitted_product_count",
    "omitted_version_count",
    "snapshot_id",
    "snapshot_generated_at",
    "kev_catalog_url",
    "cve_record_url",
    "cvelist_v5_url",
    "nvd_url",
    "nvd_status",
    "cvss_versions",
    "cvss_sources",
    "attack_vector",
    "privileges_required",
    "user_interaction",
    "cwe_ids",
    "has_fixed_version",
    "has_vendor_advisory",
    "has_affected_versions",
    "source_conflicts",
)


def sanitize_csv_cell(value: object) -> str:
    if value is None or value == "":
        text = UNAVAILABLE
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (list, tuple)):
        if not value:
            text = UNAVAILABLE
        else:
            text = "; ".join(sanitize_csv_cell(item) for item in value)
            return _neutralize(text)
    else:
        text = str(value)
    return _neutralize(text)


def _neutralize(text: str) -> str:
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def export_rows(
    rows: Iterable[dict[str, Any]],
    *,
    snapshot_id: str | None,
    snapshot_generated_at: str | None,
) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow([sanitize_csv_cell(_cell(row, column, snapshot_id, snapshot_generated_at)) for column in CSV_COLUMNS])
    return buffer.getvalue()


def _cell(
    row: dict[str, Any],
    column: str,
    snapshot_id: str | None,
    snapshot_generated_at: str | None,
) -> object:
    if column == "kev_due_date":
        return row.get("due_date")
    if column == "cvss_severity_status":
        return row.get("severity_status") or UNAVAILABLE
    if column == "cwes":
        return row.get("cwes") or UNAVAILABLE
    if column == "remediation_status":
        remediation = row.get("remediation")
        if isinstance(remediation, dict):
            return remediation.get("status") or UNAVAILABLE
        return row.get("remediation_status") or UNAVAILABLE
    if column == "remediation_kinds":
        kinds = row.get("remediation_kinds")
        if kinds:
            return kinds
        remediation = row.get("remediation")
        if isinstance(remediation, dict) and isinstance(remediation.get("items"), list):
            return [item.get("kind") for item in remediation["items"] if isinstance(item, dict)]
        return UNAVAILABLE
    if column == "snapshot_id":
        return row.get("snapshot_id") or snapshot_id
    if column == "snapshot_generated_at":
        return row.get("snapshot_generated_at") or snapshot_generated_at
    if column == "kev_catalog_url":
        return (row.get("links") or {}).get("kev_catalog")
    if column == "cve_record_url":
        return (row.get("links") or {}).get("cve_record")
    if column == "cvelist_v5_url":
        return (row.get("links") or {}).get("cvelist_v5")
    if column == "nvd_url":
        return (row.get("links") or {}).get("nvd")
    intelligence = row.get("intelligence") if isinstance(row.get("intelligence"), dict) else {}
    coverage = intelligence.get("coverage") if isinstance(intelligence.get("coverage"), dict) else {}
    sources = intelligence.get("sources") if isinstance(intelligence.get("sources"), dict) else {}
    if column == "nvd_status":
        return (sources.get("nvd") or {}).get("status") or row.get("nvd_status") or UNAVAILABLE
    if column == "cvss_versions":
        versions = row.get("cvss_versions")
        if versions:
            return versions
        assessments = ((intelligence.get("cvss") or {}).get("assessments")) if isinstance(intelligence.get("cvss"), dict) else []
        if isinstance(assessments, list) and assessments:
            return sorted({str(item.get("cvss_version")) for item in assessments if isinstance(item, dict) and item.get("cvss_version")})
        return UNAVAILABLE
    if column == "cvss_sources":
        sources_col = row.get("cvss_sources")
        if sources_col:
            return sources_col
        assessments = ((intelligence.get("cvss") or {}).get("assessments")) if isinstance(intelligence.get("cvss"), dict) else []
        if isinstance(assessments, list) and assessments:
            return sorted({str(item.get("source")) for item in assessments if isinstance(item, dict) and item.get("source")})
        return UNAVAILABLE
    if column in {"attack_vector", "privileges_required", "user_interaction"}:
        if row.get(column):
            return row.get(column)
        assessments = ((intelligence.get("cvss") or {}).get("assessments")) if isinstance(intelligence.get("cvss"), dict) else []
        key = {
            "attack_vector": "attackVector",
            "privileges_required": "privilegesRequired",
            "user_interaction": "userInteraction",
        }[column]
        values = []
        if isinstance(assessments, list):
            for item in assessments:
                if not isinstance(item, dict):
                    continue
                metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
                value = metrics.get(key) or metrics.get(key.replace("attackVector", "accessVector"))
                if value:
                    values.append(f"{item.get('source')}:{item.get('cvss_version')}:{value}")
        return values or UNAVAILABLE
    if column == "cwe_ids":
        if row.get("cwe_ids"):
            return row.get("cwe_ids")
        assertions = ((intelligence.get("cwes") or {}).get("assertions")) if isinstance(intelligence.get("cwes"), dict) else []
        if isinstance(assertions, list) and assertions:
            return sorted({str(item.get("cwe_id")) for item in assertions if isinstance(item, dict) and item.get("cwe_id")})
        return row.get("cwes") or UNAVAILABLE
    if column == "has_fixed_version":
        if row.get("has_fixed_version") is not None:
            return row.get("has_fixed_version")
        if not intelligence:
            return UNAVAILABLE
        return True if coverage.get("has_fixed_version") else False
    if column == "has_vendor_advisory":
        if row.get("has_vendor_advisory") is not None:
            return row.get("has_vendor_advisory")
        if not intelligence:
            return UNAVAILABLE
        return True if coverage.get("has_vendor_advisory") else False
    if column == "has_affected_versions":
        if row.get("has_affected_versions") is not None:
            return row.get("has_affected_versions")
        if not intelligence:
            return UNAVAILABLE
        return True if coverage.get("has_affected_versions") else False
    if column == "source_conflicts":
        if row.get("source_conflicts") is not None:
            return row.get("source_conflicts")
        conflicts = intelligence.get("conflicts")
        if isinstance(conflicts, list) and conflicts:
            return [item.get("kind") for item in conflicts if isinstance(item, dict)]
        return UNAVAILABLE
    return row.get(column)
