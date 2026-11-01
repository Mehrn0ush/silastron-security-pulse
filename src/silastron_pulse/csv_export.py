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
    return row.get(column)
