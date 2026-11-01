"""Per-CVE published-to-published history from immutable snapshots.

History is generated only from published snapshots. Collect-time candidate
diffs are never consulted. Missing fields are recorded as unavailable, never
invented. Extraction/remediation enrichment is labeled separately from
confirmed upstream KEV/CVE/CVSS changes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.store import atomic_write_json, load_json_file, load_snapshot

HISTORY_SCHEMA_VERSION = "1.0.0"
MAX_HISTORY_SNAPSHOTS = 36
MAX_HISTORY_EVENTS_PER_CVE = 48
HISTORY_INDEX_NAME = "history/index.json"
HISTORY_CVE_DIR = "history/cves"

KEV_FIELDS = (
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "short_description",
    "required_action",
    "due_date",
    "known_ransomware_campaign_use",
    "notes",
    "cwes",
)
CVE_CORE_FIELDS = (
    "description",
    "title",
    "state",
    "assigner_short_name",
    "date_updated",
)
CVSS_FIELDS = ("base_score", "base_severity", "vector")

def write_cve_history(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    index = build_cve_history(
        published_dir, max_bytes=max_bytes, max_depth=max_depth
    )
    _replace_history_tree(published_dir, index)
    return index["index"]


def build_cve_history(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    snapshots = _load_published_snapshots(
        published_dir, max_bytes=max_bytes, max_depth=max_depth
    )
    bounded = snapshots[-MAX_HISTORY_SNAPSHOTS:]
    dropped = max(0, len(snapshots) - len(bounded))
    coverage = "bounded" if dropped else "complete_for_retained_snapshots"
    first_retained = bounded[0]["snapshot_id"] if bounded else None
    per_cve: dict[str, dict[str, Any]] = {}
    for snapshot in bounded:
        generated_at = snapshot.get("generated_at")
        snapshot_id = snapshot.get("snapshot_id")
        if not isinstance(snapshot_id, str) or not isinstance(generated_at, str):
            continue
        for record in snapshot.get("records") or []:
            if not isinstance(record, dict):
                continue
            try:
                cve_id = parse_cve_id(record.get("cve_id"))
            except ValidationError:
                continue
            entry = per_cve.setdefault(cve_id, _empty_history(cve_id, coverage, dropped))
            view = _record_view(record)
            if entry["first_observed_snapshot_id"] is None:
                entry["first_observed_snapshot_id"] = snapshot_id
                entry["first_observed_generated_at"] = generated_at
                entry["first_observed_may_be_incomplete"] = bool(
                    dropped and snapshot_id == first_retained
                )
                entry["kev_date_added"] = view["kev_date_added"]
                entry["events"].append(
                    {
                        "kind": "first_observed",
                        "classification": "published_observation",
                        "snapshot_id": snapshot_id,
                        "generated_at": generated_at,
                        "note": (
                            "First appearance in the retained published snapshot set. "
                            "This is not CISA KEV dateAdded."
                        ),
                    }
                )
            else:
                previous = entry["_previous"]
                events = _diff_views(
                    previous,
                    view,
                    snapshot_id=snapshot_id,
                    generated_at=generated_at,
                )
                entry["events"].extend(events)
            entry["_previous"] = view
            entry["latest_snapshot_id"] = snapshot_id
            entry["latest_generated_at"] = generated_at
            if view["kev_date_added"] not in (None, "unavailable"):
                entry["kev_date_added"] = view["kev_date_added"]

    documents = []
    for cve_id in sorted(per_cve):
        document = per_cve[cve_id]
        document.pop("_previous", None)
        events = document["events"][:MAX_HISTORY_EVENTS_PER_CVE]
        if len(document["events"]) > MAX_HISTORY_EVENTS_PER_CVE:
            document["events_truncated"] = True
        document["events"] = events
        document["event_count"] = len(events)
        documents.append(document)

    index = {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "generated_from": "published_snapshots",
        "coverage": coverage,
        "retained_snapshot_count": len(bounded),
        "omitted_older_snapshot_count": dropped,
        "max_snapshots": MAX_HISTORY_SNAPSHOTS,
        "cve_count": len(documents),
        "cves": [
            {
                "cve_id": item["cve_id"],
                "first_observed_snapshot_id": item["first_observed_snapshot_id"],
                "first_observed_generated_at": item["first_observed_generated_at"],
                "first_observed_may_be_incomplete": item["first_observed_may_be_incomplete"],
                "kev_date_added": item["kev_date_added"],
                "event_count": item["event_count"],
                "path": f"cves/{item['cve_id']}.json",
            }
            for item in documents
        ],
        "note": (
            "History is published-to-published only. Collect-time candidate "
            "changes are excluded. Remediation and completeness events are "
            "extraction enrichment, not confirmed upstream vulnerability changes. "
            "Values absent from earlier snapshots are marked unavailable, not invented."
        ),
    }
    return {"index": index, "documents": documents}


def load_cve_history_document(published_dir: Path, cve_id: str, *, max_bytes: int, max_depth: int) -> dict[str, Any]:
    parsed = parse_cve_id(cve_id)
    path = published_dir / HISTORY_CVE_DIR / f"{parsed}.json"
    return load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)


def _empty_history(cve_id: str, coverage: str, dropped: int) -> dict[str, Any]:
    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "cve_id": cve_id,
        "coverage": coverage,
        "omitted_older_snapshot_count": dropped,
        "first_observed_snapshot_id": None,
        "first_observed_generated_at": None,
        "first_observed_may_be_incomplete": False,
        "kev_date_added": "unavailable",
        "latest_snapshot_id": None,
        "latest_generated_at": None,
        "events": [],
        "events_truncated": False,
        "note": (
            "kev_date_added is the CISA KEV dateAdded field. first_observed is "
            "the first retained published snapshot that contained this CVE."
        ),
        "_previous": None,
    }


def _load_published_snapshots(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> list[dict[str, Any]]:
    snapshot_dir = published_dir / "snapshots"
    files = []
    if snapshot_dir.is_dir():
        files.extend(sorted(snapshot_dir.glob("*.json")))
    latest = published_dir / "latest.json"
    snapshots: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in files:
        try:
            payload = load_snapshot(path, max_bytes=max_bytes, max_depth=max_depth, compatible=True)
        except (ValidationError, OSError):
            continue
        snapshot_id = payload.get("snapshot_id")
        if not isinstance(snapshot_id, str) or snapshot_id in seen:
            continue
        seen.add(snapshot_id)
        snapshots.append(payload)
    if latest.exists():
        try:
            payload = load_snapshot(latest, max_bytes=max_bytes, max_depth=max_depth, compatible=True)
        except (ValidationError, OSError):
            payload = None
        if payload:
            snapshot_id = payload.get("snapshot_id")
            if isinstance(snapshot_id, str) and snapshot_id not in seen:
                snapshots.append(payload)
    snapshots.sort(key=lambda item: (str(item.get("generated_at") or ""), str(item.get("snapshot_id") or "")))
    return snapshots


def _record_view(record: dict[str, Any]) -> dict[str, Any]:
    kev = record.get("kev") if isinstance(record.get("kev"), dict) else {}
    cve = record.get("cve") if isinstance(record.get("cve"), dict) else {}
    severity = cve.get("severity") if isinstance(cve.get("severity"), dict) else {}
    remediation = record.get("remediation") if isinstance(record.get("remediation"), dict) else {}
    items = remediation.get("items") if isinstance(remediation.get("items"), list) else []
    products = cve.get("products") if isinstance(cve.get("products"), list) else None
    return {
        "kev": {field: _present(kev.get(field)) for field in KEV_FIELDS},
        "kev_date_added": _present(kev.get("date_added")),
        "cve": {field: _present(cve.get(field)) for field in CVE_CORE_FIELDS},
        "products": _canonicalize(products) if products is not None else "unavailable",
        "products_available": products is not None,
        "cvss": {field: _present(severity.get(field)) for field in CVSS_FIELDS},
        "completeness": _present(record.get("completeness")),
        "remediation_status": _present(remediation.get("status")),
        "remediation_items": _canonicalize(items) if items else "unavailable",
        "field_evidence": "available",
    }


def _diff_views(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
    *,
    snapshot_id: str,
    generated_at: str,
) -> list[dict[str, Any]]:
    if not previous:
        return []
    events: list[dict[str, Any]] = []
    kev_changes = _changed_fields(previous["kev"], current["kev"])
    if kev_changes:
        events.append(
            _event(
                "kev_field_change",
                "upstream_kev",
                snapshot_id,
                generated_at,
                kev_changes,
                "CISA KEV field values changed between published snapshots.",
            )
        )
    cve_changes = _changed_fields(previous["cve"], current["cve"])
    product_change = _value_change(previous["products"], current["products"])
    if product_change is not None and current["products_available"] and previous["products_available"]:
        cve_changes.append({"field": "products", **product_change})
    elif product_change is not None:
        cve_changes.append(
            {
                "field": "products",
                "before": previous["products"],
                "after": current["products"],
                "coverage": "incomplete",
                "note": "One or both snapshots lacked structured product evidence.",
            }
        )
    if cve_changes:
        events.append(
            _event(
                "cna_change",
                "upstream_cve",
                snapshot_id,
                generated_at,
                cve_changes,
                "CNA CVE description, products, or versions changed when structured data existed.",
            )
        )
    cvss_changes = _changed_fields(previous["cvss"], current["cvss"])
    if cvss_changes:
        events.append(
            _event(
                "cvss_change",
                "upstream_cvss",
                snapshot_id,
                generated_at,
                cvss_changes,
                "CVSS score or severity changed between published snapshots.",
            )
        )
    if previous["completeness"] != current["completeness"]:
        events.append(
            _event(
                "completeness_change",
                "extraction_enrichment",
                snapshot_id,
                generated_at,
                [
                    {
                        "field": "completeness",
                        "before": previous["completeness"],
                        "after": current["completeness"],
                    }
                ],
                "Extraction completeness changed. This is not a confirmed upstream vulnerability change.",
            )
        )
    rem_change = _value_change(previous["remediation_items"], current["remediation_items"])
    if rem_change is not None or previous["remediation_status"] != current["remediation_status"]:
        events.append(
            _event(
                "remediation_change",
                "extraction_enrichment",
                snapshot_id,
                generated_at,
                [
                    {
                        "field": "remediation",
                        "before": {
                            "status": previous["remediation_status"],
                            "items": previous["remediation_items"],
                        },
                        "after": {
                            "status": current["remediation_status"],
                            "items": current["remediation_items"],
                        },
                    }
                ],
                "Newly available or modified extracted remediation evidence. Not a confirmed upstream KEV/CVE fact change.",
            )
        )
    return events


def _event(
    kind: str,
    classification: str,
    snapshot_id: str,
    generated_at: str,
    changes: list[dict[str, Any]],
    note: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "classification": classification,
        "snapshot_id": snapshot_id,
        "generated_at": generated_at,
        "changes": changes,
        "note": note,
    }


def _changed_fields(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    changes = []
    for field in before:
        change = _value_change(before.get(field), after.get(field))
        if change is not None:
            changes.append({"field": field, **change})
    return changes


def _value_change(before: Any, after: Any) -> dict[str, Any] | None:
    if before == after:
        return None
    payload = {"before": before, "after": after}
    if before == "unavailable" or after == "unavailable":
        payload["coverage"] = "incomplete"
        payload["note"] = "A value was unavailable in one snapshot and was not invented."
    return payload


def _present(value: Any) -> Any:
    if value is None or value == "":
        return "unavailable"
    if isinstance(value, list):
        return _canonicalize(value)
    return value


def _canonicalize(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    return value


def _replace_history_tree(published_dir: Path, built: dict[str, Any]) -> None:
    history_root = published_dir / "history"
    cve_dir = published_dir / HISTORY_CVE_DIR
    if history_root.exists():
        for path in sorted(history_root.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    pass
    cve_dir.mkdir(parents=True, exist_ok=True)
    for document in built["documents"]:
        parse_cve_id(document["cve_id"])
        atomic_write_json(cve_dir / f"{document['cve_id']}.json", document)
    atomic_write_json(published_dir / HISTORY_INDEX_NAME, built["index"])
