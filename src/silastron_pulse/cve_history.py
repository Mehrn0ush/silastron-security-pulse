"""Per-CVE published-to-published history from immutable snapshots.

History is generated only from published snapshots. Collect-time candidate
diffs are never consulted. Missing fields are recorded as unavailable, never
invented. Extraction/remediation enrichment is labeled separately from
confirmed upstream KEV/CVE/CVSS changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.intelligence import comparable_intelligence
from silastron_pulse.store import atomic_write_json, load_json_file, load_snapshot

HISTORY_SCHEMA_VERSION = "1.1.0"
MAX_HISTORY_SNAPSHOTS = 36
MAX_HISTORY_EVENTS_PER_CVE = 48
HISTORY_INDEX_NAME = "history/index.json"
HISTORY_CVE_DIR = "history/cves"
HISTORY_LEDGER_DIR = "history/ledger/cves"

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
    ledgers = _load_existing_ledgers(
        published_dir, max_bytes=max_bytes, max_depth=max_depth
    )
    comparison = snapshots[-MAX_HISTORY_SNAPSHOTS:]
    dropped = max(0, len(snapshots) - len(comparison))
    snapshot_ids = {
        item.get("snapshot_id")
        for item in snapshots
        if isinstance(item.get("snapshot_id"), str)
    }
    rebuilt = _rebuild_from_snapshots(snapshots)
    per_cve: dict[str, dict[str, Any]] = {}
    for cve_id in sorted(set(rebuilt) | set(ledgers)):
        per_cve[cve_id] = _merge_history(
            cve_id,
            rebuilt.get(cve_id),
            ledgers.get(cve_id),
            snapshot_ids=snapshot_ids,
            dropped=dropped,
        )

    documents = []
    ledgers_out = []
    for cve_id in sorted(per_cve):
        ledger = per_cve[cve_id]
        ledger.pop("_previous", None)
        events = _dedupe_events(ledger.get("events") or [])
        ledger["events"] = events
        ledger["durable_event_count"] = len(events)
        frontend_events, truncated = _frontend_events(events)
        document = dict(ledger)
        document["events"] = frontend_events
        document["events_truncated"] = truncated
        document["event_count"] = len(frontend_events)
        document["frontend_event_limit"] = MAX_HISTORY_EVENTS_PER_CVE
        documents.append(document)
        ledgers_out.append(ledger)

    coverage = "durable"
    if dropped and not ledgers:
        coverage = "bounded"
    elif not dropped:
        coverage = "complete_for_retained_snapshots"
    index = {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "generated_from": "published_snapshots_and_durable_ledger",
        "coverage": coverage,
        "retained_snapshot_count": len(snapshots),
        "comparison_snapshot_count": len(comparison),
        "omitted_older_snapshot_count": dropped,
        "max_snapshots": MAX_HISTORY_SNAPSHOTS,
        "max_frontend_events_per_cve": MAX_HISTORY_EVENTS_PER_CVE,
        "cve_count": len(documents),
        "cves": [
            {
                "cve_id": item["cve_id"],
                "first_observed_snapshot_id": item["first_observed_snapshot_id"],
                "first_observed_generated_at": item["first_observed_generated_at"],
                "first_observed_may_be_incomplete": item["first_observed_may_be_incomplete"],
                "kev_date_added": item["kev_date_added"],
                "event_count": item["event_count"],
                "durable_event_count": item["durable_event_count"],
                "path": f"cves/{item['cve_id']}.json",
            }
            for item in documents
        ],
        "note": (
            "History is published-to-published only. Collect-time candidate "
            "changes are excluded. Remediation and completeness events are "
            "extraction enrichment, not confirmed upstream vulnerability changes. "
            "Values absent from earlier snapshots are marked unavailable, not invented. "
            "first_observed and events persist in history/ledger after older "
            "immutable snapshots are no longer compared. Frontend CVE files keep "
            f"at most {MAX_HISTORY_EVENTS_PER_CVE} events plus first_observed."
        ),
    }
    return {"index": index, "documents": documents, "ledgers": ledgers_out}


def load_cve_history_document(published_dir: Path, cve_id: str, *, max_bytes: int, max_depth: int) -> dict[str, Any]:
    parsed = parse_cve_id(cve_id)
    path = published_dir / HISTORY_CVE_DIR / f"{parsed}.json"
    return load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)


def _rebuild_from_snapshots(snapshots: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    per_cve: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
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
            entry = per_cve.setdefault(cve_id, _empty_history(cve_id, "complete_for_retained_snapshots", 0))
            view = _record_view(record)
            if entry["first_observed_snapshot_id"] is None:
                entry["first_observed_snapshot_id"] = snapshot_id
                entry["first_observed_generated_at"] = generated_at
                entry["first_observed_may_be_incomplete"] = False
                entry["kev_date_added"] = view["kev_date_added"]
                entry["events"].append(
                    {
                        "kind": "first_observed",
                        "classification": "published_observation",
                        "snapshot_id": snapshot_id,
                        "generated_at": generated_at,
                        "note": (
                            "First verifiable appearance in a published snapshot still "
                            "available when this event was recorded. This is not CISA "
                            "KEV dateAdded."
                        ),
                    }
                )
            else:
                entry["events"].extend(
                    _diff_views(
                        entry["_previous"],
                        view,
                        snapshot_id=snapshot_id,
                        generated_at=generated_at,
                    )
                )
            entry["_previous"] = view
            entry["latest_snapshot_id"] = snapshot_id
            entry["latest_generated_at"] = generated_at
            if view["kev_date_added"] not in (None, "unavailable"):
                entry["kev_date_added"] = view["kev_date_added"]
    return per_cve


def _merge_history(
    cve_id: str,
    rebuilt: dict[str, Any] | None,
    ledger: dict[str, Any] | None,
    *,
    snapshot_ids: set[object],
    dropped: int,
) -> dict[str, Any]:
    if rebuilt is None and ledger is None:
        return _empty_history(cve_id, "durable", dropped)
    if ledger is None:
        assert rebuilt is not None
        rebuilt["coverage"] = "durable" if dropped else rebuilt.get("coverage")
        rebuilt["omitted_older_snapshot_count"] = dropped
        return rebuilt
    if rebuilt is None:
        preserved = dict(ledger)
        preserved["coverage"] = "durable"
        preserved["omitted_older_snapshot_count"] = dropped
        preserved["first_observed_may_be_incomplete"] = bool(
            preserved.get("first_observed_may_be_incomplete")
            or preserved.get("first_observed_snapshot_id") not in snapshot_ids
        )
        return preserved
    merged = dict(rebuilt)
    ledger_first_at = ledger.get("first_observed_generated_at")
    rebuilt_first_at = rebuilt.get("first_observed_generated_at")
    if _is_earlier(
        ledger.get("first_observed_snapshot_id"),
        ledger_first_at,
        rebuilt.get("first_observed_snapshot_id"),
        rebuilt_first_at,
    ):
        merged["first_observed_snapshot_id"] = ledger.get("first_observed_snapshot_id")
        merged["first_observed_generated_at"] = ledger_first_at
        merged["first_observed_may_be_incomplete"] = bool(
            ledger.get("first_observed_may_be_incomplete")
            or ledger.get("first_observed_snapshot_id") not in snapshot_ids
        )
    else:
        merged["first_observed_may_be_incomplete"] = bool(
            rebuilt.get("first_observed_may_be_incomplete") and dropped
        )
    if merged.get("kev_date_added") in (None, "unavailable"):
        merged["kev_date_added"] = ledger.get("kev_date_added") or "unavailable"
    merged["events"] = _dedupe_events(
        _keep_earliest_first_observed(
            list(ledger.get("events") or []) + list(rebuilt.get("events") or []),
            snapshot_id=merged.get("first_observed_snapshot_id"),
        )
    )
    merged["coverage"] = "durable"
    merged["omitted_older_snapshot_count"] = dropped
    return merged


def _keep_earliest_first_observed(
    events: list[dict[str, Any]],
    *,
    snapshot_id: object,
) -> list[dict[str, Any]]:
    first = [event for event in events if event.get("kind") == "first_observed"]
    later = [event for event in events if event.get("kind") != "first_observed"]
    if not first:
        return later
    chosen = None
    for event in first:
        if event.get("snapshot_id") == snapshot_id:
            chosen = event
            break
    if chosen is None:
        chosen = min(
            first,
            key=lambda item: (
                str(item.get("generated_at") or ""),
                str(item.get("snapshot_id") or ""),
            ),
        )
    return [chosen] + later


def _is_earlier(
    left_id: object,
    left_at: object,
    right_id: object,
    right_at: object,
) -> bool:
    if not left_at:
        return False
    if not right_at:
        return True
    return (str(left_at), str(left_id or "")) < (str(right_at), str(right_id or ""))


def _dedupe_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        key = _event_key(event)
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    unique.sort(
        key=lambda item: (
            str(item.get("generated_at") or ""),
            str(item.get("snapshot_id") or ""),
            str(item.get("kind") or ""),
        )
    )
    return unique


def _event_key(event: dict[str, Any]) -> str:
    payload = {
        "kind": event.get("kind"),
        "classification": event.get("classification"),
        "snapshot_id": event.get("snapshot_id"),
        "generated_at": event.get("generated_at"),
        "changes": event.get("changes") or [],
    }
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def _frontend_events(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    if len(events) <= MAX_HISTORY_EVENTS_PER_CVE:
        return events, False
    first = [event for event in events if event.get("kind") == "first_observed"][:1]
    later = [event for event in events if event.get("kind") != "first_observed"]
    keep = later[-(MAX_HISTORY_EVENTS_PER_CVE - len(first)) :]
    return first + keep, True


def _load_existing_ledgers(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> dict[str, dict[str, Any]]:
    ledgers: dict[str, dict[str, Any]] = {}
    for directory in (
        published_dir / HISTORY_LEDGER_DIR,
        published_dir / HISTORY_CVE_DIR,
    ):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("CVE-*.json")):
            try:
                payload = load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)
                cve_id = parse_cve_id(payload.get("cve_id") or path.stem)
            except (ValidationError, OSError):
                continue
            if cve_id in ledgers:
                continue
            events = payload.get("events")
            if not isinstance(events, list):
                continue
            ledgers[cve_id] = payload
    return ledgers


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
    intelligence = record.get("intelligence") if isinstance(record.get("intelligence"), dict) else {}
    comparable = comparable_intelligence(intelligence) if intelligence else {}
    assessments = comparable.get("cvss") if intelligence else None
    cwes = comparable.get("cwes") if intelligence else None
    affected = comparable.get("affected") if intelligence else None
    fixed = comparable.get("fixed_versions") if intelligence else None
    conflicts = comparable.get("conflicts") if intelligence else None
    nvd_status = ((comparable.get("source_status") or {}).get("nvd") or {}).get("status")
    return {
        "kev": {field: _present(kev.get(field)) for field in KEV_FIELDS},
        "kev_date_added": _present(kev.get("date_added")),
        "cve": {field: _present(cve.get(field)) for field in CVE_CORE_FIELDS},
        "products": _canonicalize(products) if products is not None else "unavailable",
        "products_available": products is not None,
        "cvss": {field: _present(severity.get(field)) for field in CVSS_FIELDS},
        "cvss_assessments": _canonicalize(assessments) if assessments is not None else "unavailable",
        "cwe_assertions": _canonicalize(cwes) if cwes is not None else "unavailable",
        "affected_ranges": _canonicalize(affected) if affected is not None else "unavailable",
        "fixed_versions": _canonicalize(fixed) if fixed is not None else "unavailable",
        "conflicts": _canonicalize(conflicts) if conflicts is not None else "unavailable",
        "nvd_status": _present(nvd_status),
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
    if previous.get("cvss_assessments") != current.get("cvss_assessments") and (
        previous.get("cvss_assessments") != "unavailable"
        or current.get("cvss_assessments") != "unavailable"
    ):
        change = _value_change(previous.get("cvss_assessments"), current.get("cvss_assessments"))
        if change is not None:
            events.append(
                _event(
                    "cvss_assessment_change",
                    "upstream_cvss",
                    snapshot_id,
                    generated_at,
                    [{"field": "cvss_assessments", **change}],
                    "Source-attributed CVSS assessments changed. Retrieval timestamps are excluded.",
                )
            )
    if previous.get("cwe_assertions") != current.get("cwe_assertions") and (
        previous.get("cwe_assertions") != "unavailable" or current.get("cwe_assertions") != "unavailable"
    ):
        change = _value_change(previous.get("cwe_assertions"), current.get("cwe_assertions"))
        if change is not None:
            events.append(
                _event(
                    "cwe_change",
                    "upstream_cve",
                    snapshot_id,
                    generated_at,
                    [{"field": "cwes", **change}],
                    "Source-attributed CWE classifications changed.",
                )
            )
    if previous.get("affected_ranges") != current.get("affected_ranges") and (
        previous.get("affected_ranges") != "unavailable" or current.get("affected_ranges") != "unavailable"
    ):
        change = _value_change(previous.get("affected_ranges"), current.get("affected_ranges"))
        if change is not None:
            events.append(
                _event(
                    "affected_range_change",
                    "upstream_cve",
                    snapshot_id,
                    generated_at,
                    [{"field": "affected_ranges", **change}],
                    "Source-attributed affected version ranges changed. Ranges were not merged.",
                )
            )
    if previous.get("fixed_versions") != current.get("fixed_versions") and (
        previous.get("fixed_versions") != "unavailable" or current.get("fixed_versions") != "unavailable"
    ):
        change = _value_change(previous.get("fixed_versions"), current.get("fixed_versions"))
        if change is not None:
            events.append(
                _event(
                    "fixed_version_change",
                    "extraction_enrichment",
                    snapshot_id,
                    generated_at,
                    [{"field": "fixed_versions", **change}],
                    "Explicit fixed-version evidence changed. Upper bounds of affected ranges are not treated as fixes.",
                )
            )
    if previous.get("nvd_status") != current.get("nvd_status"):
        events.append(
            _event(
                "nvd_change",
                "extraction_enrichment",
                snapshot_id,
                generated_at,
                [
                    {
                        "field": "nvd_status",
                        "before": previous.get("nvd_status"),
                        "after": current.get("nvd_status"),
                    }
                ],
                "NVD enrichment availability changed. This does not alter KEV eligibility.",
            )
        )
    if previous.get("conflicts") != current.get("conflicts") and (
        previous.get("conflicts") != "unavailable" or current.get("conflicts") != "unavailable"
    ):
        change = _value_change(previous.get("conflicts"), current.get("conflicts"))
        if change is not None:
            events.append(
                _event(
                    "intelligence_conflict_change",
                    "extraction_enrichment",
                    snapshot_id,
                    generated_at,
                    [{"field": "conflicts", **change}],
                    "Visible source conflicts changed. Conflicts are preserved, not resolved.",
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
    cve_dir = published_dir / HISTORY_CVE_DIR
    ledger_dir = published_dir / HISTORY_LEDGER_DIR
    cve_dir.mkdir(parents=True, exist_ok=True)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    wanted = {parse_cve_id(document["cve_id"]) for document in built["documents"]}
    for document in built["documents"]:
        cve_id = parse_cve_id(document["cve_id"])
        atomic_write_json(cve_dir / f"{cve_id}.json", document)
    for ledger in built.get("ledgers") or []:
        cve_id = parse_cve_id(ledger["cve_id"])
        atomic_write_json(ledger_dir / f"{cve_id}.json", ledger)
    for directory in (cve_dir, ledger_dir):
        for path in directory.glob("CVE-*.json"):
            try:
                parse_cve_id(path.stem)
            except ValidationError:
                path.unlink()
                continue
            if path.stem not in wanted:
                path.unlink()
    atomic_write_json(published_dir / HISTORY_INDEX_NAME, built["index"])
