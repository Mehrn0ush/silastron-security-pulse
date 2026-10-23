"""Atomic snapshot publication with fail-closed rollback."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from silastron_pulse.clock import format_datetime, parse_generated_at as parse_clock
from silastron_pulse.constants import MANIFEST_SCHEMA_VERSION, PREVIEW_SCHEMA_VERSION
from silastron_pulse.diff import publication_comparison
from silastron_pulse.errors import PublishGuardError, ValidationError
from silastron_pulse.jsonutil import dump_bytes, load_bounded_json, sha256_bytes
from silastron_pulse.lock import ExclusiveLock
from silastron_pulse.validate import validate_manifest, validate_snapshot


def atomic_write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    data = dump_bytes(payload)
    tmp.write_bytes(data)
    tmp.replace(path)


def load_json_file(path: Path, *, max_bytes: int, max_depth: int) -> dict[str, Any]:
    data = path.read_bytes()
    payload = load_bounded_json(
        data, max_bytes=max_bytes, max_depth=max_depth, source=str(path)
    )
    if not isinstance(payload, dict):
        raise ValidationError(f"{path} is not a JSON object")
    return payload


def load_snapshot(
    path: Path, *, max_bytes: int, max_depth: int, compatible: bool = False
) -> dict[str, Any]:
    payload = load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)
    return validate_snapshot(payload, compatible=compatible)


def parse_generated_at(value: str) -> datetime:
    try:
        return parse_clock(value)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


def promote_lock_path(published_dir: Path) -> Path:
    return published_dir.parent / f".{published_dir.name}.promote.lock"


def promote_snapshot(
    candidate: dict[str, Any],
    published_dir: Path,
    *,
    now: datetime,
    stale_after_hours: int,
    max_bytes: int,
    max_depth: int,
    allow_older: bool = False,
    rollback_of: str | None = None,
) -> dict[str, Any]:
    try:
        candidate = validate_snapshot(candidate)
    except ValidationError as exc:
        raise PublishGuardError(f"Refusing to publish an invalid snapshot: {exc}") from exc
    if candidate["status"] == "failed":
        raise PublishGuardError("Refusing to publish a failed snapshot")
    if not candidate.get("records"):
        raise PublishGuardError("Refusing to publish an empty snapshot")

    published_dir.mkdir(parents=True, exist_ok=True)
    with ExclusiveLock(
        promote_lock_path(published_dir),
        conflict=(
            "Another publish holds this published directory; "
            "refusing concurrent promote"
        ),
        error=PublishGuardError,
    ):
        return _promote_snapshot_locked(
            candidate,
            published_dir,
            now=now,
            stale_after_hours=stale_after_hours,
            max_bytes=max_bytes,
            max_depth=max_depth,
            allow_older=allow_older,
            rollback_of=rollback_of,
        )


def _promote_snapshot_locked(
    candidate: dict[str, Any],
    published_dir: Path,
    *,
    now: datetime,
    stale_after_hours: int,
    max_bytes: int,
    max_depth: int,
    allow_older: bool,
    rollback_of: str | None,
) -> dict[str, Any]:
    latest_path = published_dir / "latest.json"
    current = None
    if latest_path.exists():
        current = load_snapshot(latest_path, max_bytes=max_bytes, max_depth=max_depth)
        _guard_against_regression(
            current,
            candidate,
            published_dir=published_dir,
            max_bytes=max_bytes,
            max_depth=max_depth,
            allow_older=allow_older,
        )
        if candidate.get("snapshot_id") == current.get("snapshot_id"):
            return load_json_file(
                published_dir / "manifest.json", max_bytes=max_bytes, max_depth=max_depth
            )

    snapshot_name = f"{candidate['snapshot_id']}.json"
    snapshot_path = published_dir / "snapshots" / snapshot_name
    atomic_write_json(snapshot_path, candidate)
    written = load_snapshot(snapshot_path, max_bytes=max_bytes, max_depth=max_depth)
    if written != candidate:
        raise PublishGuardError("Written snapshot did not match candidate")

    atomic_write_json(latest_path, candidate)
    preview = build_preview_document(candidate, previous_published=current)
    atomic_write_json(published_dir / "preview.json", preview)
    manifest = build_manifest(
        candidate,
        snapshot_relpath=f"snapshots/{snapshot_name}",
        now=now,
        stale_after_hours=stale_after_hours,
        rollback_of=rollback_of,
    )
    atomic_write_json(published_dir / "manifest.json", manifest)
    _record_history(published_dir, candidate["snapshot_id"])
    validate_manifest(manifest)
    return manifest


def rollback_snapshot(
    published_dir: Path,
    snapshot_id: str,
    *,
    now: datetime,
    stale_after_hours: int,
    max_bytes: int,
    max_depth: int,
    confirm: str,
) -> dict[str, Any]:
    if confirm != "ROLLBACK":
        raise PublishGuardError("Rollback requires explicit confirm=ROLLBACK")
    path = published_dir / "snapshots" / f"{snapshot_id}.json"
    if not path.exists():
        raise PublishGuardError(f"No archived snapshot {snapshot_id}")
    candidate = load_snapshot(path, max_bytes=max_bytes, max_depth=max_depth)
    latest_path = published_dir / "latest.json"
    previous_id = None
    if latest_path.exists():
        current = load_snapshot(latest_path, max_bytes=max_bytes, max_depth=max_depth)
        previous_id = current["snapshot_id"]
        if previous_id == snapshot_id:
            raise PublishGuardError("Published snapshot is already at the requested revision")
    return promote_snapshot(
        candidate,
        published_dir,
        now=now,
        stale_after_hours=stale_after_hours,
        max_bytes=max_bytes,
        max_depth=max_depth,
        allow_older=True,
        rollback_of=previous_id,
    )


def _guard_against_regression(
    current: dict[str, Any],
    candidate: dict[str, Any],
    *,
    published_dir: Path,
    max_bytes: int,
    max_depth: int,
    allow_older: bool,
) -> None:
    if candidate.get("snapshot_id") == current.get("snapshot_id"):
        return
    history = _load_history(published_dir, max_bytes=max_bytes, max_depth=max_depth)
    if candidate["snapshot_id"] in history and not allow_older:
        raise PublishGuardError(
            "Refusing to replay a superseded snapshot; use the explicit rollback command"
        )
    if candidate["status"] == "degraded" and current["status"] == "ok":
        if len(candidate["records"]) < len(current["records"]) * 0.9:
            raise PublishGuardError(
                "Degraded candidate dropped more than 10% of records versus the current snapshot"
            )
    current_ts = parse_generated_at(current["generated_at"])
    candidate_ts = parse_generated_at(candidate["generated_at"])
    if candidate_ts < current_ts and not allow_older:
        raise PublishGuardError("Refusing to replace a newer snapshot with an older one")


def verify_publication_transition(
    *,
    incoming_dir: Path,
    current_dir: Path,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    """Refuse persist when the comparison baseline is not the live published latest."""
    incoming_latest = load_snapshot(
        incoming_dir / "latest.json", max_bytes=max_bytes, max_depth=max_depth
    )
    incoming_preview = load_json_file(
        incoming_dir / "preview.json", max_bytes=max_bytes, max_depth=max_depth
    )
    incoming_comparison = incoming_preview.get("publication_comparison")
    if not isinstance(incoming_comparison, dict):
        raise PublishGuardError("Incoming preview is missing publication_comparison")
    incoming_id = incoming_latest.get("snapshot_id")
    compared_to = incoming_comparison.get("compared_to_snapshot_id")
    current_latest_path = current_dir / "latest.json"
    if not current_latest_path.exists():
        if incoming_comparison.get("available") is True:
            raise PublishGuardError(
                "Refusing to persist a published comparison when no published snapshot exists"
            )
        if compared_to:
            raise PublishGuardError(
                "First persist cannot name a previous published snapshot"
            )
        return {"status": "first_publish", "snapshot_id": incoming_id}

    current_latest = load_snapshot(
        current_latest_path, max_bytes=max_bytes, max_depth=max_depth
    )
    current_id = current_latest.get("snapshot_id")
    if incoming_id == current_id:
        if incoming_latest != current_latest:
            raise PublishGuardError(
                "Idempotent persist cannot replace latest.json for the same snapshot_id"
            )
        current_preview_path = current_dir / "preview.json"
        if current_preview_path.exists():
            current_preview = load_json_file(
                current_preview_path, max_bytes=max_bytes, max_depth=max_depth
            )
            if current_preview.get("publication_comparison") != incoming_comparison:
                raise PublishGuardError(
                    "Idempotent persist cannot change publication_comparison"
                )
        return {"status": "idempotent", "snapshot_id": incoming_id}

    if incoming_comparison.get("available") is not True:
        raise PublishGuardError(
            "Refusing to replace a published snapshot without an available "
            "publication_comparison"
        )
    if compared_to != current_id:
        raise PublishGuardError(
            f"publication_comparison baseline {compared_to!r} is not the "
            f"current published snapshot {current_id!r}"
        )
    return {
        "status": "successor",
        "snapshot_id": incoming_id,
        "compared_to": current_id,
    }


PUBLISHED_SITE_FILES = ("latest.json", "manifest.json", "preview.json")


def verify_published_site(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    """Fail closed if published Pages data is missing, invalid, or inconsistent."""
    for name in PUBLISHED_SITE_FILES:
        if not (published_dir / name).exists():
            raise PublishGuardError(f"Published {name} is missing")
    latest = load_snapshot(
        published_dir / "latest.json", max_bytes=max_bytes, max_depth=max_depth
    )
    if latest.get("status") not in {"ok", "degraded"}:
        raise PublishGuardError("Published latest.json is not a successful snapshot")
    manifest = validate_manifest(
        load_json_file(
            published_dir / "manifest.json", max_bytes=max_bytes, max_depth=max_depth
        )
    )
    if manifest.get("status") not in {"ok", "degraded"}:
        raise PublishGuardError("Published manifest is not a successful snapshot")
    if manifest.get("publication_state") not in {"published", "rolled_back"}:
        raise PublishGuardError("Published manifest is not in a published state")
    if manifest.get("snapshot_id") != latest.get("snapshot_id"):
        raise PublishGuardError("Published manifest snapshot_id does not match latest.json")
    preview = load_json_file(
        published_dir / "preview.json", max_bytes=max_bytes, max_depth=max_depth
    )
    if preview.get("snapshot_id") != latest.get("snapshot_id"):
        raise PublishGuardError("Published preview snapshot_id does not match latest.json")
    return {
        "snapshot_id": latest["snapshot_id"],
        "status": latest["status"],
        "record_count": len(latest.get("records") or []),
    }


def assert_site_data_matches_published(site_data: Path, published_dir: Path) -> None:
    """Frontend deploy must copy published JSON bytes without rewriting them."""
    published_files = sorted(
        path.relative_to(published_dir) for path in published_dir.rglob("*") if path.is_file()
    )
    if not published_files:
        raise PublishGuardError("Published data is empty")
    for name in PUBLISHED_SITE_FILES:
        if Path(name) not in published_files:
            raise PublishGuardError(f"Published {name} is missing")
    for rel in published_files:
        left = site_data / rel
        right = published_dir / rel
        if not left.exists():
            raise PublishGuardError(f"Frontend deploy is missing {rel}")
        if sha256_bytes(left.read_bytes()) != sha256_bytes(right.read_bytes()):
            raise PublishGuardError(f"Frontend deploy mutated published {rel}")


def _history_path(published_dir: Path) -> Path:
    return published_dir / "history.json"


def _load_history(published_dir: Path, *, max_bytes: int, max_depth: int) -> list[str]:
    path = _history_path(published_dir)
    if not path.exists():
        current = published_dir / "latest.json"
        if current.exists():
            snapshot = load_json_file(current, max_bytes=max_bytes, max_depth=max_depth)
            identity = snapshot.get("snapshot_id")
            return [identity] if isinstance(identity, str) else []
        return []
    payload = load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)
    ids = payload.get("snapshot_ids") or []
    return [item for item in ids if isinstance(item, str)]


def _record_history(published_dir: Path, snapshot_id: str) -> None:
    path = _history_path(published_dir)
    ids: list[str] = []
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            ids = [item for item in payload.get("snapshot_ids") or [] if isinstance(item, str)]
        except (OSError, json.JSONDecodeError):
            ids = []
    if snapshot_id not in ids:
        ids.append(snapshot_id)
    atomic_write_json(path, {"snapshot_ids": ids, "current": snapshot_id})


def build_manifest(
    snapshot: dict[str, Any],
    *,
    snapshot_relpath: str,
    now: datetime,
    stale_after_hours: int,
    rollback_of: str | None = None,
) -> dict[str, Any]:
    generated = parse_generated_at(snapshot["generated_at"])
    age_hours = (now.astimezone(timezone.utc) - generated).total_seconds() / 3600.0
    stale = age_hours > stale_after_hours
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": format_datetime(now),
        "status": snapshot["status"],
        "latest_snapshot": snapshot_relpath,
        "latest_ok_snapshot": snapshot_relpath if snapshot["status"] in {"ok", "degraded"} else None,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_generated_at": snapshot["generated_at"],
        "record_count": len(snapshot.get("records", [])),
        "stale": stale,
        "fresh": not stale,
        "stale_after_hours": stale_after_hours,
        "age_hours": round(age_hours, 3),
        "sources": snapshot.get("sources", {}),
        "publication_state": "rolled_back" if rollback_of else "published",
        "rollback_of": rollback_of,
        "note": (
            "stale/fresh in this file are computed at promote time only. "
            "Consumers must recompute freshness at viewing time from "
            "snapshot_generated_at and stale_after_hours. Do not treat "
            "estimated signals as confirmed exploitation."
        ),
    }


def build_preview_document(
    snapshot: dict[str, Any],
    *,
    previous_published: dict[str, Any] | None = None,
) -> dict[str, Any]:
    changes = snapshot.get("changes") or {}
    change_rows = []
    for kind, key in (
        ("new_kev_entry", "new_kev_entries"),
        ("updated_kev_entry", "updated_kev_entries"),
        ("removed_kev_entry", "removed_kev_entries"),
        ("changed_cve_information", "changed_cve_information"),
        ("epss_change", "epss_changes"),
    ):
        for cve_id in changes.get(key, []):
            change_rows.append({"cve_id": cve_id, "change": kind})
    records_by_id = {item["cve_id"]: item for item in snapshot.get("records", [])}
    sources = snapshot.get("sources") or {}
    preview_changes = []
    max_changes = snapshot.get("limits", {}).get("max_preview_changes", 50)
    for row in change_rows[:max_changes]:
        record = records_by_id.get(row["cve_id"])
        if record:
            preview_changes.append(_preview_row(record, row["change"], sources))
        elif row["change"] == "removed_kev_entry":
            preview_changes.append(
                {
                    "cve_id": row["cve_id"],
                    "change": "removed_kev_entry",
                    "kev_listed": False,
                    "cve_status": "removed",
                    "links": {},
                }
            )
    recent = []
    sorted_records = sorted(
        snapshot.get("records", []),
        key=lambda item: (item["kev"]["date_added"], item["cve_id"]),
        reverse=True,
    )
    limit = snapshot.get("limits", {}).get("max_preview_recent", 25)
    for record in sorted_records[:limit]:
        recent.append(_preview_row(record, "recent_kev_addition", sources))
    comparison = publication_comparison(
        previous_published,
        snapshot,
        max_rows=max_changes,
    )
    return {
        "schema_version": PREVIEW_SCHEMA_VERSION,
        "snapshot_id": snapshot["snapshot_id"],
        "collection_started_at": snapshot.get("collection_started_at"),
        "collection_completed_at": snapshot.get("collection_completed_at"),
        "generated_at": snapshot["generated_at"],
        "status": snapshot["status"],
        "sources": snapshot.get("sources", {}),
        "summary": snapshot.get("summary", {}),
        "changes_available": bool(change_rows),
        "changes": preview_changes,
        "recent_kev_additions": recent,
        "publication_comparison": comparison,
        "note": snapshot.get("consumer_note"),
    }


def _preview_row(record: dict[str, Any], change: str, sources: dict[str, Any]) -> dict[str, Any]:
    cve = record.get("cve") or {}
    kev = record.get("kev") or {}
    epss = record.get("epss") or {}
    links = record.get("links") or {}
    severity = (cve.get("severity") or {}) if isinstance(cve.get("severity"), dict) else {}
    kev_source = sources.get("kev") or {}
    truncated = list(cve.get("truncated_fields") or []) + list(kev.get("truncated_fields") or [])
    return {
        "cve_id": record["cve_id"],
        "change": change,
        "kev_listed": True,
        "kev_date_added": kev.get("date_added"),
        "vendor_project": kev.get("vendor_project"),
        "product": kev.get("product"),
        "vulnerability_name": kev.get("vulnerability_name"),
        "cve_state": cve.get("state"),
        "cve_status": cve.get("status"),
        "cve_date_updated": cve.get("date_updated"),
        "severity_status": "available" if severity else "unavailable",
        "cvss_base_score": severity.get("base_score"),
        "epss_status": epss.get("status"),
        "epss_score": epss.get("score"),
        "truncated_fields": truncated,
        "partial": bool(truncated) or cve.get("status") != "ok",
        "completeness": record.get("completeness")
        or ("unavailable" if cve.get("status") != "ok" else "partial" if truncated else "complete"),
        "omitted_product_count": cve.get("omitted_product_count") or 0,
        "omitted_version_count": cve.get("omitted_version_count") or 0,
        "links": {
            "cve_record": links.get("cve_record"),
            "kev_catalog": links.get("kev_catalog"),
            "cvelist_v5": links.get("cvelist_v5"),
        },
        "kev_retrieved_at": kev_source.get("retrieved_at"),
        "kev_source_published_at": kev_source.get("source_published_at"),
        "cve_retrieved_at": cve.get("retrieved_at"),
        "cve_source_updated_at": cve.get("date_updated"),
        "retrieved_at": cve.get("retrieved_at") or kev_source.get("retrieved_at"),
        "source_published_at": kev_source.get("source_published_at") or kev.get("date_added"),
    }


def unpublished_status(*, generated_at: str) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "status": "unpublished",
        "latest_snapshot": None,
        "latest_ok_snapshot": None,
        "stale": True,
        "fresh": False,
        "publication_state": "not_published",
        "message": (
            "No snapshot has been approved for public deployment. This is not "
            "a live intelligence feed."
        ),
    }


def write_collection_status(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_json(path, payload)


def read_optional_snapshot(
    path: Path | None, *, max_bytes: int, max_depth: int
) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        return load_snapshot(path, max_bytes=max_bytes, max_depth=max_depth)
    except (ValidationError, OSError, json.JSONDecodeError):
        # A placeholder or corrupt previous file must not fail a new collection.
        return None


def snapshot_entries_from_json(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload))
