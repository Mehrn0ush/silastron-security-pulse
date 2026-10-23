"""Deterministic, bounded collection pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from silastron_pulse.adapters.cve import (
    CveEnrichment,
    cve_record_from_dict,
    enrich_cves,
    storage_limits,
)
from silastron_pulse.adapters.epss import collect_epss, unavailable_record
from silastron_pulse.adapters.kev import KevCatalog, fetch_kev_catalog
from silastron_pulse.clock import Clock, SystemClock, format_datetime
from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import (
    CISA_KEV_ATTRIBUTION,
    CVE_LIST_V5_BLOB_BASE,
    MITRE_CVE_ATTRIBUTION,
    PACKAGE_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
)
from silastron_pulse.diff import detect_changes, entries_from_snapshot
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.http import CountingFetcher, Fetcher, HttpsFetcher
from silastron_pulse.ids import cvelist_v5_relpath
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.lock import CollectionLock
from silastron_pulse.models import ChangeSet, KevRecord, PulseEntry, Signals, SourceMeta
from silastron_pulse.sanitize import authoritative_cve_url, authoritative_kev_url
from silastron_pulse.signals import build_signals
from silastron_pulse.state import PulseState
from silastron_pulse.store import (
    atomic_write_json,
    load_snapshot,
    promote_snapshot,
    write_collection_status,
)
from silastron_pulse.validate import validate_snapshot


@dataclass
class CollectionResult:
    status: str
    snapshot: dict[str, Any] | None
    error: str | None


def collect(
    *,
    config: PulseConfig,
    fetcher: Fetcher | None = None,
    clock: Clock | None = None,
    previous_snapshot_path: Path | None = None,
    promote: bool = False,
    published_dir: Path | None = None,
    state_dir: Path | None = None,
    collector_commit_sha: str | None = None,
) -> CollectionResult:
    clock = clock or SystemClock()
    fetcher = fetcher or HttpsFetcher(
        timeout_seconds=config.http_timeout_seconds,
        max_redirects=config.max_redirects,
        clock=clock,
        max_attempts=config.http_max_attempts,
        backoff_seconds=float(config.http_backoff_seconds),
        min_interval_ms=config.cve_min_interval_ms,
    )
    now = clock.now()
    started_at = format_datetime(now)
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    status_path = output_dir / "collection-status.json"
    state = PulseState(state_dir) if state_dir is not None else None
    lock_ctx = (
        CollectionLock(state.root / ".collect.lock")
        if state is not None
        else _NullLock()
    )
    started = time.monotonic()
    counting = fetcher if isinstance(fetcher, CountingFetcher) else CountingFetcher(fetcher)

    try:
        with lock_ctx:
            return _collect_locked(
                config=config,
                fetcher=counting,
                clock=clock,
                started_at=started_at,
                status_path=status_path,
                previous_snapshot_path=previous_snapshot_path,
                promote=promote,
                published_dir=published_dir,
                state=state,
                collector_commit_sha=collector_commit_sha,
                started=started,
            )
    except (FetchError, ValidationError, OSError) as exc:
        completed_at = format_datetime(clock.now())
        write_collection_status(
            status_path,
            _run_metrics(
                counting,
                started,
                {
                    "status": "failed",
                    "collection_started_at": started_at,
                    "collection_completed_at": completed_at,
                    "generated_at": completed_at,
                    "snapshot_id": None,
                    "record_count": 0,
                    "candidate": None,
                    "promoted": False,
                    "collector_commit_sha": collector_commit_sha,
                    "error": str(exc),
                },
            ),
        )
        return CollectionResult(status="failed", snapshot=None, error=str(exc))


class _NullLock:
    def __enter__(self) -> "_NullLock":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _run_metrics(fetcher: Fetcher, started: float, payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
    payload["bytes_transferred"] = int(getattr(fetcher, "bytes_received", 0) or 0)
    payload["http_gets"] = int(getattr(fetcher, "get_count", 0) or 0)
    payload["http_heads"] = int(getattr(fetcher, "head_count", 0) or 0)
    return payload


def _collect_locked(
    *,
    config: PulseConfig,
    fetcher: Fetcher,
    clock: Clock,
    started_at: str,
    status_path: Path,
    previous_snapshot_path: Path | None,
    promote: bool,
    published_dir: Path | None,
    state: PulseState | None,
    collector_commit_sha: str | None,
    started: float,
) -> CollectionResult:
    output_dir = config.output_dir
    previous = _load_previous(
        previous_snapshot_path=previous_snapshot_path,
        state=state,
        max_bytes=config.max_kev_bytes,
        max_depth=config.max_json_depth,
    )
    cache_index, cached_records = _load_cve_cache(state, config)
    kev = fetch_kev_catalog(fetcher, config)
    cve = enrich_cves(
        [record.cve_id for record in kev.records],
        fetcher,
        config,
        cache_index=cache_index,
        cached_records=cached_records,
    )
    if cve.meta.status == "failed":
        error = cve.meta.error or "CVE enrichment failed"
        completed_at = format_datetime(clock.now())
        write_collection_status(
            status_path,
            _run_metrics(
                fetcher,
                started,
                {
                    "status": "failed",
                    "collection_started_at": started_at,
                    "collection_completed_at": completed_at,
                    "generated_at": completed_at,
                    "snapshot_id": None,
                    "record_count": 0,
                    "candidate": None,
                    "promoted": False,
                    "collector_commit_sha": collector_commit_sha,
                    "cve_strategy": cve.strategy,
                    "cve_delta_sha256": cve.delta_sha256,
                    "cve_delta_log_sha256": cve.delta_log_sha256,
                    "error": error,
                },
            ),
        )
        return CollectionResult(status="failed", snapshot=None, error=error)
    epss = collect_epss([record.cve_id for record in kev.records], enabled=False)
    entries = _build_entries(kev, cve, epss)
    if previous:
        previous_entries = _entries_from_snapshot(previous)
        changes = detect_changes(
            previous_entries,
            entries,
            previous_sources=previous.get("sources"),
            current_sources={
                "kev": kev.meta.to_dict(),
                "cve": cve.meta.to_dict(),
                "epss": epss.meta.to_dict(),
            },
        )
    else:
        changes = ChangeSet()
    source_state_revision = _source_revision(kev, cve)
    completed = clock.now()
    completed_at = format_datetime(completed)
    generated_at = completed_at
    metrics = _run_metrics(
        fetcher,
        started,
        {
            "cve_strategy": cve.strategy,
            "collector_commit_sha": collector_commit_sha,
            "kev_content_sha256": kev.meta.content_sha256,
            "cve_delta_sha256": cve.delta_sha256,
            "cve_delta_log_sha256": cve.delta_log_sha256,
            "cve_records_sha256": cve.meta.content_sha256,
        },
    )
    snapshot = _build_snapshot(
        generated_at=generated_at,
        collection_started_at=started_at,
        collection_completed_at=completed_at,
        kev=kev,
        cve=cve,
        epss_meta=epss.meta,
        entries=entries,
        changes=changes,
        config=config,
        collector_commit_sha=collector_commit_sha,
        source_state_revision=source_state_revision,
        metrics=metrics,
    )
    validate_snapshot(snapshot)
    candidate_path = output_dir / "candidate.json"
    atomic_write_json(candidate_path, snapshot)
    digest = sha256_bytes(candidate_path.read_bytes())
    meta = {
        "snapshot_id": snapshot["snapshot_id"],
        "collection_started_at": started_at,
        "collection_completed_at": completed_at,
        "generated_at": generated_at,
        "collector_commit_sha": collector_commit_sha,
        "source_state_revision": source_state_revision,
        "content_sha256": digest,
        "pipeline_version": PACKAGE_VERSION,
        "status": snapshot["status"],
        "cve_strategy": cve.strategy,
        "kev_content_sha256": kev.meta.content_sha256,
        "cve_delta_sha256": cve.delta_sha256,
        "cve_delta_log_sha256": cve.delta_log_sha256,
        "bytes_transferred": metrics["bytes_transferred"],
        "http_gets": metrics["http_gets"],
        "http_heads": metrics["http_heads"],
        "duration_ms": metrics["duration_ms"],
    }
    atomic_write_json(output_dir / "candidate.meta.json", meta)
    if state is not None:
        _persist_state(
            state,
            snapshot,
            meta,
            kev,
            cve,
            generated_at,
            collector_commit_sha,
            config,
        )
    write_collection_status(
        status_path,
        {
            "status": snapshot["status"],
            "collection_started_at": started_at,
            "collection_completed_at": completed_at,
            "generated_at": generated_at,
            "snapshot_id": snapshot["snapshot_id"],
            "record_count": len(snapshot["records"]),
            "candidate": str(candidate_path),
            "promoted": False,
            "content_sha256": digest,
            "collector_commit_sha": collector_commit_sha,
            "source_state_revision": source_state_revision,
            "cve_strategy": cve.strategy,
            "kev_content_sha256": kev.meta.content_sha256,
            "cve_delta_sha256": cve.delta_sha256,
            "cve_delta_log_sha256": cve.delta_log_sha256,
            "bytes_transferred": metrics["bytes_transferred"],
            "http_gets": metrics["http_gets"],
            "http_heads": metrics["http_heads"],
            "duration_ms": metrics["duration_ms"],
            "error": None,
        },
    )
    if promote:
        target = published_dir or (output_dir / "published")
        promote_snapshot(
            snapshot,
            target,
            now=completed,
            stale_after_hours=config.stale_after_hours,
            max_bytes=config.max_kev_bytes,
            max_depth=config.max_json_depth,
        )
        write_collection_status(
            status_path,
            {
                "status": snapshot["status"],
                "collection_started_at": started_at,
                "collection_completed_at": completed_at,
                "generated_at": generated_at,
                "snapshot_id": snapshot["snapshot_id"],
                "record_count": len(snapshot["records"]),
                "candidate": str(candidate_path),
                "promoted": True,
                "content_sha256": digest,
                "collector_commit_sha": collector_commit_sha,
                "cve_strategy": cve.strategy,
                "bytes_transferred": metrics["bytes_transferred"],
                "duration_ms": metrics["duration_ms"],
                "error": None,
            },
        )
    return CollectionResult(status=snapshot["status"], snapshot=snapshot, error=None)


def _load_previous(
    *,
    previous_snapshot_path: Path | None,
    state: PulseState | None,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any] | None:
    if previous_snapshot_path is not None:
        if not previous_snapshot_path.exists():
            raise ValidationError(
                f"Previous snapshot is unavailable at {previous_snapshot_path}"
            )
        return load_snapshot(
            previous_snapshot_path,
            max_bytes=max_bytes,
            max_depth=max_depth,
            compatible=True,
        )
    if state is not None:
        return state.load_previous_snapshot(
            max_bytes=max_bytes,
            max_depth=max_depth,
            required=state.has_source_state(),
        )
    return None


def _load_cve_cache(
    state: PulseState | None, config: PulseConfig
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    if state is None or not state.has_source_state():
        return None, {}
    index = state.load_cve_index(max_bytes=config.max_kev_bytes, max_depth=config.max_json_depth)
    cached: dict[str, dict[str, Any]] = {}
    records = index.get("records") if isinstance(index.get("records"), dict) else {}
    for cve_id in records:
        payload = state.load_json(
            state.cve_record_path(cve_id),
            max_bytes=config.max_cve_bytes,
            max_depth=config.max_json_depth,
        )
        if payload:
            cached[cve_id] = payload
    return index, cached


def _source_revision(kev: KevCatalog, cve: CveEnrichment) -> str:
    kev_rev = kev.meta.source_revision or kev.meta.content_sha256 or "unknown-kev"
    cve_rev = cve.meta.source_revision or cve.meta.content_sha256 or "unknown-cve"
    return f"{kev_rev}:{cve_rev}"


def _persist_state(
    state: PulseState,
    snapshot: dict[str, Any],
    meta: dict[str, Any],
    kev: KevCatalog,
    cve: CveEnrichment,
    generated_at: str,
    collector_commit_sha: str | None,
    config: PulseConfig,
) -> None:
    cve_index = {
        "delta_fetch_time": cve.delta_fetch_time,
        "delta_sha256": cve.delta_sha256,
        "delta_log_sha256": cve.delta_log_sha256,
        "delta_log_etag": cve.delta_log_etag,
        "delta_log_bytes": cve.delta_log_bytes,
        "delta_log_skipped": cve.delta_log_skipped,
        "storage_limits": storage_limits(config),
        "updated_at": generated_at,
        "strategy": cve.strategy,
        "records": {
            cve_id: {
                "sha256": record.record_sha256,
                "etag": record.etag,
                "retrieved_at": record.retrieved_at,
                "date_updated": record.date_updated,
                "status": record.status,
            }
            for cve_id, record in cve.records.items()
        },
    }
    state.write_source(
        manifest={
            "schema_version": "1.0.0",
            "updated_at": generated_at,
            "collector_commit_sha": collector_commit_sha,
            "source_state_revision": meta["source_state_revision"],
            "kev_revision": kev.meta.source_revision,
            "cve_revision": cve.meta.source_revision,
            "record_count": len(kev.records),
        },
        kev_meta=kev.meta.to_dict(),
        kev_catalog={
            "meta": kev.meta.to_dict(),
            "records": [record.to_dict() for record in kev.records],
        },
        cve_index=cve_index,
        cve_records={cve_id: record.to_dict() for cve_id, record in cve.records.items()},
    )
    state.write_candidate(snapshot, meta)


def _build_entries(
    kev: KevCatalog,
    cve: CveEnrichment,
    epss: Any,
) -> dict[str, PulseEntry]:
    entries: dict[str, PulseEntry] = {}
    for kev_record in kev.records:
        cve_record = cve.records[kev_record.cve_id]
        epss_record = epss.records.get(kev_record.cve_id) or unavailable_record(
            kev_record.cve_id
        )
        links = {
            "kev_catalog": authoritative_kev_url(),
            "cve_record": authoritative_cve_url(kev_record.cve_id),
            "cvelist_v5": CVE_LIST_V5_BLOB_BASE + cvelist_v5_relpath(kev_record.cve_id),
        }
        entries[kev_record.cve_id] = PulseEntry(
            cve_id=kev_record.cve_id,
            kev=kev_record,
            cve=cve_record,
            epss=epss_record,
            signals=build_signals(kev_record, cve_record, epss_record),
            links=links,
        )
    return entries


def _build_snapshot(
    *,
    generated_at: str,
    collection_started_at: str,
    collection_completed_at: str,
    kev: KevCatalog,
    cve: CveEnrichment,
    epss_meta: SourceMeta,
    entries: dict[str, PulseEntry],
    changes: Any,
    config: PulseConfig,
    collector_commit_sha: str | None,
    source_state_revision: str,
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = [entries[key].to_dict() for key in sorted(entries)]
    status = "ok"
    if cve.meta.status == "degraded":
        status = "degraded"
    material = f"{kev.meta.content_sha256}:{generated_at}:{SNAPSHOT_SCHEMA_VERSION}:{source_state_revision}"
    snapshot_id = f"{generated_at.replace('-', '').replace(':', '')}_{sha256_bytes(material.encode('utf-8'))[:12]}"
    truncated_records = [
        item["cve_id"]
        for item in records
        if (item.get("cve") or {}).get("truncated_fields")
        or (item.get("kev") or {}).get("truncated_fields")
        or (item.get("kev") or {}).get("cwes_incomplete")
    ]
    summary = {
        "kev_records": len(kev.records),
        "cve_enriched_ok": sum(1 for item in cve.records.values() if item.status == "ok"),
        "cve_unavailable": sum(
            1 for item in cve.records.values() if item.status != "ok"
        ),
        "truncated_records": len(truncated_records),
        "complete_records": sum(1 for item in records if item.get("completeness") == "complete"),
        "partial_records": sum(1 for item in records if item.get("completeness") == "partial"),
        "unavailable_records": sum(
            1 for item in records if item.get("completeness") == "unavailable"
        ),
        "epss_enabled": False,
        "new_kev_entries": len(changes.new_kev_entries),
        "updated_kev_entries": len(changes.updated_kev_entries),
        "removed_kev_entries": len(changes.removed_kev_entries),
        "changed_cve_information": len(changes.changed_cve_information),
        "epss_changes": len(changes.epss_changes),
        "cve_strategy": cve.strategy,
        "cve_fetched": len(cve.fetched_ids),
        "cve_reused": len(cve.reused_ids),
        "cve_delta_sha256": cve.delta_sha256,
        "cve_delta_log_sha256": cve.delta_log_sha256,
        "kev_content_sha256": kev.meta.content_sha256,
        "bytes_transferred": (metrics or {}).get("bytes_transferred"),
        "http_gets": (metrics or {}).get("http_gets"),
        "http_heads": (metrics or {}).get("http_heads"),
        "duration_ms": (metrics or {}).get("duration_ms"),
        "collector_commit_sha": collector_commit_sha,
    }
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "collection_started_at": collection_started_at,
        "collection_completed_at": collection_completed_at,
        "generated_at": generated_at,
        "status": status,
        "pipeline_version": PACKAGE_VERSION,
        "composite_risk_score": None,
        "binding": {
            "collector_commit_sha": collector_commit_sha,
            "source_state_revision": source_state_revision,
        },
        "consumer_note": (
            "This snapshot is public vulnerability intelligence. status is "
            "collection outcome (ok, degraded, or failed), not freshness and "
            "not per-record completeness. records[].completeness describes "
            "extracted inventory completeness; a complete extraction does not "
            "prove complete real-world product affectedness. Freshness must be "
            "recomputed at viewing time. Confirmed exploitation, estimated "
            "probability, severity, product affectedness, and deployment "
            "exposure are separate signals."
        ),
        "attribution": {
            "cisa_kev": CISA_KEV_ATTRIBUTION,
            "cve": MITRE_CVE_ATTRIBUTION,
            "epss": epss_meta.notes,
        },
        "limits": {
            "max_kev_records": config.max_kev_records,
            "max_cve_enrichments": config.max_cve_enrichments,
            "max_preview_changes": config.max_preview_changes,
            "max_preview_recent": config.max_preview_recent,
            "max_products": config.max_products,
            "max_versions_per_product": config.max_versions_per_product,
            "max_description_chars": config.max_description_chars,
            "max_cve_bytes": config.max_cve_bytes,
            "stale_after_hours": config.stale_after_hours,
        },
        "sources": {
            "kev": kev.meta.to_dict(),
            "cve": cve.meta.to_dict(),
            "epss": epss_meta.to_dict(),
        },
        "summary": summary,
        "changes": changes.to_dict(),
        "records": records,
    }


def _entries_from_snapshot(payload: dict[str, Any]) -> dict[str, PulseEntry]:
    """Rebuild comparable entries from a previous snapshot JSON."""
    return entries_from_snapshot(payload)
