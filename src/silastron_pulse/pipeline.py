"""Deterministic, bounded collection pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from silastron_pulse.adapters.cve import CveEnrichment, enrich_cves
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
from silastron_pulse.diff import detect_changes
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.models import ChangeSet, PulseEntry, SourceMeta
from silastron_pulse.http import Fetcher, HttpsFetcher
from silastron_pulse.ids import cvelist_v5_relpath
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.sanitize import authoritative_cve_url, authoritative_kev_url
from silastron_pulse.signals import build_signals
from silastron_pulse.store import (
    atomic_write_json,
    promote_snapshot,
    read_optional_snapshot,
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
) -> CollectionResult:
    clock = clock or SystemClock()
    fetcher = fetcher or HttpsFetcher(
        timeout_seconds=config.http_timeout_seconds,
        max_redirects=config.max_redirects,
        clock=clock,
    )
    now = clock.now()
    generated_at = format_datetime(now)
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    status_path = output_dir / "collection-status.json"

    try:
        kev = fetch_kev_catalog(fetcher, config)
        cve = enrich_cves([record.cve_id for record in kev.records], fetcher, config)
        if cve.meta.status == "failed":
            raise ValidationError(cve.meta.error or "CVE enrichment failed")
        epss = collect_epss([record.cve_id for record in kev.records], enabled=False)
        entries = _build_entries(kev, cve, epss)
        previous = read_optional_snapshot(
            previous_snapshot_path,
            max_bytes=config.max_kev_bytes,
            max_depth=config.max_json_depth,
        )
        if previous:
            previous_entries = _entries_from_snapshot(previous)
            changes = detect_changes(previous_entries, entries)
        else:
            # An initial snapshot has no prior Pulse revision to diff against.
            changes = ChangeSet()
        snapshot = _build_snapshot(
            generated_at=generated_at,
            kev=kev,
            cve=cve,
            epss_meta=epss.meta,
            entries=entries,
            changes=changes,
            config=config,
        )
        validate_snapshot(snapshot)
        candidate_path = output_dir / "candidate.json"
        atomic_write_json(candidate_path, snapshot)
        write_collection_status(
            status_path,
            {
                "status": snapshot["status"],
                "generated_at": generated_at,
                "snapshot_id": snapshot["snapshot_id"],
                "record_count": len(snapshot["records"]),
                "candidate": str(candidate_path),
                "promoted": False,
                "error": None,
            },
        )
        if promote:
            target = published_dir or (output_dir / "published")
            promote_snapshot(
                snapshot,
                target,
                now=now,
                stale_after_hours=config.stale_after_hours,
                max_bytes=config.max_kev_bytes,
                max_depth=config.max_json_depth,
            )
            write_collection_status(
                status_path,
                {
                    "status": snapshot["status"],
                    "generated_at": generated_at,
                    "snapshot_id": snapshot["snapshot_id"],
                    "record_count": len(snapshot["records"]),
                    "candidate": str(candidate_path),
                    "promoted": True,
                    "error": None,
                },
            )
        return CollectionResult(status=snapshot["status"], snapshot=snapshot, error=None)
    except (FetchError, ValidationError, OSError) as exc:
        write_collection_status(
            status_path,
            {
                "status": "failed",
                "generated_at": generated_at,
                "snapshot_id": None,
                "record_count": 0,
                "candidate": None,
                "promoted": False,
                "error": str(exc),
            },
        )
        return CollectionResult(status="failed", snapshot=None, error=str(exc))


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
    kev: KevCatalog,
    cve: CveEnrichment,
    epss_meta: SourceMeta,
    entries: dict[str, PulseEntry],
    changes: Any,
    config: PulseConfig,
) -> dict[str, Any]:
    records = [entries[key].to_dict() for key in sorted(entries)]
    status = "ok"
    if cve.meta.status == "degraded":
        status = "degraded"
    material = f"{kev.meta.content_sha256}:{generated_at}:{SNAPSHOT_SCHEMA_VERSION}"
    snapshot_id = f"{generated_at.replace('-', '').replace(':', '')}_{sha256_bytes(material.encode('utf-8'))[:12]}"
    summary = {
        "kev_records": len(kev.records),
        "cve_enriched_ok": sum(1 for item in cve.records.values() if item.status == "ok"),
        "cve_unavailable": sum(
            1 for item in cve.records.values() if item.status != "ok"
        ),
        "epss_enabled": False,
        "new_kev_entries": len(changes.new_kev_entries),
        "updated_kev_entries": len(changes.updated_kev_entries),
        "changed_cve_information": len(changes.changed_cve_information),
        "epss_changes": len(changes.epss_changes),
    }
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "generated_at": generated_at,
        "status": status,
        "pipeline_version": PACKAGE_VERSION,
        "composite_risk_score": None,
        "consumer_note": (
            "This snapshot is public vulnerability intelligence. It does not "
            "assess whether any Silastron or customer system is affected, "
            "exposed, or exploited. Confirmed exploitation, estimated "
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
    from silastron_pulse.models import (
        CveProduct,
        CveRecord,
        CveSeverity,
        EpssRecord,
        KevRecord,
        PulseEntry,
        Signals,
    )

    entries: dict[str, PulseEntry] = {}
    for item in payload.get("records", []):
        kev = item["kev"]
        cve = item["cve"]
        epss = item["epss"]
        severity_raw = cve.get("severity")
        severity = None
        if isinstance(severity_raw, dict) and severity_raw.get("base_score") is not None:
            severity = CveSeverity(
                source=severity_raw.get("source") or "cve_cna",
                cvss_version=str(severity_raw.get("cvss_version") or ""),
                base_score=float(severity_raw["base_score"]),
                base_severity=severity_raw.get("base_severity"),
                vector=severity_raw.get("vector"),
            )
        kev_record = KevRecord(
            cve_id=kev["cve_id"],
            vendor_project=kev["vendor_project"],
            product=kev["product"],
            vulnerability_name=kev["vulnerability_name"],
            date_added=kev["date_added"],
            short_description=kev["short_description"],
            required_action=kev["required_action"],
            due_date=kev["due_date"],
            known_ransomware_campaign_use=kev.get("known_ransomware_campaign_use"),
            forensic_triage=kev.get("forensic_triage"),
            notes=kev.get("notes"),
            cwes=list(kev.get("cwes") or []),
            source_url=kev.get("source_url") or "",
            record_sha256=kev.get("record_sha256") or "",
        )
        cve_record = CveRecord(
            cve_id=cve["cve_id"],
            state=cve.get("state") or "UNKNOWN",
            data_version=cve.get("data_version"),
            date_published=cve.get("date_published"),
            date_updated=cve.get("date_updated"),
            assigner_short_name=cve.get("assigner_short_name"),
            title=cve.get("title"),
            description=cve.get("description"),
            severity=severity,
            products=[
                CveProduct(
                    vendor=prod.get("vendor"),
                    product=prod.get("product"),
                    status=prod.get("status"),
                    versions=list(prod.get("versions") or []),
                )
                for prod in cve.get("products") or []
            ],
            source_url=cve.get("source_url") or "",
            record_page_url=cve.get("record_page_url") or "",
            record_sha256=cve.get("record_sha256") or "",
            status=cve.get("status") or "unavailable",
            error=cve.get("error"),
        )
        epss_record = EpssRecord(
            status=epss.get("status") or "unavailable",
            cve_id=epss.get("cve_id") or item["cve_id"],
            score=epss.get("score"),
            percentile=epss.get("percentile"),
            score_date=epss.get("score_date"),
            notes=epss.get("notes"),
        )
        signals_raw = item.get("signals") or {}
        entries[item["cve_id"]] = PulseEntry(
            cve_id=item["cve_id"],
            kev=kev_record,
            cve=cve_record,
            epss=epss_record,
            signals=Signals(
                confirmed_exploitation=signals_raw.get("confirmed_exploitation") or {},
                estimated_exploitation_probability=signals_raw.get(
                    "estimated_exploitation_probability"
                )
                or {},
                vulnerability_severity=signals_raw.get("vulnerability_severity") or {},
                product_affectedness=signals_raw.get("product_affectedness") or {},
                deployment_exposure=signals_raw.get("deployment_exposure") or {},
            ),
            links=item.get("links") or {},
        )
    return entries
