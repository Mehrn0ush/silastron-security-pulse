"""Runtime validation for versioned Pulse snapshots and manifests."""

from __future__ import annotations

from typing import Any

from silastron_pulse.constants import MANIFEST_SCHEMA_VERSION, SNAPSHOT_SCHEMA_VERSION
from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import CVE_ID_RE


def validate_snapshot(payload: object, *, compatible: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("Snapshot must be a JSON object")
    if compatible:
        payload = _backfill_snapshot(payload)
    _require(payload, "schema_version", SNAPSHOT_SCHEMA_VERSION)
    _require_string(payload, "snapshot_id")
    _require_string(payload, "collection_started_at")
    _require_string(payload, "collection_completed_at")
    _require_string(payload, "generated_at")
    status = payload.get("status")
    if status not in {"ok", "degraded", "failed"}:
        raise ValidationError("Snapshot status is invalid")
    if payload.get("composite_risk_score") is not None:
        raise ValidationError("Snapshots must not include a composite risk score value")
    sources = payload.get("sources")
    if not isinstance(sources, dict):
        raise ValidationError("Snapshot sources must be an object")
    for key in ("kev", "cve", "epss"):
        if key not in sources or not isinstance(sources[key], dict):
            raise ValidationError(f"Snapshot sources.{key} is required")
        _require_string(sources[key], "status")
    records = payload.get("records")
    if not isinstance(records, list):
        raise ValidationError("Snapshot records must be an array")
    if status in {"ok", "degraded"} and not records:
        raise ValidationError("Successful snapshots must contain records")
    seen: set[str] = set()
    previous = ""
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValidationError(f"records[{index}] must be an object")
        cve_id = record.get("cve_id")
        if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
            raise ValidationError(f"records[{index}] has an invalid cve_id")
        if cve_id in seen:
            raise ValidationError(f"Duplicate snapshot record {cve_id}")
        if cve_id < previous:
            raise ValidationError("Snapshot records must be sorted by cve_id")
        seen.add(cve_id)
        previous = cve_id
        kev = record.get("kev")
        if not isinstance(kev, dict) or kev.get("listed") is not True:
            raise ValidationError(f"{cve_id} is missing KEV listing")
        if kev.get("cve_id") != cve_id:
            raise ValidationError(f"{cve_id} KEV identifier mismatch")
        completeness = record.get("completeness")
        if completeness not in {"complete", "partial", "unavailable"}:
            raise ValidationError(f"{cve_id} completeness must be complete, partial, or unavailable")
        cve = record.get("cve")
        if not isinstance(cve, dict) or cve.get("cve_id") != cve_id:
            raise ValidationError(f"{cve_id} CVE identifier mismatch")
        cve_status = cve.get("status")
        truncated = bool(cve.get("truncated_fields") or kev.get("truncated_fields") or kev.get("cwes_incomplete"))
        omitted = int(cve.get("omitted_product_count") or 0) + int(cve.get("omitted_version_count") or 0)
        if completeness == "unavailable":
            if cve_status == "ok":
                raise ValidationError(f"{cve_id} unavailable completeness requires a non-ok CVE status")
        elif cve_status != "ok":
            raise ValidationError(f"{cve_id} non-ok CVE status must be completeness unavailable")
        if completeness == "complete" and (truncated or omitted):
            raise ValidationError(f"{cve_id} complete records must not omit or truncate fields")
        if completeness == "partial" and not truncated and not omitted:
            raise ValidationError(f"{cve_id} partial records must record truncation or omission")
        signals = record.get("signals")
        if not isinstance(signals, dict):
            raise ValidationError(f"{cve_id} signals are required")
        for name in (
            "confirmed_exploitation",
            "estimated_exploitation_probability",
            "vulnerability_severity",
            "product_affectedness",
            "deployment_exposure",
        ):
            if name not in signals:
                raise ValidationError(f"{cve_id} missing signal {name}")
        if signals.get("composite_risk_score") not in (None,):
            raise ValidationError(f"{cve_id} must not set a composite risk score")
        links = record.get("links")
        if not isinstance(links, dict):
            raise ValidationError(f"{cve_id} links are required")
    changes = payload.get("changes")
    if not isinstance(changes, dict):
        raise ValidationError("Snapshot changes must be an object")
    for key in (
        "new_kev_entries",
        "updated_kev_entries",
        "removed_kev_entries",
        "changed_cve_information",
        "epss_changes",
    ):
        if key not in changes or not isinstance(changes[key], list):
            raise ValidationError(f"Snapshot changes.{key} must be an array")
    extra = changes.get("source_metadata_changes")
    if extra is not None and not isinstance(extra, list):
        raise ValidationError("Snapshot changes.source_metadata_changes must be an array")
    kev_meta = sources.get("kev") or {}
    if payload["status"] in {"ok", "degraded"} and not kev_meta.get("retrieved_at"):
        raise ValidationError("Snapshot sources.kev.retrieved_at is required")
    return payload


def validate_manifest(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("Manifest must be a JSON object")
    _require(payload, "schema_version", MANIFEST_SCHEMA_VERSION)
    _require_string(payload, "generated_at")
    status = payload.get("status")
    if status not in {"ok", "degraded", "failed", "unpublished"}:
        raise ValidationError("Manifest status is invalid")
    if payload.get("fresh") is True and payload.get("stale") is True:
        raise ValidationError("Manifest cannot be both fresh and stale")
    if status in {"ok", "degraded"}:
        _require_string(payload, "latest_snapshot")
        _require_string(payload, "latest_ok_snapshot")
    return payload


def _backfill_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    """Accept last-known-good snapshots written before completeness timestamps."""
    payload = dict(payload)
    generated = payload.get("generated_at")
    if not payload.get("collection_started_at") and isinstance(generated, str):
        payload["collection_started_at"] = generated
    if not payload.get("collection_completed_at") and isinstance(generated, str):
        payload["collection_completed_at"] = generated
    records = payload.get("records")
    if isinstance(records, list):
        filled = []
        for record in records:
            if not isinstance(record, dict):
                filled.append(record)
                continue
            item = dict(record)
            if item.get("completeness") not in {"complete", "partial", "unavailable"}:
                cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
                kev = item.get("kev") if isinstance(item.get("kev"), dict) else {}
                truncated = bool(
                    (cve or {}).get("truncated_fields")
                    or (kev or {}).get("truncated_fields")
                    or (kev or {}).get("cwes_incomplete")
                )
                omitted = int((cve or {}).get("omitted_product_count") or 0) + int(
                    (cve or {}).get("omitted_version_count") or 0
                )
                if (cve or {}).get("status") != "ok":
                    item["completeness"] = "unavailable"
                elif truncated or omitted:
                    item["completeness"] = "partial"
                else:
                    item["completeness"] = "complete"
            filled.append(item)
        payload["records"] = filled
    return payload


def _require(payload: dict[str, Any], key: str, expected: str) -> None:
    if payload.get(key) != expected:
        raise ValidationError(f"{key} must be {expected!r}")


def _require_string(payload: dict[str, Any], key: str) -> None:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{key} must be a non-empty string")
