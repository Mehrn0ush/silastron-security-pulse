"""Validated operational verification status for the public site.

This is not a vulnerability snapshot. It records whether Collect independently
validated sources and what Publish decided. It must not invent KEV rows or
rewrite immutable history.
"""

from __future__ import annotations

from typing import Any

from silastron_pulse.errors import ValidationError
from silastron_pulse.jsonutil import sha256_bytes, dump_canonical
from silastron_pulse.safe_fs import require_run_id, require_safe_token

VERIFICATION_STATUS_SCHEMA = "1.0.0"
VERIFICATION_KIND = "verification_status"
STATUS_ONLY_REASONS = frozenset({"unchanged_upstream", "already_published"})


def build_verification_status(
    *,
    candidate: dict[str, Any],
    decision_outcome: str,
    decision_reason: str,
    collect_run_id: object | None,
    collect_event: object | None,
    published: dict[str, Any] | None,
    publication_state: str | None,
    candidate_digest: str | None,
) -> dict[str, Any]:
    sources = candidate.get("sources") if isinstance(candidate.get("sources"), dict) else {}
    kev = sources.get("kev") if isinstance(sources.get("kev"), dict) else {}
    cve = sources.get("cve") if isinstance(sources.get("cve"), dict) else {}
    nvd = sources.get("nvd") if isinstance(sources.get("nvd"), dict) else {}
    summary = candidate.get("summary") if isinstance(candidate.get("summary"), dict) else {}
    kev_validated = (
        kev.get("status") == "ok"
        and isinstance(kev.get("content_sha256"), str)
        and bool(kev.get("content_sha256"))
        and isinstance(kev.get("retrieved_at"), str)
        and bool(kev.get("retrieved_at"))
        and candidate.get("status") in {"ok", "degraded"}
    )
    verified = kev_validated and decision_outcome in {"publish", "skip"}
    published_snapshot = published if isinstance(published, dict) else {}
    payload = {
        "schema_version": VERIFICATION_STATUS_SCHEMA,
        "kind": VERIFICATION_KIND,
        "verified": verified,
        "verification_state": _verification_state(
            verified=verified,
            kev_validated=kev_validated,
            outcome=decision_outcome,
        ),
        "verified_at": candidate.get("collection_completed_at") if verified else None,
        "collection_started_at": candidate.get("collection_started_at"),
        "collection_completed_at": candidate.get("collection_completed_at"),
        "collect_run_id": str(collect_run_id) if collect_run_id is not None else None,
        "collect_event": collect_event if isinstance(collect_event, str) else None,
        "candidate_snapshot_id": candidate.get("snapshot_id"),
        "candidate_digest": candidate_digest,
        "published_snapshot_id": published_snapshot.get("snapshot_id"),
        "published_generated_at": published_snapshot.get("generated_at"),
        "publication_decision": decision_outcome,
        "publication_reason": decision_reason,
        "publication_state": publication_state,
        "status_only": decision_outcome == "skip" and decision_reason in STATUS_ONLY_REASONS,
        "kev": _source_view(kev, validated=kev_validated),
        "cve": _source_view(cve, validated=cve.get("status") in {"ok", "degraded"}),
        "nvd": _source_view(nvd, validated=False),
        "collection_outcome": candidate.get("status"),
        "nvd_metrics": {
            "ok": summary.get("nvd_ok"),
            "unavailable": summary.get("nvd_unavailable"),
            "fetched": summary.get("nvd_fetched"),
            "reused": summary.get("nvd_reused"),
            "pending_backfill": summary.get("nvd_pending_backfill"),
            "requests_attempted": summary.get("nvd_requests_attempted"),
            "cache_hits": summary.get("nvd_cache_hits"),
            "records_refreshed": summary.get("nvd_records_refreshed"),
            "rate_limited": summary.get("nvd_rate_limited"),
            "failed_requests": summary.get("nvd_failed_requests"),
            "processing_ms": summary.get("nvd_processing_ms"),
        },
        "note": _note(verified, decision_outcome, decision_reason, kev_validated),
    }
    payload["content_sha256"] = sha256_bytes(dump_canonical({k: v for k, v in payload.items() if k != "content_sha256"}).encode("utf-8"))
    return validate_verification_status(payload)


def validate_verification_status(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("Verification status must be a JSON object")
    if payload.get("schema_version") != VERIFICATION_STATUS_SCHEMA:
        raise ValidationError("Verification status schema_version is invalid")
    if payload.get("kind") != VERIFICATION_KIND:
        raise ValidationError("Verification status kind is invalid")
    if payload.get("verified") is True:
        if payload.get("verification_state") != "verified":
            raise ValidationError("verified=true requires verification_state=verified")
        _require_string(payload, "verified_at")
        kev = payload.get("kev") if isinstance(payload.get("kev"), dict) else {}
        if kev.get("status") != "ok" or not kev.get("content_sha256") or not kev.get("retrieved_at"):
            raise ValidationError("verified=true requires durable KEV validation evidence")
        if payload.get("publication_decision") not in {"publish", "skip"}:
            raise ValidationError("verified=true requires a publish or skip decision")
    else:
        if payload.get("verification_state") not in {"failed", "rejected", "insufficient"}:
            raise ValidationError("Unverified status must be failed, rejected, or insufficient")
        if payload.get("verified_at") is not None:
            raise ValidationError("verified_at is only allowed when verification succeeded")
    if payload.get("status_only") is True and payload.get("publication_decision") != "skip":
        raise ValidationError("status_only is only valid for skip decisions")
    collect_run_id = payload.get("collect_run_id")
    if collect_run_id is not None:
        require_run_id(collect_run_id)
    snapshot_id = payload.get("candidate_snapshot_id")
    if snapshot_id is not None:
        require_safe_token(snapshot_id, label="candidate_snapshot_id")
    published_id = payload.get("published_snapshot_id")
    if published_id is not None:
        require_safe_token(published_id, label="published_snapshot_id")
    return payload


def _source_view(meta: dict[str, Any], *, validated: bool) -> dict[str, Any]:
    return {
        "status": meta.get("status"),
        "retrieved_at": meta.get("retrieved_at"),
        "source_updated_at": meta.get("source_updated_at") or meta.get("source_published_at"),
        "content_sha256": meta.get("content_sha256"),
        "validated": validated and meta.get("status") == "ok" and bool(meta.get("content_sha256")),
    }


def _verification_state(*, verified: bool, kev_validated: bool, outcome: str) -> str:
    if verified:
        return "verified"
    if outcome == "reject":
        return "rejected"
    if not kev_validated:
        return "failed"
    return "insufficient"


def _note(verified: bool, outcome: str, reason: str, kev_validated: bool) -> str:
    if verified and outcome == "skip" and reason in STATUS_ONLY_REASONS:
        return (
            "Sources were independently re-validated. Published snapshot "
            "content is unchanged. This is not a new vulnerability snapshot."
        )
    if verified and outcome == "publish":
        return "Sources were independently validated and a new snapshot was published."
    if outcome == "reject":
        return f"Publication was rejected ({reason}). This is not successful verification."
    if not kev_validated:
        return "KEV was not independently validated. Do not treat this as last-verified evidence."
    return "Verification evidence is incomplete."


def _require_string(payload: dict[str, Any], key: str) -> None:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Verification status {key} is required")
