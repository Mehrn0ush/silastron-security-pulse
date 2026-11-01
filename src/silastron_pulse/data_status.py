"""Neutral public data-status presentation.

Age of a published snapshot is not treated as collection failure. Last
verified is claimed only when durable verification evidence exists.
"""

from __future__ import annotations

from typing import Any

from silastron_pulse.freshness import freshness
from silastron_pulse.verification_status import validate_verification_status
from silastron_pulse.errors import ValidationError


def evaluate_data_status(
    *,
    snapshot: dict[str, Any] | None,
    manifest: dict[str, Any] | None,
    verification: dict[str, Any] | None,
    publication_status: dict[str, Any] | None,
    now,
    stale_after_hours: int,
) -> dict[str, Any]:
    """Return a presentation model. Does not mutate snapshots."""
    pub_state = None
    if isinstance(publication_status, dict):
        pub_state = publication_status.get("state")
    integrity_problem = bool(pub_state and pub_state != "consistent")
    verification_doc = None
    verification_error = None
    if verification is not None:
        try:
            verification_doc = validate_verification_status(verification)
        except (ValidationError, TypeError, ValueError) as exc:
            verification_error = str(exc)
    snapshot_generated = None
    if isinstance(snapshot, dict):
        snapshot_generated = snapshot.get("generated_at")
    elif isinstance(manifest, dict):
        snapshot_generated = manifest.get("snapshot_generated_at") or manifest.get("generated_at")
    age = None
    if snapshot_generated:
        try:
            age = freshness(
                generated_at=str(snapshot_generated),
                now=now,
                stale_after_hours=stale_after_hours,
            )
        except ValidationError:
            age = {"invalid": True, "stale": False, "fresh": False, "age_hours": None}
    verified = bool(verification_doc and verification_doc.get("verified") is True)
    sources = (snapshot or {}).get("sources") if isinstance(snapshot, dict) else {}
    if not sources and isinstance(manifest, dict):
        sources = manifest.get("sources") or {}
    kev = sources.get("kev") if isinstance(sources.get("kev"), dict) else {}
    cve = sources.get("cve") if isinstance(sources.get("cve"), dict) else {}
    nvd = sources.get("nvd") if isinstance(sources.get("nvd"), dict) else {}
    if verification_doc:
        kev_view = verification_doc.get("kev") or kev
        cve_view = verification_doc.get("cve") or cve
        nvd_view = verification_doc.get("nvd") or nvd
    else:
        kev_view, cve_view, nvd_view = kev, cve, nvd
    collection_outcome = None
    if isinstance(snapshot, dict):
        collection_outcome = snapshot.get("status")
    elif isinstance(manifest, dict):
        collection_outcome = manifest.get("status")
    headline, message, tone = _copy(
        integrity_problem=integrity_problem,
        publication_status=publication_status if isinstance(publication_status, dict) else None,
        verification=verification_doc,
        verification_error=verification_error,
        verified=verified,
        collection_outcome=collection_outcome,
        age=age,
    )
    return {
        "tone": tone,
        "headline": headline,
        "message": message,
        "verified": verified,
        "verification_available": verification_doc is not None,
        "verification_invalid": verification_error is not None,
        "integrity_problem": integrity_problem,
        "publication_state": pub_state,
        "last_successful_verification_at": verification_doc.get("verified_at") if verified else None,
        "last_successful_collection_at": _successful_collection_at(
            verification_doc, snapshot if isinstance(snapshot, dict) else None
        ),
        "last_published_snapshot_at": snapshot_generated,
        "last_upstream_kev_update_at": kev_view.get("source_updated_at") or kev_view.get("source_published_at"),
        "kev_retrieved_at": kev_view.get("retrieved_at"),
        "cve_retrieved_at": cve_view.get("retrieved_at"),
        "nvd_retrieved_at": nvd_view.get("retrieved_at"),
        "kev_status": kev_view.get("status"),
        "cve_status": cve_view.get("status"),
        "nvd_status": nvd_view.get("status"),
        "collection_outcome": collection_outcome,
        "publication_decision": verification_doc.get("publication_decision") if verification_doc else None,
        "publication_reason": verification_doc.get("publication_reason") if verification_doc else None,
        "snapshot_age_hours": None if not age or age.get("invalid") else age.get("age_hours"),
        "snapshot_age_is_not_verification": True,
    }


def _copy(
    *,
    integrity_problem: bool,
    publication_status: dict[str, Any] | None,
    verification: dict[str, Any] | None,
    verification_error: str | None,
    verified: bool,
    collection_outcome: str | None,
    age: dict[str, Any] | None,
) -> tuple[str, str, str]:
    if integrity_problem:
        classification = (publication_status or {}).get("classification") or "unresolved"
        return (
            "Publication consistency problem",
            (
                "Published Pages data and persisted pulse-state may have diverged. "
                "Do not treat this page as an authoritative publication until an "
                f"operator reconciles. Classification: {classification}."
            ),
            "unavailable",
        )
    if verification_error:
        return (
            "Verification evidence is invalid",
            "A verification-status document was present but failed validation. "
            "Do not treat snapshot age as proof of a recent successful collection.",
            "unavailable",
        )
    if verification is None:
        published_note = (
            "Timestamps below come from the last published snapshot only. "
            "A later successful Collect that skipped publication is not visible here."
        )
        if collection_outcome == "degraded":
            return (
                "Published snapshot",
                "Collection of this snapshot succeeded with incomplete extracted "
                f"inventories or unavailable enrichments. {published_note}",
                "warn",
            )
        return (
            "Verification evidence unavailable",
            published_note,
            "neutral",
        )
    if verification.get("verification_state") == "failed":
        return (
            "Collection verification failed",
            verification.get("note")
            or "The latest recorded collection did not independently validate KEV.",
            "unavailable",
        )
    if verification.get("verification_state") == "rejected":
        return (
            "Publication rejected",
            verification.get("note") or "The latest Collect artifact was not published.",
            "unavailable",
        )
    if verified and verification.get("status_only"):
        extra = ""
        if collection_outcome == "degraded":
            extra = " Optional enrichment in the published snapshot is incomplete."
        return (
            "Unchanged catalog, independently verified",
            (verification.get("note") or "") + extra,
            "ok" if collection_outcome != "degraded" else "warn",
        )
    if verified:
        extra = ""
        if collection_outcome == "degraded":
            extra = " Collection succeeded with incomplete extracted inventories or unavailable enrichments."
        return (
            "Published snapshot, independently verified",
            (verification.get("note") or "") + extra,
            "ok" if collection_outcome != "degraded" else "warn",
        )
    return (
        "Verification evidence incomplete",
        verification.get("note")
        or "Do not infer a successful verification from snapshot age or an HTTP response.",
        "neutral",
    )


def _successful_collection_at(
    verification: dict[str, Any] | None,
    snapshot: dict[str, Any] | None,
) -> str | None:
    if verification and (
        verification.get("verified") is True
        or verification.get("collection_outcome") in {"ok", "degraded"}
    ):
        completed = verification.get("collection_completed_at")
        return completed if isinstance(completed, str) and completed else None
    if snapshot and snapshot.get("status") in {"ok", "degraded"}:
        completed = snapshot.get("collection_completed_at")
        return completed if isinstance(completed, str) and completed else None
    return None
