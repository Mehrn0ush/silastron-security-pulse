"""Fail-closed publication eligibility for a bound Collect artifact."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from silastron_pulse.adapters.epss import REDISTRIBUTION_CLEARED
from silastron_pulse.constants import DEFAULT_LIMITS
from silastron_pulse.errors import ArtifactVerifyError, PulseError, ValidationError
from silastron_pulse.freshness import freshness
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.store import load_snapshot, parse_generated_at
from silastron_pulse.validate import validate_snapshot
from silastron_pulse.verify_run import ALLOWED_COLLECT_EVENTS, verify_collect_run

AUTO_COLLECT_EVENTS = frozenset({"schedule"})
MAX_KEV_DROP_RATIO = 0.10
MAX_COMPLETE_REGRESSION_RATIO = 0.10


@dataclass(frozen=True)
class PublicationDecision:
    outcome: str
    reason: str
    snapshot_id: str | None = None
    collect_run_id: object | None = None
    digest: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def should_publish(self) -> bool:
        return self.outcome == "publish"


def evaluate_publication(
    *,
    mode: str,
    run: dict[str, Any],
    expected_repository: str,
    expected_branch: str,
    artifact: dict[str, Any] | None,
    candidate_bytes: bytes,
    metadata: dict[str, Any] | None,
    sha256sums_text: str | None,
    published_dir: Path | None,
    now: datetime,
    max_bytes: int,
    max_depth: int,
    stale_after_hours: int | None = None,
) -> PublicationDecision:
    """Return publish, skip, or reject for one already-bound Collect artifact."""
    if mode not in {"auto", "manual"}:
        return _reject("invalid_mode", f"Publication mode {mode!r} is not auto or manual")
    if not isinstance(metadata, dict) or not metadata.get("content_sha256"):
        return _reject(
            "artifact_invalid",
            "candidate.meta.json digest is missing",
            collect_run_id=run.get("id"),
        )
    allowed_events = AUTO_COLLECT_EVENTS if mode == "auto" else ALLOWED_COLLECT_EVENTS
    try:
        verified = verify_collect_run(
            run,
            expected_repository=expected_repository,
            expected_branch=expected_branch,
            expected_head_sha=run.get("headSha") or run.get("head_sha"),
            artifact=artifact,
            candidate_bytes=candidate_bytes,
            expected_digest=(metadata or {}).get("content_sha256") if metadata else sha256_bytes(candidate_bytes),
            metadata=metadata,
            sha256sums_text=sha256sums_text,
            allowed_events=allowed_events,
        )
    except ArtifactVerifyError as exc:
        return _reject("collect_run_untrusted", str(exc), collect_run_id=run.get("id"))

    try:
        payload = json.loads(candidate_bytes.decode("utf-8"))
        candidate = validate_snapshot(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, ValidationError) as exc:
        return _reject(
            "snapshot_invalid",
            str(exc),
            collect_run_id=verified.get("run_id"),
            digest=verified.get("digest"),
        )

    snapshot_id = candidate.get("snapshot_id")
    digest = verified.get("digest")
    collect_run_id = verified.get("run_id")
    hours = _stale_after_hours(candidate, stale_after_hours)
    try:
        fresh = freshness(
            generated_at=candidate["generated_at"],
            now=now,
            stale_after_hours=hours,
        )
    except ValidationError as exc:
        return _reject(
            "stale_candidate",
            str(exc),
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
        )

    details = {
        "mode": mode,
        "collect_event": run.get("event"),
        "collection_freshness": fresh,
        "source_freshness": {
            "kev_retrieved_at": ((candidate.get("sources") or {}).get("kev") or {}).get("retrieved_at"),
            "kev_source_updated_at": ((candidate.get("sources") or {}).get("kev") or {}).get(
                "source_updated_at"
            ),
            "cve_retrieved_at": ((candidate.get("sources") or {}).get("cve") or {}).get("retrieved_at"),
            "cve_source_updated_at": ((candidate.get("sources") or {}).get("cve") or {}).get(
                "source_updated_at"
            ),
        },
        "publication_freshness": None,
        "status": candidate.get("status"),
        "record_count": len(candidate.get("records") or []),
    }

    epss_reason = _epss_block_reason(candidate)
    if epss_reason:
        return _reject(
            "epss_forbidden",
            epss_reason,
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    source_reason = _source_integrity_reason(candidate)
    if source_reason:
        code, message = source_reason
        return _reject(
            code,
            message,
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    if candidate["status"] == "failed":
        return _reject(
            "failed_snapshot",
            "Refusing to publish a failed snapshot",
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )
    if not candidate.get("records"):
        return _reject(
            "empty_snapshot",
            "Refusing to publish an empty snapshot",
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    degraded_reason = _degraded_policy_reason(candidate)
    if degraded_reason:
        return _reject(
            "degraded_blocked",
            degraded_reason,
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    if fresh["stale"]:
        return _reject(
            "stale_candidate",
            (
                f"Candidate age {fresh['age_hours']} hours exceeds "
                f"stale_after_hours {hours}"
            ),
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    try:
        published = _load_published(
            published_dir, max_bytes=max_bytes, max_depth=max_depth
        )
    except (PulseError, OSError, json.JSONDecodeError) as exc:
        return _reject(
            "published_state_invalid",
            str(exc),
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )
    if published is None:
        details["publication_freshness"] = {"state": "none"}
        return PublicationDecision(
            outcome="publish",
            reason="first_publish",
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    details["publication_freshness"] = {
        "snapshot_id": published.get("snapshot_id"),
        "snapshot_generated_at": published.get("generated_at"),
        "status": published.get("status"),
        "record_count": len(published.get("records") or []),
    }
    if published.get("snapshot_id") == snapshot_id:
        return PublicationDecision(
            outcome="skip",
            reason="already_published",
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    published_ts = parse_generated_at(published["generated_at"])
    candidate_ts = parse_generated_at(candidate["generated_at"])
    if candidate_ts < published_ts:
        return _reject(
            "older_than_published",
            "Refusing to replace a newer published snapshot with an older Collect run",
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    if _upstream_identity(candidate) == _upstream_identity(published):
        return PublicationDecision(
            outcome="skip",
            reason="unchanged_upstream",
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    drop_reason = _regression_reason(published, candidate)
    if drop_reason:
        code, message = drop_reason
        return _reject(
            code,
            message,
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            digest=digest,
            details=details,
        )

    return PublicationDecision(
        outcome="publish",
        reason="eligible",
        snapshot_id=snapshot_id,
        collect_run_id=collect_run_id,
        digest=digest,
        details=details,
    )


def write_decision_outputs(
    decision: PublicationDecision,
    *,
    output_path: Path | None,
    summary_path: Path | None,
) -> None:
    if output_path is not None:
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(f"decision={decision.outcome}\n")
            handle.write(f"reason={_one_line(decision.reason)}\n")
            handle.write(f"snapshot_id={decision.snapshot_id or ''}\n")
            handle.write(f"digest={decision.digest or ''}\n")
            handle.write(f"collect_run_id={decision.collect_run_id or ''}\n")
    if summary_path is not None:
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(_format_summary(decision))


def _reject(
    reason: str,
    message: str,
    *,
    snapshot_id: str | None = None,
    collect_run_id: object | None = None,
    digest: str | None = None,
    details: dict[str, Any] | None = None,
) -> PublicationDecision:
    payload = dict(details or {})
    payload["message"] = message
    return PublicationDecision(
        outcome="reject",
        reason=reason,
        snapshot_id=snapshot_id,
        collect_run_id=collect_run_id,
        digest=digest,
        details=payload,
    )


def _stale_after_hours(candidate: dict[str, Any], override: int | None) -> int:
    if override is not None:
        return override
    limits = candidate.get("limits") or {}
    raw = limits.get("stale_after_hours", DEFAULT_LIMITS["stale_after_hours"])
    try:
        hours = int(raw)
    except (TypeError, ValueError):
        hours = int(DEFAULT_LIMITS["stale_after_hours"])
    return hours if hours > 0 else int(DEFAULT_LIMITS["stale_after_hours"])


def _epss_block_reason(candidate: dict[str, Any]) -> str | None:
    summary = candidate.get("summary") or {}
    if not REDISTRIBUTION_CLEARED and summary.get("epss_enabled") is True:
        return "EPSS is enabled on the candidate; redistribution is not approved"
    epss = (candidate.get("sources") or {}).get("epss") or {}
    if epss.get("status") not in {"disabled", "unavailable"}:
        return f"EPSS source status {epss.get('status')!r} is not disabled"
    for record in candidate.get("records") or []:
        payload = record.get("epss") or {}
        if payload.get("score") is not None or payload.get("percentile") is not None:
            return f"{record.get('cve_id')} contains an EPSS score"
        if (record.get("signals") or {}).get("estimated_exploitation_probability", {}).get(
            "value"
        ) is not None:
            return f"{record.get('cve_id')} contains an EPSS probability value"
    return None


def _source_integrity_reason(candidate: dict[str, Any]) -> tuple[str, str] | None:
    sources = candidate.get("sources") or {}
    kev = sources.get("kev") or {}
    summary = candidate.get("summary") or {}
    records = candidate.get("records") or []
    if kev.get("status") != "ok":
        return (
            "kev_unverified",
            f"KEV source status {kev.get('status')!r} is not independently verified",
        )
    if not kev.get("content_sha256"):
        return (
            "kev_unverified",
            "KEV content digest is missing; HTTP retrieval is not proof of source validity",
        )
    if not kev.get("retrieved_at"):
        return ("kev_unverified", "KEV retrieved_at is missing")
    kev_records = summary.get("kev_records")
    if kev_records != len(records):
        return (
            "source_inconsistent",
            f"summary.kev_records {kev_records!r} does not match {len(records)} snapshot records",
        )
    ids = [item.get("cve_id") for item in records]
    if len(ids) != len(set(ids)):
        return ("source_inconsistent", "Snapshot contains duplicate CVE IDs")
    return None


def _degraded_policy_reason(candidate: dict[str, Any]) -> str | None:
    if candidate.get("status") != "degraded":
        return None
    cve = (candidate.get("sources") or {}).get("cve") or {}
    if cve.get("status") not in {"ok", "degraded"}:
        return f"Degraded snapshot has unverified CVE source status {cve.get('status')!r}"
    summary = candidate.get("summary") or {}
    unavailable = summary.get("unavailable_records") or 0
    if unavailable:
        return (
            "Degraded snapshot has unavailable CVE enrichments; "
            "only bounded partial extraction is allowed"
        )
    partial = summary.get("partial_records") or 0
    truncated = summary.get("truncated_records") or 0
    if not partial and not truncated:
        return "Degraded snapshot has no bounded partial CVE extraction"
    if partial and truncated == 0:
        return "Degraded snapshot reports partial records without truncated extraction"
    return None


def _load_published(
    published_dir: Path | None, *, max_bytes: int, max_depth: int
) -> dict[str, Any] | None:
    if published_dir is None:
        return None
    latest = published_dir / "latest.json"
    if not latest.exists():
        return None
    return load_snapshot(latest, max_bytes=max_bytes, max_depth=max_depth)


def _upstream_identity(snapshot: dict[str, Any]) -> tuple[object, ...]:
    sources = snapshot.get("sources") or {}
    kev = sources.get("kev") or {}
    cve = sources.get("cve") or {}
    summary = snapshot.get("summary") or {}
    ids = tuple(item.get("cve_id") for item in snapshot.get("records") or [])
    return (
        kev.get("content_sha256"),
        cve.get("content_sha256"),
        cve.get("source_revision"),
        summary.get("complete_records"),
        summary.get("partial_records"),
        summary.get("unavailable_records"),
        ids,
    )


def _regression_reason(
    published: dict[str, Any], candidate: dict[str, Any]
) -> tuple[str, str] | None:
    published_ids = {
        item.get("cve_id") for item in published.get("records") or [] if item.get("cve_id")
    }
    candidate_ids = {
        item.get("cve_id") for item in candidate.get("records") or [] if item.get("cve_id")
    }
    published_kev = ((published.get("sources") or {}).get("kev") or {}).get("content_sha256")
    candidate_kev = ((candidate.get("sources") or {}).get("kev") or {}).get("content_sha256")
    if published_kev and published_kev == candidate_kev and published_ids != candidate_ids:
        missing = sorted(published_ids - candidate_ids)
        extra = sorted(candidate_ids - published_ids)
        return (
            "source_inconsistent",
            "KEV digest is unchanged but CVE IDs changed"
            + (f"; missing {missing[:8]}" if missing else "")
            + (f"; extra {extra[:8]}" if extra else ""),
        )
    published_count = len(published.get("records") or [])
    candidate_count = len(candidate.get("records") or [])
    if published_count and candidate_count < published_count * (1 - MAX_KEV_DROP_RATIO):
        return (
            "unexpected_kev_drop",
            (
                f"Candidate record count {candidate_count} dropped more than "
                f"{int(MAX_KEV_DROP_RATIO * 100)}% from published {published_count}"
            ),
        )
    published_complete = (published.get("summary") or {}).get("complete_records")
    candidate_complete = (candidate.get("summary") or {}).get("complete_records")
    if (
        isinstance(published_complete, int)
        and isinstance(candidate_complete, int)
        and published_complete
        and published_kev == candidate_kev
        and candidate_complete < published_complete * (1 - MAX_COMPLETE_REGRESSION_RATIO)
    ):
        return (
            "completeness_regression",
            (
                f"Complete extracted inventories fell from {published_complete} to "
                f"{candidate_complete} while the KEV digest is unchanged"
            ),
        )
    return None


def _format_summary(decision: PublicationDecision) -> str:
    details = decision.details or {}
    collection = details.get("collection_freshness") or {}
    source = details.get("source_freshness") or {}
    published = details.get("publication_freshness") or {}
    lines = [
        "## Publication decision",
        "",
        f"- Outcome: `{decision.outcome}`",
        f"- Reason: `{decision.reason}`",
        f"- Mode: `{details.get('mode') or 'unknown'}`",
        f"- Collect run ID: `{decision.collect_run_id or 'none'}`",
        f"- Collect event: `{details.get('collect_event') or 'unknown'}`",
        f"- Snapshot ID: `{decision.snapshot_id or 'none'}`",
        f"- Candidate digest: `{decision.digest or 'none'}`",
        f"- Collection status: `{details.get('status') or 'unknown'}`",
        f"- Record count: `{details.get('record_count')}`",
        "",
        "### Freshness",
        "",
        f"- Collection age hours: `{collection.get('age_hours')}` (stale={collection.get('stale')})",
        f"- KEV retrieved at: `{source.get('kev_retrieved_at')}`",
        f"- KEV source updated at: `{source.get('kev_source_updated_at')}`",
        f"- CVE retrieved at: `{source.get('cve_retrieved_at')}`",
        f"- Published snapshot: `{published.get('snapshot_id') or published.get('state') or 'none'}`",
        f"- Published generated at: `{published.get('snapshot_generated_at') or 'none'}`",
    ]
    message = details.get("message")
    if message:
        lines.extend(["", f"- Detail: {message}"])
    if decision.outcome == "skip" and decision.reason == "unchanged_upstream":
        lines.extend(
            [
                "",
                "Unchanged upstream KEV/CVE identity is a normal skip. "
                "The Collect run succeeded; Pages was not redeployed.",
            ]
        )
    return "\n".join(lines) + "\n"


def _one_line(value: str) -> str:
    return " ".join(value.split())
