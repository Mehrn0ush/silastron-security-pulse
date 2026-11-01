"""Auditable GitHub Pages deploy versus pulse-state persist reconciliation.

GitHub Pages deploy and pulse-state persistence are not atomic. This module
records an explicit recovery state so later publication cannot silently build
on a diverged baseline. It never claims atomicity and never overwrites
immutable snapshot history.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from silastron_pulse.errors import PublishGuardError, ValidationError
from silastron_pulse.jsonutil import load_bounded_json, sha256_bytes
from silastron_pulse.safe_fs import require_run_id, require_safe_token
from silastron_pulse.store import (
    load_json_file,
    load_snapshot,
    verify_publication_transition,
)

PUBLICATION_STATUS_NAME = "publication-status.json"
PUBLICATION_INTENT_NAME = "publication-intent.json"
DEPLOY_RECEIPT_NAME = "deploy-receipt.json"
PUBLICATION_STATUS_SCHEMA = "1.0.0"
CONSISTENT = "consistent"
DEPLOYED_UNPERSISTED = "deployed_unpersisted"
UNKNOWN = "unknown"
BLOCKED = "blocked"
PENDING_DEPLOY = "pending_deploy"
FAILED = "failed"
RECOVERY_STATES = frozenset(
    {CONSISTENT, DEPLOYED_UNPERSISTED, UNKNOWN, BLOCKED, PENDING_DEPLOY, FAILED}
)
BLOCKING_STATES = frozenset({DEPLOYED_UNPERSISTED, UNKNOWN, BLOCKED})
RECONCILE_CONFIRM = "RECONCILE"
CLASSIFICATION_LABELS = {
    "deployment_failed_before_publication": "Deployment failed before publication.",
    "deployment_succeeded_persist_failed": "Deployment succeeded but persistence failed.",
    "persistence_succeeded_and_consistent": "Persistence succeeded and deployment is consistent.",
    "deployment_outcome_unknown": "Deployment outcome is unknown.",
    "intent_recorded_pending_deploy": "Publication intent is recorded; Pages deploy has not completed.",
    "deployment_job_succeeded_content_unconfirmed": "Deploy job succeeded; the public Pages manifest is not yet confirmed.",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def publication_status_path(published_dir: Path) -> Path:
    return published_dir / PUBLICATION_STATUS_NAME


def deploy_receipt_path(published_dir: Path) -> Path:
    return published_dir / DEPLOY_RECEIPT_NAME


def load_publication_status(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    """Legacy published trees without a status file are treated as consistent."""
    path = publication_status_path(published_dir)
    if not path.exists():
        return default_consistent_status()
    payload = load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)
    return validate_publication_status(payload)


def default_consistent_status() -> dict[str, Any]:
    return {
        "schema_version": PUBLICATION_STATUS_SCHEMA,
        "state": CONSISTENT,
        "classification": "persistence_succeeded_and_consistent",
        "legacy_missing_status": True,
        "note": (
            "No publication-status.json was present. Pre-reconciliation published "
            "trees are treated as consistent and are not silently rewritten."
        ),
    }


def validate_publication_status(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("publication-status.json must be a JSON object")
    state = payload.get("state")
    if state not in RECOVERY_STATES:
        raise ValidationError(f"publication-status state {state!r} is not recognized")
    if payload.get("schema_version") != PUBLICATION_STATUS_SCHEMA:
        raise ValidationError("publication-status schema_version is unsupported")
    for key in ("snapshot_id", "collect_run_id", "deployment_run_id", "manifest_digest"):
        value = payload.get(key)
        if value in (None, ""):
            continue
        if key in {"collect_run_id", "deployment_run_id"}:
            require_run_id(value)
        elif key == "manifest_digest":
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise ValidationError("publication-status manifest_digest is not a SHA-256 hex digest")
        else:
            require_safe_token(value, label=key)
    return payload


def publication_status_block_reason(
    published_dir: Path | None,
    *,
    max_bytes: int,
    max_depth: int,
) -> str | None:
    if published_dir is None or not published_dir.exists():
        return None
    try:
        status = load_publication_status(
            published_dir, max_bytes=max_bytes, max_depth=max_depth
        )
    except (ValidationError, PublishGuardError, OSError) as exc:
        return (
            f"Published reconciliation state is unreadable ({exc}). "
            "Refusing to publish on an unverified baseline. "
            + operator_recovery_instructions(None)
        )
    if status.get("state") == PENDING_DEPLOY:
        return (
            "Publication intent is recorded and Pages deploy is not confirmed consistent. "
            "This is an unresolved publication, not proof the CDN serves the intended snapshot. "
            + operator_recovery_instructions(status)
        )
    if status.get("state") == FAILED:
        return None
    if status.get("state") not in BLOCKING_STATES:
        return None
    classification = status.get("classification") or "deployment_outcome_unknown"
    label = CLASSIFICATION_LABELS.get(classification, CLASSIFICATION_LABELS["deployment_outcome_unknown"])
    identities = _identity_lines(status)
    return (
        f"Publication is blocked because Pages and pulse-state have diverged. "
        f"{label} {identities} GitHub Pages deploy and pulse-state persist are "
        f"not atomic. {operator_recovery_instructions(status)}"
    )


def classify_workflow_outcome(
    *,
    deploy_result: str | None,
    persist_result: str | None,
    receipt_result: str | None = None,
) -> str:
    deploy = (deploy_result or "").lower()
    persist = (persist_result or "").lower()
    if deploy == "success" and persist == "success":
        return "persistence_succeeded_and_consistent"
    if deploy in {"failure", "cancelled"} and persist != "success":
        return "deployment_failed_before_publication"
    if deploy == "success" and persist != "success":
        return "deployment_succeeded_persist_failed"
    if deploy in {"", "skipped"} or persist in {"", "skipped"}:
        if receipt_result == "success":
            return "deployment_succeeded_persist_failed"
        return "deployment_outcome_unknown"
    return "deployment_outcome_unknown"


def build_publication_status(
    *,
    state: str,
    classification: str,
    now: datetime,
    snapshot_id: str | None = None,
    collect_run_id: str | None = None,
    deployment_run_id: str | None = None,
    manifest_digest: str | None = None,
    persisted_snapshot_id: str | None = None,
    persisted_manifest_digest: str | None = None,
    page_url: str | None = None,
    note: str | None = None,
    recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if state not in RECOVERY_STATES:
        raise ValidationError(f"publication-status state {state!r} is not recognized")
    payload: dict[str, Any] = {
        "schema_version": PUBLICATION_STATUS_SCHEMA,
        "state": state,
        "classification": classification,
        "updated_at": _format_now(now),
        "snapshot_id": snapshot_id,
        "collect_run_id": str(collect_run_id) if collect_run_id is not None else None,
        "deployment_run_id": str(deployment_run_id) if deployment_run_id is not None else None,
        "manifest_digest": manifest_digest,
        "persisted_snapshot_id": persisted_snapshot_id,
        "persisted_manifest_digest": persisted_manifest_digest,
        "page_url": page_url,
        "note": note
        or (
            "GitHub Pages cannot update atomically with pulse-state. "
            "This file records deploy/persist agreement; it is not a lock on CISA data."
        ),
        "recovery": recovery,
        "legacy_missing_status": False,
    }
    return validate_publication_status(payload)


def write_publication_status(published_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    validated = validate_publication_status(payload)
    published_dir.mkdir(parents=True, exist_ok=True)
    path = publication_status_path(published_dir)
    body = json.dumps(validated, indent=2, sort_keys=True) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)
    return validated


def assert_publication_consistent(
    published_dir: Path,
    *,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    reason = publication_status_block_reason(
        published_dir, max_bytes=max_bytes, max_depth=max_depth
    )
    if reason:
        raise PublishGuardError(reason)
    return load_publication_status(
        published_dir, max_bytes=max_bytes, max_depth=max_depth
    )


def reconcile_publication(
    *,
    incoming_dir: Path,
    current_dir: Path,
    expected_snapshot_id: str,
    expected_digest: str,
    expected_collect_run_id: str,
    confirm: str,
    now: datetime,
    max_bytes: int,
    max_depth: int,
    deployment_run_id: str | None = None,
) -> dict[str, Any]:
    """Idempotent recovery: persist only the verified deployed snapshot.

    Never overwrites an already-correct newer latest.json. Never deletes
    immutable snapshots. Duplicate recovery of the same snapshot is a no-op.
    """
    if confirm != RECONCILE_CONFIRM:
        raise PublishGuardError("Reconciliation requires explicit confirm=RECONCILE")
    snapshot_id = require_safe_token(expected_snapshot_id, label="snapshot_id")
    if not isinstance(expected_digest, str) or not _SHA256_RE.fullmatch(expected_digest):
        raise PublishGuardError("expected digest is not a SHA-256 hex digest")
    collect_run_id = require_run_id(expected_collect_run_id)
    incoming_latest = load_snapshot(
        incoming_dir / "latest.json", max_bytes=max_bytes, max_depth=max_depth
    )
    incoming_id = incoming_latest.get("snapshot_id")
    if incoming_id != snapshot_id:
        raise PublishGuardError(
            f"Incoming snapshot {incoming_id} does not match expected {snapshot_id}. "
            "Refusing a stale or conflicting recovery request."
        )
    incoming_bytes = (incoming_dir / "latest.json").read_bytes()
    incoming_digest = sha256_bytes(incoming_bytes)
    if incoming_digest != expected_digest:
        raise PublishGuardError(
            "Incoming latest.json digest does not match the original validated artifact. "
            "Refusing to repair from unverified content."
        )
    current_status = load_publication_status(
        current_dir, max_bytes=max_bytes, max_depth=max_depth
    )
    current_latest_path = current_dir / "latest.json"
    if current_latest_path.exists():
        current_latest = load_snapshot(
            current_latest_path, max_bytes=max_bytes, max_depth=max_depth
        )
        current_id = current_latest.get("snapshot_id")
        if current_id == snapshot_id:
            if incoming_latest != current_latest:
                raise PublishGuardError(
                    "Current latest.json already uses this snapshot_id but the bytes differ. "
                    "Refusing to overwrite published/latest."
                )
            status = write_publication_status(
                current_dir,
                build_publication_status(
                    state=CONSISTENT,
                    classification="persistence_succeeded_and_consistent",
                    now=now,
                    snapshot_id=snapshot_id,
                    collect_run_id=collect_run_id,
                    deployment_run_id=deployment_run_id or current_status.get("deployment_run_id"),
                    manifest_digest=expected_digest,
                    persisted_snapshot_id=snapshot_id,
                    persisted_manifest_digest=expected_digest,
                    note="Idempotent reconciliation: published state already matches the deployed snapshot.",
                    recovery={"result": "already_consistent", "duplicate": True},
                ),
            )
            return {
                "status": "already_consistent",
                "snapshot_id": snapshot_id,
                "collect_run_id": collect_run_id,
                "publication_status": status,
            }
        if current_status.get("state") == CONSISTENT and current_id != snapshot_id:
            raise PublishGuardError(
                f"Published latest is {current_id}, not {snapshot_id}. "
                "Refusing to silently roll back production data. "
                "Use the explicit rollback command if an older snapshot must be restored."
            )
        receipt_id = current_status.get("snapshot_id")
        if receipt_id and receipt_id != snapshot_id:
            raise PublishGuardError(
                f"Recovery request for {snapshot_id} conflicts with recorded "
                f"deploy receipt {receipt_id}. Refusing a stale recovery request."
            )

    verify_publication_transition(
        incoming_dir=incoming_dir,
        current_dir=current_dir,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )
    status = write_publication_status(
        current_dir,
        build_publication_status(
            state=CONSISTENT,
            classification="persistence_succeeded_and_consistent",
            now=now,
            snapshot_id=snapshot_id,
            collect_run_id=collect_run_id,
            deployment_run_id=deployment_run_id or current_status.get("deployment_run_id"),
            manifest_digest=expected_digest,
            persisted_snapshot_id=snapshot_id,
            persisted_manifest_digest=expected_digest,
            note="Reconciliation verified the original artifact and publication transition before marking consistent.",
            recovery={"result": "repaired", "duplicate": False},
        ),
    )
    return {
        "status": "repaired",
        "snapshot_id": snapshot_id,
        "collect_run_id": collect_run_id,
        "publication_status": status,
        "copy_required": True,
    }


def operator_recovery_instructions(status: dict[str, Any] | None) -> str:
    identities = _identity_lines(status) if status else ""
    return (
        "Operator recovery: 1) Do not dispatch Deploy frontend while "
        "publication-status state is pending_deploy, deployed_unpersisted, "
        "unknown, or blocked. 2) If Pages deploy failed after intent was "
        "recorded, re-run mark-deploy-failed or write publication-status "
        "state=failed so later publication is not permanently locked. "
        "3) If Pages deploy succeeded, re-run persist-published on that "
        "Publish run, or dispatch silastron-pulse reconcile-publication "
        "with --confirm RECONCILE, the original Collect artifact "
        "(pulse-published / latest.json), --expected-snapshot-id, "
        "--expected-digest, and --expected-collect-run-id. "
        "4) Recovery verifies the original validated artifact and the "
        "publication transition before writing publication-status.json. "
        "It never overwrites a different published/latest or deletes "
        f"immutable snapshots. {identities}"
    ).strip()


def load_optional_json(path: Path, *, max_bytes: int, max_depth: int) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = load_bounded_json(
        path.read_bytes(), max_bytes=max_bytes, max_depth=max_depth, source=str(path)
    )
    if not isinstance(payload, dict):
        raise ValidationError(f"{path} is not a JSON object")
    return payload


def _identity_lines(status: dict[str, Any] | None) -> str:
    if not status:
        return ""
    parts = []
    for label, key in (
        ("Collect run ID", "collect_run_id"),
        ("snapshot ID", "snapshot_id"),
        ("manifest digest", "manifest_digest"),
        ("deployment run", "deployment_run_id"),
        ("persisted snapshot", "persisted_snapshot_id"),
        ("state", "state"),
        ("classification", "classification"),
    ):
        value = status.get(key)
        if value:
            parts.append(f"{label}={value}")
    return "Identities: " + "; ".join(parts) + "." if parts else ""


def _format_now(now: datetime) -> str:
    from silastron_pulse.clock import format_datetime

    return format_datetime(now)


def publication_intent_path(published_dir: Path) -> Path:
    return published_dir / PUBLICATION_INTENT_NAME


def build_publication_intent(
    *,
    now: datetime,
    snapshot_id: str,
    collect_run_id: str,
    candidate_digest: str,
    expected_previous_snapshot_id: str | None,
    deployment_run_id: str,
    state: str = PENDING_DEPLOY,
) -> dict[str, Any]:
    require_safe_token(snapshot_id, label="snapshot_id")
    require_run_id(collect_run_id)
    require_run_id(deployment_run_id)
    if not _SHA256_RE.fullmatch(candidate_digest):
        raise ValidationError("publication intent digest is not a SHA-256 hex digest")
    if expected_previous_snapshot_id:
        require_safe_token(expected_previous_snapshot_id, label="expected_previous_snapshot_id")
    return {
        "schema_version": PUBLICATION_STATUS_SCHEMA,
        "state": state,
        "updated_at": _format_now(now),
        "snapshot_id": snapshot_id,
        "collect_run_id": str(collect_run_id),
        "deployment_run_id": str(deployment_run_id),
        "candidate_digest": candidate_digest,
        "expected_previous_snapshot_id": expected_previous_snapshot_id,
        "note": (
            "Intent is recorded before Pages deploy. A successful deploy-pages "
            "job is not proof the public CDN serves this snapshot."
        ),
    }


def write_publication_intent(published_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    published_dir.mkdir(parents=True, exist_ok=True)
    path = publication_intent_path(published_dir)
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)
    return payload


def load_publication_intent(
    published_dir: Path, *, max_bytes: int, max_depth: int
) -> dict[str, Any]:
    path = publication_intent_path(published_dir)
    if not path.exists():
        raise PublishGuardError("publication-intent.json is missing")
    payload = load_json_file(path, max_bytes=max_bytes, max_depth=max_depth)
    for key in ("snapshot_id", "collect_run_id", "candidate_digest", "deployment_run_id"):
        if not payload.get(key):
            raise PublishGuardError(f"publication intent is missing {key}")
    return payload


def assert_intent_matches(
    published_dir: Path,
    *,
    snapshot_id: str,
    collect_run_id: str,
    candidate_digest: str,
    max_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    intent = load_publication_intent(
        published_dir, max_bytes=max_bytes, max_depth=max_depth
    )
    if intent.get("snapshot_id") != snapshot_id:
        raise PublishGuardError("publication intent snapshot_id does not match the validated candidate")
    if str(intent.get("collect_run_id")) != str(collect_run_id):
        raise PublishGuardError("publication intent collect_run_id does not match the bound Collect run")
    if intent.get("candidate_digest") != candidate_digest:
        raise PublishGuardError("publication intent digest does not match the validated candidate")
    return intent
