"""Verify a GitHub Actions collect run before using its artifact."""

from __future__ import annotations

import json
from typing import Any

from silastron_pulse.errors import ArtifactVerifyError
from silastron_pulse.jsonutil import sha256_bytes


ALLOWED_WORKFLOW_PATHS = {".github/workflows/collect.yml"}
ALLOWED_WORKFLOW_NAMES = {"Collect"}
ALLOWED_COLLECT_EVENTS = frozenset({"workflow_dispatch", "schedule"})


def _normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ArtifactVerifyError("SHA-256 digest must be a string")
    digest = value.strip()
    if digest.startswith("sha256:"):
        digest = digest.split(":", 1)[1]
    digest = digest.strip().lower()
    if not digest:
        return None
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ArtifactVerifyError(f"Invalid SHA-256 digest {value!r}")
    return digest


def parse_sha256sums(text: str, *, filename: str = "candidate.json") -> str:
    """Return the content digest listed for filename in GNU sha256sum format."""
    if not isinstance(text, str) or not text.strip():
        raise ArtifactVerifyError("SHA256SUMS is empty")
    found: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        listed_name = parts[1][1:] if parts[1].startswith("*") else parts[1]
        listed_name = listed_name.rsplit("/", 1)[-1]
        if listed_name != filename:
            continue
        digest = _normalize_sha256(parts[0])
        if digest is None:
            raise ArtifactVerifyError("SHA256SUMS digest is missing")
        if found is not None and found != digest:
            raise ArtifactVerifyError("SHA256SUMS lists conflicting candidate.json digests")
        found = digest
    if found is None:
        raise ArtifactVerifyError(f"SHA256SUMS has no {filename} entry")
    return found


def verify_candidate_content(
    candidate_bytes: bytes,
    *,
    expected_digest: str | None,
    metadata_digest: str | None = None,
    sha256sums_text: str | None = None,
) -> str:
    """Verify candidate.json bytes against content digests, not a zip archive hash."""
    digest = sha256_bytes(candidate_bytes)
    expected = _normalize_sha256(expected_digest)
    if expected is None:
        raise ArtifactVerifyError("Candidate content digest is missing")
    if expected != digest:
        raise ArtifactVerifyError("Candidate digest does not match bound metadata")
    if metadata_digest is not None:
        meta = _normalize_sha256(metadata_digest)
        if meta is None:
            raise ArtifactVerifyError("candidate.meta.json digest is missing")
        if meta != digest:
            raise ArtifactVerifyError("candidate.meta.json digest mismatch")
    if sha256sums_text is not None:
        listed = parse_sha256sums(sha256sums_text)
        if listed != digest:
            raise ArtifactVerifyError("SHA256SUMS digest does not match candidate.json")
    return digest


def verify_collect_run(
    run: dict[str, Any],
    *,
    expected_repository: str,
    expected_branch: str,
    expected_head_sha: str | None,
    artifact: dict[str, Any] | None,
    candidate_bytes: bytes | None,
    expected_digest: str | None,
    metadata: dict[str, Any] | None = None,
    sha256sums_text: str | None = None,
    allowed_events: frozenset[str] | None = None,
) -> dict[str, Any]:
    repo = (
        (run.get("headRepository") or {}).get("nameWithOwner")
        or run.get("repository")
        or (run.get("head_repository") or {}).get("full_name")
    )
    if run.get("repository_full_name"):
        repo = run["repository_full_name"]
    if repo != expected_repository:
        raise ArtifactVerifyError(
            f"Collect run repository {repo!r} does not match {expected_repository!r}"
        )
    workflow = run.get("path") or (run.get("workflow") or {}).get("path") or ""
    name = run.get("name") or (run.get("workflow") or {}).get("name") or ""
    if workflow not in ALLOWED_WORKFLOW_PATHS and name not in ALLOWED_WORKFLOW_NAMES:
        raise ArtifactVerifyError(
            f"Run workflow {workflow or name!r} is not the Collect workflow"
        )
    branch = run.get("headBranch") or run.get("head_branch")
    if branch != expected_branch:
        raise ArtifactVerifyError(
            f"Collect run branch {branch!r} is not {expected_branch!r}"
        )
    conclusion = run.get("conclusion")
    if conclusion != "success":
        raise ArtifactVerifyError(f"Collect run conclusion is {conclusion!r}, not success")
    event = run.get("event")
    accepted_events = allowed_events if allowed_events is not None else ALLOWED_COLLECT_EVENTS
    if event is not None and event not in accepted_events:
        raise ArtifactVerifyError(
            f"Collect run event {event!r} is not allowed ({sorted(accepted_events)})"
        )
    head_sha = run.get("headSha") or run.get("head_sha")
    if not head_sha:
        raise ArtifactVerifyError("Collect run is missing head SHA")
    if expected_head_sha and head_sha != expected_head_sha:
        raise ArtifactVerifyError(
            f"Collect run SHA {head_sha} does not match checkout SHA {expected_head_sha}"
        )
    if artifact is None:
        raise ArtifactVerifyError("Collect artifact pulse-candidate is missing")
    if artifact.get("name") != "pulse-candidate":
        raise ArtifactVerifyError(
            f"Artifact name {artifact.get('name')!r} is not pulse-candidate"
        )
    if artifact.get("expired") is True:
        raise ArtifactVerifyError("Collect artifact has expired")
    if candidate_bytes is None:
        raise ArtifactVerifyError("Candidate bytes are missing")
    # GitHub artifact.digest is the SHA-256 of the uploaded zip archive
    # (actions/upload-artifact), not candidate.json. Archive integrity is
    # enforced by actions/download-artifact. Content integrity is the
    # candidate.json SHA-256 checked against expected_digest, metadata, and
    # SHA256SUMS below. Do not compare artifact.digest to candidate bytes.
    metadata_digest = None
    expected_revision = None
    if metadata is not None:
        metadata_digest = metadata.get("content_sha256")
        expected_revision = metadata.get("source_state_revision")
        if metadata_digest is None:
            raise ArtifactVerifyError("candidate.meta.json digest is missing")
    digest = verify_candidate_content(
        candidate_bytes,
        expected_digest=expected_digest,
        metadata_digest=metadata_digest,
        sha256sums_text=sha256sums_text,
    )
    snapshot: dict[str, Any] | None
    try:
        parsed = json.loads(candidate_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        parsed = None
    snapshot = parsed if isinstance(parsed, dict) else None
    binding = (snapshot or {}).get("binding") if snapshot else None
    if not isinstance(binding, dict):
        binding = {}
    collector_sha = binding.get("collector_commit_sha")
    source_revision = binding.get("source_state_revision")
    if collector_sha and collector_sha != head_sha:
        raise ArtifactVerifyError(
            "Candidate collector SHA does not match collect run head SHA"
        )
    if metadata is not None:
        if collector_sha != head_sha:
            raise ArtifactVerifyError(
                "Candidate collector SHA does not match collect run head SHA"
            )
        if expected_revision is not None and source_revision != expected_revision:
            raise ArtifactVerifyError(
                "Candidate source-state revision does not match metadata"
            )
    return {
        "repository": repo,
        "workflow": workflow or name,
        "branch": branch,
        "head_sha": head_sha,
        "digest": digest,
        "snapshot_id": (snapshot or {}).get("snapshot_id") if snapshot else None,
        "run_id": run.get("id"),
    }
