"""Verify a GitHub Actions collect run before using its artifact."""

from __future__ import annotations

from typing import Any

from silastron_pulse.errors import ArtifactVerifyError
from silastron_pulse.jsonutil import sha256_bytes


ALLOWED_WORKFLOW_PATHS = {".github/workflows/collect.yml"}
ALLOWED_WORKFLOW_NAMES = {"Collect"}


def verify_collect_run(
    run: dict[str, Any],
    *,
    expected_repository: str,
    expected_branch: str,
    expected_head_sha: str | None,
    artifact: dict[str, Any] | None,
    candidate_bytes: bytes | None,
    expected_digest: str | None,
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
    if event not in {None, "workflow_dispatch"}:
        raise ArtifactVerifyError(f"Collect run event {event!r} is not workflow_dispatch")
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
    digest = sha256_bytes(candidate_bytes)
    artifact_digest = artifact.get("digest") or artifact.get("content_sha256")
    if not artifact_digest and not expected_digest:
        raise ArtifactVerifyError("Artifact digest is missing")
    if isinstance(artifact_digest, str) and artifact_digest.startswith("sha256:"):
        artifact_digest = artifact_digest.split(":", 1)[1]
    if artifact_digest and artifact_digest != digest:
        raise ArtifactVerifyError("Artifact digest does not match candidate bytes")
    if expected_digest and expected_digest != digest:
        raise ArtifactVerifyError("Candidate digest does not match bound metadata")
    return {
        "repository": repo,
        "workflow": workflow or name,
        "branch": branch,
        "head_sha": head_sha,
        "digest": digest,
    }
