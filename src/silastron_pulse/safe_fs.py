"""Refuse symlinks and unexpected artifact paths in privileged publication."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from silastron_pulse.errors import ArtifactVerifyError, PublishGuardError

SAFE_OUTPUT_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_RUN_ID_RE = re.compile(r"^[0-9]{1,32}$")
ARTIFACT_FILES = frozenset(
    {
        "candidate.json",
        "candidate.meta.json",
        "collection-status.json",
        "SHA256SUMS",
        "source-kev-catalog.json",
        "source-kev-meta.json",
    }
)


def require_safe_token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not SAFE_OUTPUT_RE.fullmatch(value):
        raise ArtifactVerifyError(f"{label} is not a safe token")
    return value


def require_run_id(value: object) -> str:
    text = str(value).strip() if value is not None else ""
    if not SAFE_RUN_ID_RE.fullmatch(text):
        raise ArtifactVerifyError("Collect run ID must be a numeric GitHub Actions run id")
    return text


def assert_artifact_tree(directory: Path) -> None:
    """Require dist/ to contain only expected regular files, with no traversal."""
    resolved = directory.resolve()
    if not resolved.is_dir() or resolved.is_symlink():
        raise ArtifactVerifyError("Collect artifact directory is missing or is a symlink")
    names: set[str] = set()
    for path in sorted(resolved.iterdir()):
        if path.is_symlink() or path.is_dir() or not path.is_file():
            raise ArtifactVerifyError(f"Refusing unexpected artifact path {path.name}")
        if path.name not in ARTIFACT_FILES:
            raise ArtifactVerifyError(f"Unexpected artifact file {path.name}")
        try:
            path.resolve().relative_to(resolved)
        except ValueError as exc:
            raise ArtifactVerifyError(f"Artifact path escaped {directory}") from exc
        names.add(path.name)
    missing = ARTIFACT_FILES - names
    if missing:
        raise ArtifactVerifyError(f"Collect artifact is missing {sorted(missing)}")


def copy_tree_without_symlinks(src: Path, dst: Path) -> None:
    """Copy a published-data tree without following or preserving symlinks."""
    if not src.exists() or not src.is_dir() or src.is_symlink():
        raise PublishGuardError("Source tree is missing or is a symlink")
    dst.mkdir(parents=True, exist_ok=True)
    src_resolved = src.resolve()
    for path in src.rglob("*"):
        if path.is_symlink():
            raise PublishGuardError(f"Refusing symlink in published tree {path.name}")
        rel = path.relative_to(src)
        if ".." in rel.parts:
            raise PublishGuardError(f"Refusing path traversal {rel}")
        target = dst / rel
        try:
            path.resolve().relative_to(src_resolved)
            if target.exists() or target.is_symlink():
                target.resolve().relative_to(dst.resolve())
        except ValueError as exc:
            raise PublishGuardError(f"Copy escaped published tree {rel}") from exc
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            raise PublishGuardError(f"Refusing special file {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target, follow_symlinks=False)
