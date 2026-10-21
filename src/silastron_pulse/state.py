"""Filesystem layout for the pulse-state branch.

Source, candidate, and published snapshots are separate directories. A failed
collection must not replace last-known-good candidate or published files.
"""

from __future__ import annotations

from typing import Any
from pathlib import Path

from silastron_pulse.jsonutil import dump_canonical, load_bounded_json, sha256_bytes
from silastron_pulse.store import atomic_write_json, load_snapshot
from silastron_pulse.errors import ValidationError


class PulseState:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.candidates = root / "candidates"
        self.published = root / "published"

    def source_manifest_path(self) -> Path:
        return self.source / "manifest.json"

    def kev_meta_path(self) -> Path:
        return self.source / "kev" / "meta.json"

    def kev_catalog_path(self) -> Path:
        return self.source / "kev" / "catalog.json"

    def cve_index_path(self) -> Path:
        return self.source / "cve" / "index.json"

    def cve_record_path(self, cve_id: str) -> Path:
        return self.source / "cve" / "records" / f"{cve_id}.json"

    def candidate_path(self) -> Path:
        return self.candidates / "latest.json"

    def candidate_meta_path(self) -> Path:
        return self.candidates / "latest.meta.json"

    def published_latest_path(self) -> Path:
        return self.published / "latest.json"

    def has_source_state(self) -> bool:
        return self.source_manifest_path().exists()

    def load_json(self, path: Path, *, max_bytes: int, max_depth: int) -> dict[str, Any] | None:
        if not path.exists():
            return None
        payload = load_bounded_json(
            path.read_bytes(), max_bytes=max_bytes, max_depth=max_depth, source=str(path)
        )
        if not isinstance(payload, dict):
            raise ValidationError(f"{path} is not a JSON object")
        return payload

    def load_cve_index(self, *, max_bytes: int, max_depth: int) -> dict[str, Any]:
        payload = self.load_json(self.cve_index_path(), max_bytes=max_bytes, max_depth=max_depth)
        return payload or {"records": {}}

    def load_previous_snapshot(
        self, *, max_bytes: int, max_depth: int, required: bool
    ) -> dict[str, Any] | None:
        for path in (self.published_latest_path(), self.candidate_path()):
            if path.exists():
                return load_snapshot(path, max_bytes=max_bytes, max_depth=max_depth)
        if required:
            raise ValidationError(
                "Previous snapshot is required because source state exists, "
                "but neither published/latest.json nor candidates/latest.json is present"
            )
        return None

    def write_source(
        self,
        *,
        manifest: dict[str, Any],
        kev_meta: dict[str, Any],
        kev_catalog: dict[str, Any],
        cve_index: dict[str, Any],
        cve_records: dict[str, dict[str, Any]],
    ) -> None:
        atomic_write_json(self.kev_meta_path(), kev_meta)
        atomic_write_json(self.kev_catalog_path(), kev_catalog)
        atomic_write_json(self.cve_index_path(), cve_index)
        for cve_id, record in cve_records.items():
            atomic_write_json(self.cve_record_path(cve_id), record)
        atomic_write_json(self.source_manifest_path(), manifest)

    def write_candidate(self, snapshot: dict[str, Any], meta: dict[str, Any]) -> str:
        body = dump_canonical(snapshot).encode("utf-8")
        digest = sha256_bytes(body)
        meta = dict(meta)
        meta["content_sha256"] = digest
        self.candidate_path().parent.mkdir(parents=True, exist_ok=True)
        tmp = self.candidate_path().with_name("latest.json.tmp")
        tmp.write_bytes(body)
        tmp.replace(self.candidate_path())
        atomic_write_json(self.candidate_meta_path(), meta)
        return digest


def candidate_digest(snapshot: dict[str, Any]) -> str:
    return sha256_bytes(dump_canonical(snapshot).encode("utf-8"))
