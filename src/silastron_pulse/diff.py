"""Meaningful change detection. Retrieval timestamps alone are not changes."""

from __future__ import annotations

from typing import Any, Mapping

from silastron_pulse.models import ChangeSet, PulseEntry

SOURCE_IDENTITY_KEYS = (
    "id",
    "status",
    "source_revision",
    "content_sha256",
    "license",
    "parser_version",
    "schema_version",
)
COMPARED_SOURCES = ("kev", "cve")


def source_identity(meta: Mapping[str, Any] | None) -> dict[str, Any]:
    payload = meta or {}
    return {key: payload.get(key) for key in SOURCE_IDENTITY_KEYS}


def detect_source_metadata_changes(
    previous_sources: Mapping[str, Any] | None,
    current_sources: Mapping[str, Any] | None,
) -> list[str]:
    previous = previous_sources or {}
    current = current_sources or {}
    changed: list[str] = []
    for name in COMPARED_SOURCES:
        previous_meta = previous.get(name) if isinstance(previous.get(name), dict) else {}
        current_meta = current.get(name) if isinstance(current.get(name), dict) else {}
        if source_identity(previous_meta) != source_identity(current_meta):
            changed.append(name)
    return changed


def detect_changes(
    previous_entries: dict[str, PulseEntry],
    current_entries: dict[str, PulseEntry],
    *,
    previous_sources: Mapping[str, Any] | None = None,
    current_sources: Mapping[str, Any] | None = None,
) -> ChangeSet:
    changes = ChangeSet()
    for cve_id, current in sorted(current_entries.items()):
        previous = previous_entries.get(cve_id)
        if previous is None:
            changes.new_kev_entries.append(cve_id)
            continue
        if previous.kev.comparable() != current.kev.comparable():
            changes.updated_kev_entries.append(cve_id)
        if previous.cve.comparable() != current.cve.comparable():
            changes.changed_cve_information.append(cve_id)
        if previous.epss.comparable() != current.epss.comparable():
            if current.epss.status == "ok" or previous.epss.status == "ok":
                changes.epss_changes.append(cve_id)
    for cve_id in sorted(previous_entries):
        if cve_id not in current_entries:
            changes.removed_kev_entries.append(cve_id)
    if previous_sources is not None or current_sources is not None:
        changes.source_metadata_changes = detect_source_metadata_changes(
            previous_sources, current_sources
        )
    return changes
