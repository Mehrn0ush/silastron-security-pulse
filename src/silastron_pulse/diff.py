"""Meaningful change detection. Retrieval timestamps alone are not changes."""

from __future__ import annotations

from silastron_pulse.models import ChangeSet, PulseEntry


def detect_changes(
    previous_entries: dict[str, PulseEntry],
    current_entries: dict[str, PulseEntry],
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
    return changes
