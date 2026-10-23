from __future__ import annotations

import copy
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from silastron_pulse.diff import detect_changes, detect_source_metadata_changes
from silastron_pulse.pipeline import collect
from tests.support import frozen_clock, test_config, valid_fetcher


class DiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config = test_config(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _entries(self):
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        assert result.snapshot is not None
        from silastron_pulse.pipeline import _entries_from_snapshot

        return _entries_from_snapshot(result.snapshot)

    def test_new_and_updated_kev_and_changed_cve(self) -> None:
        current = self._entries()
        previous = copy.deepcopy(current)
        removed = previous.pop("CVE-2099-0002")
        first = previous["CVE-2099-0001"]
        object.__setattr__(first.kev, "required_action", "patched guidance")  # type: ignore[misc]
        object.__setattr__(first.cve, "date_updated", "2099-01-09T00:00:00Z")  # type: ignore[misc]
        changes = detect_changes(previous, current)
        self.assertEqual(changes.new_kev_entries, ["CVE-2099-0002"])
        self.assertEqual(changes.updated_kev_entries, ["CVE-2099-0001"])
        self.assertEqual(changes.changed_cve_information, ["CVE-2099-0001"])
        self.assertEqual(changes.removed_kev_entries, [])
        self.assertEqual(changes.epss_changes, [])
        self.assertIs(removed.cve_id, removed.cve_id)

    def test_removed_kev_entries_are_detected(self) -> None:
        current = self._entries()
        previous = copy.deepcopy(current)
        previous_only = previous["CVE-2099-0002"]
        current.pop("CVE-2099-0002")
        changes = detect_changes(previous, current)
        self.assertEqual(changes.removed_kev_entries, ["CVE-2099-0002"])
        self.assertEqual(previous_only.cve_id, "CVE-2099-0002")

    def test_retrieval_only_changes_are_ignored(self) -> None:
        current = self._entries()
        previous = copy.deepcopy(current)
        object.__setattr__(previous["CVE-2099-0001"].kev, "record_sha256", "changed")  # type: ignore[misc]
        changes = detect_changes(previous, current)
        self.assertTrue(changes.is_empty())

    def test_first_collection_does_not_invent_a_historical_diff(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        assert result.snapshot is not None
        changes = result.snapshot["changes"]
        self.assertEqual(changes["new_kev_entries"], [])
        self.assertEqual(changes["updated_kev_entries"], [])
        self.assertEqual(changes["removed_kev_entries"], [])
        self.assertEqual(changes["changed_cve_information"], [])
        self.assertEqual(changes["epss_changes"], [])
        self.assertEqual(changes["source_metadata_changes"], [])

    def test_cvss_change_is_changed_cve_information(self) -> None:
        current = self._entries()
        previous = copy.deepcopy(current)
        record = previous["CVE-2099-0001"]
        severity = record.cve.severity
        assert severity is not None
        object.__setattr__(record.cve, "severity", replace(severity, base_score=9.9))  # type: ignore[misc]
        changes = detect_changes(previous, current)
        self.assertEqual(changes.changed_cve_information, ["CVE-2099-0001"])
        self.assertEqual(changes.new_kev_entries, [])
        self.assertEqual(changes.updated_kev_entries, [])

    def test_completeness_change_is_changed_cve_information(self) -> None:
        current = self._entries()
        previous = copy.deepcopy(current)
        record = previous["CVE-2099-0001"]
        object.__setattr__(record.cve, "truncated_fields", ("versions",))  # type: ignore[misc]
        object.__setattr__(record.cve, "omitted_version_count", 12)  # type: ignore[misc]
        changes = detect_changes(previous, current)
        self.assertEqual(changes.changed_cve_information, ["CVE-2099-0001"])

    def test_source_metadata_identity_ignores_retrieval_timestamps(self) -> None:
        previous = {
            "kev": {
                "id": "cisa-kev",
                "status": "ok",
                "source_revision": "2026.10.21",
                "content_sha256": "aa",
                "retrieved_at": "2099-01-01T00:00:00Z",
            }
        }
        current = {
            "kev": {
                "id": "cisa-kev",
                "status": "ok",
                "source_revision": "2026.10.21",
                "content_sha256": "aa",
                "retrieved_at": "2099-01-10T12:00:00Z",
            }
        }
        self.assertEqual(detect_source_metadata_changes(previous, current), [])
        current["kev"]["content_sha256"] = "bb"
        self.assertEqual(detect_source_metadata_changes(previous, current), ["kev"])

    def test_empty_previous_entries_do_not_mark_current_catalog_as_new_without_caller(self) -> None:
        current = self._entries()
        changes = detect_changes({}, current)
        self.assertEqual(sorted(changes.new_kev_entries), ["CVE-2099-0001", "CVE-2099-0002"])
        first = collect(
            config=test_config(Path(self.tmp.name) / "first"),
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        assert first.snapshot is not None
        self.assertEqual(first.snapshot["changes"]["new_kev_entries"], [])


if __name__ == "__main__":
    unittest.main()
