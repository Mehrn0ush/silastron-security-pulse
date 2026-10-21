from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.diff import detect_changes
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
        self.assertEqual(changes.epss_changes, [])
        self.assertIs(removed.cve_id, removed.cve_id)

    def test_retrieval_only_changes_are_ignored(self) -> None:
        current = self._entries()
        previous = copy.deepcopy(current)
        object.__setattr__(previous["CVE-2099-0001"].kev, "record_sha256", "changed")  # type: ignore[misc]
        changes = detect_changes(previous, current)
        self.assertTrue(changes.is_empty())


if __name__ == "__main__":
    unittest.main()
