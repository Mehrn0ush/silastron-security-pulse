"""Only the latest two snapshots are deployed; pulse-state keeps them all."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.cve_history import build_cve_history
from silastron_pulse.errors import PublishGuardError
from silastron_pulse.pipeline import collect
from silastron_pulse.safe_fs import copy_tree_without_symlinks
from silastron_pulse.store import (
    assert_site_data_matches_published,
    assert_snapshots_immutable,
    deployed_snapshot_names,
    promote_snapshot,
    prune_deployed_snapshots,
    rollback_snapshot,
)
from tests.support import frozen_clock, test_config, valid_fetcher

IDS = [
    "20990110T120000Z_aaaaaaaaaaaa",
    "20990110T130000Z_bbbbbbbbbbbb",
    "20990110T140000Z_cccccccccccc",
    "20990110T150000Z_dddddddddddd",
]


class DeployedSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = test_config(self.root / "cfg")
        self.kw = {"max_bytes": self.config.max_kev_bytes, "max_depth": self.config.max_json_depth}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def pulse_state(self, count: int = 4) -> Path:
        with tempfile.TemporaryDirectory() as collect_tmp:
            result = collect(config=test_config(Path(collect_tmp)), fetcher=valid_fetcher(), clock=frozen_clock())
        assert result.snapshot is not None
        published = self.root / "pulse-state" / "published"
        for index, snapshot_id in enumerate(IDS[:count]):
            snapshot = dict(result.snapshot)
            snapshot["snapshot_id"] = snapshot_id
            snapshot["generated_at"] = f"2099-01-10T{12 + index}:00:00Z"
            promote_snapshot(
                snapshot, published, now=datetime(2099, 1, 10, 12 + index, 30, tzinfo=timezone.utc),
                stale_after_hours=36, **self.kw,
            )
        return published

    def site_copy(self, published: Path, *, prune: bool = True) -> Path:
        site = self.root / "site" / "data"
        if site.parent.exists():
            shutil.rmtree(site.parent)
        copy_tree_without_symlinks(published, site)
        if prune:
            prune_deployed_snapshots(site)
        return site

    def names(self, directory: Path) -> list[str]:
        return sorted(p.name for p in (directory / "snapshots").glob("*.json"))

    def test_deploys_current_plus_newest_other_and_keeps_all_in_pulse_state(self) -> None:
        published = self.pulse_state()
        site = self.site_copy(published)
        self.assertEqual(self.names(published), [f"{i}.json" for i in IDS])
        self.assertEqual(self.names(site), [f"{IDS[2]}.json", f"{IDS[3]}.json"])

    def test_manifest_latest_snapshot_resolves_on_the_deployed_copy(self) -> None:
        site = self.site_copy(self.pulse_state())
        manifest = json.loads((site / "manifest.json").read_text())
        self.assertTrue((site / manifest["latest_snapshot"]).is_file())
        self.assertTrue((site / manifest["latest_ok_snapshot"]).is_file())

    def test_rollback_to_a_snapshot_that_is_not_deployed(self) -> None:
        published = self.pulse_state()
        self.assertNotIn(f"{IDS[0]}.json", self.names(self.site_copy(published)))
        rollback_snapshot(
            published, IDS[0], now=datetime(2099, 1, 11, tzinfo=timezone.utc), stale_after_hours=36,
            confirm="ROLLBACK", **self.kw,
        )
        manifest = json.loads((published / "manifest.json").read_text())
        self.assertEqual(manifest["snapshot_id"], IDS[0])
        self.assertEqual(manifest["publication_state"], "rolled_back")
        # The rolled-back snapshot is now current, plus the newest other one.
        self.assertEqual(deployed_snapshot_names(published), [f"{IDS[0]}.json", f"{IDS[3]}.json"])
        site = self.site_copy(published)
        self.assertEqual(self.names(site), [f"{IDS[0]}.json", f"{IDS[3]}.json"])
        assert_site_data_matches_published(site, published)

    def test_rollback_reads_pulse_state_not_a_pruned_copy(self) -> None:
        published = self.pulse_state()
        pruned = self.site_copy(published)
        with self.assertRaises(PublishGuardError):
            rollback_snapshot(
                pruned, IDS[0], now=datetime(2099, 1, 11, tzinfo=timezone.utc), stale_after_hours=36,
                confirm="ROLLBACK", **self.kw,
            )

    def test_cve_history_is_rebuilt_from_the_full_retained_set(self) -> None:
        published = self.pulse_state()
        site = self.site_copy(published)
        full = build_cve_history(published, **self.kw)
        self.assertEqual(full["index"]["retained_snapshot_count"], 4)
        # A pruned copy would lose history coverage, which is why history is only ever
        # built from pulse-state (or its pre-prune staging copy), never the deployed tree.
        self.assertEqual(build_cve_history(site, **self.kw)["index"]["retained_snapshot_count"], 2)

    def test_integrity_check_passes_with_exactly_two_deployed(self) -> None:
        published = self.pulse_state()
        assert_site_data_matches_published(self.site_copy(published), published)

    def test_integrity_check_fails_on_missing_altered_or_extra_snapshot(self) -> None:
        published = self.pulse_state()
        site = self.site_copy(published)
        (site / "snapshots" / f"{IDS[3]}.json").unlink()
        with self.assertRaisesRegex(PublishGuardError, "missing"):
            assert_site_data_matches_published(site, published)
        site = self.site_copy(published)
        altered = site / "snapshots" / f"{IDS[3]}.json"
        altered.write_text(altered.read_text() + " ")
        with self.assertRaisesRegex(PublishGuardError, "mutated"):
            assert_site_data_matches_published(site, published)
        site = self.site_copy(published)
        shutil.copy(published / "snapshots" / f"{IDS[0]}.json", site / "snapshots")
        with self.assertRaisesRegex(PublishGuardError, "must not be deployed"):
            assert_site_data_matches_published(site, published)

    def test_first_publish_after_the_trim_shrinks_the_deployed_tree(self) -> None:
        published = self.pulse_state()
        untrimmed = self.site_copy(published, prune=False)
        self.assertEqual(len(self.names(untrimmed)), 4)
        with self.assertRaisesRegex(PublishGuardError, "must not be deployed"):
            assert_site_data_matches_published(untrimmed, published)
        removed = prune_deployed_snapshots(untrimmed)
        self.assertEqual(len(removed), 2)
        assert_site_data_matches_published(untrimmed, published)
        self.assertEqual(prune_deployed_snapshots(untrimmed), [])

    def test_first_ever_publish_with_one_snapshot(self) -> None:
        published = self.pulse_state(count=1)
        site = self.site_copy(published)
        self.assertEqual(self.names(site), [f"{IDS[0]}.json"])
        assert_site_data_matches_published(site, published)

    def test_snapshots_are_immutable_in_pulse_state(self) -> None:
        published = self.pulse_state()
        incoming = self.site_copy(published)
        assert_snapshots_immutable(incoming, published)
        target = incoming / "snapshots" / f"{IDS[3]}.json"
        target.write_text(target.read_text() + " ")
        with self.assertRaisesRegex(PublishGuardError, "immutable"):
            assert_snapshots_immutable(incoming, published)

    def test_manifest_pointing_at_a_missing_snapshot_fails_closed(self) -> None:
        published = self.pulse_state()
        site = self.site_copy(published, prune=False)
        (site / "snapshots" / f"{IDS[3]}.json").unlink()
        with self.assertRaises(PublishGuardError):
            prune_deployed_snapshots(site)


if __name__ == "__main__":
    unittest.main()
