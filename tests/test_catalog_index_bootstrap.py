"""Regression: a published dir with only latest.json must not break site builds.

catalog-index.json and cve/*.json are written by promote_snapshot. Three
workflow paths never call promote in a given run (they only copy an
already-published directory): a status-only republish (unchanged upstream),
a failed-collect status update, and a frontend-only redeploy. Before
store.rebuild_catalog_index existed, any of those paths running against a
published dir that predates this feature (or has otherwise lost these
derived files) would crash in build-static-cve-pages with
FileNotFoundError, aborting the whole site build.

Each test here reproduces one path's exact command sequence via direct
function calls, in the same order the corresponding workflow step uses.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.pipeline import collect
from silastron_pulse.static_pages import build_static_cve_pages
from silastron_pulse.store import (
    assert_site_data_matches_published,
    promote_snapshot,
    rebuild_catalog_index,
)
from silastron_pulse.safe_fs import copy_tree_without_symlinks
from tests.support import frozen_clock, test_config, valid_fetcher

BASE = "https://pulse.silastron.com"
MAX_BYTES = 8_000_000
MAX_DEPTH = 32


def _published_with_only_latest_json(tmp: Path) -> Path:
    """A pulse-state/published dir predating the catalog-index split.

    Promotes normally, then removes catalog-index.json and cve/* to
    reproduce exactly the gap this regression guards against: everything a
    real earlier promote wrote, minus the two files that split added.
    """
    with tempfile.TemporaryDirectory() as collect_tmp:
        result = collect(config=test_config(Path(collect_tmp)), fetcher=valid_fetcher(), clock=frozen_clock())
    assert result.snapshot is not None
    published = tmp / "pulse-state-published"
    promote_snapshot(
        result.snapshot,
        published,
        now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
        stale_after_hours=36,
        max_bytes=MAX_BYTES,
        max_depth=MAX_DEPTH,
    )
    (published / "catalog-index.json").unlink()
    import shutil

    shutil.rmtree(published / "cve")
    assert not (published / "catalog-index.json").exists()
    assert not (published / "cve").exists()
    return published


class BootstrapGapReproducedTests(unittest.TestCase):
    def test_build_static_cve_pages_fails_closed_without_the_rebuild_step(self) -> None:
        """Proves the bug: skipping build-catalog-index still fails loudly,
        it does not silently produce an empty or wrong site."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            published = _published_with_only_latest_json(tmp)
            site_data = tmp / "_site" / "data"
            copy_tree_without_symlinks(published, site_data)
            with self.assertRaises(FileNotFoundError):
                build_static_cve_pages(published_dir=site_data, site_dir=tmp / "_site", base_url=BASE)


class WorkflowPathSequenceTests(unittest.TestCase):
    """Each test mirrors one workflow step's command order exactly."""

    def _site_data_from_gap(self, tmp: Path) -> tuple[Path, Path, Path]:
        published = _published_with_only_latest_json(tmp)
        site_dir = tmp / "_site"
        site_data = site_dir / "data"
        copy_tree_without_symlinks(published, site_data)
        return published, site_dir, site_data

    def test_status_only_publish_path(self) -> None:
        # publish.yml "Build status-only site": safe-copy, build-catalog-index,
        # (verification-status copy), build-static-cve-pages.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            published, site_dir, site_data = self._site_data_from_gap(tmp)
            rebuild_catalog_index(site_data, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)
            count = build_static_cve_pages(published_dir=site_data, site_dir=site_dir, base_url=BASE)
            self.assertGreater(count, 0)
            self.assertTrue((site_data / "catalog-index.json").is_file())
            assert_site_data_matches_published(site_data, published)

    def test_failed_collect_status_path(self) -> None:
        # publish.yml "Build site with failed attempt recorded": safe-copy,
        # build-catalog-index, record-failed-collect, build-static-cve-pages.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _published, site_dir, site_data = self._site_data_from_gap(tmp)
            rebuild_catalog_index(site_data, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)
            from silastron_pulse.verification_status import record_failed_attempt
            import json

            status_path = site_data / "verification-status.json"
            if status_path.is_file():
                existing = json.loads(status_path.read_text())
                updated = record_failed_attempt(
                    existing, collect_run_id="123", conclusion="failure", attempted_at="2099-01-11T00:00:00Z"
                )
                status_path.write_text(json.dumps(updated))
            count = build_static_cve_pages(published_dir=site_data, site_dir=site_dir, base_url=BASE)
            self.assertGreater(count, 0)

    def test_deploy_frontend_without_promote_path(self) -> None:
        # deploy-frontend.yml: safe-copy, build-catalog-index, (copy preview
        # assets), build-static-cve-pages.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _published, site_dir, site_data = self._site_data_from_gap(tmp)
            rebuild_catalog_index(site_data, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)
            count = build_static_cve_pages(published_dir=site_data, site_dir=site_dir, base_url=BASE)
            self.assertGreater(count, 0)

    def test_rebuild_output_is_identical_to_what_promote_would_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            published = _published_with_only_latest_json(tmp)
            rebuilt_count = rebuild_catalog_index(published, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)

            with tempfile.TemporaryDirectory() as collect_tmp:
                result = collect(config=test_config(Path(collect_tmp)), fetcher=valid_fetcher(), clock=frozen_clock())
            assert result.snapshot is not None
            reference = tmp / "reference-published"
            promote_snapshot(
                result.snapshot,
                reference,
                now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=MAX_BYTES,
                max_depth=MAX_DEPTH,
            )
            self.assertEqual(rebuilt_count, len(result.snapshot["records"]))
            self.assertEqual(
                (published / "catalog-index.json").read_bytes(),
                (reference / "catalog-index.json").read_bytes(),
            )
            for cve_id in {r["cve_id"] for r in result.snapshot["records"]}:
                self.assertEqual(
                    (published / "cve" / f"{cve_id}.json").read_bytes(),
                    (reference / "cve" / f"{cve_id}.json").read_bytes(),
                )

    def test_rebuild_without_latest_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "nothing-published-yet"
            empty.mkdir()
            from silastron_pulse.errors import PublishGuardError

            with self.assertRaises(PublishGuardError):
                rebuild_catalog_index(empty, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)


if __name__ == "__main__":
    unittest.main()
