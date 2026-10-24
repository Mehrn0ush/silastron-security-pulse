from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.cli import main
from silastron_pulse.errors import PublishGuardError
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.pipeline import collect
from silastron_pulse.store import (
    assert_site_data_matches_published,
    promote_snapshot,
    verify_published_site,
)
from tests.support import frozen_clock, test_config, valid_fetcher

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


class FrontendDeployWorkflowTests(unittest.TestCase):
    def test_frontend_deploy_is_manual_isolated_and_shares_pages_lock(self) -> None:
        frontend = _workflow("deploy-frontend.yml")
        publish = _workflow("publish.yml")
        self.assertIn("workflow_dispatch:", frontend)
        self.assertNotIn("schedule:", frontend)
        self.assertIn("confirm == 'DEPLOY_FRONTEND'", frontend)
        self.assertIn("group: pages", frontend)
        self.assertIn("cancel-in-progress: false", frontend)
        self.assertIn("group: pages", publish)
        self.assertIn("cancel-in-progress: false", publish)
        self.assertIn("python3 -m silastron_pulse verify-published-site", frontend)
        self.assertIn("cp -a pulse-state/published/. _site/data/", frontend)
        self.assertIn("cp preview/index.html preview/styles.css preview/app.js _site/", frontend)
        self.assertNotIn("silastron_pulse promote", frontend)
        self.assertNotIn("silastron_pulse collect", frontend)
        self.assertNotIn("collect_run_id", frontend)
        self.assertNotIn("publication_comparison", frontend)
        self.assertNotIn("persist-published", frontend)
        self.assertNotIn("git push", frontend)
        self.assertNotIn("contents: write", frontend)
        self.assertIn("actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346", frontend)
        self.assertIn("actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9", frontend)
        self.assertNotIn("actions/upload-artifact@v4", frontend)
        self.assertIn("github-pages", frontend)
        self.assertIn("needs: build", frontend)

    def test_publish_integrity_checks_remain_on_intelligence_path(self) -> None:
        publish = _workflow("publish.yml")
        self.assertIn("silastron_pulse promote", publish)
        self.assertIn("verify-publication", publish)
        self.assertIn("persist-published:", publish)
        self.assertIn("confirm == 'PUBLISH'", publish)


class FrontendDeployIsolationTests(unittest.TestCase):
    def _published(self, root: Path) -> tuple[dict, Path, object]:
        config = test_config(root / "collect")
        result = collect(
            config=config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        published = root / "published"
        promote_snapshot(
            result.snapshot,
            published,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=config.max_kev_bytes,
            max_depth=config.max_json_depth,
        )
        return result.snapshot, published, config

    def test_copy_keeps_published_bytes_and_comparison_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, published, config = self._published(root)
            before = {
                path.relative_to(published): sha256_bytes(path.read_bytes())
                for path in published.rglob("*")
                if path.is_file()
            }
            comparison = json.loads((published / "preview.json").read_text())[
                "publication_comparison"
            ]
            site = root / "site" / "data"
            shutil.copytree(published, site)
            result = verify_published_site(
                published,
                max_bytes=config.max_kev_bytes,
                max_depth=config.max_json_depth,
            )
            assert_site_data_matches_published(site, published)
            after = {
                path.relative_to(published): sha256_bytes(path.read_bytes())
                for path in published.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before, after)
            self.assertEqual(result["snapshot_id"], snapshot["snapshot_id"])
            copied_comparison = json.loads((site / "preview.json").read_text())[
                "publication_comparison"
            ]
            self.assertEqual(copied_comparison, comparison)
            self.assertEqual(main(["verify-published-site", "--published-dir", str(published), "--site-data", str(site)]), 0)

    def test_mutated_or_missing_published_data_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, published, config = self._published(root)
            site = root / "site" / "data"
            shutil.copytree(published, site)
            preview = json.loads((site / "preview.json").read_text())
            preview["publication_comparison"] = {"available": True, "added_count": 0}
            (site / "preview.json").write_text(json.dumps(preview), encoding="utf-8")
            with self.assertRaises(PublishGuardError):
                assert_site_data_matches_published(site, published)

            missing = root / "missing"
            missing.mkdir()
            with self.assertRaises(PublishGuardError):
                verify_published_site(
                    missing,
                    max_bytes=config.max_kev_bytes,
                    max_depth=config.max_json_depth,
                )

            bad = root / "bad"
            shutil.copytree(published, bad)
            latest = json.loads((bad / "latest.json").read_text())
            latest["status"] = "failed"
            (bad / "latest.json").write_text(json.dumps(latest), encoding="utf-8")
            with self.assertRaises(PublishGuardError):
                verify_published_site(
                    bad,
                    max_bytes=config.max_kev_bytes,
                    max_depth=config.max_json_depth,
                )

            mismatch = root / "mismatch"
            shutil.copytree(published, mismatch)
            preview = json.loads((mismatch / "preview.json").read_text())
            preview["snapshot_id"] = "not-the-published-snapshot"
            (mismatch / "preview.json").write_text(json.dumps(preview), encoding="utf-8")
            with self.assertRaises(PublishGuardError):
                verify_published_site(
                    mismatch,
                    max_bytes=config.max_kev_bytes,
                    max_depth=config.max_json_depth,
                )
            self.assertEqual(
                main(
                    [
                        "verify-published-site",
                        "--published-dir",
                        str(mismatch),
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
