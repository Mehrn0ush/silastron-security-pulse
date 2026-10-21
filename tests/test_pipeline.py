from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.constants import KEV_JSON_URL
from silastron_pulse.errors import FetchError
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.pipeline import collect
from silastron_pulse.store import load_snapshot
from tests.support import fetch_result, frozen_clock, test_config, valid_fetcher


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = test_config(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_successful_collection_writes_candidate_not_latest_unless_promoted(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "ok")
        self.assertTrue((self.root / "candidate.json").exists())
        self.assertFalse((self.root / "latest.json").exists())
        status = json.loads((self.root / "collection-status.json").read_text())
        self.assertFalse(status["promoted"])
        snapshot = result.snapshot
        assert snapshot is not None
        self.assertEqual(snapshot["sources"]["epss"]["status"], "disabled")
        self.assertIsNone(snapshot["composite_risk_score"])
        self.assertEqual(snapshot["records"][0]["cve_id"], "CVE-2099-0001")
        self.assertTrue(
            snapshot["records"][0]["signals"]["confirmed_exploitation"]["value"]
        )
        self.assertTrue(snapshot["sources"]["kev"]["retrieved_at"])
        self.assertTrue(snapshot["sources"]["cve"]["retrieved_at"])
        self.assertIn("removed_kev_entries", snapshot["changes"])
        self.assertIn("binding", snapshot)

    def test_source_failure_does_not_replace_published_snapshot(self) -> None:
        first = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
            promote=True,
            published_dir=self.root / "published",
        )
        self.assertEqual(first.status, "ok")
        published = load_snapshot(
            self.root / "published" / "latest.json",
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        failed = collect(
            config=self.config,
            fetcher=valid_fetcher(**{KEV_JSON_URL: FetchError("500")}),
            clock=frozen_clock(),
            promote=True,
            published_dir=self.root / "published",
        )
        self.assertEqual(failed.status, "failed")
        still = load_snapshot(
            self.root / "published" / "latest.json",
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(still["snapshot_id"], published["snapshot_id"])
        status = json.loads((self.root / "collection-status.json").read_text())
        self.assertEqual(status["status"], "failed")
        self.assertFalse(status["promoted"])

    def test_malformed_kev_fails_closed(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(
                **{KEV_JSON_URL: fetch_result(KEV_JSON_URL, "kev_malformed.json")}
            ),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.snapshot)

    def test_unsafe_strings_do_not_become_links(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(
                **{KEV_JSON_URL: fetch_result(KEV_JSON_URL, "kev_unsafe.json")}
            ),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        record = result.snapshot["records"][0]
        self.assertIn("<script>", record["kev"]["vendor_project"])
        self.assertEqual(
            record["links"]["kev_catalog"],
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        )
        self.assertTrue(record["links"]["cve_record"].startswith("https://www.cve.org/"))

    def test_cve_failure_threshold_fails_collection(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(
                **{
                    cvelist_v5_raw_url("CVE-2099-0001"): FetchError("404"),
                    cvelist_v5_raw_url("CVE-2099-0002"): FetchError("404"),
                }
            ),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "failed")


if __name__ == "__main__":
    unittest.main()
