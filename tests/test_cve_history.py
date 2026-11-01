"""Published-to-published CVE history generation."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.cve_history import build_cve_history, write_cve_history
from silastron_pulse.pipeline import collect
from silastron_pulse.store import promote_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher

NOW = datetime(2099, 1, 10, 14, tzinfo=timezone.utc)


class CveHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = test_config(self.root / "collect")
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
            collector_commit_sha="abc",
        )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        self.first = result.snapshot
        self.published = self.root / "published"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _promote(self, snapshot: dict, now: datetime | None = None) -> None:
        promote_snapshot(
            snapshot,
            self.published,
            now=now or NOW,
            stale_after_hours=36,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )

    def test_first_observed_is_not_kev_date_added(self) -> None:
        self._promote(self.first)
        document = json.loads(
            (self.published / "history" / "cves" / "CVE-2099-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(document["first_observed_snapshot_id"], self.first["snapshot_id"])
        self.assertEqual(document["kev_date_added"], self.first["records"][0]["kev"]["date_added"])
        self.assertNotEqual(document["first_observed_generated_at"], document["kev_date_added"])
        self.assertEqual(document["events"][0]["kind"], "first_observed")
        self.assertIn("not CISA KEV dateAdded", document["events"][0]["note"])

    def test_core_change_is_not_remediation_enrichment(self) -> None:
        self._promote(self.first)
        later = copy.deepcopy(self.first)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["collection_completed_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "later-core-1"
        later["records"][0]["cve"]["description"] = "Updated CNA description"
        later["records"][0]["cve"]["severity"]["base_score"] = 9.8
        later["records"][0]["cve"]["omitted_version_count"] = 1
        later["records"][0]["cve"]["truncated_fields"] = ["versions"]
        later["records"][0]["completeness"] = "partial"
        later["records"][0]["remediation"] = {
            "status": "available",
            "items": [
                {
                    "kind": "verified_fix",
                    "source": "cve_list_v5",
                    "attribution": "CNA solution",
                    "text": "Apply the vendor patch",
                }
            ],
        }
        self._promote(later, now=datetime(2099, 1, 10, 15, tzinfo=timezone.utc))
        document = json.loads(
            (self.published / "history" / "cves" / "CVE-2099-0001.json").read_text(encoding="utf-8")
        )
        kinds = [event["kind"] for event in document["events"]]
        self.assertIn("cna_change", kinds)
        self.assertIn("cvss_change", kinds)
        self.assertIn("completeness_change", kinds)
        self.assertIn("remediation_change", kinds)
        remediation = next(event for event in document["events"] if event["kind"] == "remediation_change")
        self.assertEqual(remediation["classification"], "extraction_enrichment")
        self.assertIn("Not a confirmed upstream", remediation["note"])
        cna = next(event for event in document["events"] if event["kind"] == "cna_change")
        self.assertEqual(cna["classification"], "upstream_cve")

    def test_legacy_snapshot_without_field_evidence(self) -> None:
        self._promote(self.first)
        later = copy.deepcopy(self.first)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "legacy-1"
        later["records"][0].pop("remediation", None)
        later["records"][0]["cve"].pop("products", None)
        self._promote(later, now=datetime(2099, 1, 10, 15, tzinfo=timezone.utc))
        document = json.loads(
            (self.published / "history" / "cves" / "CVE-2099-0001.json").read_text(encoding="utf-8")
        )
        notes = json.dumps(document)
        self.assertIn("unavailable", notes)

    def test_generation_is_deterministic_and_idempotent(self) -> None:
        self._promote(self.first)
        first = (self.published / "history" / "index.json").read_bytes()
        rebuilt = write_cve_history(
            self.published,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        second = (self.published / "history" / "index.json").read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(rebuilt["generated_from"], "published_snapshots")
        self.assertEqual(rebuilt["cve_count"], 2)

    def test_history_never_reads_candidates(self) -> None:
        self._promote(self.first)
        candidate_dir = self.root / "collect"  # unused; history must use published only
        built = build_cve_history(
            self.published,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertTrue(all(item["first_observed_snapshot_id"] == self.first["snapshot_id"] for item in built["index"]["cves"]))
        self.assertNotIn("candidates/latest.json", json.dumps(built["index"]))
        self.assertIn("published-to-published only", built["index"]["note"])
        self.assertTrue((self.published / "snapshots" / f"{self.first['snapshot_id']}.json").exists())
        _ = candidate_dir


if __name__ == "__main__":
    unittest.main()
