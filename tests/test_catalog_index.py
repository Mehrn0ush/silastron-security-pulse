"""The browser-facing catalog index and per-CVE detail split of latest.json."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from silastron_pulse.catalog_index import build_catalog_index, build_cve_detail, catalog_entry
from silastron_pulse.pipeline import collect
from silastron_pulse.store import promote_snapshot
from silastron_pulse.validate import validate_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher

from datetime import datetime, timezone


def _snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        result = collect(config=test_config(Path(tmp)), fetcher=valid_fetcher(), clock=frozen_clock())
    assert result.snapshot is not None
    return result.snapshot


class CatalogEntryTests(unittest.TestCase):
    def test_entry_never_includes_full_intelligence(self) -> None:
        snapshot = _snapshot()
        for record in snapshot["records"]:
            entry = catalog_entry(record)
            self.assertNotIn("intelligence", entry)

    def test_entry_derives_the_same_summary_fields_the_old_client_computed(self) -> None:
        snapshot = _snapshot()
        record = snapshot["records"][0]
        entry = catalog_entry(record)
        intel = record["intelligence"]
        expected_versions = sorted({a["cvss_version"] for a in intel["cvss"]["assessments"]})
        self.assertEqual(entry["cvss_versions"], expected_versions)
        expected_sources = sorted({a["source"] for a in intel["cvss"]["assessments"]})
        self.assertEqual(entry["cvss_sources"], expected_sources)
        self.assertEqual(entry["has_fixed_version"], intel["coverage"]["has_fixed_version"])
        self.assertEqual(entry["has_vendor_advisory"], intel["coverage"]["has_vendor_advisory"])
        self.assertEqual(entry["nvd_status"], intel["sources"]["nvd"]["status"])

    def test_missing_remediation_falls_back_to_kev_fields(self) -> None:
        record = _snapshot()["records"][0]
        record = dict(record)
        record["remediation"] = None
        record["kev"] = {**record["kev"], "required_action": "Apply the vendor patch.", "notes": None}
        entry = catalog_entry(record)
        self.assertEqual(entry["remediation"]["status"], "available")
        self.assertEqual(entry["remediation"]["items"][0]["kind"], "required_action")
        self.assertEqual(entry["remediation_kinds"], ["required_action"])

    def test_missing_remediation_and_kev_text_is_explicitly_unavailable(self) -> None:
        record = _snapshot()["records"][0]
        record = dict(record)
        record["remediation"] = None
        record["kev"] = {**record["kev"], "required_action": None, "notes": None}
        entry = catalog_entry(record)
        self.assertEqual(entry["remediation"]["status"], "unavailable")
        self.assertEqual(entry["remediation"]["items"], [])

    def test_products_are_bounded_and_formatted(self) -> None:
        record = _snapshot()["records"][0]
        entry = catalog_entry(record)
        self.assertIsInstance(entry["products"], list)
        self.assertLessEqual(len(entry["products"]), 8)
        for item in entry["products"]:
            self.assertIsInstance(item, str)

    def test_cve_detail_is_the_entry_plus_intelligence(self) -> None:
        record = _snapshot()["records"][0]
        entry = catalog_entry(record)
        detail = build_cve_detail(record)
        for key, value in entry.items():
            self.assertEqual(detail[key], value)
        self.assertEqual(detail["intelligence"], record.get("intelligence"))
        self.assertIn("schema_version", detail)


class CatalogIndexDocumentTests(unittest.TestCase):
    def test_index_has_one_entry_per_record_and_no_intelligence(self) -> None:
        snapshot = _snapshot()
        index = build_catalog_index(snapshot)
        self.assertEqual(index["record_count"], len(snapshot["records"]))
        self.assertEqual(len(index["records"]), len(snapshot["records"]))
        for entry in index["records"]:
            self.assertNotIn("intelligence", entry)
        self.assertEqual(index["snapshot_id"], snapshot["snapshot_id"])


class PromoteWritesSplitFilesTests(unittest.TestCase):
    def test_promote_writes_index_and_one_file_per_cve(self) -> None:
        snapshot = _snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            published = Path(tmp) / "published"
            promote_snapshot(
                snapshot,
                published,
                now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=8_000_000,
                max_depth=32,
            )
            # latest.json remains the full-fidelity source of truth.
            self.assertTrue((published / "latest.json").exists())
            index_path = published / "catalog-index.json"
            self.assertTrue(index_path.exists())
            import json

            index = json.loads(index_path.read_text())
            ids = {r["cve_id"] for r in snapshot["records"]}
            self.assertEqual({r["cve_id"] for r in index["records"]}, ids)
            for cve_id in ids:
                detail_path = published / "cve" / f"{cve_id}.json"
                self.assertTrue(detail_path.exists())
                detail = json.loads(detail_path.read_text())
                self.assertEqual(detail["cve_id"], cve_id)
                self.assertIn("intelligence", detail)

    def test_a_removed_kev_entry_drops_its_stale_detail_file(self) -> None:
        snapshot = _snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            published = Path(tmp) / "published"
            promote_snapshot(
                snapshot,
                published,
                now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=8_000_000,
                max_depth=32,
            )
            removed_id = snapshot["records"][0]["cve_id"]
            self.assertTrue((published / "cve" / f"{removed_id}.json").exists())

            shrunk = dict(snapshot)
            shrunk["records"] = [r for r in snapshot["records"] if r["cve_id"] != removed_id]
            shrunk["snapshot_id"] = snapshot["snapshot_id"] + "x"
            shrunk["generated_at"] = "2099-01-11T00:00:00Z"
            validate_snapshot(shrunk)
            promote_snapshot(
                shrunk,
                published,
                now=datetime(2099, 1, 11, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=8_000_000,
                max_depth=32,
            )
            self.assertFalse((published / "cve" / f"{removed_id}.json").exists())


if __name__ == "__main__":
    unittest.main()
