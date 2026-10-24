from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.diff import (
    INCOMPATIBLE_PUBLISHED,
    NO_PREVIOUS_PUBLISHED,
    detect_changes,
    publication_comparison,
)
from silastron_pulse.errors import PublishGuardError
from silastron_pulse.lock import ExclusiveLock
from silastron_pulse.pipeline import collect
from silastron_pulse.store import (
    build_preview_document,
    load_snapshot,
    promote_lock_path,
    promote_snapshot,
    verify_publication_transition,
)
from silastron_pulse.validate import validate_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher


class PublicationComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = test_config(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _snapshot(self) -> dict:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        return result.snapshot

    def test_missing_previous_published_is_unavailable_not_zero(self) -> None:
        current = self._snapshot()
        comparison = publication_comparison(None, current)
        self.assertFalse(comparison["available"])
        self.assertEqual(comparison["reason"], NO_PREVIOUS_PUBLISHED)
        self.assertIsNone(comparison["added_count"])
        self.assertIsNone(comparison["removed_count"])
        self.assertIsNone(comparison["updated_count"])
        self.assertIsNone(comparison["enrichment_count"])
        self.assertEqual(comparison["rows"], [])
        self.assertEqual(current["changes"]["new_kev_entries"], [])

    def test_first_snapshot_is_not_classified_as_newly_discovered(self) -> None:
        current = self._snapshot()
        preview = build_preview_document(current)
        comparison = preview["publication_comparison"]
        self.assertFalse(comparison["available"])
        self.assertIsNone(comparison["added_count"])
        self.assertNotEqual(comparison["added_count"], len(current["records"]))
        self.assertEqual(preview["recent_kev_additions"][0]["cve_id"], "CVE-2099-0002")

    def test_collect_time_changes_are_not_published_diffs(self) -> None:
        current = self._snapshot()
        current["changes"] = {
            "new_kev_entries": ["CVE-2099-0001", "CVE-2099-0002"],
            "updated_kev_entries": [],
            "removed_kev_entries": [],
            "changed_cve_information": [],
            "epss_changes": [],
            "source_metadata_changes": [],
        }
        preview = build_preview_document(current, previous_published=None)
        self.assertTrue(preview["changes_available"])
        self.assertEqual(
            [row["cve_id"] for row in preview["changes"]],
            ["CVE-2099-0001", "CVE-2099-0002"],
        )
        self.assertFalse(preview["publication_comparison"]["available"])
        self.assertIsNone(preview["publication_comparison"]["added_count"])

    def test_published_diff_ignores_empty_collect_time_changes(self) -> None:
        previous = self._snapshot()
        current = copy.deepcopy(previous)
        current["snapshot_id"] = "second-published"
        current["generated_at"] = "2099-01-11T00:00:00Z"
        current["collection_completed_at"] = current["generated_at"]
        current["records"] = [record for record in current["records"] if record["cve_id"] != "CVE-2099-0002"]
        current["summary"] = dict(current["summary"])
        current["summary"]["kev_records"] = 1
        current["changes"] = {
            "new_kev_entries": [],
            "updated_kev_entries": [],
            "removed_kev_entries": [],
            "changed_cve_information": [],
            "epss_changes": [],
            "source_metadata_changes": [],
        }
        current = validate_snapshot(current)
        preview = build_preview_document(current, previous_published=previous)
        comparison = preview["publication_comparison"]
        self.assertTrue(comparison["available"])
        self.assertEqual(comparison["compared_to_snapshot_id"], previous["snapshot_id"])
        self.assertEqual(comparison["removed_count"], 1)
        self.assertEqual(comparison["added_count"], 0)
        self.assertFalse(preview["changes_available"])
        self.assertEqual(comparison["rows"][0]["cve_id"], "CVE-2099-0002")
        self.assertEqual(comparison["rows"][0]["categories"], ["removed_kev"])
        self.assertIsNone(comparison["rows"][0]["after"])
        self.assertIsNotNone(comparison["rows"][0]["before"])

    def test_cvss_before_and_after(self) -> None:
        previous = self._snapshot()
        current = copy.deepcopy(previous)
        current["snapshot_id"] = "cvss-published"
        current["generated_at"] = "2099-01-11T00:00:00Z"
        current["collection_completed_at"] = current["generated_at"]
        record = current["records"][0]
        previous_score = record["cve"]["severity"]["base_score"]
        record["cve"]["severity"]["base_score"] = 9.8
        record["cve"]["severity"]["base_severity"] = "CRITICAL"
        current["changes"] = {
            "new_kev_entries": [],
            "updated_kev_entries": [],
            "removed_kev_entries": [],
            "changed_cve_information": [],
            "epss_changes": [],
        }
        current = validate_snapshot(current)
        comparison = publication_comparison(previous, current)
        self.assertTrue(comparison["available"])
        self.assertEqual(comparison["updated_count"], 1)
        self.assertEqual(comparison["added_count"], 0)
        row = comparison["rows"][0]
        self.assertIn("cvss_change", row["categories"])
        self.assertIn("cve_update", row["categories"])
        self.assertEqual(row["before"]["cvss_base_score"], previous_score)
        self.assertEqual(row["after"]["cvss_base_score"], 9.8)
        self.assertIn("cvss_base_score", row["changed_fields"])

    def test_completeness_change_and_unchanged_records(self) -> None:
        previous = self._snapshot()
        current = copy.deepcopy(previous)
        current["snapshot_id"] = "completeness-published"
        current["generated_at"] = "2099-01-11T00:00:00Z"
        current["collection_completed_at"] = current["generated_at"]
        record = next(item for item in current["records"] if item["cve_id"] == "CVE-2099-0001")
        record["cve"]["truncated_fields"] = ["versions"]
        record["cve"]["omitted_version_count"] = 4
        record["completeness"] = "partial"
        current["status"] = "degraded"
        current["summary"] = dict(current["summary"])
        current["summary"]["complete_records"] = 1
        current["summary"]["partial_records"] = 1
        current["summary"]["truncated_records"] = 1
        current = validate_snapshot(current)
        comparison = publication_comparison(previous, current)
        self.assertEqual(comparison["updated_count"], 1)
        self.assertEqual(comparison["added_count"], 0)
        self.assertEqual(comparison["removed_count"], 0)
        row = comparison["rows"][0]
        self.assertEqual(row["cve_id"], "CVE-2099-0001")
        self.assertIn("completeness_change", row["categories"])
        self.assertEqual(row["before"]["completeness"], "complete")
        self.assertEqual(row["after"]["completeness"], "partial")
        unchanged = next(item for item in current["records"] if item["cve_id"] == "CVE-2099-0002")
        self.assertEqual(unchanged["cve_id"], "CVE-2099-0002")
        self.assertEqual([item["cve_id"] for item in comparison["rows"]], ["CVE-2099-0001"])

    def test_retrieval_timestamp_is_not_a_published_update(self) -> None:
        previous = self._snapshot()
        current = copy.deepcopy(previous)
        current["snapshot_id"] = "retrieval-only"
        current["generated_at"] = "2099-01-11T00:00:00Z"
        current["collection_completed_at"] = current["generated_at"]
        current["sources"]["kev"]["retrieved_at"] = "2099-01-11T00:00:00Z"
        current["records"][0]["cve"]["retrieved_at"] = "2099-01-11T00:00:00Z"
        current = validate_snapshot(current)
        comparison = publication_comparison(previous, current)
        self.assertTrue(comparison["available"])
        self.assertEqual(comparison["added_count"], 0)
        self.assertEqual(comparison["removed_count"], 0)
        self.assertEqual(comparison["updated_count"], 0)
        self.assertEqual(comparison["rows"], [])

    def test_incompatible_previous_is_unavailable(self) -> None:
        current = self._snapshot()
        comparison = publication_comparison(
            {"snapshot_id": "broken", "generated_at": "2099-01-01T00:00:00Z", "records": "nope"},
            current,
        )
        self.assertFalse(comparison["available"])
        self.assertEqual(comparison["reason"], INCOMPATIBLE_PUBLISHED)
        self.assertIsNone(comparison["added_count"])

    def test_optional_publication_comparison_field_is_present_and_ignored_by_schema(self) -> None:
        current = self._snapshot()
        preview = build_preview_document(current)
        self.assertIn("publication_comparison", preview)
        self.assertFalse(preview["publication_comparison"]["available"])
        validate_snapshot(current)

    def test_epss_is_not_a_public_change_category(self) -> None:
        previous = self._snapshot()
        current = copy.deepcopy(previous)
        current["snapshot_id"] = "epss-ignored"
        current["generated_at"] = "2099-01-11T00:00:00Z"
        current["collection_completed_at"] = current["generated_at"]
        current["records"][0]["epss"]["status"] = "ok"
        current["records"][0]["epss"]["score"] = 0.9
        current = validate_snapshot(current)
        comparison = publication_comparison(previous, current)
        self.assertEqual(comparison["updated_count"], 0)
        self.assertEqual(comparison["rows"], [])
        for row in comparison["rows"]:
            self.assertNotIn("epss_change", row["categories"])
            self.assertNotIn("epss_score", row.get("changed_fields") or [])

    def test_promote_writes_published_comparison_from_previous_latest(self) -> None:
        first = self._snapshot()
        published = self.root / "published"
        promote_snapshot(
            first,
            published,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        first_preview = json.loads((published / "preview.json").read_text(encoding="utf-8"))
        self.assertFalse(first_preview["publication_comparison"]["available"])
        self.assertIsNone(first_preview["publication_comparison"]["added_count"])

        second = copy.deepcopy(first)
        second["snapshot_id"] = "second-live"
        second["generated_at"] = "2099-01-11T12:00:00Z"
        second["collection_completed_at"] = second["generated_at"]
        extra = copy.deepcopy(second["records"][0])
        extra["cve_id"] = "CVE-2099-0003"
        extra["kev"]["cve_id"] = "CVE-2099-0003"
        extra["cve"]["cve_id"] = "CVE-2099-0003"
        extra["epss"]["cve_id"] = "CVE-2099-0003"
        extra["kev"]["date_added"] = "2099-01-03"
        extra["links"] = {
            "cve_record": "https://www.cve.org/CVERecord?id=CVE-2099-0003",
            "kev_catalog": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "cvelist_v5": extra["links"]["cvelist_v5"],
        }
        second["records"].append(extra)
        second["records"].sort(key=lambda item: item["cve_id"])
        second["summary"] = dict(second["summary"])
        second["summary"]["kev_records"] = 3
        second["summary"]["complete_records"] = 3
        second["changes"]["new_kev_entries"] = ["CVE-2099-0003"]
        second = validate_snapshot(second)
        promote_snapshot(
            second,
            published,
            now=datetime(2099, 1, 11, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        preview = json.loads((published / "preview.json").read_text(encoding="utf-8"))
        comparison = preview["publication_comparison"]
        self.assertTrue(comparison["available"])
        self.assertEqual(comparison["compared_to_snapshot_id"], first["snapshot_id"])
        self.assertEqual(comparison["added_count"], 1)
        self.assertEqual(comparison["rows"][0]["categories"], ["added_kev"])
        latest = load_snapshot(
            published / "latest.json",
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(latest["snapshot_id"], "second-live")
        self.assertEqual(latest["changes"]["new_kev_entries"], ["CVE-2099-0003"])

    def test_detect_changes_still_uses_collect_semantics(self) -> None:
        current_entries = detect_changes({}, {})
        self.assertTrue(current_entries.is_empty())

    def test_republishing_the_same_snapshot_does_not_change_comparison(self) -> None:
        first = self._snapshot()
        published = self.root / "published"
        limits = {
            "max_bytes": self.config.max_kev_bytes,
            "max_depth": self.config.max_json_depth,
        }
        promote_snapshot(
            first,
            published,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            **limits,
        )
        second = copy.deepcopy(first)
        second["snapshot_id"] = "second-idempotent"
        second["generated_at"] = "2099-01-11T12:00:00Z"
        second["collection_completed_at"] = second["generated_at"]
        second["records"][0]["cve"]["severity"]["base_score"] = 9.8
        second["records"][0]["cve"]["severity"]["base_severity"] = "CRITICAL"
        second = validate_snapshot(second)
        promote_snapshot(
            second,
            published,
            now=datetime(2099, 1, 11, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            **limits,
        )
        preview_before = json.loads((published / "preview.json").read_text(encoding="utf-8"))
        latest_before = json.loads((published / "latest.json").read_text(encoding="utf-8"))
        manifest_before = json.loads((published / "manifest.json").read_text(encoding="utf-8"))
        again = promote_snapshot(
            second,
            published,
            now=datetime(2099, 1, 11, 18, tzinfo=timezone.utc),
            stale_after_hours=36,
            **limits,
        )
        preview_after = json.loads((published / "preview.json").read_text(encoding="utf-8"))
        latest_after = json.loads((published / "latest.json").read_text(encoding="utf-8"))
        self.assertEqual(preview_after["publication_comparison"], preview_before["publication_comparison"])
        self.assertEqual(
            preview_after["publication_comparison"]["compared_to_snapshot_id"],
            first["snapshot_id"],
        )
        self.assertTrue(preview_after["publication_comparison"]["available"])
        self.assertEqual(latest_after, latest_before)
        self.assertEqual(again["generated_at"], manifest_before["generated_at"])
        self.assertEqual(
            verify_publication_transition(
                incoming_dir=published,
                current_dir=published,
                **limits,
            )["status"],
            "idempotent",
        )

    def test_stale_comparison_baseline_cannot_be_persisted(self) -> None:
        first = self._snapshot()
        current = self.root / "current"
        incoming = self.root / "incoming"
        limits = {
            "max_bytes": self.config.max_kev_bytes,
            "max_depth": self.config.max_json_depth,
        }
        promote_snapshot(
            first,
            current,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            **limits,
        )
        shutil.copytree(current, incoming)
        successor = copy.deepcopy(first)
        successor["snapshot_id"] = "live-successor"
        successor["generated_at"] = "2099-01-11T12:00:00Z"
        successor["collection_completed_at"] = successor["generated_at"]
        successor = validate_snapshot(successor)
        promote_snapshot(
            successor,
            current,
            now=datetime(2099, 1, 11, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            **limits,
        )

        stale = copy.deepcopy(first)
        stale["snapshot_id"] = "stale-sibling"
        stale["generated_at"] = "2099-01-11T13:00:00Z"
        stale["collection_completed_at"] = stale["generated_at"]
        stale = validate_snapshot(stale)
        promote_snapshot(
            stale,
            incoming,
            now=datetime(2099, 1, 11, 13, tzinfo=timezone.utc),
            stale_after_hours=36,
            **limits,
        )
        with self.assertRaises(PublishGuardError) as raised:
            verify_publication_transition(
                incoming_dir=incoming,
                current_dir=current,
                **limits,
            )
        self.assertIn(successor["snapshot_id"], str(raised.exception))
        self.assertIn("not the current published snapshot", str(raised.exception))

        mutated = json.loads((current / "preview.json").read_text(encoding="utf-8"))
        mutated["publication_comparison"]["compared_to_snapshot_id"] = "invented-baseline"
        (incoming / "preview.json").write_text(json.dumps(mutated), encoding="utf-8")
        (incoming / "latest.json").write_text(
            (current / "latest.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        with self.assertRaises(PublishGuardError) as raised:
            verify_publication_transition(
                incoming_dir=incoming,
                current_dir=current,
                **limits,
            )
        self.assertIn("cannot change publication_comparison", str(raised.exception))

    def test_first_persist_cannot_claim_a_published_baseline(self) -> None:
        first = self._snapshot()
        incoming = self.root / "incoming"
        promote_snapshot(
            first,
            incoming,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        preview = json.loads((incoming / "preview.json").read_text(encoding="utf-8"))
        preview["publication_comparison"]["available"] = True
        preview["publication_comparison"]["compared_to_snapshot_id"] = "ghost"
        preview["publication_comparison"]["added_count"] = 12
        (incoming / "preview.json").write_text(json.dumps(preview), encoding="utf-8")
        with self.assertRaises(PublishGuardError):
            verify_publication_transition(
                incoming_dir=incoming,
                current_dir=self.root / "missing-published",
                max_bytes=self.config.max_kev_bytes,
                max_depth=self.config.max_json_depth,
            )

    def test_overlapping_promote_is_refused_while_lock_is_held(self) -> None:
        first = self._snapshot()
        published = self.root / "published"
        with ExclusiveLock(
            promote_lock_path(published),
            conflict="held",
            error=PublishGuardError,
        ):
            with self.assertRaises(PublishGuardError) as raised:
                promote_snapshot(
                    first,
                    published,
                    now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
                    stale_after_hours=36,
                    max_bytes=self.config.max_kev_bytes,
                    max_depth=self.config.max_json_depth,
                )
        self.assertIn("refusing concurrent promote", str(raised.exception))
        self.assertFalse((published / "latest.json").exists())
        self.assertFalse((published / "preview.json").exists())


if __name__ == "__main__":
    unittest.main()
