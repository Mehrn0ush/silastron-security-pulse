from __future__ import annotations

import copy
import unittest
from pathlib import Path

from silastron_pulse.diff import (
    _row_displayable_fields,
    interpret_publication_comparison,
    publication_comparison,
)
from silastron_pulse.store import build_preview_document
from tests.support import load_fixture_json

ROOT = Path(__file__).resolve().parents[1]
LIVE = load_fixture_json("publication_live_20261024.json")


def _record(cve_id: str, template: dict, *, remediation_items: list | None = None) -> dict:
    record = copy.deepcopy(template)
    record["cve_id"] = cve_id
    record["kev"]["cve_id"] = cve_id
    record["cve"]["cve_id"] = cve_id
    record["epss"]["cve_id"] = cve_id
    if remediation_items is not None:
        record["cve"]["remediation_items"] = copy.deepcopy(remediation_items)
    return record


def _snapshot(snapshot_id: str, generated_at: str, records: list[dict]) -> dict:
    return {
        "snapshot_id": snapshot_id,
        "generated_at": generated_at,
        "records": records,
        "sources": {},
    }


def live_snapshot_pair() -> tuple[dict, dict]:
    example_previous = LIVE["enrichment_example"]["previous"]
    example_current = LIVE["enrichment_example"]["current"]
    rem_items = example_current["cve"]["remediation_items"]
    previous_records = []
    current_records = []
    for cve_id in LIVE["enrichment_only_cve_ids"]:
        previous_records.append(_record(cve_id, example_previous, remediation_items=[]))
        current_records.append(_record(cve_id, example_current, remediation_items=rem_items))
    for cve_id, pair in LIVE["core_records"].items():
        previous_records.append(copy.deepcopy(pair["previous"]))
        current_records.append(copy.deepcopy(pair["current"]))
    for cve_id, record in LIVE["added_records"].items():
        current_records.append(copy.deepcopy(record))
    previous = _snapshot(
        LIVE["previous_snapshot_id"],
        LIVE["previous_generated_at"],
        previous_records,
    )
    current = _snapshot(
        LIVE["current_snapshot_id"],
        LIVE["current_generated_at"],
        current_records,
    )
    return previous, current


class PublishedChangePresentationTests(unittest.TestCase):
    def test_live_634_update_is_mostly_remediation_enrichment(self) -> None:
        previous, current = live_snapshot_pair()
        comparison = publication_comparison(previous, current)
        expected = LIVE["expected"]
        self.assertTrue(comparison["available"])
        self.assertEqual(comparison["added_count"], expected["added_count"])
        self.assertEqual(comparison["removed_count"], expected["removed_count"])
        self.assertEqual(comparison["updated_count"], expected["updated_count"])
        self.assertEqual(comparison["enrichment_count"], expected["enrichment_count"])
        self.assertEqual(expected["enrichment_count"], 632)
        self.assertEqual(comparison["added_count"] + comparison["updated_count"] + comparison["enrichment_count"], 636)
        row_ids = [row["cve_id"] for row in comparison["rows"]]
        self.assertEqual(row_ids[:2], LIVE["added_cve_ids"])
        self.assertEqual(sorted(row_ids[2:]), LIVE["core_update_cve_ids"])
        self.assertFalse(set(LIVE["enrichment_only_cve_ids"]) & set(row_ids))
        self.assertFalse(comparison["truncated"])
        for row in comparison["rows"]:
            if "added_kev" in row["categories"]:
                self.assertIsNone(row["before"])
                self.assertTrue(row["after"])
                continue
            self.assertTrue(row["changed_fields"], row)
            self.assertIn("cve_update", row["categories"])
            self.assertNotIn("enrichment_update", row["categories"])
            for field in row["changed_fields"]:
                self.assertNotEqual(row["before"].get(field), row["after"].get(field), field)

    def test_live_core_updates_expose_meaningful_before_after(self) -> None:
        previous, current = live_snapshot_pair()
        comparison = publication_comparison(previous, current)
        by_id = {row["cve_id"]: row for row in comparison["rows"]}
        fortinet = by_id["CVE-2024-21762"]
        self.assertIn("cve_date_updated", fortinet["changed_fields"])
        self.assertIn("cve_description", fortinet["changed_fields"])
        self.assertIn("affected_products", fortinet["changed_fields"])
        self.assertTrue(fortinet["before"]["cve_description"])
        self.assertTrue(fortinet["after"]["cve_description"])
        dated = by_id["CVE-2026-96951"]
        self.assertIn("cve_date_updated", dated["changed_fields"])
        self.assertNotEqual(dated["before"]["cve_date_updated"], dated["after"]["cve_date_updated"])

    def test_already_published_634_comparison_does_not_invent_enrichment(self) -> None:
        self.assertEqual(LIVE["published_comparison"]["updated_count"], 634)
        self.assertNotIn("enrichment_count", LIVE["published_comparison"])
        self.assertTrue(LIVE["published_comparison"]["truncated"])
        presented = interpret_publication_comparison(LIVE["published_comparison"])
        self.assertTrue(presented["available"])
        self.assertEqual(presented["added_count"], 2)
        self.assertEqual(presented["removed_count"], 0)
        self.assertIsNone(presented["updated_count"])
        self.assertIsNone(presented["enrichment_count"])
        self.assertEqual(presented["unresolved_count"], 634)
        self.assertGreater(len(presented["unresolved_rows"]), 0)
        self.assertLess(len(presented["unresolved_rows"]), presented["unresolved_count"])
        self.assertEqual(len(presented["added_rows"]), 2)
        self.assertEqual(presented["field_evidence"], "unavailable")
        self.assertEqual([row["cve_id"] for row in presented["added_rows"]], LIVE["added_cve_ids"])
        self.assertEqual(presented["core_rows"], [])
        self.assertEqual(presented["enrichment_rows"], [])
        self.assertTrue(presented["unresolved_rows"])
        for row in presented["unresolved_rows"]:
            self.assertEqual(row["categories"], ["cve_update"])
            self.assertEqual(row["changed_fields"], [])
            self.assertEqual(row["before"], row["after"])
        added = presented["added_rows"][0]
        fields = _row_displayable_fields(added)
        self.assertIn("product", fields)
        self.assertNotIn("cve_description", fields)
        self.assertTrue(fields)

    def test_new_comparison_counts_are_used_when_enrichment_count_is_present(self) -> None:
        presented = interpret_publication_comparison(
            {
                "available": True,
                "added_count": 2,
                "removed_count": 0,
                "updated_count": 2,
                "enrichment_count": 632,
                "enrichment_sample": ["CVE-2002-0367"],
                "rows": [
                    {
                        "cve_id": "CVE-2026-110447",
                        "categories": ["added_kev"],
                        "changed_fields": [],
                        "before": None,
                        "after": {"product": "OpenPLC"},
                    },
                    {
                        "cve_id": "CVE-2024-21762",
                        "categories": ["cve_update"],
                        "changed_fields": ["cve_date_updated"],
                        "before": {"cve_date_updated": "2026-08-04T03:55:55.226Z"},
                        "after": {"cve_date_updated": "2026-10-22T13:48:34.670Z"},
                    },
                ],
            }
        )
        self.assertEqual(presented["updated_count"], 2)
        self.assertEqual(presented["enrichment_count"], 632)
        self.assertEqual(presented["enrichment_sample"], ["CVE-2002-0367"])
        self.assertEqual(len(presented["core_rows"]), 1)
        self.assertEqual(len(presented["added_rows"]), 1)
        self.assertEqual(presented["field_evidence"], "stored")

    def test_truncation_does_not_change_full_catalog_counts(self) -> None:
        previous, current = live_snapshot_pair()
        comparison = publication_comparison(previous, current, max_rows=1)
        self.assertEqual(comparison["added_count"], 2)
        self.assertEqual(comparison["removed_count"], 0)
        self.assertEqual(comparison["updated_count"], 2)
        self.assertEqual(comparison["enrichment_count"], 632)
        self.assertTrue(comparison["truncated"])
        self.assertEqual(len(comparison["rows"]), 1)
        self.assertEqual(comparison["rows"][0]["categories"], ["added_kev"])
        self.assertNotEqual(comparison["updated_count"], len(comparison["rows"]))
        current = copy.deepcopy(current)
        current["limits"] = {"max_preview_changes": 1, "max_preview_recent": 1}
        current["status"] = "ok"
        current["changes"] = {}
        preview = build_preview_document(current, previous_published=previous)
        stored = preview["publication_comparison"]
        self.assertEqual(
            (
                stored["added_count"],
                stored["removed_count"],
                stored["updated_count"],
                stored["enrichment_count"],
            ),
            (2, 0, 2, 632),
        )
        self.assertTrue(stored["truncated"])
        self.assertEqual(len(stored["rows"]), 1)
        presented = interpret_publication_comparison(stored)
        self.assertEqual(presented["field_evidence"], "stored")
        self.assertEqual(presented["updated_count"], 2)
        self.assertEqual(presented["enrichment_count"], 632)
        self.assertEqual(presented["added_count"], 2)
        self.assertNotEqual(presented["updated_count"], len(presented["core_rows"]))


class PreviewChangePresentationContractTests(unittest.TestCase):
    def test_dashboard_summarizes_and_does_not_invent_empty_diffs(self) -> None:
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        css = (ROOT / "preview" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("classifyPublishedComparison", js)
        self.assertIn("displayableChangedFields", js)
        self.assertIn("changedFieldsLabel", js)
        self.assertIn("change-summary", js)
        self.assertIn("change-summary", css)
        self.assertIn("Extracted remediation evidence newly present", js)
        self.assertIn("New in current published snapshot", js)
        self.assertIn("Records with field-level updates", js)
        self.assertIn("if (classified.unresolved_count)", js)
        self.assertIn("listed updates have no stored field-level before/after values", js)
        self.assertIn("unresolved_count", js)
        self.assertNotIn("Published updates without stored field-level diffs", js)
        self.assertNotIn("No stored field-level diff", js)
        self.assertIn("Field-level evidence not stored", js)
        self.assertIn("Vulnerability Updates", js)
        self.assertIn("objectHasKey", js)
        self.assertIn("textContent", js)
        self.assertNotIn("innerHTML", js)
        self.assertIn("presentEpssNote", js)
        self.assertIn("https://www.first.org/epss/faq", js)
        self.assertIn("Missing field-level diffs are not treated as enrichment", js)
        self.assertNotIn("Not applicable", js)
        self.assertNotIn("No displayable field differences.", js)
        self.assertNotIn("Verified Fix", js)
        self.assertIn("CNA-Reported Solution", js)
        self.assertNotIn("See https://www.first.org/epss/#Usage-Agreement", js)

    def test_epss_docs_do_not_claim_a_current_usage_agreement_license(self) -> None:
        usage = (ROOT / "docs" / "licenses" / "first-epss-usage.txt").read_text(encoding="utf-8")
        contracts = (ROOT / "docs" / "source-contracts.md").read_text(encoding="utf-8")
        self.assertIn("https://www.first.org/epss/faq", usage)
        self.assertIn("obsolete fragment", usage.lower())
        self.assertNotIn("are used under the FIRST EPSS Usage Agreement", usage)
        self.assertIn("https://www.first.org/epss/faq", contracts)
        self.assertIn("OBSOLETE", contracts)
        self.assertIn("does not claim a current EPSS", contracts)


if __name__ == "__main__":
    unittest.main()
