"""Evidence-based enrichment availability and the 2026-10-31 incident."""

from __future__ import annotations

import unittest
from copy import deepcopy

from silastron_pulse.auto_publish import evaluate_publication
from silastron_pulse.enrichment_policy import (
    CVELIST_V5_NOT_FOUND,
    TRANSIENT_FAILURE,
    classify_fetch_failure,
    evaluate_enrichment_policy,
)
from silastron_pulse.errors import FetchError
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.kev_integrity import catalog_from_snapshot
from tests.test_auto_publish import AutoPublishFixtures


class EnrichmentClassificationTests(unittest.TestCase):
    def test_404_on_constructed_path_is_cvelist_absence_not_unpublished(self) -> None:
        url = cvelist_v5_raw_url("CVE-2026-118527")
        self.assertEqual(url.endswith("cves/2026/118xxx/CVE-2026-118527.json"), True)
        info = classify_fetch_failure(
            "CVE-2026-118527",
            url,
            FetchError("HTTP 404 fetching " + url, status_code=404),
        )
        self.assertEqual(info["state"], CVELIST_V5_NOT_FOUND)
        self.assertIn("does not prove", info["note"])

    def test_timeout_is_transient(self) -> None:
        url = cvelist_v5_raw_url("CVE-2099-0001")
        info = classify_fetch_failure(
            "CVE-2099-0001",
            url,
            FetchError("Timeout fetching " + url, retryable=True),
        )
        self.assertEqual(info["state"], TRANSIENT_FAILURE)


class EnrichmentPublicationTests(AutoPublishFixtures):
    def _unavailable(self, snapshot: dict, index: int, availability: dict | None) -> dict:
        payload = deepcopy(snapshot)
        payload["status"] = "degraded"
        payload["sources"]["cve"]["status"] = "degraded"
        payload["summary"]["unavailable_records"] = 1
        payload["summary"]["complete_records"] = payload["summary"]["complete_records"] - 1
        record = payload["records"][index]
        record["completeness"] = "unavailable"
        record["cve"]["status"] = "unavailable"
        record["cve"]["error"] = "HTTP 404 fetching example"
        if availability is not None:
            record["cve"]["enrichment_availability"] = availability
        else:
            record["cve"].pop("enrichment_availability", None)
        return payload

    def test_verified_kev_with_one_classified_absence_is_publishable(self) -> None:
        url = cvelist_v5_raw_url(self.snapshot["records"][0]["cve_id"])
        candidate = self._unavailable(
            self.snapshot,
            0,
            {
                "state": CVELIST_V5_NOT_FOUND,
                "http_status": 404,
                "requested_url": url,
                "constructed_path_valid": True,
                "note": "CVE List V5 returned HTTP 404",
            },
        )
        decision, _ = self._decide(candidate)
        self.assertEqual(decision.outcome, "publish")
        self.assertIn("enrichment_policy", decision.details)
        self.assertEqual(decision.details["enrichment_policy"]["counts"][CVELIST_V5_NOT_FOUND], 1)
        self.assertEqual(
            [record["cve_id"] for record in candidate["records"]],
            [record["cve_id"] for record in self.snapshot["records"]],
        )

    def test_historical_unclassified_404_string_remains_rejected(self) -> None:
        candidate = self._unavailable(self.snapshot, 0, None)
        candidate["snapshot_id"] = "20261031T141620Z_c8b8ec309b66"
        decision, _ = self._decide(candidate)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "degraded_blocked")
        self.assertIn("lack structured fetch evidence", decision.details["message"])

    def test_several_bounded_missing_enrichments_are_publishable(self) -> None:
        candidate = deepcopy(self.snapshot)
        candidate["status"] = "degraded"
        candidate["sources"]["cve"]["status"] = "degraded"
        candidate["summary"]["unavailable_records"] = 2
        candidate["summary"]["complete_records"] = candidate["summary"]["complete_records"] - 2
        for index, record in enumerate(candidate["records"]):
            record["completeness"] = "unavailable"
            record["cve"]["status"] = "unavailable"
            record["cve"]["enrichment_availability"] = {
                "state": CVELIST_V5_NOT_FOUND,
                "http_status": 404,
                "requested_url": cvelist_v5_raw_url(record["cve_id"]),
                "constructed_path_valid": True,
            }
        decision, _ = self._decide(candidate)
        self.assertEqual(decision.outcome, "publish")

    def test_systemic_enrichment_outage_is_blocked(self) -> None:
        candidate = deepcopy(self.snapshot)
        candidate["status"] = "degraded"
        candidate["sources"]["cve"]["status"] = "failed"
        decision, _ = self._decide(candidate)
        self.assertEqual(decision.outcome, "reject")
        self.assertIn("Systemic CVE List V5", decision.details["message"])

    def test_transient_failures_over_cap_are_blocked(self) -> None:
        candidate = deepcopy(self.snapshot)
        candidate["status"] = "degraded"
        candidate["sources"]["cve"]["status"] = "degraded"
        template = candidate["records"][0]
        records = []
        for index in range(3):
            record = deepcopy(template)
            record["cve_id"] = f"CVE-2099-{index + 1:04d}"
            record["kev"]["cve_id"] = record["cve_id"]
            record["cve"]["cve_id"] = record["cve_id"]
            record["completeness"] = "unavailable"
            record["cve"]["status"] = "unavailable"
            record["cve"]["enrichment_availability"] = {
                "state": TRANSIENT_FAILURE,
                "retryable": True,
                "requested_url": cvelist_v5_raw_url(record["cve_id"]),
            }
            records.append(record)
        candidate["records"] = records
        report = evaluate_enrichment_policy(candidate)
        self.assertFalse(report["eligible"])
        self.assertIn("transient", report["block_reason"] or "")

    def test_invalid_kev_still_blocks_despite_complete_enrichment(self) -> None:
        broken = deepcopy(self.snapshot)
        broken["records"][0]["kev"]["vendor_project"] = "Not the catalog"
        catalog, meta = catalog_from_snapshot(self.snapshot)
        decision, _ = self._decide(broken, catalog=catalog, kev_meta=meta, extra_files=None)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "kev_catalog_mismatch")

    def test_enrichment_recovery_on_unchanged_kev_is_publishable(self) -> None:
        missing = self._unavailable(
            self.snapshot,
            0,
            {
                "state": CVELIST_V5_NOT_FOUND,
                "http_status": 404,
                "requested_url": cvelist_v5_raw_url(self.snapshot["records"][0]["cve_id"]),
                "constructed_path_valid": True,
            },
        )
        missing["snapshot_id"] = "20990110T120000Z_missing"
        self._promote(missing)
        later = deepcopy(self.snapshot)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["collection_completed_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "20990110T130000Z_enrich"
        later["sources"]["cve"]["content_sha256"] = "a" * 64
        decision, _ = self._decide(later)
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "enrichment_update")

    def test_previous_enrichment_loss_is_blocked(self) -> None:
        self._promote(self.snapshot)
        later = self._unavailable(
            self.snapshot,
            0,
            {
                "state": CVELIST_V5_NOT_FOUND,
                "http_status": 404,
                "requested_url": cvelist_v5_raw_url(self.snapshot["records"][0]["cve_id"]),
                "constructed_path_valid": True,
            },
        )
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "20990110T130000Z_loss"
        decision, _ = self._decide(later)
        self.assertEqual(decision.outcome, "reject")
        self.assertIn("Previously published CVE List V5 enrichment is missing", decision.details["message"])

    def test_production_sized_ratio_blocks_over_absent_cap(self) -> None:
        candidate = deepcopy(self.snapshot)
        template = candidate["records"][0]
        records = []
        for index in range(200):
            record = deepcopy(template)
            record["cve_id"] = f"CVE-2099-{index:04d}"
            record["kev"]["cve_id"] = record["cve_id"]
            record["cve"]["cve_id"] = record["cve_id"]
            if index < 9:
                record["completeness"] = "unavailable"
                record["cve"]["status"] = "unavailable"
                record["cve"]["enrichment_availability"] = {
                    "state": CVELIST_V5_NOT_FOUND,
                    "http_status": 404,
                    "requested_url": cvelist_v5_raw_url(record["cve_id"]),
                    "constructed_path_valid": True,
                }
            records.append(record)
        candidate["records"] = records
        report = evaluate_enrichment_policy(candidate)
        self.assertFalse(report["eligible"])
        self.assertIn("were not found", report["block_reason"] or "")

    def test_policy_report_lists_ids(self) -> None:
        candidate = self._unavailable(self.snapshot, 0, None)
        report = evaluate_enrichment_policy(candidate)
        self.assertFalse(report["eligible"])
        self.assertEqual(report["affected"]["unclassified"], [self.snapshot["records"][0]["cve_id"]])


if __name__ == "__main__":
    unittest.main()
