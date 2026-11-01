from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.cve import parse_cve_record
from silastron_pulse.adapters.nvd import parse_nvd_response
from silastron_pulse.auto_publish import _intelligence_improved, _upstream_identity
from silastron_pulse.cve_history import build_cve_history
from silastron_pulse.errors import FetchError
from silastron_pulse.ids import cvelist_v5_raw_url, nvd_cve_api_url
from silastron_pulse.intelligence import assemble_intelligence, comparable_intelligence
from silastron_pulse.pipeline import collect
from silastron_pulse.store import atomic_write_json
from silastron_pulse.validate import validate_snapshot
from tests.support import fetch_result, fixture_bytes, frozen_clock, test_config, valid_fetcher


def _intel_pair():
    config = test_config(Path("."))
    cve = parse_cve_record(
        json.loads(fixture_bytes("cve_2099_0001_intel.json")),
        expected_cve_id="CVE-2099-0001",
        raw=fixture_bytes("cve_2099_0001_intel.json"),
        source_url=cvelist_v5_raw_url("CVE-2099-0001"),
        config=config,
        retrieved_at="2099-01-10T12:00:00Z",
    )
    nvd = parse_nvd_response(
        json.loads(fixture_bytes("nvd_2099_0001.json")),
        expected_cve_id="CVE-2099-0001",
        raw=fixture_bytes("nvd_2099_0001.json"),
        source_url=nvd_cve_api_url("CVE-2099-0001"),
        config=config,
        retrieved_at="2099-01-10T12:05:00Z",
        etag='"nvd-1"',
    )
    return config, cve, nvd


class IntelligenceModelTests(unittest.TestCase):
    def test_preserves_multiple_cvss_versions_and_conflicts(self) -> None:
        _config, cve, nvd = _intel_pair()
        from silastron_pulse.models import KevRecord

        kev = KevRecord(
            cve_id="CVE-2099-0001",
            vendor_project="Fixture Vendor",
            product="Fixture Product",
            vulnerability_name="Fixture vuln",
            date_added="2099-01-01",
            short_description="fixture",
            required_action="Apply vendor patch",
            due_date="2099-01-15",
            known_ransomware_campaign_use="Unknown",
            forensic_triage=None,
            notes=None,
            cwes=["CWE-79"],
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            record_sha256="abc",
        )
        intel = assemble_intelligence(kev=kev, cve=cve, nvd=nvd).to_dict()
        versions = {(item["source"], item["cvss_version"], item["base_score"]) for item in intel["cvss"]["assessments"]}
        self.assertIn(("cve_cna", "3.1", 7.5), versions)
        self.assertIn(("cve_cna", "4.0", 8.7), versions)
        self.assertIn(("nvd", "3.1", 9.8), versions)
        self.assertIn(("nvd", "2.0", 10.0), versions)
        kinds = {item["kind"] for item in intel["conflicts"]}
        self.assertIn("cvss", kinds)
        self.assertIn("cwe", kinds)
        cwe_ids = {(item["source"], item["cwe_id"]) for item in intel["cwes"]["assertions"]}
        self.assertIn(("cve_cna", "CWE-79"), cwe_ids)
        self.assertIn(("nvd", "CWE-502"), cwe_ids)
        self.assertEqual(intel["cwes"]["assertions"][1]["name"], "Cross-site Scripting")
        fixed = intel["remediation"]["fixed_versions"]
        self.assertEqual(fixed[0]["version"], "1.1.0")
        self.assertEqual(fixed[0]["evidence"], "cna_changes_status_fixed")
        nvd_ranges = next(item for item in intel["affected"]["products"] if item["source"] == "nvd")
        self.assertTrue(all(row["fixed_version"] is None for row in nvd_ranges["ranges"]))
        self.assertTrue(any(row["less_than"] == "1.1" for row in nvd_ranges["ranges"]))
        self.assertTrue(intel["coverage"]["has_vendor_advisory"])
        self.assertEqual(intel["cvss"]["display_preference"][0]["cvss_version"], "4.0")
        first = comparable_intelligence(intel)
        intel["sources"]["nvd"]["retrieved_at"] = "2099-01-11T00:00:00Z"
        self.assertEqual(comparable_intelligence(intel), first)

    def test_missing_nvd_and_missing_fixed_versions_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
        assert result.snapshot is not None
        validate_snapshot(result.snapshot)
        record = result.snapshot["records"][0]
        intel = record["intelligence"]
        self.assertEqual(intel["sources"]["nvd"]["status"], "unavailable")
        self.assertFalse(intel["coverage"]["nvd_available"])
        self.assertEqual(intel["remediation"]["fixed_versions"], [])
        self.assertFalse(intel["coverage"]["has_fixed_version"])
        self.assertNotIn("composite_risk_score", intel)
        self.assertIsNone(result.snapshot["composite_risk_score"])

    def test_legacy_snapshot_without_intelligence_still_validates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
        assert result.snapshot is not None
        legacy = copy.deepcopy(result.snapshot)
        legacy["sources"].pop("nvd", None)
        for record in legacy["records"]:
            record.pop("intelligence", None)
            record.get("links", {}).pop("nvd", None)
        validate_snapshot(legacy, compatible=True)

    def test_nvd_enrichment_only_can_publish_and_kev_valid_nvd_unavailable_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
            assert first.snapshot is not None
            published = copy.deepcopy(first.snapshot)
            enriched = collect(
                config=test_config(root / "two"),
                fetcher=valid_fetcher(
                    **{
                        nvd_cve_api_url("CVE-2099-0001"): fetch_result(
                            nvd_cve_api_url("CVE-2099-0001"), "nvd_2099_0001.json"
                        )
                    }
                ),
                clock=frozen_clock(),
            )
            assert enriched.snapshot is not None
            self.assertTrue(_intelligence_improved(published, enriched.snapshot))
            self.assertNotEqual(
                _upstream_identity(published),
                _upstream_identity(enriched.snapshot),
            )
            unavailable = collect(
                config=test_config(root / "three"),
                fetcher=valid_fetcher(
                    **{
                        nvd_cve_api_url("CVE-2099-0001"): FetchError(
                            "HTTP 503", retryable=True, status_code=503
                        )
                    }
                ),
                clock=frozen_clock(),
            )
            assert unavailable.snapshot is not None
            self.assertEqual(unavailable.snapshot["sources"]["kev"]["status"], "ok")
            self.assertEqual(unavailable.status, "ok")

    def test_history_classifies_nvd_and_conflict_events_without_timestamp_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
            assert first.snapshot is not None
            published = root / "published"
            (published / "snapshots").mkdir(parents=True)
            snap1 = copy.deepcopy(first.snapshot)
            snap1["snapshot_id"] = "snap-1"
            snap1["generated_at"] = "2099-01-10T12:00:00Z"
            snap2 = copy.deepcopy(first.snapshot)
            snap2["snapshot_id"] = "snap-2"
            snap2["generated_at"] = "2099-01-11T12:00:00Z"
            for record in snap2["records"]:
                record["intelligence"]["sources"]["nvd"]["retrieved_at"] = "2099-01-11T12:00:00Z"
                record["intelligence"]["sources"]["nvd"]["last_checked_at"] = "2099-01-11T12:00:00Z"
            snap3 = copy.deepcopy(snap2)
            snap3["snapshot_id"] = "snap-3"
            snap3["generated_at"] = "2099-01-12T12:00:00Z"
            intel = snap3["records"][0]["intelligence"]
            intel["sources"]["nvd"]["status"] = "ok"
            intel["coverage"]["nvd_available"] = True
            intel["cvss"]["assessments"].append(
                {
                    "source": "nvd",
                    "cvss_version": "3.1",
                    "base_score": 9.8,
                    "severity": "CRITICAL",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {"attackVector": "NETWORK"},
                    "source_updated_at": "2099-01-09T00:00:00.000",
                }
            )
            intel["conflicts"] = [{"kind": "cvss", "note": "disagree"}]
            atomic_write_json(published / "snapshots" / "snap-1.json", snap1)
            atomic_write_json(published / "snapshots" / "snap-2.json", snap2)
            atomic_write_json(published / "snapshots" / "snap-3.json", snap3)
            atomic_write_json(published / "latest.json", snap3)
            built = build_cve_history(published, max_bytes=5_000_000, max_depth=32)
            events = built["documents"][0]["events"]
            kinds = [event["kind"] for event in events]
            self.assertIn("first_observed", kinds)
            self.assertIn("nvd_change", kinds)
            self.assertIn("cvss_assessment_change", kinds)
            self.assertIn("intelligence_conflict_change", kinds)
            self.assertEqual(kinds.count("nvd_change"), 1)

    def test_secret_and_serialization_stability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=valid_fetcher(
                    **{
                        cvelist_v5_raw_url("CVE-2099-0001"): fetch_result(
                            cvelist_v5_raw_url("CVE-2099-0001"), "cve_2099_0001_intel.json"
                        ),
                        nvd_cve_api_url("CVE-2099-0001"): fetch_result(
                            nvd_cve_api_url("CVE-2099-0001"), "nvd_2099_0001.json"
                        ),
                    }
                ),
                clock=frozen_clock(),
            )
        assert result.snapshot is not None
        validate_snapshot(result.snapshot)
        blob = json.dumps(result.snapshot)
        self.assertNotIn("NVD_API_KEY", blob)
        self.assertNotIn("apiKey", blob)
        self.assertGreater(result.snapshot["summary"]["intelligence"]["records_with_cvss"], 0)
        self.assertGreater(result.snapshot["summary"]["intelligence"]["records_with_cwe"], 0)
        again = collect(
            config=test_config(Path(tempfile.mkdtemp())),
            fetcher=valid_fetcher(
                **{
                    cvelist_v5_raw_url("CVE-2099-0001"): fetch_result(
                        cvelist_v5_raw_url("CVE-2099-0001"), "cve_2099_0001_intel.json"
                    ),
                    nvd_cve_api_url("CVE-2099-0001"): fetch_result(
                        nvd_cve_api_url("CVE-2099-0001"), "nvd_2099_0001.json"
                    ),
                }
            ),
            clock=frozen_clock(),
        )
        assert again.snapshot is not None
        first_records = comparable_intelligence(result.snapshot["records"][0]["intelligence"])
        second_records = comparable_intelligence(again.snapshot["records"][0]["intelligence"])
        self.assertEqual(first_records, second_records)


if __name__ == "__main__":
    unittest.main()
