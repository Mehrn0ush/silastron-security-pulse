from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.cve import enrich_cves, parse_cve_record
from silastron_pulse.errors import CorrelationError, FetchError, ValidationError
from silastron_pulse.ids import cvelist_v5_raw_url
from tests.support import fetch_result, fixture_bytes, test_config, valid_fetcher


class CveAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config = test_config(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_valid_record(self) -> None:
        raw = fixture_bytes("cve_2099_0001.json")
        record = parse_cve_record(
            json.loads(raw),
            expected_cve_id="CVE-2099-0001",
            raw=raw,
            source_url=cvelist_v5_raw_url("CVE-2099-0001"),
            config=self.config,
        )
        self.assertEqual(record.status, "ok")
        self.assertEqual(record.severity.base_score, 7.5)  # type: ignore[union-attr]
        self.assertEqual(record.severity.source, "cve_cna")  # type: ignore[union-attr]

    def test_incorrect_correlation_is_rejected(self) -> None:
        raw = fixture_bytes("cve_mismatch.json")
        with self.assertRaises(CorrelationError):
            parse_cve_record(
                json.loads(raw),
                expected_cve_id="CVE-2099-0001",
                raw=raw,
                source_url=cvelist_v5_raw_url("CVE-2099-0001"),
                config=self.config,
            )

    def test_zero_padding_is_not_correlated(self) -> None:
        raw = fixture_bytes("cve_2099_0001.json")
        with self.assertRaises(CorrelationError):
            parse_cve_record(
                json.loads(raw),
                expected_cve_id="CVE-2099-00001",
                raw=raw,
                source_url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/x",
                config=self.config,
            )

    def test_missing_cna_still_parses_metadata(self) -> None:
        payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2099-0001", "state": "REJECTED"},
            "containers": {},
        }
        record = parse_cve_record(
            payload,
            expected_cve_id="CVE-2099-0001",
            raw=b"{}",
            source_url=cvelist_v5_raw_url("CVE-2099-0001"),
            config=self.config,
        )
        self.assertIsNone(record.severity)
        self.assertEqual(record.state, "REJECTED")

    def test_enrichment_source_failure_marks_record_unavailable(self) -> None:
        fetcher = valid_fetcher(
            **{
                cvelist_v5_raw_url("CVE-2099-0001"): FetchError("404"),
            }
        )
        result = enrich_cves(["CVE-2099-0001", "CVE-2099-0002"], fetcher, self.config)
        self.assertEqual(result.records["CVE-2099-0001"].status, "unavailable")
        self.assertEqual(result.records["CVE-2099-0002"].status, "ok")
        # One failure in a two-record set exceeds the 5% threshold and fails closed.
        self.assertEqual(result.meta.status, "failed")

    def test_mismatch_during_enrichment_does_not_publish_wrong_cve(self) -> None:
        fetcher = valid_fetcher(
            **{
                cvelist_v5_raw_url("CVE-2099-0001"): fetch_result(
                    cvelist_v5_raw_url("CVE-2099-0001"), "cve_mismatch.json"
                )
            }
        )
        result = enrich_cves(["CVE-2099-0001"], fetcher, self.config)
        self.assertEqual(result.records["CVE-2099-0001"].cve_id, "CVE-2099-0001")
        self.assertEqual(result.records["CVE-2099-0001"].status, "unavailable")
        self.assertIn("does not match", result.records["CVE-2099-0001"].error or "")


if __name__ == "__main__":
    unittest.main()
