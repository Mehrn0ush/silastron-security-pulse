from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.adapters.nvd import collect_nvd, parse_nvd_response
from silastron_pulse.errors import CorrelationError, FetchError
from silastron_pulse.http import FetchResult, MapFetcher, ScriptedFetcher
from silastron_pulse.ids import nvd_cve_api_url
from silastron_pulse.pipeline import collect
from tests.support import fetch_result, fixture_bytes, frozen_clock, test_config, valid_fetcher


def _nvd_fetcher(*cve_ids: str, fixture: str = "nvd_2099_0001.json") -> MapFetcher:
    overrides: dict[str, FetchResult | Exception] = {}
    for cve_id in cve_ids:
        url = nvd_cve_api_url(cve_id)
        overrides[url] = fetch_result(url, fixture)
    return valid_fetcher(**overrides)


class NvdCollectorTests(unittest.TestCase):
    def test_parses_valid_nvd_response_and_drops_unsafe_urls(self) -> None:
        payload = json.loads(fixture_bytes("nvd_2099_0001.json"))
        record = parse_nvd_response(
            payload,
            expected_cve_id="CVE-2099-0001",
            raw=fixture_bytes("nvd_2099_0001.json"),
            source_url=nvd_cve_api_url("CVE-2099-0001"),
            config=test_config(Path(".")),
            retrieved_at="2099-01-10T12:00:00Z",
            etag='"nvd-1"',
        )
        self.assertEqual(record.status, "ok")
        self.assertEqual(record.last_modified, "2099-01-09T00:00:00.000")
        versions = {item["cvss_version"] for item in record.assessments}
        self.assertEqual(versions, {"3.1", "2.0"})
        v31 = next(item for item in record.assessments if item["cvss_version"] == "3.1")
        self.assertEqual(v31["base_score"], 9.8)
        self.assertEqual(v31["metrics"]["attackVector"], "NETWORK")
        self.assertEqual(record.cwes[0]["cwe_id"], "CWE-502")
        affected = record.products[0]["ranges"]
        self.assertTrue(any(row["less_than"] == "1.1" and row["fixed_version"] is None for row in affected))
        urls = [item["url"] for item in record.references]
        self.assertIn("https://vendor.example/advisory/CVE-2099-0001", urls)
        self.assertNotIn("javascript:alert(1)", urls)

    def test_missing_nvd_record_is_explicitly_unavailable(self) -> None:
        payload = json.loads(fixture_bytes("nvd_empty.json"))
        record = parse_nvd_response(
            payload,
            expected_cve_id="CVE-2099-0001",
            raw=fixture_bytes("nvd_empty.json"),
            source_url=nvd_cve_api_url("CVE-2099-0001"),
            config=test_config(Path(".")),
            retrieved_at="2099-01-10T12:00:00Z",
            etag=None,
        )
        self.assertEqual(record.status, "unavailable")
        self.assertEqual(record.availability["class"], "missing_record")

    def test_rate_limit_and_failures_do_not_block_kev(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        fetcher = valid_fetcher(
            **{
                url: FetchError("HTTP 429 fetching NVD", retryable=True, status_code=429),
                nvd_cve_api_url("CVE-2099-0002"): FetchError(
                    "HTTP 403 fetching NVD", retryable=False, status_code=403
                ),
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=fetcher,
                clock=frozen_clock(),
            )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        self.assertEqual(result.snapshot["sources"]["kev"]["status"], "ok")
        self.assertIn(result.snapshot["sources"]["nvd"]["status"], {"unavailable", "degraded"})
        for record in result.snapshot["records"]:
            self.assertEqual(record["intelligence"]["sources"]["nvd"]["status"], "unavailable")
            self.assertFalse(record["intelligence"]["coverage"]["nvd_available"])

    def test_invalid_and_oversized_responses_stay_unavailable(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        oversized = FetchResult(
            requested_url=url,
            final_url=url,
            status_code=200,
            content_type="application/json",
            body=b'{"totalResults":1}' + b"x" * 64,
            retrieved_at="2099-01-10T12:00:00Z",
        )
        malformed = FetchResult(
            requested_url=url,
            final_url=url,
            status_code=200,
            content_type="application/json",
            body=b'{"totalResults":"nope"}',
            retrieved_at="2099-01-10T12:00:00Z",
        )
        config = replace(test_config(Path(".")), max_nvd_bytes=32)
        first = collect_nvd(
            ["CVE-2099-0001"],
            MapFetcher({url: oversized}),
            config,
        )
        self.assertEqual(first.records["CVE-2099-0001"].availability["class"], "oversized")
        second = collect_nvd(["CVE-2099-0001"], MapFetcher({url: malformed}), test_config(Path(".")))
        self.assertEqual(second.records["CVE-2099-0001"].availability["class"], "invalid_payload")

    def test_etag_cache_avoids_refetch_of_unchanged_records(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        first_body = fixture_bytes("nvd_2099_0001.json")
        scripted = ScriptedFetcher(
            {
                url: [
                    FetchResult(
                        requested_url=url,
                        final_url=url,
                        status_code=200,
                        content_type="application/json",
                        body=first_body,
                        retrieved_at="2099-01-10T12:00:00Z",
                        etag='"nvd-1"',
                    ),
                    FetchResult(
                        requested_url=url,
                        final_url=url,
                        status_code=304,
                        content_type="",
                        body=b"",
                        retrieved_at="2099-01-10T13:00:00Z",
                        etag='"nvd-1"',
                        not_modified=True,
                    ),
                ]
            }
        )
        config = replace(test_config(Path(".")), nvd_ok_ttl_hours=1)
        first = collect_nvd(
            ["CVE-2099-0001"],
            scripted,
            config,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
        )
        cached = {first.records["CVE-2099-0001"].cve_id: first.records["CVE-2099-0001"].to_dict()}
        index = {
            "records": {
                "CVE-2099-0001": {"etag": '"nvd-1"', "status": "ok"}
            }
        }
        second = collect_nvd(
            ["CVE-2099-0001"],
            scripted,
            config,
            cache_index=index,
            cached_records=cached,
            now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
        )
        self.assertEqual(first.records["CVE-2099-0001"].status, "ok")
        self.assertTrue(second.records["CVE-2099-0001"].cached)
        self.assertEqual(second.records["CVE-2099-0001"].comparable(), first.records["CVE-2099-0001"].comparable())
        self.assertEqual(len(scripted.calls), 2)

    def test_configured_api_key_is_flagged_and_never_serialized(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        config = replace(test_config(Path(".")), nvd_api_key="test-nvd-key-not-real")
        result = collect_nvd(
            ["CVE-2099-0001"],
            MapFetcher({url: fetch_result(url, "nvd_2099_0001.json")}),
            config,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
        )
        self.assertTrue(result.metrics["api_key_configured"])
        blob = json.dumps({cve_id: record.to_dict() for cve_id, record in result.records.items()})
        self.assertNotIn("test-nvd-key-not-real", blob)
        self.assertNotIn("apiKey", blob)
        self.assertNotIn("NVD_API_KEY", blob)

    def test_previously_failed_enrichment_is_recovered(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        config = replace(test_config(Path(".")), nvd_retry_ttl_hours=1, nvd_ok_ttl_hours=24)
        cached = {
            "CVE-2099-0001": {
                "cve_id": "CVE-2099-0001",
                "status": "unavailable",
                "assessments": [],
                "cwes": [],
                "products": [],
                "references": [],
                "source_url": url,
                "record_page_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                "record_sha256": "a",
                "retrieved_at": "2099-01-01T00:00:00Z",
                "last_checked_at": "2099-01-01T00:00:00Z",
            }
        }
        recovered = collect_nvd(
            ["CVE-2099-0001"],
            MapFetcher({url: fetch_result(url, "nvd_2099_0001.json")}),
            config,
            cached_records=cached,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            previous_ids=["CVE-2099-0001"],
        )
        self.assertEqual(recovered.records["CVE-2099-0001"].status, "ok")
        self.assertEqual(recovered.metrics["records_refreshed"], 1)
        self.assertEqual(recovered.metrics["requests_attempted"], 1)
        self.assertFalse(recovered.records["CVE-2099-0001"].cached)

    def test_api_key_is_optional_and_never_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=_nvd_fetcher("CVE-2099-0001", "CVE-2099-0002"),
                clock=frozen_clock(),
            )
        assert result.snapshot is not None
        blob = json.dumps(result.snapshot)
        self.assertNotIn("apiKey", blob)
        self.assertNotIn("NVD_API_KEY", blob)
        self.assertFalse(result.snapshot["summary"]["nvd_api_key_configured"])
        self.assertIn("not endorsed or certified by the NVD", result.snapshot["attribution"]["nvd"])

    def test_warm_cache_skips_http_and_cold_cache_fetches(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        now = datetime(2099, 1, 10, 12, tzinfo=timezone.utc)
        config = replace(test_config(Path(".")), nvd_ok_ttl_hours=24, nvd_max_fetches_per_run=8)
        first = collect_nvd(
            ["CVE-2099-0001"],
            MapFetcher({url: fetch_result(url, "nvd_2099_0001.json")}),
            config,
            now=now,
        )
        cached = {first.records["CVE-2099-0001"].cve_id: first.records["CVE-2099-0001"].to_dict()}
        scripted = ScriptedFetcher({url: []})
        warm = collect_nvd(
            ["CVE-2099-0001"],
            scripted,
            config,
            cached_records=cached,
            now=now,
            previous_ids=["CVE-2099-0001"],
        )
        self.assertEqual(warm.metrics["requests_attempted"], 0)
        self.assertEqual(warm.metrics["cache_hits"], 1)
        self.assertEqual(len(scripted.calls), 0)

    def test_partial_backfill_resumes_and_prioritizes_missing(self) -> None:
        ids = ["CVE-2099-0001", "CVE-2099-0002"]
        config = replace(
            test_config(Path(".")),
            nvd_max_fetches_per_run=1,
            nvd_ok_ttl_hours=24,
            nvd_retry_ttl_hours=1,
        )
        now = datetime(2099, 1, 10, 12, tzinfo=timezone.utc)
        mixed = valid_fetcher(
            **{
                nvd_cve_api_url("CVE-2099-0001"): fetch_result(
                    nvd_cve_api_url("CVE-2099-0001"), "nvd_2099_0001.json"
                ),
                nvd_cve_api_url("CVE-2099-0002"): fetch_result(
                    nvd_cve_api_url("CVE-2099-0002"), "nvd_empty.json"
                ),
            }
        )
        first = collect_nvd(
            ids,
            mixed,
            config,
            now=now,
            previous_ids=[],
        )
        self.assertEqual(first.metrics["requests_attempted"], 1)
        self.assertEqual(first.metrics["pending_backfill"], 1)
        pending = first.pending_ids[0]
        cached = {
            cve_id: record.to_dict()
            for cve_id, record in first.records.items()
            if record.status == "ok"
        }
        second = collect_nvd(
            ids,
            mixed,
            config,
            cached_records=cached,
            now=now,
            previous_ids=["CVE-2099-0001", "CVE-2099-0002"],
        )
        self.assertIn(pending, second.fetched_ids)
        self.assertEqual(second.metrics["pending_backfill"], 0)

    def test_expired_cache_is_refreshed_and_rate_limit_is_counted(self) -> None:
        url = nvd_cve_api_url("CVE-2099-0001")
        config = replace(test_config(Path(".")), nvd_ok_ttl_hours=1)
        cached = {
            "CVE-2099-0001": {
                "cve_id": "CVE-2099-0001",
                "status": "ok",
                "assessments": [],
                "cwes": [],
                "products": [],
                "references": [],
                "source_url": url,
                "record_page_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                "record_sha256": "a",
                "retrieved_at": "2099-01-01T00:00:00Z",
                "last_checked_at": "2099-01-01T00:00:00Z",
            }
        }
        limited = collect_nvd(
            ["CVE-2099-0001"],
            MapFetcher({url: FetchError("HTTP 429 fetching NVD", retryable=True, status_code=429)}),
            config,
            cached_records=cached,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            previous_ids=["CVE-2099-0001"],
        )
        self.assertEqual(limited.metrics["rate_limited"], 1)
        self.assertEqual(limited.metrics["requests_attempted"], 1)

    def test_wrong_identifier_is_rejected(self) -> None:
        payload = json.loads(fixture_bytes("nvd_2099_0001.json"))
        with self.assertRaises(CorrelationError):
            parse_nvd_response(
                payload,
                expected_cve_id="CVE-2099-0002",
                raw=fixture_bytes("nvd_2099_0001.json"),
                source_url=nvd_cve_api_url("CVE-2099-0002"),
                config=test_config(Path(".")),
                retrieved_at="2099-01-10T12:00:00Z",
                etag=None,
            )


if __name__ == "__main__":
    unittest.main()
