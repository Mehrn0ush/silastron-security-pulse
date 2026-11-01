from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
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
        config = test_config(Path("."))
        first = collect_nvd(["CVE-2099-0001"], scripted, config)
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
        )
        self.assertEqual(first.records["CVE-2099-0001"].status, "ok")
        self.assertTrue(second.records["CVE-2099-0001"].cached)
        self.assertEqual(second.records["CVE-2099-0001"].comparable(), first.records["CVE-2099-0001"].comparable())
        self.assertEqual(len(scripted.calls), 2)

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
