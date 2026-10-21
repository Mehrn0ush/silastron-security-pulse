"""CVE List V5 incremental sync: missed windows and incomplete logs."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from silastron_pulse.adapters.cve import enrich_cves
from silastron_pulse.constants import CVE_DELTA_JSON_URL, CVE_DELTA_LOG_URL
from silastron_pulse.http import FetchResult
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.pipeline import collect
from tests.support import fetch_result, frozen_clock, test_config, valid_fetcher


class CveSyncTests(unittest.TestCase):
    def test_unchanged_delta_window_does_not_refetch_cached_cves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "ok")
            fetcher = valid_fetcher()
            second = collect(
                config=test_config(root / "two"),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["summary"]["cve_strategy"], "unchanged")
            cve_gets = [
                url
                for url, marker in fetcher.calls
                if "/CVE-2099-" in url and marker != "HEAD"
            ]
            self.assertEqual(cve_gets, [])

    def test_delta_log_fetches_only_kev_intersection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "ok")
            updated = cvelist_v5_raw_url("CVE-2099-0001")
            other = cvelist_v5_raw_url("CVE-2099-0002")
            fetcher = valid_fetcher(
                **{
                    CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta.json"),
                    CVE_DELTA_LOG_URL: fetch_result(CVE_DELTA_LOG_URL, "delta_log.json"),
                    updated: fetch_result(updated, "cve_2099_0001_updated.json"),
                }
            )
            second = collect(
                config=test_config(root / "two"),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["summary"]["cve_strategy"], "delta")
            urls = [url for url, marker in fetcher.calls if marker != "HEAD"]
            self.assertIn(updated, urls)
            self.assertNotIn(other, urls)
            record = next(item for item in second.snapshot["records"] if item["cve_id"] == "CVE-2099-0001")
            self.assertEqual(record["cve"]["date_updated"], "2099-01-11T00:00:00.000Z")

    def test_missed_update_window_resyncs_kev_subset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "ok")
            fetcher = valid_fetcher(
                **{
                    CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta.json"),
                    CVE_DELTA_LOG_URL: fetch_result(CVE_DELTA_LOG_URL, "delta_gap_log.json"),
                }
            )
            second = collect(
                config=test_config(root / "two"),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["summary"]["cve_strategy"], "resync")
            urls = [url for url, marker in fetcher.calls if marker != "HEAD"]
            self.assertIn(cvelist_v5_raw_url("CVE-2099-0001"), urls)
            self.assertIn(cvelist_v5_raw_url("CVE-2099-0002"), urls)

    def test_oversized_delta_log_is_not_downloaded_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "ok")
            oversized = FetchResult(
                requested_url=CVE_DELTA_LOG_URL,
                final_url=CVE_DELTA_LOG_URL,
                status_code=200,
                content_type="application/json",
                body=b"[]",
                retrieved_at="2099-01-10T12:00:00Z",
                etag='"oversized"',
                content_length=50_000_000,
            )
            fetcher = valid_fetcher(
                **{
                    CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta.json"),
                    CVE_DELTA_LOG_URL: oversized,
                }
            )
            config = replace(test_config(root / "two"), max_delta_bytes=1_000)
            second = collect(
                config=config,
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(second.status, "failed")
            self.assertIn("exceeds max_delta_bytes", second.error or "")
            get_log = [
                (url, marker)
                for url, marker in fetcher.calls
                if url == CVE_DELTA_LOG_URL and marker != "HEAD"
            ]
            self.assertEqual(get_log, [])
            index = json.loads((root / "state" / "source" / "cve" / "index.json").read_text())
            self.assertEqual(index.get("strategy"), "full")

    def test_matching_oversized_etag_is_not_redownloaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(test_config(Path(tmp)), max_delta_bytes=100)
            result = enrich_cves(
                ["CVE-2099-0001"],
                valid_fetcher(
                    **{
                        CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta.json"),
                        CVE_DELTA_LOG_URL: FetchResult(
                            requested_url=CVE_DELTA_LOG_URL,
                            final_url=CVE_DELTA_LOG_URL,
                            status_code=200,
                            content_type="application/json",
                            body=b"[]",
                            retrieved_at="2099-01-10T12:00:00Z",
                            etag='"still-big"',
                            content_length=50_000_000,
                        ),
                    }
                ),
                config,
                cache_index={
                    "delta_fetch_time": "2099-01-08T00:00:00Z",
                    "delta_log_etag": '"still-big"',
                    "delta_log_bytes": 50_000_000,
                    "delta_log_skipped": True,
                    "records": {"CVE-2099-0001": {"status": "ok", "etag": '"x"'}},
                },
                cached_records={
                    "CVE-2099-0001": {
                        "cve_id": "CVE-2099-0001",
                        "state": "PUBLISHED",
                        "status": "ok",
                        "source_url": cvelist_v5_raw_url("CVE-2099-0001"),
                        "record_page_url": "https://www.cve.org/CVERecord?id=CVE-2099-0001",
                        "record_sha256": "abc",
                        "products": [],
                    }
                },
            )
            self.assertEqual(result.strategy, "failed")
            self.assertTrue(result.delta_log_skipped)
            self.assertIn("exceeds max_delta_bytes", result.meta.error or "")

    def test_same_fetch_time_with_rewritten_window_is_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
                collector_commit_sha="abc123",
            )
            self.assertEqual(first.status, "ok")
            updated = cvelist_v5_raw_url("CVE-2099-0001")
            fetcher = valid_fetcher(
                **{
                    CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta_same_fetch_time.json"),
                    updated: fetch_result(updated, "cve_2099_0001_updated.json"),
                }
            )
            second = collect(
                config=test_config(root / "two"),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
                collector_commit_sha="abc123",
            )
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["summary"]["cve_strategy"], "delta")
            urls = [url for url, marker in fetcher.calls if marker != "HEAD"]
            self.assertIn(updated, urls)
            record = next(item for item in second.snapshot["records"] if item["cve_id"] == "CVE-2099-0001")
            self.assertEqual(record["cve"]["date_updated"], "2099-01-11T00:00:00.000Z")

    def test_stale_fetch_time_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "ok")
            second = collect(
                config=test_config(root / "two"),
                fetcher=valid_fetcher(
                    **{CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta_stale.json")}
                ),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(second.status, "failed")
            self.assertIn("older than the stored watermark", second.error or "")
            index = json.loads((root / "state" / "source" / "cve" / "index.json").read_text())
            self.assertEqual(index.get("strategy"), "full")

    def test_collection_records_hashes_strategy_transfer_and_duration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = collect(
                config=test_config(root),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                collector_commit_sha="def456",
            )
            assert result.snapshot is not None
            summary = result.snapshot["summary"]
            self.assertEqual(summary["cve_strategy"], "full")
            self.assertEqual(summary["collector_commit_sha"], "def456")
            self.assertEqual(len(summary["cve_delta_sha256"] or ""), 64)
            self.assertEqual(len(summary["kev_content_sha256"] or ""), 64)
            self.assertGreater(summary["bytes_transferred"], 0)
            self.assertGreaterEqual(summary["http_gets"], 3)
            self.assertGreaterEqual(summary["duration_ms"], 0)
            self.assertEqual(result.snapshot["binding"]["collector_commit_sha"], "def456")
            status = json.loads((root / "collection-status.json").read_text())
            self.assertEqual(status["cve_strategy"], "full")
            self.assertEqual(status["content_sha256"], json.loads((root / "candidate.meta.json").read_text())["content_sha256"])
            self.assertEqual(status["bytes_transferred"], summary["bytes_transferred"])


if __name__ == "__main__":
    unittest.main()
