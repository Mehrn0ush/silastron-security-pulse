from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from silastron_pulse.adapters.cve import parse_cve_record
from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.models import CveRecord, KevRecord, record_completeness
from silastron_pulse.pipeline import collect
from silastron_pulse.signals import build_signals
from silastron_pulse.store import build_preview_document
from silastron_pulse.validate import validate_snapshot
from tests.support import fetch_result, fixture_bytes, frozen_clock, stepping_clock, test_config, valid_fetcher
from tests.test_signals import _cve, _kev


class CompletenessTests(unittest.TestCase):
    def test_default_limits_store_all_fixture_products(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            raw = fixture_bytes("cve_many_products.json")
            record = parse_cve_record(
                json.loads(raw),
                expected_cve_id="CVE-2099-0001",
                raw=raw,
                source_url=cvelist_v5_raw_url("CVE-2099-0001"),
                config=config,
            )
            self.assertEqual(len(record.products), 12)
            self.assertEqual(record.omitted_product_count, 0)
            self.assertEqual(record.omitted_version_count, 0)
            self.assertEqual(record.truncated_fields, ())

    def test_version_omission_is_counted_and_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(test_config(Path(tmp)), max_versions_per_product=2)
            payload = {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": "CVE-2099-0001",
                    "state": "PUBLISHED",
                    "assignerShortName": "fixture",
                    "datePublished": "2099-01-01T00:00:00.000Z",
                    "dateUpdated": "2099-01-02T00:00:00.000Z",
                },
                "containers": {
                    "cna": {
                        "title": "TEST FIXTURE ONLY",
                        "descriptions": [{"lang": "en", "value": "Synthetic."}],
                        "affected": [
                            {
                                "vendor": "Vendor",
                                "product": "Product",
                                "defaultStatus": "affected",
                                "versions": [
                                    {"version": str(index), "status": "affected"}
                                    for index in range(6)
                                ],
                            }
                        ],
                    }
                },
            }
            raw = json.dumps(payload).encode("utf-8")
            record = parse_cve_record(
                payload,
                expected_cve_id="CVE-2099-0001",
                raw=raw,
                source_url=cvelist_v5_raw_url("CVE-2099-0001"),
                config=config,
            )
            self.assertEqual(len(record.products[0].versions), 2)
            self.assertEqual(record.omitted_version_count, 4)
            self.assertIn("versions", record.truncated_fields)
            self.assertEqual(record_completeness(kev=_kev(), cve=record), "partial")
            affectedness = build_signals(_kev(), record, _cve_epss()).product_affectedness
            self.assertEqual(affectedness["status"], "source_asserted_partial")
            self.assertEqual(affectedness["omitted_version_count"], 4)
            self.assertIn("were not stored", affectedness["note"])

    def test_description_truncation_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(test_config(Path(tmp)), max_description_chars=32)
            payload = json.loads(fixture_bytes("cve_2099_0001.json"))
            payload["containers"]["cna"]["descriptions"] = [
                {"lang": "en", "value": "A" * 80}
            ]
            raw = json.dumps(payload).encode("utf-8")
            record = parse_cve_record(
                payload,
                expected_cve_id="CVE-2099-0001",
                raw=raw,
                source_url=cvelist_v5_raw_url("CVE-2099-0001"),
                config=config,
            )
            self.assertTrue((record.description or "").endswith("…"))
            self.assertLessEqual(len(record.description or ""), 33)
            self.assertIn("description", record.truncated_fields)
            self.assertEqual(record_completeness(kev=_kev(), cve=record), "partial")

    def test_unavailable_cve_is_record_unavailable(self) -> None:
        cve = CveRecord(
            cve_id="CVE-2099-0001",
            state="UNKNOWN",
            data_version=None,
            date_published=None,
            date_updated=None,
            assigner_short_name=None,
            title=None,
            description=None,
            severity=None,
            products=[],
            source_url=cvelist_v5_raw_url("CVE-2099-0001"),
            record_page_url="https://www.cve.org/CVERecord?id=CVE-2099-0001",
            record_sha256="",
            status="unavailable",
            error="Response exceeded max bytes 1000000",
        )
        self.assertEqual(record_completeness(kev=_kev(), cve=cve), "unavailable")

    def test_complete_record_requires_ok_untruncated_sources(self) -> None:
        self.assertEqual(record_completeness(kev=_kev(), cve=_cve()), "complete")
        kev = KevRecord(
            **{
                **_kev().__dict__,
                "truncated_fields": ("cwes",),
                "cwes_incomplete": True,
            }
        )
        self.assertEqual(record_completeness(kev=kev, cve=_cve()), "partial")

    def test_snapshot_separates_collection_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = collect(
                config=test_config(root),
                fetcher=valid_fetcher(),
                clock=stepping_clock(step_seconds=5),
            )
            self.assertEqual(result.status, "ok")
            snapshot = result.snapshot
            assert snapshot is not None
            self.assertEqual(snapshot["collection_started_at"], "2099-01-10T12:00:00Z")
            self.assertEqual(snapshot["collection_completed_at"], "2099-01-10T12:00:05Z")
            self.assertEqual(snapshot["generated_at"], snapshot["collection_completed_at"])
            self.assertNotEqual(
                snapshot["collection_started_at"], snapshot["collection_completed_at"]
            )
            self.assertEqual(snapshot["records"][0]["completeness"], "complete")
            self.assertEqual(snapshot["summary"]["complete_records"], 2)
            self.assertEqual(snapshot["summary"]["partial_records"], 0)
            self.assertEqual(snapshot["summary"]["unavailable_records"], 0)
            status = json.loads((root / "collection-status.json").read_text())
            self.assertEqual(status["collection_started_at"], snapshot["collection_started_at"])
            self.assertEqual(
                status["collection_completed_at"], snapshot["collection_completed_at"]
            )
            preview = build_preview_document(snapshot)
            self.assertEqual(preview["collection_started_at"], snapshot["collection_started_at"])
            self.assertEqual(preview["recent_kev_additions"][0]["completeness"], "complete")

    def test_validate_rejects_complete_when_products_were_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=valid_fetcher(),
                clock=stepping_clock(),
            )
            assert result.snapshot is not None
            record = result.snapshot["records"][0]
            record["completeness"] = "complete"
            record["cve"]["omitted_product_count"] = 3
            record["cve"]["truncated_fields"] = ["products"]
            with self.assertRaises(ValidationError):
                validate_snapshot(result.snapshot)

    def test_truncated_cache_is_refetched_when_storage_limits_increase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            many = cvelist_v5_raw_url("CVE-2099-0001")
            first = collect(
                config=replace(test_config(root / "one"), max_products=8),
                fetcher=valid_fetcher(
                    **{many: fetch_result(many, "cve_many_products.json")}
                ),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "degraded")
            record = next(item for item in first.snapshot["records"] if item["cve_id"] == "CVE-2099-0001")  # type: ignore[index]
            self.assertEqual(record["completeness"], "partial")
            self.assertEqual(len(record["cve"]["products"]), 8)
            fetcher = valid_fetcher(
                **{many: fetch_result(many, "cve_many_products.json")}
            )
            second = collect(
                config=test_config(root / "two"),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(second.status, "ok")
            urls = [url for url, marker in fetcher.calls if marker != "HEAD"]
            self.assertIn(many, urls)
            self.assertNotIn(cvelist_v5_raw_url("CVE-2099-0002"), urls)
            recovered = next(
                item for item in second.snapshot["records"] if item["cve_id"] == "CVE-2099-0001"  # type: ignore[index]
            )
            self.assertEqual(recovered["completeness"], "complete")
            self.assertEqual(len(recovered["cve"]["products"]), 12)
            third_fetcher = valid_fetcher()
            third = collect(
                config=test_config(root / "three"),
                fetcher=third_fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(third.status, "ok")
            third_cve_gets = [
                url
                for url, marker in third_fetcher.calls
                if "/CVE-2099-" in url and marker != "HEAD"
            ]
            self.assertEqual(third_cve_gets, [])

    def test_truncated_cache_is_reused_when_storage_limits_are_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            many = cvelist_v5_raw_url("CVE-2099-0001")
            config = replace(test_config(root / "one"), max_products=8)
            first = collect(
                config=config,
                fetcher=valid_fetcher(
                    **{many: fetch_result(many, "cve_many_products.json")}
                ),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "degraded")
            fetcher = valid_fetcher(
                **{many: fetch_result(many, "cve_many_products.json")}
            )
            second = collect(
                config=replace(test_config(root / "two"), max_products=8),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(second.status, "degraded")
            cve_gets = [
                url for url, marker in fetcher.calls if "/CVE-2099-" in url and marker != "HEAD"
            ]
            self.assertEqual(cve_gets, [])

    def test_previous_snapshot_without_new_fields_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            assert first.snapshot is not None
            legacy = dict(first.snapshot)
            legacy.pop("collection_started_at")
            legacy.pop("collection_completed_at")
            for record in legacy["records"]:
                record.pop("completeness")
            candidate = root / "state" / "candidates" / "latest.json"
            candidate.write_text(json.dumps(legacy), encoding="utf-8")
            second = collect(
                config=test_config(root / "two"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(second.status, "ok")
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["records"][0]["completeness"], "complete")


def _cve_epss():
    from silastron_pulse.models import EpssRecord

    return EpssRecord(status="disabled", cve_id="CVE-2099-0001", notes="disabled")


if __name__ == "__main__":
    unittest.main()
