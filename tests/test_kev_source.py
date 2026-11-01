"""Collect-time CISA KEV source integrity."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.kev import fetch_kev_catalog, parse_kev_catalog
from silastron_pulse.constants import KEV_JSON_URL
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.http import FetchResult
from silastron_pulse.kev_source import (
    INDEPENDENT_CHECKSUM,
    PUBLISHER_AUTHENTICATION,
    assert_catalog_matches_raw,
    validate_kev_fetch,
)
from tests.support import fetch_result, load_fixture_json, test_config, valid_fetcher

ROOT = Path(__file__).resolve().parents[1]


class KevSourceIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = test_config(ROOT / "unused")
        self.raw = (ROOT / "tests" / "fixtures" / "kev_valid.json").read_bytes()
        self.payload = load_fixture_json("kev_valid.json")

    def test_fetch_records_provenance_and_matches_raw(self) -> None:
        catalog = fetch_kev_catalog(valid_fetcher(), self.config)
        self.assertIsNotNone(catalog.provenance)
        assert catalog.provenance is not None
        self.assertEqual(catalog.provenance["requested_url"], KEV_JSON_URL)
        self.assertEqual(
            catalog.provenance["verification"]["publisher_authentication"],
            PUBLISHER_AUTHENTICATION,
        )
        self.assertEqual(
            catalog.provenance["verification"]["independent_checksum"],
            INDEPENDENT_CHECKSUM,
        )
        self.assertTrue(catalog.provenance["verification"]["parsed_matches_raw"])
        self.assertEqual(catalog.provenance["declared_count"], 2)
        self.assertEqual(catalog.provenance["parsed_unique_records"], 2)

    def test_html_or_wrong_content_type_fails(self) -> None:
        html = FetchResult(
            requested_url=KEV_JSON_URL,
            final_url=KEV_JSON_URL,
            status_code=200,
            content_type="text/html",
            body=b"<html>not kev</html>",
            retrieved_at="2099-01-10T12:00:00Z",
        )
        with self.assertRaises(ValidationError):
            validate_kev_fetch(html, max_bytes=self.config.max_kev_bytes)

    def test_truncated_content_length_fails(self) -> None:
        result = FetchResult(
            requested_url=KEV_JSON_URL,
            final_url=KEV_JSON_URL,
            status_code=200,
            content_type="application/json",
            body=self.raw[:40],
            retrieved_at="2099-01-10T12:00:00Z",
            content_length=len(self.raw),
        )
        with self.assertRaises(ValidationError):
            validate_kev_fetch(result, max_bytes=self.config.max_kev_bytes)

    def test_non_authoritative_final_url_fails(self) -> None:
        result = FetchResult(
            requested_url=KEV_JSON_URL,
            final_url="https://github.com/cisagov/kev-data/raw/main/known_exploited_vulnerabilities.json",
            status_code=200,
            content_type="application/json",
            body=self.raw,
            retrieved_at="2099-01-10T12:00:00Z",
        )
        with self.assertRaises(ValidationError):
            validate_kev_fetch(result, max_bytes=self.config.max_kev_bytes)

    def test_declared_count_mismatch_fails(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["count"] = 99
        with self.assertRaises(ValidationError):
            parse_kev_catalog(
                payload, raw=self.raw, retrieved_at="2099-01-10T12:00:00Z", config=self.config
            )

    def test_duplicate_conflicting_cve_fails(self) -> None:
        payload = copy.deepcopy(self.payload)
        extra = copy.deepcopy(payload["vulnerabilities"][0])
        extra["vendorProject"] = "Different Vendor"
        payload["vulnerabilities"].append(extra)
        payload["count"] = 3
        with self.assertRaises(ValidationError):
            parse_kev_catalog(
                payload,
                raw=json.dumps(payload).encode("utf-8"),
                retrieved_at="2099-01-10T12:00:00Z",
                config=self.config,
            )

    def test_identical_duplicate_cve_is_kept_once(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["vulnerabilities"].append(copy.deepcopy(payload["vulnerabilities"][0]))
        payload["count"] = 3
        raw = json.dumps(payload).encode("utf-8")
        catalog = parse_kev_catalog(
            payload, raw=raw, retrieved_at="2099-01-10T12:00:00Z", config=self.config
        )
        self.assertEqual(len(catalog.records), 2)
        match = assert_catalog_matches_raw(
            catalog,
            raw=raw,
            payload=payload,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(match["identical_duplicate_records"], 1)

    def test_invalid_cve_and_date_fail(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["vulnerabilities"][0]["cveID"] = "CVE-99-1"
        with self.assertRaises(ValidationError):
            parse_kev_catalog(
                payload,
                raw=json.dumps(payload).encode("utf-8"),
                retrieved_at="2099-01-10T12:00:00Z",
                config=self.config,
            )
        payload = copy.deepcopy(self.payload)
        payload["vulnerabilities"][0]["dateAdded"] = "January 1"
        with self.assertRaises(ValidationError):
            parse_kev_catalog(
                payload,
                raw=json.dumps(payload).encode("utf-8"),
                retrieved_at="2099-01-10T12:00:00Z",
                config=self.config,
            )

    def test_parsed_versus_raw_mismatch_fails(self) -> None:
        catalog = parse_kev_catalog(
            self.payload, raw=self.raw, retrieved_at="2099-01-10T12:00:00Z", config=self.config
        )
        other = copy.deepcopy(self.payload)
        other["vulnerabilities"][0]["cveID"] = "CVE-2099-0099"
        with self.assertRaises(ValidationError):
            assert_catalog_matches_raw(
                catalog,
                raw=json.dumps(other).encode("utf-8"),
                payload=self.payload,
                max_bytes=self.config.max_kev_bytes,
                max_depth=self.config.max_json_depth,
            )

    def test_legitimate_addition_removal_and_correction_parse(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["vulnerabilities"][0]["shortDescription"] = "Corrected CISA text"
        extra = copy.deepcopy(payload["vulnerabilities"][0])
        extra["cveID"] = "CVE-2099-0003"
        extra["dateAdded"] = "2099-01-03"
        extra["dueDate"] = "2099-01-20"
        payload["vulnerabilities"].append(extra)
        payload["vulnerabilities"].pop(1)
        payload["count"] = 2
        catalog = parse_kev_catalog(
            payload,
            raw=json.dumps(payload).encode("utf-8"),
            retrieved_at="2099-01-10T12:00:00Z",
            config=self.config,
        )
        ids = {record.cve_id for record in catalog.records}
        self.assertEqual(ids, {"CVE-2099-0001", "CVE-2099-0003"})
        self.assertIn("Corrected CISA text", catalog.records[0].short_description)

    def test_http_error_still_fails_closed(self) -> None:
        fetcher = valid_fetcher(**{KEV_JSON_URL: FetchError("upstream 500")})
        with self.assertRaises(FetchError):
            fetch_kev_catalog(fetcher, self.config)

    def test_collect_persists_provenance(self) -> None:
        from silastron_pulse.pipeline import collect
        from tests.support import frozen_clock

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            config = test_config(output)
            result = collect(
                config=config,
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                collector_commit_sha="abc",
                state_dir=output / "state",
            )
            self.assertEqual(result.status, "ok")
            provenance = json.loads(
                (output / "state" / "source" / "kev" / "provenance.json").read_text(encoding="utf-8")
            )
            self.assertEqual(provenance["source"], "cisa-kev")
            self.assertEqual(provenance["verification"]["independent_checksum"], INDEPENDENT_CHECKSUM)

    def test_text_plain_json_is_accepted(self) -> None:
        result = fetch_result(KEV_JSON_URL, "kev_valid.json")
        plain = FetchResult(
            requested_url=result.requested_url,
            final_url=result.final_url,
            status_code=200,
            content_type="text/plain",
            body=result.body,
            retrieved_at=result.retrieved_at,
        )
        validate_kev_fetch(plain, max_bytes=self.config.max_kev_bytes)


if __name__ == "__main__":
    unittest.main()
