from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.kev import parse_kev_catalog
from silastron_pulse.constants import KEV_JSON_URL
from silastron_pulse.errors import FetchError, ValidationError
from tests.support import fetch_result, fixture_bytes, load_fixture_json, test_config, valid_fetcher


class KevAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config = test_config(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _parse(self, name: str):
        raw = fixture_bytes(name)
        return parse_kev_catalog(
            json.loads(raw),
            raw=raw,
            retrieved_at="2099-01-10T12:00:00Z",
            config=self.config,
        )

    def test_valid_catalog(self) -> None:
        catalog = self._parse("kev_valid.json")
        self.assertEqual(catalog.meta.status, "ok")
        self.assertEqual([item.cve_id for item in catalog.records], ["CVE-2099-0001", "CVE-2099-0002"])
        self.assertEqual(catalog.meta.source_revision, "2099.01.01-TEST")
        self.assertEqual(catalog.meta.source_published_at, "2099-01-01T00:00:00.000Z")

    def test_malformed_payload(self) -> None:
        with self.assertRaises(ValidationError):
            self._parse("kev_malformed.json")

    def test_missing_fields(self) -> None:
        with self.assertRaises(ValidationError):
            self._parse("kev_missing_fields.json")

    def test_conflicting_duplicates_fail(self) -> None:
        with self.assertRaises(ValidationError):
            self._parse("kev_duplicates.json")

    def test_identical_duplicates_are_deduplicated(self) -> None:
        catalog = self._parse("kev_identical_duplicates.json")
        self.assertEqual(len(catalog.records), 1)

    def test_unsafe_strings_are_preserved_as_text_not_urls(self) -> None:
        catalog = self._parse("kev_unsafe.json")
        record = catalog.records[0]
        self.assertIn("<script>", record.vendor_project)
        self.assertEqual(record.source_url, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

    def test_empty_catalog_fails(self) -> None:
        payload = {
            "catalogVersion": "x",
            "dateReleased": "2099-01-01T00:00:00Z",
            "count": 0,
            "vulnerabilities": [],
        }
        with self.assertRaises(ValidationError):
            parse_kev_catalog(
                payload,
                raw=b"{}",
                retrieved_at="2099-01-10T12:00:00Z",
                config=self.config,
            )

    def test_count_mismatch_fails(self) -> None:
        payload = load_fixture_json("kev_valid.json")
        assert isinstance(payload, dict)
        payload["count"] = 99
        with self.assertRaises(ValidationError):
            parse_kev_catalog(
                payload,
                raw=b"{}",
                retrieved_at="2099-01-10T12:00:00Z",
                config=self.config,
            )

    def test_source_failure(self) -> None:
        from silastron_pulse.adapters.kev import fetch_kev_catalog

        fetcher = valid_fetcher(
            **{KEV_JSON_URL: FetchError("upstream 500")}
        )
        with self.assertRaises(FetchError):
            fetch_kev_catalog(fetcher, self.config)

    def test_oversize_body(self) -> None:
        from silastron_pulse.adapters.kev import fetch_kev_catalog

        fetcher = valid_fetcher(
            **{
                KEV_JSON_URL: fetch_result(KEV_JSON_URL, "kev_valid.json"),
            }
        )
        tiny = self.config
        object.__setattr__(tiny, "max_kev_bytes", 10)  # type: ignore[misc]
        with self.assertRaises((FetchError, ValidationError)):
            fetch_kev_catalog(fetcher, tiny)


if __name__ == "__main__":
    unittest.main()
