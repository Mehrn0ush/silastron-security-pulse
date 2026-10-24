from __future__ import annotations

import unittest

from silastron_pulse.adapters.epss import (
    EPSS_BLOCKER,
    REDISTRIBUTION_CLEARED,
    collect_epss,
    parse_epss_api_payload,
)
from silastron_pulse.constants import EPSS_FAQ_URL, EPSS_USAGE_AGREEMENT_URL
from silastron_pulse.errors import ValidationError
from tests.support import load_fixture_json


class EpssAdapterTests(unittest.TestCase):
    def test_production_collection_is_disabled(self) -> None:
        self.assertFalse(REDISTRIBUTION_CLEARED)
        result = collect_epss(["CVE-2099-0001"], enabled=True)
        self.assertEqual(result.meta.status, "disabled")
        self.assertIn("redistribution", (result.meta.error or "").lower())
        self.assertEqual(result.records, {})

    def test_parser_accepts_valid_fixture_without_enabling_publish(self) -> None:
        record = parse_epss_api_payload(load_fixture_json("epss_valid.json"), "CVE-2099-0001")
        self.assertEqual(record.score, 0.1234)
        self.assertEqual(record.cve_id, "CVE-2099-0001")

    def test_parser_rejects_wrong_cve(self) -> None:
        with self.assertRaises(ValidationError):
            parse_epss_api_payload(load_fixture_json("epss_valid.json"), "CVE-2099-0002")

    def test_parser_rejects_out_of_range_scores(self) -> None:
        payload = {
            "data": [
                {
                    "cve": "CVE-2099-0001",
                    "epss": "1.2",
                    "percentile": "0.1",
                    "date": "2099-01-01",
                }
            ]
        }
        with self.assertRaises(ValidationError):
            parse_epss_api_payload(payload, "CVE-2099-0001")

    def test_blocker_is_explicit(self) -> None:
        self.assertFalse(REDISTRIBUTION_CLEARED)
        self.assertEqual(EPSS_USAGE_AGREEMENT_URL, EPSS_FAQ_URL)
        self.assertEqual(EPSS_FAQ_URL, "https://www.first.org/epss/faq")
        self.assertIn(EPSS_FAQ_URL, EPSS_BLOCKER)
        self.assertNotIn("#Usage-Agreement", EPSS_BLOCKER)
        self.assertNotIn("Usage Agreement with requested attribution", EPSS_BLOCKER)


if __name__ == "__main__":
    unittest.main()
