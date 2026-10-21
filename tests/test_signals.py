from __future__ import annotations

import unittest

from silastron_pulse.models import CveRecord, EpssRecord, KevRecord
from silastron_pulse.signals import build_signals


def _kev() -> KevRecord:
    return KevRecord(
        cve_id="CVE-2099-0001",
        vendor_project="Fixture Vendor",
        product="Fixture Product",
        vulnerability_name="TEST",
        date_added="2099-01-01",
        short_description="fixture",
        required_action="none",
        due_date="2099-01-15",
        known_ransomware_campaign_use=None,
        forensic_triage=None,
        notes=None,
        cwes=[],
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        record_sha256="abc",
    )


def _cve() -> CveRecord:
    return CveRecord(
        cve_id="CVE-2099-0001",
        state="PUBLISHED",
        data_version="5.1",
        date_published="2099-01-01T00:00:00Z",
        date_updated="2099-01-02T00:00:00Z",
        assigner_short_name="fixture",
        title="TEST",
        description="fixture",
        severity=None,
        products=[],
        source_url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2099/0xxx/CVE-2099-0001.json",
        record_page_url="https://www.cve.org/CVERecord?id=CVE-2099-0001",
        record_sha256="def",
    )


class SignalTests(unittest.TestCase):
    def test_signals_remain_distinct(self) -> None:
        epss = EpssRecord(status="unavailable", cve_id="CVE-2099-0001", notes="disabled")
        signals = build_signals(_kev(), _cve(), epss).to_dict()
        self.assertTrue(signals["confirmed_exploitation"]["value"])
        self.assertIsNone(signals["estimated_exploitation_probability"]["value"])
        self.assertEqual(signals["vulnerability_severity"]["status"], "unavailable")
        self.assertEqual(signals["deployment_exposure"]["status"], "not_assessed")
        self.assertIsNone(signals["composite_risk_score"])

    def test_epss_is_never_treated_as_confirmation(self) -> None:
        epss = EpssRecord(
            status="ok",
            cve_id="CVE-2099-0001",
            score=0.99,
            percentile=0.99,
            score_date="2099-01-01",
        )
        signals = build_signals(_kev(), _cve(), epss).to_dict()
        self.assertEqual(signals["estimated_exploitation_probability"]["status"], "estimated")
        self.assertNotEqual(
            signals["confirmed_exploitation"]["basis"],
            signals["estimated_exploitation_probability"]["basis"],
        )


if __name__ == "__main__":
    unittest.main()
