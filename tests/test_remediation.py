from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.cve import parse_cve_record
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.models import CveRecord, KevRecord
from silastron_pulse.pipeline import collect
from silastron_pulse.remediation import assemble_remediation
from silastron_pulse.sanitize import sanitize_public_https_url
from silastron_pulse.validate import validate_snapshot
from tests.support import fixture_bytes, frozen_clock, test_config, valid_fetcher


def _kev(**overrides: object) -> KevRecord:
    payload = {
        "cve_id": "CVE-2099-0001",
        "vendor_project": "Fixture Vendor",
        "product": "Fixture Product",
        "vulnerability_name": "TEST",
        "date_added": "2099-01-01",
        "short_description": "fixture",
        "required_action": "Apply updates per vendor instructions.",
        "due_date": "2099-01-15",
        "known_ransomware_campaign_use": None,
        "forensic_triage": None,
        "notes": None,
        "cwes": [],
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "record_sha256": "abc",
    }
    payload.update(overrides)
    return KevRecord(**payload)  # type: ignore[arg-type]


class RemediationProvenanceTests(unittest.TestCase):
    def test_cna_solutions_workarounds_and_vendor_advisories_keep_source_labels(self) -> None:
        raw = fixture_bytes("cve_2099_0001_remediation.json")
        record = parse_cve_record(
            json.loads(raw),
            expected_cve_id="CVE-2099-0001",
            raw=raw,
            source_url=cvelist_v5_raw_url("CVE-2099-0001"),
            config=test_config(Path(tempfile.mkdtemp())),
        )
        kinds = {(item.kind, item.source, item.attribution) for item in record.remediation_items}
        self.assertIn(
            ("verified_fix", "cve_list_v5", "CVE List V5 CNA solutions"),
            kinds,
        )
        self.assertIn(
            ("mitigation", "cve_list_v5", "CVE List V5 CNA workarounds"),
            kinds,
        )
        self.assertIn(
            ("reference", "cve_list_v5", "CVE List V5 CNA reference"),
            kinds,
        )
        self.assertNotIn(
            ("reference", "cve_list_v5", "CVE List V5 CNA vendor-advisory"),
            kinds,
        )
        advisory = next(
            item
            for item in record.remediation_items
            if item.attribution == "CVE List V5 CNA reference"
        )
        self.assertEqual(advisory.kind, "reference")
        self.assertIsNone(advisory.text)
        self.assertEqual(advisory.url, "https://vendor.example/security/CVE-2099-0001")
        self.assertNotIn("official", advisory.attribution.lower())
        self.assertNotIn("vendor-advisory", advisory.attribution.lower())
        urls = {item.url for item in record.remediation_items if item.url}
        self.assertNotIn("javascript:alert(1)", urls)
        self.assertNotIn("https://research.example/writeup", urls)
        self.assertNotIn("https://third-party.example/advisory", urls)
        self.assertNotIn("https://cisa.gov.evil.example/advisory", urls)
        self.assertNotIn("https://xn--80ak6aa92e.com/advisory", urls)
        self.assertNotIn("https://user:pass@vendor.example/steal", urls)
        self.assertNotIn("https://0x7f.0x00.0x00.0x01/advisory", urls)

    def test_cna_tag_and_url_title_are_not_verified_or_official(self) -> None:
        payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2099-0001", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Apply the official vendor patch 3.2.1 immediately.",
                        }
                    ],
                    "references": [
                        {
                            "url": "https://untrusted.example/advisory",
                            "name": "Official vendor advisory — fixed in 3.2.1",
                            "tags": ["vendor-advisory"],
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
            config=test_config(Path(tempfile.mkdtemp())),
        )
        kinds = {item.kind for item in record.remediation_items}
        self.assertEqual(kinds, {"reference"})
        item = record.remediation_items[0]
        self.assertEqual(item.attribution, "CVE List V5 CNA reference")
        self.assertIsNone(item.text)
        self.assertEqual(item.url, "https://untrusted.example/advisory")
        self.assertNotIn("official", " ".join(item.attribution.lower() for item in record.remediation_items))
        self.assertNotIn("verified_fix", kinds)
        self.assertNotIn("mitigation", kinds)

    def test_cvss_affected_ranges_and_descriptions_are_not_verified_fixes(self) -> None:
        raw = fixture_bytes("cve_2099_0001_remediation.json")
        record = parse_cve_record(
            json.loads(raw),
            expected_cve_id="CVE-2099-0001",
            raw=raw,
            source_url=cvelist_v5_raw_url("CVE-2099-0001"),
            config=test_config(Path(tempfile.mkdtemp())),
        )
        self.assertEqual(record.severity.base_score, 9.8)  # type: ignore[union-attr]
        self.assertIn("Fixed in 9.9.9", record.description or "")
        self.assertEqual(record.products[0].versions, ["affected 1.0 1.1"])
        inferred = [
            item
            for item in record.remediation_items
            if item.kind == "verified_fix" and "9.9.9" in (item.text or "")
        ]
        self.assertEqual(inferred, [])
        range_fixes = [
            item
            for item in record.remediation_items
            if item.kind == "verified_fix" and "1.1" in (item.text or "")
        ]
        self.assertEqual(range_fixes, [])

    def test_missing_evidence_is_unavailable(self) -> None:
        cve = CveRecord(
            cve_id="CVE-2099-0001",
            state="PUBLISHED",
            data_version="5.1",
            date_published=None,
            date_updated=None,
            assigner_short_name=None,
            title=None,
            description="Apply vendor patch 3.2.1 immediately.",
            severity=None,
            products=[],
            source_url="",
            record_page_url="",
            record_sha256="",
            status="ok",
        )
        kev = _kev(required_action="", notes=None)
        object.__setattr__(kev, "required_action", "")
        payload = assemble_remediation(kev=kev, cve=cve)
        self.assertEqual(payload["status"], "unavailable")
        self.assertEqual(payload["items"], [])

    def test_kev_required_action_is_not_a_verified_fix(self) -> None:
        cve = CveRecord(
            cve_id="CVE-2099-0001",
            state="PUBLISHED",
            data_version="5.1",
            date_published=None,
            date_updated=None,
            assigner_short_name=None,
            title=None,
            description=None,
            severity=None,
            products=[],
            source_url="",
            record_page_url="",
            record_sha256="",
        )
        payload = assemble_remediation(
            kev=_kev(
                required_action="Apply updates per vendor instructions at https://vendor.example/fix",
                notes="See https://www.cisa.gov/news-events/alerts/2099/01/01",
            ),
            cve=cve,
        )
        self.assertEqual(payload["status"], "available")
        kinds = [item["kind"] for item in payload["items"]]
        self.assertIn("required_action", kinds)
        self.assertNotIn("verified_fix", kinds)
        self.assertIn("reference", kinds)
        action = payload["items"][0]
        self.assertEqual(action["attribution"], "CISA KEV requiredAction")
        notes = next(item for item in payload["items"] if item["attribution"] == "CISA KEV notes")
        self.assertEqual(notes["kind"], "reference")
        self.assertIn("classification hints", payload["note"])

    def test_collected_snapshot_includes_optional_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
            assert result.snapshot is not None
            validate_snapshot(result.snapshot)
            record = result.snapshot["records"][0]
            self.assertEqual(record["remediation"]["status"], "available")
            self.assertEqual(record["remediation"]["items"][0]["kind"], "required_action")
            self.assertEqual(record["cve"]["remediation_items"], [])


class RemediationUrlSafetyTests(unittest.TestCase):
    def test_display_sanitizer_rejects_private_and_script_urls(self) -> None:
        for url in [
            "javascript:alert(1)",
            "http://vendor.example/advisory",
            "https://127.0.0.1/advisory",
            "https://localhost/advisory",
            "https://user:pass@vendor.example/advisory",
            "https://vendor.example:8443/advisory",
            "https://vendor.example/advisory#xss",
        ]:
            with self.subTest(url=url):
                self.assertIsNone(sanitize_public_https_url(url))
        self.assertEqual(
            sanitize_public_https_url("https://vendor.example/security/CVE-2099-0001"),
            "https://vendor.example/security/CVE-2099-0001",
        )


if __name__ == "__main__":
    unittest.main()
