"""CISA ADP (Vulnrichment) CVSS and SSVC copied from CVE List V5 records."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.cve import parse_cve_record
from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.intelligence import assemble_intelligence, extract_cisa_adp_assertions
from silastron_pulse.models import KevRecord
from silastron_pulse.pipeline import collect
from silastron_pulse.validate import _validate_intelligence
from tests.support import fixture_bytes, frozen_clock, test_config, valid_fetcher

LOG4J = "CVE-2021-44228"


def _kev() -> KevRecord:
    return KevRecord(
        cve_id=LOG4J,
        vendor_project="Apache",
        product="Log4j2",
        vulnerability_name="Log4Shell",
        date_added="2021-12-10",
        short_description="fixture",
        required_action="Apply updates",
        due_date="2021-12-24",
        known_ransomware_campaign_use="Known",
        forensic_triage=None,
        notes=None,
        cwes=[],
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        record_sha256="abc",
    )


def _parse(payload: dict):
    raw = json.dumps(payload).encode("utf-8")
    return parse_cve_record(
        payload,
        expected_cve_id=LOG4J,
        raw=raw,
        source_url=cvelist_v5_raw_url(LOG4J),
        config=test_config(Path(".")),
        retrieved_at="2026-11-07T00:00:00Z",
    )


def _log4j() -> dict:
    return json.loads(fixture_bytes("upstream/CVE-2021-44228.json"))


class CisaAdpTests(unittest.TestCase):
    def test_real_record_yields_attributed_cvss_and_ssvc(self) -> None:
        intel = assemble_intelligence(kev=_kev(), cve=_parse(_log4j()), nvd=None).to_dict()
        adp = intel["cisa_adp"]
        self.assertEqual(adp["status"], "available")
        self.assertEqual(adp["source_updated_at"], "2025-10-21T23:25:23.121Z")
        self.assertEqual(
            {k: adp["ssvc"][k] for k in ("exploitation", "automatable", "technical_impact")},
            {"exploitation": "active", "automatable": "yes", "technical_impact": "total"},
        )
        self.assertEqual(adp["ssvc"]["assessed_at"], "2025-02-04T14:25:34.416117Z")
        adp_cvss = [a for a in intel["cvss"]["assessments"] if a["source"] == "cisa_adp"]
        self.assertEqual(len(adp_cvss), 1)
        self.assertEqual(adp_cvss[0]["base_score"], 10.0)
        self.assertEqual(adp_cvss[0]["source_updated_at"], "2025-10-21T23:25:23.121Z")
        self.assertTrue(intel["coverage"]["has_ssvc"])
        self.assertNotIn("composite_risk_score", intel)
        _validate_intelligence(LOG4J, intel)

    def test_missing_adp_is_explicitly_unavailable(self) -> None:
        payload = _log4j()
        payload["containers"]["adp"] = [
            a for a in payload["containers"]["adp"] if a["providerMetadata"]["shortName"] != "CISA-ADP"
        ]
        intel = assemble_intelligence(kev=_kev(), cve=_parse(payload), nvd=None).to_dict()
        self.assertEqual(intel["cisa_adp"]["status"], "unavailable")
        self.assertIsNone(intel["cisa_adp"]["ssvc"])
        self.assertFalse(intel["coverage"]["has_ssvc"])
        self.assertFalse(any(a["source"] == "cisa_adp" for a in intel["cvss"]["assessments"]))

    def test_malformed_adp_degrades_without_raising(self) -> None:
        for adp in ("x", [None, {"providerMetadata": "x"}], [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"other": {"type": "ssvc", "content": {"options": ["bad", {"Unknown": "x"}]}}}, {"cvssV3_1": {"baseScore": "10"}}]}]):
            result = extract_cisa_adp_assertions({"adp": adp})
            self.assertIsNone(result["ssvc"])
            self.assertEqual(result["assessments"], [])

    def test_failed_cve_source_does_not_claim_adp_absence(self) -> None:
        cve = _parse(_log4j())
        from dataclasses import replace

        failed = replace(cve, status="failed", adp_assertions=None)
        intel = assemble_intelligence(kev=_kev(), cve=failed, nvd=None).to_dict()
        self.assertEqual(intel["cisa_adp"]["status"], "failed")
        self.assertIsNone(intel["cisa_adp"]["ssvc"])

    def test_validator_rejects_derived_ssvc_score(self) -> None:
        intel = assemble_intelligence(kev=_kev(), cve=_parse(_log4j()), nvd=None).to_dict()
        bad = copy.deepcopy(intel)
        bad["cisa_adp"]["ssvc"]["priority"] = "act"
        with self.assertRaises(ValidationError):
            _validate_intelligence(LOG4J, bad)
        bad = copy.deepcopy(intel)
        bad["cisa_adp"]["status"] = "unavailable"
        with self.assertRaises(ValidationError):
            _validate_intelligence(LOG4J, bad)

    def test_cache_without_adp_assertions_triggers_one_resync(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(config=test_config(root / "one"), fetcher=valid_fetcher(), clock=frozen_clock(), state_dir=root / "state")
            self.assertEqual(first.status, "ok")
            for path in (root / "state").rglob("records/CVE-*.json"):
                record = json.loads(path.read_text())
                record.pop("adp_assertions", None)
                path.write_text(json.dumps(record))
            second = collect(config=test_config(root / "two"), fetcher=valid_fetcher(), clock=frozen_clock(), state_dir=root / "state")
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["summary"]["cve_strategy"], "resync")
            third = collect(config=test_config(root / "three"), fetcher=valid_fetcher(), clock=frozen_clock(), state_dir=root / "state")
            assert third.snapshot is not None
            self.assertEqual(third.snapshot["summary"]["cve_strategy"], "unchanged")


if __name__ == "__main__":
    unittest.main()
