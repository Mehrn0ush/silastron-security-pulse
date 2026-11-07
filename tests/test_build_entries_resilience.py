"""A single malformed CVE must degrade its own record, never abort collection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from silastron_pulse import pipeline
from silastron_pulse.pipeline import _build_entries, collect
from silastron_pulse.signals import build_signals as _real_build_signals
from tests.support import frozen_clock, test_config, valid_fetcher


def _boom(kev, cve, epss):
    if kev.cve_id == "CVE-2099-0001":
        raise TypeError("'<' not supported between instances of 'dict' and 'dict'")
    return _real_build_signals(kev, cve, epss)


class BuildEntriesResilienceTests(unittest.TestCase):
    def test_one_bad_record_does_not_raise_and_is_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(pipeline, "build_signals", side_effect=_boom):
                result = collect(
                    config=test_config(Path(tmp)),
                    fetcher=valid_fetcher(),
                    clock=frozen_clock(),
                )
        # The run must complete, not raise and not report "failed".
        self.assertIn(result.status, {"ok", "degraded"})
        self.assertEqual(result.status, "degraded")
        assert result.snapshot is not None
        records = {r["cve_id"]: r for r in result.snapshot["records"]}
        self.assertEqual(set(records), {"CVE-2099-0001", "CVE-2099-0002"})

        bad = records["CVE-2099-0001"]
        # The underlying CVE/KEV data was extracted fine; only our own signal
        # computation failed, so record completeness is unaffected.
        self.assertEqual(bad["completeness"], "complete")
        self.assertNotIn("intelligence", bad)
        self.assertEqual(bad["signals"]["confirmed_exploitation"]["status"], "unavailable")
        self.assertIsNone(bad["signals"]["composite_risk_score"])
        self.assertIn("build failed", bad["signals"]["confirmed_exploitation"]["note"])

        good = records["CVE-2099-0002"]
        self.assertEqual(good["signals"]["confirmed_exploitation"]["status"], "confirmed_by_source")

        summary = result.snapshot["summary"]
        self.assertEqual(summary["entry_build_error_count"], 1)
        self.assertEqual(summary["entry_build_errors"][0]["cve_id"], "CVE-2099-0001")
        self.assertIn("TypeError", summary["entry_build_errors"][0]["error"])

    def test_build_entries_returns_errors_list_directly(self) -> None:
        from silastron_pulse.adapters.cve import enrich_cves
        from silastron_pulse.adapters.epss import collect_epss
        from silastron_pulse.adapters.kev import fetch_kev_catalog
        from silastron_pulse.adapters.nvd import collect_nvd
        from silastron_pulse.clock import parse_generated_at

        config = test_config(Path("."))
        fetcher = valid_fetcher()
        kev = fetch_kev_catalog(fetcher, config)
        cve = enrich_cves([r.cve_id for r in kev.records], fetcher, config)
        nvd = collect_nvd(
            [r.cve_id for r in kev.records],
            fetcher,
            config,
            now=parse_generated_at("2099-01-10T12:00:00Z"),
        )
        epss = collect_epss([r.cve_id for r in kev.records], enabled=False)

        with mock.patch.object(pipeline, "build_signals", side_effect=_boom):
            entries, errors = _build_entries(kev, cve, epss, nvd)

        self.assertEqual(set(entries), {"CVE-2099-0001", "CVE-2099-0002"})
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["cve_id"], "CVE-2099-0001")
        self.assertIsNone(entries["CVE-2099-0001"].intelligence)
        self.assertIsNotNone(entries["CVE-2099-0002"].intelligence)

    def test_all_records_failing_is_degraded_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                pipeline,
                "build_signals",
                side_effect=TypeError("boom"),
            ):
                result = collect(
                    config=test_config(Path(tmp)),
                    fetcher=valid_fetcher(),
                    clock=frozen_clock(),
                )
        self.assertEqual(result.status, "degraded")
        assert result.snapshot is not None
        self.assertEqual(result.snapshot["summary"]["entry_build_error_count"], 2)
        for record in result.snapshot["records"]:
            self.assertNotIn("intelligence", record)


class SerializationResilienceTests(unittest.TestCase):
    def test_to_dict_failure_is_isolated_and_does_not_abort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from silastron_pulse.models import PulseEntry

            real_to_dict = PulseEntry.to_dict

            def _boom_to_dict(self):
                if self.cve_id == "CVE-2099-0001":
                    raise ValueError("unexpected shape")
                return real_to_dict(self)

            with mock.patch.object(PulseEntry, "to_dict", _boom_to_dict):
                result = collect(
                    config=test_config(Path(tmp)),
                    fetcher=valid_fetcher(),
                    clock=frozen_clock(),
                )
        self.assertEqual(result.status, "degraded")
        assert result.snapshot is not None
        records = {r["cve_id"]: r for r in result.snapshot["records"]}
        self.assertEqual(set(records), {"CVE-2099-0001", "CVE-2099-0002"})
        bad = records["CVE-2099-0001"]
        self.assertEqual(bad["completeness"], "unavailable")
        self.assertEqual(bad["cve"]["status"], "failed")
        self.assertNotIn("intelligence", bad)
        good = records["CVE-2099-0002"]
        self.assertEqual(good["completeness"], "complete")
        summary = result.snapshot["summary"]
        self.assertEqual(summary["entry_build_error_count"], 1)
        self.assertIn("ValueError", summary["entry_build_errors"][0]["error"])


if __name__ == "__main__":
    unittest.main()
