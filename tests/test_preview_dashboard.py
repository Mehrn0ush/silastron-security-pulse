from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PreviewDashboardTests(unittest.TestCase):
    def test_dashboard_prioritizes_overview_and_hides_first_snapshot_diff(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertLess(html.find('id="overview"'), html.find('id="recent"'))
        self.assertLess(html.find('id="recent"'), html.find('id="catalog"'))
        self.assertLess(html.find('id="catalog"'), html.find('id="provenance"'))
        self.assertIn("Recently Added to CISA KEV", html)
        self.assertIn("Data provenance and methodology", html)
        self.assertIn("Load published catalog", html)
        self.assertIn('id="recent-change-col" hidden', html)
        self.assertIn("data/latest.json", js)
        self.assertIn("changes_available", js)
        self.assertIn("Disabled is not a zero probability", js)
        self.assertIn("KEV added is the CISA date_added", js)
        self.assertIn("credentials: \"same-origin\"", js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("composite_risk_score", js)
        self.assertNotIn("gtag(", js)
        self.assertNotIn("analytics", js.lower())

    def test_csp_still_forbids_third_party_and_form_actions(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        self.assertIn("form-action 'none'", html)
        self.assertIn("connect-src 'self'", html)
        self.assertIn("frame-ancestors 'none'", html)
        self.assertNotIn("cdn.", html)

    def test_dashboard_reads_summary_fields_without_inventing_scores(self) -> None:
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        for field in (
            "complete_records",
            "partial_records",
            "unavailable_records",
            "record_count",
            "epss_enabled",
            "snapshot_generated_at",
        ):
            self.assertIn(field, js)
        self.assertIn('epssLabel', js)
        self.assertIn('return "Disabled"', js)


if __name__ == "__main__":
    unittest.main()
