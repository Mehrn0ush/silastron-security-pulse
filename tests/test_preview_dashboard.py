from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PreviewDashboardTests(unittest.TestCase):
    def test_dashboard_prioritizes_overview_and_hides_first_snapshot_diff(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertLess(html.find('id="overview"'), html.find('id="changes"'))
        self.assertLess(html.find('id="changes"'), html.find('id="recent"'))
        self.assertLess(html.find('id="recent"'), html.find('id="catalog"'))
        self.assertLess(html.find('id="catalog"'), html.find('id="provenance"'))
        self.assertIn("Recently Added to CISA KEV", html)
        self.assertIn("What's Changed", html)
        self.assertIn("Vulnerability explorer", html)
        self.assertIn("Data provenance and methodology", html)
        self.assertIn("Load published catalog", html)
        self.assertIn('id="recent-change-col" hidden', html)
        self.assertIn("data/latest.json", js)
        self.assertIn("changes_available", js)
        self.assertIn("publication_comparison", js)
        self.assertIn("No comparison available", js)
        self.assertIn("Baseline unavailable", js)
        self.assertIn("Disabled is not a zero probability", js)
        self.assertIn("KEV added is the CISA date_added", js)
        self.assertIn("credentials: \"same-origin\"", js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("composite_risk_score", js)
        self.assertNotIn("gtag(", js)
        self.assertNotIn("analytics", js.lower())
        self.assertNotIn("preview.changes || []", js)

    def test_dashboard_keeps_recent_kev_separate_from_published_diff(self) -> None:
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertIn("recent_kev_additions", js)
        self.assertIn("slice(0, RECENT_LIMIT)", js)
        self.assertIn("Published-to-published comparison", js)
        self.assertIn("Collect-time candidate diffs are not shown here", js)
        self.assertIn("Newly extracted remediation is not counted", js)
        self.assertIn("catalog-cvss", js)
        self.assertIn("cvssMatches", js)
        self.assertIn("buildRecordDetails", js)
        self.assertIn("textContent", js)
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="catalog-cvss"', html)
        self.assertIn('id="technical-details"', html)
        self.assertIn("No composite risk score", html)

    def test_dashboard_overview_uses_published_counts_only(self) -> None:
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertIn("Known Exploited CVEs", js)
        self.assertIn("New in KEV", js)
        self.assertIn("Updated Records", js)
        self.assertIn("Published Data Freshness", js)
        self.assertIn("comparisonCount", js)
        self.assertIn("classifyPublishedComparison", js)
        self.assertIn("This is not zero new entries", js)
        self.assertIn("Publication ", js)
        self.assertIn("Newly extracted remediation is counted separately", js)
        self.assertNotIn("Not applicable", js)

    def test_explorer_stays_lazy_and_filterable(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="catalog-query"', html)
        self.assertIn('id="catalog-completeness"', html)
        self.assertIn('id="catalog-cvss"', html)
        self.assertIn('id="catalog-sort"', html)
        self.assertIn("Critical (9.0–10.0)", html)
        self.assertIn('addEventListener("click", loadCatalog)', js)
        self.assertNotIn("loadCatalog();", js.replace("function loadCatalog()", ""))
        self.assertIn("rowMatches", js)
        self.assertIn("cvssMatches", js)
        self.assertIn("buildRecordDetails", js)
        self.assertIn("short_description", js)
        self.assertIn("Record details", js)
        self.assertIn("buildRemediation", js)
        self.assertIn("No verified remediation data", js)
        self.assertIn('verified_fix: "CNA-Reported Solution"', js)
        self.assertNotIn("Verified Fix", js)
        self.assertIn("fallbackRemediation", js)
        self.assertIn("safePublicHttpsUrl", js)
        self.assertNotIn("loadCatalog();", js.replace("function loadCatalog()", ""))

    def test_accessibility_and_responsive_hooks(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "preview" / "styles.css").read_text(encoding="utf-8")
        self.assertIn('name="viewport"', html)
        self.assertIn('href="#main"', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn("<details id=\"technical-details\">", html)
        self.assertIn("<summary>Technical details</summary>", html)
        self.assertIn("@media (max-width: 40rem)", css)
        self.assertIn("prefers-reduced-motion", css)
        self.assertIn(":focus-visible", css)
        self.assertNotIn("onclick=", html)
        self.assertNotIn('style="', html)

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
