"""Explorer filters, pagination, and CSV export."""

from __future__ import annotations

import unittest
from pathlib import Path

from silastron_pulse.catalog_query import apply_catalog_filters, paginate, unique_cwes, unique_values
from silastron_pulse.csv_export import CSV_COLUMNS, export_rows, sanitize_csv_cell

ROOT = Path(__file__).resolve().parents[1]


def _row(**overrides: object) -> dict:
    row = {
        "cve_id": "CVE-2099-0001",
        "vendor_project": "Fixture Vendor",
        "product": "Fixture Product",
        "vulnerability_name": "Sample one",
        "kev_date_added": "2099-01-01",
        "due_date": "2099-01-15",
        "cwes": ["CWE-79"],
        "completeness": "complete",
        "cvss_base_score": 9.1,
        "severity_status": "available",
        "cvss_vector": "CVSS:3.1/AV:N",
        "cve_state": "PUBLISHED",
        "cve_description": "Synthetic fixture",
        "truncated_fields": [],
        "omitted_version_count": 0,
        "omitted_product_count": 0,
        "remediation": {
            "status": "available",
            "items": [{"kind": "required_action", "text": "Patch"}],
        },
        "remediation_kinds": ["required_action"],
        "links": {
            "kev_catalog": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "cve_record": "https://www.cve.org/CVERecord?id=CVE-2099-0001",
        },
    }
    row.update(overrides)
    return row


class ExplorerExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [
            _row(),
            _row(
                cve_id="CVE-2099-0002",
                vendor_project="Other Vendor",
                product="Other Product",
                kev_date_added="2099-01-02",
                cwes=["CWE-89"],
                completeness="partial",
                cvss_base_score=5.0,
                cve_description="Second fixture",
                remediation={"status": "unavailable", "items": []},
                remediation_kinds=[],
            ),
            _row(
                cve_id="CVE-2099-0003",
                vendor_project="Fixture Vendor",
                product="Other Product",
                kev_date_added="2099-01-03",
                cwes=[],
                completeness="unavailable",
                cvss_base_score=None,
                severity_status="unavailable",
                remediation={"status": "available", "items": [{"kind": "verified_fix"}]},
                remediation_kinds=["verified_fix"],
            ),
        ]

    def test_combined_filters(self) -> None:
        matched = apply_catalog_filters(
            self.rows,
            {
                "vendor": "Fixture Vendor",
                "product": "Fixture Product",
                "date_from": "2099-01-01",
                "date_to": "2099-01-01",
                "cvss_min": 9,
                "cvss_max": 10,
                "cwe": "CWE-79",
                "completeness": "complete",
                "remediation": "required_action",
                "query": "fixture",
                "sort": "cve_id",
            },
        )
        self.assertEqual([row["cve_id"] for row in matched], ["CVE-2099-0001"])

    def test_missing_data_is_not_zero(self) -> None:
        matched = apply_catalog_filters(self.rows, {"cvss": "unavailable", "cwe": "unavailable"})
        self.assertEqual([row["cve_id"] for row in matched], ["CVE-2099-0003"])
        self.assertIsNone(matched[0]["cvss_base_score"])
        self.assertEqual(matched[0]["cwes"], [])

    def test_sorting_and_pagination(self) -> None:
        sorted_rows = apply_catalog_filters(self.rows, {"sort": "kev_date_added"})
        self.assertEqual(sorted_rows[0]["cve_id"], "CVE-2099-0003")
        page = paginate(sorted_rows, page=0, page_size=2)
        self.assertEqual(page["total"], 3)
        self.assertEqual(len(page["rows"]), 2)
        self.assertEqual(page["end"], 2)
        page_two = paginate(sorted_rows, page=1, page_size=2)
        self.assertEqual(len(page_two["rows"]), 1)

    def test_large_catalog_stays_in_memory(self) -> None:
        rows = [_row(cve_id=f"CVE-2099-{index:04d}", vendor_project=f"V{index % 7}") for index in range(3000)]
        matched = apply_catalog_filters(rows, {"vendor": "V1", "query": "2099", "sort": "cve_id"})
        self.assertGreater(len(matched), 400)
        self.assertLess(len(matched), 500)
        self.assertTrue(all(row["vendor_project"] == "V1" for row in matched))
        self.assertEqual(unique_values(rows, "vendor_project")[0], "V0")
        self.assertIn("CWE-79", unique_cwes(self.rows))

    def test_csv_exports_filtered_set_not_page(self) -> None:
        matched = apply_catalog_filters(self.rows, {"vendor": "Fixture Vendor"})
        csv_text = export_rows(
            matched,
            snapshot_id="snap-1",
            snapshot_generated_at="2099-01-10T12:00:00Z",
        )
        self.assertIn("CVE-2099-0001", csv_text)
        self.assertIn("CVE-2099-0003", csv_text)
        self.assertNotIn("CVE-2099-0002", csv_text)
        self.assertNotIn("epss", csv_text.lower())
        self.assertTrue(csv_text.startswith(",".join(CSV_COLUMNS)))
        self.assertIn("snap-1", csv_text)
        self.assertIn("unavailable", csv_text)

    def test_csv_formula_injection_and_quoting(self) -> None:
        self.assertEqual(sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(sanitize_csv_cell("+cmd"), "'+cmd")
        self.assertEqual(sanitize_csv_cell("-2"), "'-2")
        self.assertEqual(sanitize_csv_cell("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(sanitize_csv_cell("\tTAB"), "'\tTAB")
        quoted = export_rows(
            [
                _row(
                    vendor_project='Vendor, "Inc"',
                    short_description="line1\nline2",
                    vulnerability_name="=HYPERLINK()",
                    cve_description="café",
                )
            ],
            snapshot_id="snap",
            snapshot_generated_at="2099-01-10T12:00:00Z",
        )
        self.assertIn("\"Vendor, \"\"Inc\"\"\"", quoted)
        self.assertIn("'=HYPERLINK()", quoted)
        self.assertIn("café", quoted)
        self.assertIn("line1\nline2", quoted)

    def test_frontend_contains_filters_export_and_a11y_hooks(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        css = (ROOT / "preview" / "styles.css").read_text(encoding="utf-8")
        for element_id in (
            "catalog-vendor",
            "catalog-product",
            "catalog-date-from",
            "catalog-date-to",
            "catalog-cvss-min",
            "catalog-cvss-max",
            "catalog-cwe",
            "catalog-remediation",
            "catalog-cvss-version",
            "catalog-attack-vector",
            "catalog-nvd",
            "catalog-fixed-version",
            "catalog-clear",
            "catalog-export",
        ):
            self.assertIn(f'id="{element_id}"', html)
        self.assertIn("exportFilteredCsv", js)
        self.assertIn("#cve/", js)
        self.assertIn("renderCveDetail", js)
        self.assertIn("sanitizeCsvCell", js)
        self.assertIn("CSV_FORMULA_PREFIXES", js)
        self.assertIn("buildCveHistory", js)
        self.assertIn("data/history/cves/", js)
        self.assertIn("publication-status.json", js)
        self.assertIn("Clear filters", html)
        self.assertIn("Export filtered CSV", html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn("@media (max-width: 40rem)", css)
        self.assertIn("html[data-theme=\"light\"]", css)
        self.assertIn("html[data-theme=\"dark\"]", css)
        self.assertIn("html[data-theme=\"system\"]", css)
        self.assertNotIn("gtag(", js)
        self.assertNotIn("epss_score", js[js.find("CSV_COLUMNS") : js.find("CSV_COLUMNS") + 800] if "CSV_COLUMNS" in js else "")
        self.assertNotIn("innerHTML", js)


if __name__ == "__main__":
    unittest.main()
