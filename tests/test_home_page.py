"""Pre-rendered home sections: status wording, escaping, and failure modes."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.home_page import (
    build_home_page,
    fill_template,
    format_age,
    format_count,
    format_instant,
    render_sections,
)
from silastron_pulse.methodology_page import build_methodology_page

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(1)>"\'&‮evil'


def manifest(**over):
    return {
        "status": "ok", "snapshot_id": "s1", "schema_version": "1.0.0", "record_count": 1773,
        "snapshot_generated_at": "2026-11-12T16:00:00Z", "generated_at": "2026-11-12T16:10:00Z",
        "stale_after_hours": 36, **over,
    }


def verification(**over):
    return {
        "kind": "verification_status", "schema_version": "1.0.0", "verified": True,
        "verification_state": "verified", "verified_at": "2026-11-13T08:00:00Z",
        "kev": {"status": "ok", "content_sha256": "a" * 64, "retrieved_at": "2026-11-13T08:00:00Z", "validated": True},
        "cve": {"status": "ok", "validated": True}, "nvd": {"status": "degraded", "validated": False},
        "publication_decision": "publish", **over,
    }


def row(**over):
    return {
        "cve_id": "CVE-2026-0001", "vendor_project": "Acme", "product": "Widget", "kev_date_added": "2026-11-01",
        "completeness": "complete", "severity_status": "available", "cvss_base_score": 9.8,
        "epss_status": "disabled", "epss_score": None,
        "links": {"cve_record": "https://www.cve.org/CVERecord?id=CVE-2026-0001"}, **over,
    }


def preview(rows=None, comparison=None, **over):
    return {
        "status": "ok", "schema_version": "1.0.0", "summary": {"epss_enabled": False},
        "sources": {"epss": {"status": "disabled"}, "kev": {}, "cve": {}},
        "recent_kev_additions": rows if rows is not None else [row()],
        "publication_comparison": comparison, **over,
    }


def sections(**kw):
    args = {"manifest": manifest(), "preview": preview(), "publication_status": {"state": "consistent"},
            "verification": verification(), "now": NOW}
    args.update(kw)
    return render_sections(**args)


class HostileInputTests(unittest.TestCase):
    def test_upstream_text_is_escaped_everywhere(self) -> None:
        comparison = {
            "available": True, "added_count": 1, "removed_count": 0, "updated_count": 1, "enrichment_count": 0,
            "compared_to_snapshot_id": HOSTILE, "compared_to_generated_at": HOSTILE, "truncated": False,
            "rows": [
                {"cve_id": HOSTILE, "categories": ["added_kev", HOSTILE], "links": {"nvd": "javascript:alert(1)"}},
                {"cve_id": "CVE-2026-0002", "categories": ["kev_update"], "changed_fields": ["product"],
                 "before": {"product": HOSTILE}, "after": {"product": "<b>x</b>"}},
            ],
        }
        out = sections(
            preview=preview(rows=[row(vendor_project=HOSTILE, product=HOSTILE, vulnerability_name=HOSTILE,
                                       cve_id=HOSTILE, links={"cve_record": "javascript:alert(1)", "nvd": HOSTILE})],
                            comparison=comparison),
            manifest=manifest(snapshot_id=HOSTILE),
        )
        blob = "".join(out.values())
        for needle in ("<script", "<img", 'href="javascript', "<b>x"):
            self.assertNotIn(needle, blob)
        self.assertIn("&lt;script&gt;", blob)

    def test_unsafe_links_are_dropped(self) -> None:
        out = sections(preview=preview(rows=[row(links={"cve_record": "http://www.cve.org/CVERecord?id=CVE-2026-0001",
                                                          "nvd": "https://evil.example/x"})]))
        self.assertNotIn("evil.example", out["recent-body"])
        self.assertNotIn("http://www.cve.org", out["recent-body"])
        self.assertIn("CVE record unavailable", out["recent-body"])

    def test_non_cve_ids_are_text_not_links(self) -> None:
        out = sections(preview=preview(rows=[row(cve_id="not-a-cve")]))
        self.assertNotIn('href="#cve/not-a-cve"', out["recent-body"])

    def test_very_long_and_non_string_values_do_not_break_rendering(self) -> None:
        out = sections(preview=preview(rows=[row(product="x" * 100_000, vendor_project=123, cvss_base_score="oops")]))
        self.assertIn("x" * 1000, out["recent-body"])


class StatusTests(unittest.TestCase):
    def banner(self, **kw) -> str:
        return sections(**kw)["status-banner"]

    def test_verified_is_ok(self) -> None:
        self.assertIn("banner ok", self.banner())
        self.assertIn("independently verified", sections()["data-status-summary"])

    def test_failed_attempt_after_verification(self) -> None:
        v = verification(last_attempt={"collect_run_id": "42", "conclusion": "failure",
                                       "attempted_at": "2026-11-13T09:00:00Z"})
        out = sections(verification=v)
        self.assertIn("Collection failed", out["status-banner"])
        self.assertIn("Collect run 42 failed", out["status-banner"])
        self.assertIn("Latest collection attempt", out["data-status-details"])

    def test_overdue(self) -> None:
        v = verification(verified_at="2026-11-01T00:00:00Z")
        self.assertIn("Verification overdue", self.banner(verification=v))

    def test_malformed_attempt_is_invalid_evidence(self) -> None:
        v = verification(last_attempt={"conclusion": "success"})
        self.assertIn("Verification evidence is invalid", sections(verification=v)["data-status-summary"])

    def test_missing_manifest(self) -> None:
        out = sections(manifest=None)
        self.assertIn("No published snapshot is available", out["status-banner"])
        self.assertIn("No comparison available", out["changes-body"])

    def test_unpublished_manifest(self) -> None:
        out = sections(manifest={"status": "unpublished"})
        self.assertIn("Publication is disabled", out["status-banner"])

    def test_invalid_timestamps(self) -> None:
        out = sections(manifest=manifest(snapshot_generated_at="not-a-date"))
        self.assertIn("timestamps are invalid", out["status-banner"])

    def test_failed_collection_banner(self) -> None:
        self.assertIn("Collection failed. No successful snapshot", self.banner(manifest=manifest(status="failed")))

    def test_inconsistent_publication_is_flagged(self) -> None:
        out = sections(publication_status={"state": "diverged", "classification": "x"})
        self.assertIn("Publication consistency problem", out["data-status-summary"])


class ComparisonTests(unittest.TestCase):
    def test_unavailable_is_not_zero(self) -> None:
        out = sections()
        self.assertIn("No comparison available", out["overview-cards"])
        self.assertIn("This is not zero new entries", out["overview-cards"])

    def test_counts_and_rows(self) -> None:
        comparison = {"available": True, "added_count": 1, "removed_count": 0, "updated_count": 0,
                      "enrichment_count": 0, "rows": [{"cve_id": "CVE-2026-0003", "categories": ["added_kev"]}]}
        out = sections(preview=preview(comparison=comparison))
        self.assertIn("Newly added KEV entries (1)", out["changes-body"])
        self.assertIn("CVE-2026-0003", out["changes-body"])

    def test_empty_comparison_says_no_changes(self) -> None:
        comparison = {"available": True, "added_count": 0, "removed_count": 0, "updated_count": 0,
                      "enrichment_count": 0, "rows": []}
        self.assertIn("No published-to-published record changes", sections(preview=preview(comparison=comparison))["changes-body"])


class EpssTests(unittest.TestCase):
    def test_epss_score_is_never_rendered_while_disabled(self) -> None:
        out = sections(preview=preview(rows=[row(epss_status="ok", epss_score=0.97)]))
        self.assertNotIn("0.97", out["recent-body"])
        self.assertNotIn("Estimated", out["recent-body"])
        self.assertIn("Disabled", out["recent-body"])


class FormattingTests(unittest.TestCase):
    def test_age_rounding_matches_script(self) -> None:
        self.assertEqual(format_age(0.5), "30 minutes")
        self.assertEqual(format_age(2.75), "2.8 hours")
        self.assertEqual(format_age(24.0), "24 hours")
        self.assertEqual(format_age(72.0), "3 days")
        self.assertEqual(format_age(None), "Unavailable")

    def test_instants_and_counts(self) -> None:
        self.assertEqual(format_instant("2026-11-12T16:00:00Z"), "2026-11-12 16:00:00 UTC")
        self.assertEqual(format_instant(None), "Unavailable")
        self.assertEqual(format_instant("garbage"), "garbage")
        self.assertEqual(format_count(1773), "1,773")
        self.assertEqual(format_count(None), "Unavailable")


class BuildTests(unittest.TestCase):
    def test_template_fill_fails_on_missing_or_unknown_slots(self) -> None:
        with self.assertRaises(ValueError):
            fill_template("<p><!--prerender:nope--></p>", {"a": "x"})
        with self.assertRaises(ValueError):
            fill_template("<p></p>", {"a": "x"})

    def test_build_writes_pages_without_leftover_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            pub, site = tmp / "pub", tmp / "site"
            pub.mkdir()
            site.mkdir()
            for name, doc in (("manifest", manifest()), ("preview", preview()),
                              ("publication-status", {"state": "consistent"}), ("verification-status", verification())):
                (pub / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")
            build_home_page(published_dir=pub, template_path=ROOT / "preview" / "index.html", site_dir=site, now=NOW)
            from silastron_pulse import page_chrome

            build_methodology_page(site, base_url="https://pulse.silastron.com",
                                   footer=page_chrome.footer(last_collected="x", last_published="y"))
            page = (site / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("prerender:", page)
            self.assertIn("2026-11-13 10:00:00 UTC", page)
            self.assertNotIn("JavaScript is required to render the published snapshot", page)
            method = (site / "methodology" / "index.html").read_text(encoding="utf-8")
            self.assertIn("EPSS is currently not published here", method)

    def test_build_survives_missing_documents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "pub").mkdir()
            (tmp / "site").mkdir()
            build_home_page(published_dir=tmp / "pub", template_path=ROOT / "preview" / "index.html",
                            site_dir=tmp / "site", now=NOW)
            self.assertIn("No published snapshot is available", (tmp / "site" / "index.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
