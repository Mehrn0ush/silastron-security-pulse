"""Minimal static per-CVE pages: escaping, provenance, sitemap, cleanup."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.catalog_index import build_cve_detail
from silastron_pulse.pipeline import collect
from silastron_pulse.static_pages import build_static_cve_pages, render_cve_page
from silastron_pulse.store import promote_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher

BASE = "https://pulse.silastron.com"


def _snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        result = collect(config=test_config(Path(tmp)), fetcher=valid_fetcher(), clock=frozen_clock())
    assert result.snapshot is not None
    return result.snapshot


class RenderCvePageTests(unittest.TestCase):
    def test_renders_facts_sources_and_explorer_link(self) -> None:
        record = _snapshot()["records"][0]
        entry = build_cve_detail(record)
        html_text = render_cve_page(entry, base_url=BASE)
        self.assertIn(record["cve_id"], html_text)
        self.assertIn(f'<link rel="canonical" href="{BASE}/cve/{record["cve_id"]}/">', html_text)
        self.assertIn(f'href="/#cve/{record["cve_id"]}"', html_text)
        self.assertIn("Sources and provenance", html_text)
        self.assertIn("application/ld+json", html_text)
        self.assertIn("no composite risk score", html_text)
        self.assertNotIn("composite_risk_score", html_text)

    def test_untrusted_text_is_html_escaped_everywhere(self) -> None:
        record = dict(_snapshot()["records"][0])
        record = json.loads(json.dumps(record))
        record["kev"] = {**record["kev"], "short_description": '<img src=x onerror=alert(1)>&"\''}
        record["cve"] = {**record["cve"], "description": "<script>alert(2)</script>"}
        entry = build_cve_detail(record)
        html_text = render_cve_page(entry, base_url=BASE)
        self.assertNotIn("<img src=x", html_text)
        self.assertNotIn("<script>alert(2)</script>", html_text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_text)

    def test_json_ld_is_safe_against_script_breakout(self) -> None:
        record = dict(_snapshot()["records"][0])
        record = json.loads(json.dumps(record))
        # short_description (KEV) takes priority over cve_description; clear
        # it so this test actually exercises the cve_description fallback.
        record["kev"] = {**record["kev"], "short_description": None}
        record["cve"] = {**record["cve"], "description": "</script><script>alert(3)</script>"}
        entry = build_cve_detail(record)
        html_text = render_cve_page(entry, base_url=BASE)
        self.assertNotIn("</script><script>alert(3)</script>", html_text)
        self.assertIn("\\u003c/script\\u003e", html_text)

    def test_csp_script_hash_matches_the_actual_inline_script(self) -> None:
        record = _snapshot()["records"][0]
        entry = build_cve_detail(record)
        html_text = render_cve_page(entry, base_url=BASE)
        start = html_text.index('<script type="application/ld+json">') + len(
            '<script type="application/ld+json">'
        )
        end = html_text.index("</script>", start)
        script_body = html_text[start:end]
        digest = base64.b64encode(hashlib.sha256(script_body.encode("utf-8")).digest()).decode("ascii")
        self.assertIn(f"'sha256-{digest}'", html_text)

    def test_missing_cvss_and_remediation_are_explicit_not_blank(self) -> None:
        record = dict(_snapshot()["records"][0])
        record = json.loads(json.dumps(record))
        record["cve"]["severity"] = None
        record["remediation"] = {"status": "unavailable", "items": []}
        entry = build_cve_detail(record)
        html_text = render_cve_page(entry, base_url=BASE)
        self.assertIn('class="unavailable">unavailable</td>', html_text)

    def test_refuses_an_unsafe_cve_id(self) -> None:
        with self.assertRaises(ValueError):
            render_cve_page({"cve_id": "CVE-2099-0001/../evil"}, base_url=BASE)


class BuildStaticCvePagesTests(unittest.TestCase):
    def _published(self, tmp: Path) -> Path:
        snapshot = _snapshot()
        published = tmp / "published"
        promote_snapshot(
            snapshot,
            published,
            now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=8_000_000,
            max_depth=32,
        )
        return published, snapshot

    def test_writes_one_page_per_cve_plus_css_and_sitemap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            published, snapshot = self._published(tmp)
            site = tmp / "site"
            count = build_static_cve_pages(published_dir=published, site_dir=site, base_url=BASE)
            ids = {r["cve_id"] for r in snapshot["records"]}
            self.assertEqual(count, len(ids))
            for cve_id in ids:
                self.assertTrue((site / "cve" / cve_id / "index.html").is_file())
            self.assertTrue((site / "cve-page.css").is_file())
            sitemap = (site / "sitemap.xml").read_text()
            self.assertEqual(sitemap.count("<loc>"), len(ids) + 1)
            self.assertIn(f"<loc>{BASE}/</loc>", sitemap)
            robots = (site / "robots.txt").read_text()
            self.assertIn(f"Sitemap: {BASE}/sitemap.xml", robots)
            self.assertNotIn("Disallow: /", robots)

    def test_a_removed_cve_loses_its_static_page(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            published, snapshot = self._published(tmp)
            site = tmp / "site"
            build_static_cve_pages(published_dir=published, site_dir=site, base_url=BASE)
            removed_id = snapshot["records"][0]["cve_id"]
            self.assertTrue((site / "cve" / removed_id).exists())

            shrunk = dict(snapshot)
            shrunk["records"] = [r for r in snapshot["records"] if r["cve_id"] != removed_id]
            shrunk["snapshot_id"] = snapshot["snapshot_id"] + "x"
            shrunk["generated_at"] = "2099-01-11T00:00:00Z"
            from silastron_pulse.validate import validate_snapshot

            validate_snapshot(shrunk)
            promote_snapshot(
                shrunk,
                published,
                now=datetime(2099, 1, 11, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=8_000_000,
                max_depth=32,
            )
            build_static_cve_pages(published_dir=published, site_dir=site, base_url=BASE)
            self.assertFalse((site / "cve" / removed_id).exists())

    def test_rerun_is_idempotent_and_does_not_duplicate_sitemap_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            published, snapshot = self._published(tmp)
            site = tmp / "site"
            build_static_cve_pages(published_dir=published, site_dir=site, base_url=BASE)
            build_static_cve_pages(published_dir=published, site_dir=site, base_url=BASE)
            sitemap = (site / "sitemap.xml").read_text()
            self.assertEqual(sitemap.count("<loc>"), len(snapshot["records"]) + 1)

    def test_missing_catalog_index_raises_instead_of_silently_building_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                build_static_cve_pages(
                    published_dir=tmp / "nothing-here", site_dir=tmp / "site", base_url=BASE
                )


if __name__ == "__main__":
    unittest.main()
