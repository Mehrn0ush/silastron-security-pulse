"""Sitemap, feeds, build.json, head tags, footer, budget and smoke test."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from silastron_pulse import page_chrome
from silastron_pulse.feeds import MAX_KEV_ENTRIES, build_feed, kev_entries
from silastron_pulse.home_page import build_home_page, footer_times
from silastron_pulse.methodology_page import (
    METHODOLOGY_BODY_SHA256,
    METHODOLOGY_REVISED,
    body_sha256,
    build_methodology_page,
)
from silastron_pulse.pipeline import collect
from silastron_pulse.site_budget import check_site_budget, load_budget
from silastron_pulse.site_files import MAX_SITEMAP_URLS, build_site_files, sitemap_xml
from silastron_pulse.smoke import compare, run as smoke_run
from silastron_pulse.static_pages import build_static_cve_pages
from silastron_pulse.store import promote_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://pulse.silastron.com"
NS = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9", "a": "http://www.w3.org/2005/Atom"}
BUILT_A = datetime(2026, 12, 5, 10, 0, tzinfo=timezone.utc)
BUILT_B = datetime(2027, 3, 1, 4, 5, tzinfo=timezone.utc)


class Head(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.meta: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.ld: list[str] = []
        self.footer_hrefs: list[str] = []
        self._in_title = self._in_ld = self._in_footer = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.meta.append(a)
        elif tag == "link":
            self.links.append(a)
        elif tag == "script" and a.get("type") == "application/ld+json":
            self._in_ld = True
        elif tag == "footer":
            self._in_footer = True
        elif tag == "a" and self._in_footer and a.get("href"):
            self.footer_hrefs.append(a["href"])

    def handle_endtag(self, tag):
        self._in_title = self._in_title and tag != "title"
        self._in_ld = self._in_ld and tag != "script"
        self._in_footer = self._in_footer and tag != "footer"

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_ld:
            self.ld.append(data)

    def named(self, key: str, value: str) -> str | None:
        for m in self.meta:
            if m.get(key) == value:
                return m.get("content")
        return None


def parse(path: Path) -> Head:
    head = Head()
    head.feed(path.read_text(encoding="utf-8"))
    return head


def make_site(root: Path, built_at: datetime = BUILT_A) -> Path:
    with tempfile.TemporaryDirectory() as collect_tmp:
        result = collect(config=test_config(Path(collect_tmp)), fetcher=valid_fetcher(), clock=frozen_clock())
    assert result.snapshot is not None
    data = root / "site" / "data"
    promote_snapshot(result.snapshot, data, now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
                     stale_after_hours=36, max_bytes=8_000_000, max_depth=32)
    site = root / "site"
    build_home_page(published_dir=data, template_path=ROOT / "preview" / "index.html", site_dir=site,
                    now=built_at, base_url=BASE)
    collected, published = footer_times(data)
    build_methodology_page(site, base_url=BASE, footer=page_chrome.footer(last_collected=collected, last_published=published))
    build_static_cve_pages(published_dir=data, site_dir=site, base_url=BASE)
    build_site_files(published_dir=data, site_dir=site, base_url=BASE, commit="a" * 40, built_at=built_at)
    return site


class SiteFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.site = make_site(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_sitemap_lists_pages_with_real_lastmod(self) -> None:
        root = ET.parse(self.site / "sitemap.xml").getroot()
        urls = {u.findtext("s:loc", namespaces=NS): u.findtext("s:lastmod", namespaces=NS) for u in root.findall("s:url", NS)}
        self.assertIn(BASE + "/", urls)
        self.assertEqual(urls[BASE + "/methodology/"], METHODOLOGY_REVISED)
        self.assertTrue(any("/cve/CVE-" in u for u in urls))
        for loc, lastmod in urls.items():
            self.assertRegex(lastmod or "", r"^\d{4}-\d{2}-\d{2}$", loc)
            self.assertNotEqual(lastmod, BUILT_A.strftime("%Y-%m-%d"), f"{loc} lastmod is the build date")
        for loc in urls:
            self.assertNotRegex(loc, r"\.(json|csv|xml)$")
            self.assertNotIn("404", loc)

    def test_rebuilding_later_does_not_change_sitemap_or_feeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            other = make_site(Path(tmp), BUILT_B)
            for name in ("sitemap.xml", "feed.xml", "kev/feed.xml"):
                self.assertEqual((self.site / name).read_bytes(), (other / name).read_bytes(), name)
            self.assertNotEqual((self.site / "build.json").read_bytes(), (other / "build.json").read_bytes())

    def test_robots_allows_all_and_points_to_the_sitemap(self) -> None:
        self.assertEqual((self.site / "robots.txt").read_text(), f"User-agent: *\nAllow: /\nSitemap: {BASE}/sitemap.xml\n")

    def test_build_json_records_commit_and_both_states(self) -> None:
        build = json.loads((self.site / "build.json").read_text())
        self.assertEqual(build["commit"], "a" * 40)
        self.assertIsNone(build["malware_state_commit"])
        self.assertEqual(build["manifest_sha256"], hashlib.sha256((self.site / "data" / "manifest.json").read_bytes()).hexdigest())
        self.assertEqual(build["snapshot_id"], json.loads((self.site / "data" / "manifest.json").read_text())["snapshot_id"])

    def test_feed_entries_are_newest_first_with_stable_ids_and_local_links(self) -> None:
        root = ET.parse(self.site / "kev" / "feed.xml").getroot()
        entries = root.findall("a:entry", NS)
        self.assertTrue(entries)
        updated = [e.findtext("a:updated", namespaces=NS) for e in entries]
        self.assertEqual(updated, sorted(updated, reverse=True))
        ids = [e.findtext("a:id", namespaces=NS) for e in entries]
        self.assertEqual(len(ids), len(set(ids)))
        for entry_id in ids:
            self.assertRegex(entry_id, r"^tag:pulse\.silastron\.com,2026:kev:CVE-\d{4}-\d{4,}$")
        for e in entries:
            self.assertTrue(e.find("a:link", NS).get("href").startswith(BASE + "/cve/CVE-"))
        self.assertEqual(root.findtext("a:updated", namespaces=NS), updated[0])

    def test_pages_have_unique_titles_canonicals_og_and_feed_links(self) -> None:
        pages = {"/": self.site / "index.html", "/methodology/": self.site / "methodology" / "index.html"}
        cve = sorted((self.site / "cve").glob("CVE-*"))[0]
        pages[f"/cve/{cve.name}/"] = cve / "index.html"
        titles = set()
        for path, file in pages.items():
            head = parse(file)
            titles.add(head.title)
            self.assertTrue(head.title.strip(), path)
            self.assertTrue(head.named("name", "description"), path)
            canon = [l["href"] for l in head.links if l.get("rel") == "canonical"]
            self.assertEqual(canon, [BASE + path])
            for prop in ("og:title", "og:description", "og:type", "og:url", "og:site_name"):
                self.assertTrue(head.named("property", prop), f"{path} {prop}")
            alternates = {l["href"] for l in head.links if l.get("rel") == "alternate"}
            self.assertEqual(alternates, {BASE + "/feed.xml", BASE + "/kev/feed.xml", BASE + "/malware/feed.xml"})
        self.assertEqual(len(titles), 3)

    def test_json_ld_dataset_on_home_and_website_once(self) -> None:
        home = parse(self.site / "index.html")
        graph = json.loads("".join(home.ld))["@graph"]
        self.assertEqual(sorted(n["@type"] for n in graph), ["Dataset", "WebSite"])
        for file in [self.site / "methodology" / "index.html", *sorted((self.site / "cve").glob("CVE-*/index.html"))[:3]]:
            blob = "".join(parse(file).ld)
            self.assertNotIn('"Dataset"', blob)
            self.assertNotIn('"@type":"WebSite"', blob.replace(" ", ""))

    def test_csp_is_strict_with_no_inline_script_or_external_origin(self) -> None:
        for file in [self.site / "index.html", self.site / "methodology" / "index.html",
                     *sorted((self.site / "cve").glob("CVE-*/index.html"))[:3]]:
            csp = parse(file).named("http-equiv", "Content-Security-Policy")
            self.assertNotIn("unsafe-inline", csp)
            self.assertNotIn("unsafe-eval", csp)
            self.assertNotRegex(csp, r"https?://|\*")
            self.assertIn("default-src 'none'", csp)
            html = file.read_text(encoding="utf-8")
            inline = [m for m in re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", html) if "ld+json" not in m]
            self.assertEqual(inline, [], file)

    def test_ld_json_hash_is_pinned_in_the_csp(self) -> None:
        for file in [self.site / "index.html"]:
            head = parse(file)
            body = "".join(head.ld)
            digest = __import__("base64").b64encode(hashlib.sha256(body.encode()).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", head.named("http-equiv", "Content-Security-Policy"))

    def test_every_page_footer_has_the_required_links_and_times(self) -> None:
        needed = {"https://silastron.com/newsletter/", "https://pqc.silastron.com", "https://silastron.com",
                  page_chrome.REPO_URL, page_chrome.REPO_URL + "/issues", "/feed.xml", "/kev/feed.xml", "/malware/feed.xml"}
        for file in [self.site / "index.html", self.site / "methodology" / "index.html",
                     *sorted((self.site / "cve").glob("CVE-*/index.html"))[:3]]:
            head = parse(file)
            self.assertTrue(needed <= set(head.footer_hrefs), (file, needed - set(head.footer_hrefs)))
            text = file.read_text(encoding="utf-8")
            self.assertIn("Last collected:", text)
            self.assertIn("Last published:", text)

    def test_methodology_date_is_bumped_with_its_text(self) -> None:
        self.assertEqual(body_sha256(), METHODOLOGY_BODY_SHA256, "methodology text changed: update METHODOLOGY_REVISED and the hash")


class FeedTests(unittest.TestCase):
    def rows(self, count: int, **over):
        return [{"cve_id": f"CVE-2026-{1000 + i}", "kev_date_added": f"2026-10-{(i % 28) + 1:02d}",
                 "vendor_project": "V", "product": "P", "vulnerability_name": "N", **over} for i in range(count)]

    def test_capped_and_ordered(self) -> None:
        entries = kev_entries(self.rows(500), BASE)
        self.assertEqual(len(entries), MAX_KEV_ENTRIES)
        self.assertEqual([e["updated"] for e in entries], sorted((e["updated"] for e in entries), reverse=True))

    def test_hostile_values_are_escaped_and_illegal_characters_removed(self) -> None:
        rows = self.rows(1, vendor_project="<script>alert(1)</script>&", product="‮evil\x00\x08", vulnerability_name="x" * 5000)
        data = build_feed(title="t", feed_id="id", self_href=BASE + "/f", alternate_href=BASE, entries=kev_entries(rows, BASE),
                          empty_updated="2026-11-01T00:00:00Z", rights="r")
        root = ET.fromstring(data)  # well-formed
        text = data.decode()
        self.assertNotIn("<script>", text)
        self.assertNotIn("\x00", text)
        summary = root.find("a:entry/a:summary", NS).text
        self.assertLessEqual(len(summary), 300)

    def test_rows_with_bad_ids_or_dates_are_skipped(self) -> None:
        rows = [{"cve_id": "../../x", "kev_date_added": "2026-01-01"}, {"cve_id": "CVE-2026-0001", "kev_date_added": "soon"},
                {"cve_id": "CVE-2026-0002", "kev_date_added": "2026-01-01"}]
        self.assertEqual([e["id"].rsplit(":", 1)[1] for e in kev_entries(rows, BASE)], ["CVE-2026-0002"])

    def test_empty_feed_is_valid_and_uses_data_date(self) -> None:
        data = build_feed(title="t", feed_id="id", self_href=BASE, alternate_href=BASE, entries=[],
                          empty_updated="2026-11-01T00:00:00Z", rights="r")
        self.assertEqual(ET.fromstring(data).findtext("a:updated", namespaces=NS), "2026-11-01T00:00:00Z")


class SitemapLimitTests(unittest.TestCase):
    def test_refuses_more_than_the_url_bound(self) -> None:
        with self.assertRaises(ValueError):
            sitemap_xml([(f"{BASE}/{i}", None) for i in range(MAX_SITEMAP_URLS + 1)])


class BudgetTests(unittest.TestCase):
    budget = load_budget(ROOT / "ops" / "site-budget.json")

    def tree(self, files: dict[str, int]) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        for rel, size in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * size)
        return root

    def problems(self, files: dict[str, int], budget=None):
        budget = budget or {**self.budget, "max_site_bytes": 10**9}
        return check_site_budget(self.tree(files), budget)[0]

    def test_small_site_passes(self) -> None:
        self.assertEqual(self.problems({"index.html": 100, "data/manifest.json": 10}), [])

    def test_new_file_over_5mb_fails(self) -> None:
        self.assertTrue(self.problems({"data/new.json": 5_000_001}))
        self.assertEqual(self.problems({"data/new.json": 5_000_000}), [])

    def test_allowlisted_files_may_grow_up_to_25_percent_only(self) -> None:
        small = {"max_file_bytes": 10, "max_site_bytes": 10**9, "malware_prefix": "malware/", "max_malware_bytes": 10**9,
                 "max_growth_fraction": 0.25, "allowlist": {"data/latest.json": 100, "data/catalog-index.json": 100},
                 "snapshot_glob": "data/snapshots/", "snapshot_baseline": "data/latest.json"}
        self.assertEqual(self.problems({"data/latest.json": 125}, small), [])
        self.assertTrue(self.problems({"data/latest.json": 126}, small))
        self.assertTrue(self.problems({"data/catalog-index.json": 126}, small))
        self.assertEqual(self.problems({"data/snapshots/a.json": 125}, small), [])
        self.assertTrue(self.problems({"data/snapshots/a.json": 126}, small))

    def test_whole_site_and_malware_caps(self) -> None:
        small = {**self.budget, "max_site_bytes": 100, "max_malware_bytes": 40}
        self.assertTrue(self.problems({"a": 60, "b": 60}, small))
        self.assertTrue(self.problems({"malware/a": 30, "malware/b": 30}, {**small, "max_site_bytes": 10**9}))

    def test_symlinks_are_refused(self) -> None:
        root = self.tree({"a": 1})
        (root / "link").symlink_to(root / "a")
        self.assertTrue(check_site_budget(root, self.budget)[0])

    def test_recorded_sizes_match_the_documented_current_files(self) -> None:
        self.assertEqual(self.budget["allowlist"]["data/latest.json"], 63019924)
        self.assertEqual(self.budget["max_site_bytes"], 600_000_000)
        self.assertEqual(self.budget["max_malware_bytes"], 150_000_000)


class SmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.site = Path(self.tmp.name)
        (self.site / "data").mkdir()
        self.build = {"commit": "c" * 40, "built_at": "2026-11-13T10:00:00Z", "snapshot_id": "s1",
                      "manifest_sha256": "m", "malware_state_commit": "w" * 40}
        (self.site / "build.json").write_text(json.dumps(self.build))
        (self.site / "data" / "manifest.json").write_text(json.dumps({"snapshot_id": "s1"}))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_compare_checks_both_state_commits(self) -> None:
        self.assertEqual(compare(self.build, {"snapshot_id": "s1"}, dict(self.build), {"snapshot_id": "s1"}), [])
        stale = {**self.build, "malware_state_commit": "x" * 40}
        self.assertTrue(any("malware_state_commit" in p for p in compare(self.build, {"snapshot_id": "s1"}, stale, {"snapshot_id": "s1"})))
        self.assertTrue(any("commit" in p for p in compare(self.build, {"snapshot_id": "s1"}, {**self.build, "commit": "d" * 40}, {"snapshot_id": "s1"})))
        self.assertTrue(compare(self.build, {"snapshot_id": "s1"}, self.build, {"snapshot_id": "old"}))

    def test_retries_until_live_matches(self) -> None:
        calls = {"n": 0}

        def fetch(url: str) -> dict:
            if "build.json" in url:
                calls["n"] += 1
                return self.build if calls["n"] >= 3 else {**self.build, "commit": "old"}
            return {"snapshot_id": "s1"}

        ticks = iter(range(0, 1000, 15))
        self.assertEqual(smoke_run(self.site, BASE, timeout=300, interval=15, fetch=fetch, sleep=lambda s: None,
                                   clock=lambda: float(next(ticks)), log=lambda m: None), [])

    def test_times_out_with_the_last_problems_and_survives_fetch_errors(self) -> None:
        def fetch(url: str) -> dict:
            raise OSError("down")

        ticks = iter(range(0, 1000, 100))
        problems = smoke_run(self.site, BASE, timeout=150, interval=15, fetch=fetch, sleep=lambda s: None,
                             clock=lambda: float(next(ticks)), log=lambda m: None)
        self.assertTrue(problems and "could not read the live site" in problems[0])


if __name__ == "__main__":
    unittest.main()
