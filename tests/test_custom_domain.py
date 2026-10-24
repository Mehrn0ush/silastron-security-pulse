"""Custom-domain artifact and workflow contracts for pulse.silastron.com."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_DOMAIN = "pulse.silastron.com"
PAGES_CNAME_TARGET = "mehrn0ush.github.io"
PREVIEW_FILES = ("index.html", "styles.css", "app.js")
UPLOAD_PAGES_ARTIFACT = "actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9"
DEPLOY_PAGES = "actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346"


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _preview(name: str) -> str:
    return (ROOT / "preview" / name).read_text(encoding="utf-8")


class CustomDomainFrontendTests(unittest.TestCase):
    def test_assets_and_json_fetches_are_same_origin_relative(self) -> None:
        html = _preview("index.html")
        js = _preview("app.js")
        self.assertNotIn("<base", html)
        self.assertIn('href="styles.css"', html)
        self.assertIn('src="app.js"', html)
        self.assertNotIn('href="/styles.css"', html)
        self.assertNotIn('src="/app.js"', html)
        self.assertIn('loadJson("data/manifest.json")', js)
        self.assertIn('loadJson("data/preview.json")', js)
        self.assertIn('loadJson("data/latest.json")', js)
        self.assertIn('fetch(path, { credentials: "same-origin" })', js)
        self.assertNotIn("github.io", html)
        self.assertNotIn("github.io", js)
        self.assertNotIn("https://pulse.silastron.com", html)
        self.assertNotIn("https://pulse.silastron.com", js)
        self.assertNotIn("https://mehrn0ush.github.io", html)
        self.assertNotIn("https://mehrn0ush.github.io", js)

    def test_internal_links_stay_on_the_published_page(self) -> None:
        html = _preview("index.html")
        hrefs = re.findall(r'<a\b[^>]*\bhref="([^"]+)"', html)
        self.assertTrue(hrefs)
        for href in hrefs:
            self.assertFalse(href.startswith("http"), href)
            self.assertFalse(href.startswith("//"), href)
            self.assertTrue(href.startswith("#"), href)

    def test_csp_allows_same_origin_json_on_a_custom_host(self) -> None:
        html = _preview("index.html")
        match = re.search(
            r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"',
            html,
        )
        self.assertIsNotNone(match)
        csp = match.group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("style-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("upgrade-insecure-requests", csp)
        self.assertNotIn("https:", csp)
        self.assertNotIn("github.io", csp)
        self.assertNotIn("silastron.com", csp)
        self.assertNotIn("wordpress.com", csp)


class CustomDomainWorkflowTests(unittest.TestCase):
    def test_actions_pages_do_not_require_a_cname_file(self) -> None:
        self.assertFalse((ROOT / "CNAME").exists())
        self.assertFalse((ROOT / "preview" / "CNAME").exists())
        for name in ("publish.yml", "deploy-frontend.yml"):
            text = _workflow(name)
            self.assertNotIn("CNAME", text)
            self.assertNotIn("actions/configure-pages", text)
            self.assertNotIn("cname:", text)
            self.assertIsNone(re.search(r"gh api[^\n]*\bpages\b", text))
            self.assertIn(UPLOAD_PAGES_ARTIFACT, text)
            self.assertIn(DEPLOY_PAGES, text)
            self.assertIn("path: _site", text)
            self.assertIn("name: github-pages", text)
            self.assertIn("group: pages", text)
            self.assertIn("cancel-in-progress: false", text)
            self.assertIn(
                "cp preview/index.html preview/styles.css preview/app.js _site/",
                text,
            )

    def test_collect_stays_off_the_pages_domain_path(self) -> None:
        text = _workflow("collect.yml")
        self.assertNotIn("deploy-pages", text)
        self.assertNotIn("upload-pages-artifact", text)
        self.assertNotIn("github-pages", text)
        self.assertNotIn("CNAME", text)

    def test_both_site_builders_emit_the_same_root_frontend_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp) / "_site"
            site.mkdir()
            for name in PREVIEW_FILES:
                (site / name).write_text(
                    (ROOT / "preview" / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            names = tuple(sorted(path.name for path in site.iterdir()))
            self.assertEqual(tuple(sorted(PREVIEW_FILES)), names)
            self.assertFalse((site / "CNAME").exists())
            html = (site / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="styles.css"', html)
            self.assertIn('src="app.js"', html)
            self.assertIn("connect-src 'self'", html)


class CustomDomainOperatorDocsTests(unittest.TestCase):
    def test_deployment_docs_name_the_verified_cname_target(self) -> None:
        text = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
        self.assertIn(CUSTOM_DOMAIN, text)
        self.assertIn(PAGES_CNAME_TARGET, text)
        self.assertIn("Enforce HTTPS", text)
        self.assertIn("GitHub Actions", text)
        self.assertIn("is ignored and is not required", text)
        self.assertIn("silastron.com", text)
        self.assertIn("Do not change", text)
        self.assertIn("wildcard", text)
