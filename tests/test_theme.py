"""Theme bootstrap, persistence, and presentation-only dashboard contracts."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _preview(name: str) -> str:
    return (ROOT / "preview" / name).read_text(encoding="utf-8")


class ThemeBootstrapTests(unittest.TestCase):
    def test_theme_script_runs_before_stylesheet(self) -> None:
        html = _preview("index.html")
        self.assertLess(html.find('src="theme.js"'), html.find('href="styles.css"'))
        self.assertLess(html.find('src="theme.js"'), html.find("<body"))
        self.assertIn('data-theme="system"', html)
        self.assertIn('data-theme-choice="system"', html)
        self.assertIn('data-theme-choice="light"', html)
        self.assertIn('data-theme-choice="dark"', html)
        self.assertIn('aria-label="Color theme"', html)
        self.assertIn('href="https://silastron.com"', html)
        self.assertIn("Apastron · Gravity of Silence", html)
        self.assertNotIn("fonts.googleapis", html)
        self.assertNotIn("cdn.", html)

    def test_theme_js_defaults_to_system_and_persists_explicit_choice(self) -> None:
        js = _preview("theme.js")
        self.assertIn('STORAGE_KEY = "silastron-pulse-theme"', js)
        self.assertIn('apply(readStored() || "system")', js)
        self.assertIn("localStorage.setItem", js)
        self.assertIn("localStorage.getItem", js)
        self.assertIn('root.setAttribute("data-theme", next)', js)
        self.assertIn("light dark", js)
        self.assertIn("aria-pressed", js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("eval(", js)

    def test_css_defines_light_dark_and_system_tokens(self) -> None:
        css = _preview("styles.css")
        self.assertIn('html[data-theme="light"]', css)
        self.assertIn('html[data-theme="dark"]', css)
        self.assertIn('html[data-theme="system"]', css)
        self.assertIn("@media (prefers-color-scheme: dark)", css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertIn("@media (max-width: 40rem)", css)
        self.assertIn("content: attr(data-label)", css)
        self.assertIn(".banner-label", css)
        self.assertIn(".severity-critical", css)
        self.assertIn(".theme-switch", css)
        self.assertNotIn("starfield", css.lower())
        self.assertNotIn("@import", css)
        self.assertNotIn("fonts.g", css)

    def test_app_keeps_status_text_when_adding_tone(self) -> None:
        js = _preview("app.js")
        self.assertIn("bannerLabel", js)
        self.assertIn('return "Degraded collection"', js)
        self.assertIn("labeledCell", js)
        self.assertIn("cvssBand", js)
        self.assertIn('freshness.invalid ? "invalid" : freshness.stale ? "stale" : "fresh"', js)
        self.assertIn("Collection succeeded with incomplete extracted inventories", js)
        self.assertIn("The published snapshot is stale at viewing time", js)
        self.assertNotIn("innerHTML", js)


class ThemeAccessibilityTests(unittest.TestCase):
    def test_focus_and_skip_link_remain_visible(self) -> None:
        css = _preview("styles.css")
        html = _preview("index.html")
        self.assertIn(".skip-link:focus", css)
        self.assertIn(":focus-visible", css)
        self.assertIn('href="#main"', html)
        self.assertIn('aria-pressed="true"', html)
        self.assertIn("Signal definitions and methodology", html)
        self.assertIn("<summary>Technical details</summary>", html)
        self.assertIn("status-banner", html)
        self.assertNotIn('style="', html)
        self.assertNotIn("onclick=", html)

    def test_csp_still_blocks_inline_and_third_party_theme_assets(self) -> None:
        html = _preview("index.html")
        match = re.search(
            r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"',
            html,
        )
        self.assertIsNotNone(match)
        csp = match.group(1)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("style-src 'self'", csp)
        self.assertIn("font-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("https:", csp)


if __name__ == "__main__":
    unittest.main()
