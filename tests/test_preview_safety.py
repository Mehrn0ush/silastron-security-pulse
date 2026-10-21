from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PreviewSafetyTests(unittest.TestCase):
    def test_preview_js_does_not_use_unsafe_sinks(self) -> None:
        source = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        for needle in ["innerHTML", "document.write", "eval(", "Function("]:
            self.assertNotIn(needle, source)

    def test_preview_html_has_csp(self) -> None:
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Content-Security-Policy", html)
        self.assertNotIn("cdn.", html)
        self.assertNotIn("http://", html)

    def test_unpublished_manifest_is_not_fresh(self) -> None:
        manifest = json.loads(
            (ROOT / "preview" / "data" / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["status"], "unpublished")
        self.assertTrue(manifest["stale"])
        self.assertFalse(manifest["fresh"])

    def test_python_allowlist_matches_schema_file(self) -> None:
        from silastron_pulse.constants import ALLOWED_HTTPS_HOSTS, AUTHORITATIVE_LINK_HOSTS

        policy = json.loads((ROOT / "schemas" / "url-allowlist.json").read_text())
        self.assertEqual(set(policy["hosts"]), set(ALLOWED_HTTPS_HOSTS))
        self.assertEqual(set(policy["preview_link_hosts"]), set(AUTHORITATIVE_LINK_HOSTS))

    def test_preview_does_not_treat_stale_manifest_flag_as_fresh(self) -> None:
        source = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertIn("evaluateFreshness", source)
        self.assertIn("Date.now()", source)
        self.assertIn("Collection outcome", source)
        self.assertIn("Complete extracted inventories", source)
        self.assertIn("Partial extracted inventories", source)
        self.assertIn("Unavailable enrichments", source)
        self.assertIn("Collection succeeded", source)
        self.assertIn("not a failed collection", source)
        self.assertIn("partial extracted inventory", source)
        self.assertIn("enrichment unavailable", source)
        self.assertNotIn('infoState = "partial"', source)
        self.assertNotIn("The published snapshot is partial", source)
        self.assertNotIn("innerHTML", source)
        self.assertIn("CVELIST_BLOB", source)
        self.assertIn("completeness", source)
        self.assertIn("products omitted", source)
        self.assertIn("Collection started at", source)
        self.assertIn("Collection completed at", source)
        html = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Collection outcome", html)
        self.assertIn("Record completeness", html)
        self.assertIn("does not prove", html)
        self.assertIn("Freshness", html)


if __name__ == "__main__":
    unittest.main()
