from __future__ import annotations

import unittest

from silastron_pulse.sanitize import clean_text, sanitize_https_url


class SanitizeTests(unittest.TestCase):
    def test_strips_control_characters_and_truncates(self) -> None:
        text = clean_text("hello\x00<script>\nalert", max_chars=12)
        self.assertEqual(text, "hello<script…")
        spaced = clean_text("a\nb", max_chars=10)
        self.assertEqual(spaced, "a b")

    def test_allows_https_allowlisted_hosts(self) -> None:
        self.assertIsNotNone(
            sanitize_https_url("https://www.cve.org/CVERecord?id=CVE-2099-0001")
        )

    def test_rejects_unsafe_urls(self) -> None:
        for url in [
            "javascript:alert(1)",
            "data:text/html,hi",
            "http://www.cve.org/x",
            "https://evil.example/steal",
            "https://user:pass@www.cve.org/x",
            "https://localhost/x",
            "https://127.0.0.1/x",
            "https://www.cve.org:8443/x",
        ]:
            with self.subTest(url=url):
                self.assertIsNone(sanitize_https_url(url))


if __name__ == "__main__":
    unittest.main()
