from __future__ import annotations

import unittest
from io import BytesIO
from urllib.request import Request

from silastron_pulse.constants import ALLOWED_HTTPS_HOSTS
from silastron_pulse.errors import FetchError, UnsafeRedirectError
from silastron_pulse.http import FetchResult, HttpsFetcher, MapFetcher, _AllowlistRedirectHandler


class HttpTests(unittest.TestCase):
    def test_map_fetcher_unknown_url_fails(self) -> None:
        fetcher = MapFetcher({})
        with self.assertRaises(FetchError):
            fetcher.get("https://www.cisa.gov/missing.json", max_bytes=100)

    def test_map_fetcher_enforces_size(self) -> None:
        fetcher = MapFetcher(
            {
                "https://www.cisa.gov/x.json": FetchResult(
                    requested_url="https://www.cisa.gov/x.json",
                    final_url="https://www.cisa.gov/x.json",
                    status_code=200,
                    content_type="application/json",
                    body=b"x" * 50,
                    retrieved_at="2099-01-01T00:00:00Z",
                )
            }
        )
        with self.assertRaises(FetchError):
            fetcher.get("https://www.cisa.gov/x.json", max_bytes=10)

    def test_https_fetcher_rejects_non_allowlisted_url(self) -> None:
        fetcher = HttpsFetcher(timeout_seconds=1, max_redirects=1)
        with self.assertRaises(FetchError):
            fetcher.get("https://evil.example/data", max_bytes=100)

    def test_redirect_handler_blocks_off_allowlist(self) -> None:
        handler = _AllowlistRedirectHandler(ALLOWED_HTTPS_HOSTS, max_redirects=3)
        req = Request("https://www.cisa.gov/start")
        with self.assertRaises(UnsafeRedirectError):
            handler.redirect_request(
                req,
                BytesIO(),
                302,
                "Found",
                {},
                "https://evil.example/next",
            )

    def test_redirect_handler_limits_hops(self) -> None:
        handler = _AllowlistRedirectHandler(ALLOWED_HTTPS_HOSTS, max_redirects=1)
        req = Request("https://www.cisa.gov/start")
        handler.redirect_request(
            req,
            BytesIO(),
            302,
            "Found",
            {},
            "https://www.cve.org/next",
        )
        with self.assertRaises(FetchError):
            handler.redirect_request(
                req,
                BytesIO(),
                302,
                "Found",
                {},
                "https://www.cve.org/again",
            )


if __name__ == "__main__":
    unittest.main()
