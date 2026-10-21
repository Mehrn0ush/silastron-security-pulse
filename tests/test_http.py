from __future__ import annotations

import inspect
import unittest
import zlib
from io import BytesIO
from urllib.request import Request

from silastron_pulse.constants import ALLOWED_HTTPS_HOSTS
from silastron_pulse.errors import FetchError, UnsafeRedirectError
from silastron_pulse.http import (
    CountingFetcher,
    FetchResult,
    HttpsFetcher,
    MapFetcher,
    RetryingFetcher,
    ScriptedFetcher,
    _AllowlistRedirectHandler,
    decode_http_body,
)


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

    def test_retrying_fetcher_gives_up_on_non_retryable(self) -> None:
        url = "https://www.cisa.gov/x.json"
        inner = ScriptedFetcher({url: [FetchError("HTTP 404", retryable=False, status_code=404)]})
        fetcher = RetryingFetcher(inner, max_attempts=3)
        with self.assertRaises(FetchError):
            fetcher.get(url, max_bytes=100)
        self.assertEqual(len(inner.calls), 1)

    def test_gzip_body_is_decoded_within_bound(self) -> None:
        payload = b'{"ok": true, "value": "' + b"x" * 200 + b'"}'
        wire = zlib.compress(payload, wbits=16 + zlib.MAX_WBITS)
        self.assertLess(len(wire), len(payload))
        self.assertEqual(decode_http_body(wire, "gzip", max_bytes=len(payload)), payload)

    def test_gzip_decode_is_bounded(self) -> None:
        payload = b"A" * 2000
        wire = zlib.compress(payload, wbits=16 + zlib.MAX_WBITS)
        with self.assertRaises(FetchError):
            decode_http_body(wire, "gzip", max_bytes=100)

    def test_get_requests_gzip_but_head_does_not(self) -> None:
        get_source = inspect.getsource(HttpsFetcher._once)
        head_source = inspect.getsource(HttpsFetcher._head_once)
        self.assertIn('"Accept-Encoding": "gzip"', get_source)
        self.assertNotIn("Accept-Encoding", head_source)

    def test_counting_fetcher_prefers_wire_bytes(self) -> None:
        url = "https://www.cisa.gov/x.json"
        inner = MapFetcher(
            {
                url: FetchResult(
                    requested_url=url,
                    final_url=url,
                    status_code=200,
                    content_type="application/json",
                    body=b"x" * 1000,
                    retrieved_at="2099-01-01T00:00:00Z",
                    wire_bytes=40,
                )
            }
        )
        fetcher = CountingFetcher(inner)
        fetcher.get(url, max_bytes=10_000)
        self.assertEqual(fetcher.bytes_received, 40)


if __name__ == "__main__":
    unittest.main()

