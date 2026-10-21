"""HTTPS-only, allowlisted, size-bounded HTTP client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from silastron_pulse.clock import Clock, SystemClock, format_datetime
from silastron_pulse.constants import ALLOWED_HTTPS_HOSTS, USER_AGENT
from silastron_pulse.errors import FetchError, UnsafeRedirectError
from silastron_pulse.sanitize import sanitize_https_url


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    retrieved_at: str


class Fetcher(Protocol):
    def get(self, url: str, *, max_bytes: int) -> FetchResult:
        ...


class _AllowlistRedirectHandler(HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str], max_redirects: int) -> None:
        super().__init__()
        self._hosts = hosts
        self._max_redirects = max_redirects
        self._seen = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self._seen += 1
        if self._seen > self._max_redirects:
            raise FetchError(f"Too many redirects (max {self._max_redirects})")
        safe = sanitize_https_url(newurl, hosts=self._hosts)
        if safe is None:
            raise UnsafeRedirectError(f"Blocked redirect to {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, safe)


class HttpsFetcher:
    def __init__(
        self,
        *,
        timeout_seconds: int,
        max_redirects: int,
        clock: Clock | None = None,
        hosts: frozenset[str] | None = None,
        user_agent: str = USER_AGENT,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_redirects = max_redirects
        self._clock = clock or SystemClock()
        self._hosts = hosts or ALLOWED_HTTPS_HOSTS
        self._user_agent = user_agent

    def get(self, url: str, *, max_bytes: int) -> FetchResult:
        safe = sanitize_https_url(url, hosts=self._hosts)
        if safe is None:
            raise FetchError(f"URL is not on the HTTPS allowlist: {url!r}")
        handler = _AllowlistRedirectHandler(self._hosts, self._max_redirects)
        opener = build_opener(handler)
        request = Request(
            safe,
            headers={
                "User-Agent": self._user_agent,
                "Accept": "application/json, text/plain;q=0.8, */*;q=0.1",
            },
            method="GET",
        )
        retrieved_at = format_datetime(self._clock.now())
        try:
            with opener.open(request, timeout=self._timeout) as response:
                status_code = getattr(response, "status", 200) or 200
                content_type = response.headers.get("Content-Type", "")
                final_url = response.geturl()
                body = _read_bounded(response, max_bytes=max_bytes)
        except UnsafeRedirectError:
            raise
        except HTTPError as exc:
            raise FetchError(f"HTTP {exc.code} fetching {safe}") from exc
        except URLError as exc:
            raise FetchError(f"Network error fetching {safe}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise FetchError(f"Timeout fetching {safe}") from exc
        except OSError as exc:
            raise FetchError(f"I/O error fetching {safe}: {exc}") from exc

        final_safe = sanitize_https_url(final_url, hosts=self._hosts)
        if final_safe is None:
            raise UnsafeRedirectError(f"Final URL left allowlist: {final_url!r}")
        if status_code != 200:
            raise FetchError(f"HTTP {status_code} fetching {safe}")
        return FetchResult(
            requested_url=safe,
            final_url=final_safe,
            status_code=status_code,
            content_type=content_type.split(";")[0].strip().lower(),
            body=body,
            retrieved_at=retrieved_at,
        )


def _read_bounded(response: object, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(64 * 1024)  # type: ignore[attr-defined]
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"Response exceeded max bytes {max_bytes}")
        chunks.append(chunk)
    return b"".join(chunks)


class MapFetcher:
    """Test double: exact URL to canned FetchResult or exception."""

    def __init__(self, mapping: dict[str, FetchResult | Exception]) -> None:
        self._mapping = mapping

    def get(self, url: str, *, max_bytes: int) -> FetchResult:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise FetchError("MapFetcher only accepts https URLs")
        if url not in self._mapping:
            raise FetchError(f"No fixture for {url}")
        result = self._mapping[url]
        if isinstance(result, Exception):
            raise result
        if len(result.body) > max_bytes:
            raise FetchError(f"Response exceeded max bytes {max_bytes}")
        return result
