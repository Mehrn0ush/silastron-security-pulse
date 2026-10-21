"""HTTPS-only, allowlisted, size-bounded HTTP client with retries."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from silastron_pulse.clock import Clock, SystemClock, format_datetime
from silastron_pulse.constants import ALLOWED_HTTPS_HOSTS, USER_AGENT
from silastron_pulse.errors import FetchError, UnsafeRedirectError
from silastron_pulse.sanitize import sanitize_https_url

RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    retrieved_at: str
    etag: str | None = None
    not_modified: bool = False


class Fetcher(Protocol):
    def get(
        self,
        url: str,
        *,
        max_bytes: int,
        etag: str | None = None,
    ) -> FetchResult:
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
        max_attempts: int = 3,
        backoff_seconds: float = 1.0,
        min_interval_ms: int = 50,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_redirects = max_redirects
        self._clock = clock or SystemClock()
        self._hosts = hosts or ALLOWED_HTTPS_HOSTS
        self._user_agent = user_agent
        self._max_attempts = max(1, max_attempts)
        self._backoff_seconds = backoff_seconds
        self._min_interval = max(0, min_interval_ms) / 1000.0
        self._sleep = sleep or time.sleep
        self._lock = threading.Lock()
        self._last_request = 0.0

    def get(
        self,
        url: str,
        *,
        max_bytes: int,
        etag: str | None = None,
    ) -> FetchResult:
        last_error: FetchError | None = None
        for attempt in range(self._max_attempts):
            try:
                return self._once(url, max_bytes=max_bytes, etag=etag)
            except FetchError as exc:
                last_error = exc
                if not exc.retryable or attempt + 1 >= self._max_attempts:
                    raise
                delay = exc.retry_after
                if delay is None:
                    delay = self._backoff_seconds * (2**attempt)
                self._sleep(max(0.0, delay))
        raise last_error or FetchError(f"Failed fetching {url}")

    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                self._sleep(wait)
            self._last_request = time.monotonic()

    def _once(self, url: str, *, max_bytes: int, etag: str | None) -> FetchResult:
        safe = sanitize_https_url(url, hosts=self._hosts)
        if safe is None:
            raise FetchError(f"URL is not on the HTTPS allowlist: {url!r}")
        self._throttle()
        handler = _AllowlistRedirectHandler(self._hosts, self._max_redirects)
        opener = build_opener(handler)
        headers = {
            "User-Agent": self._user_agent,
            "Accept": "application/json, text/plain;q=0.8, */*;q=0.1",
        }
        if etag:
            headers["If-None-Match"] = etag
        request = Request(safe, headers=headers, method="GET")
        retrieved_at = format_datetime(self._clock.now())
        try:
            with opener.open(request, timeout=self._timeout) as response:
                return _result_from_response(response, safe, retrieved_at, max_bytes, self._hosts)
        except UnsafeRedirectError:
            raise
        except HTTPError as exc:
            if exc.code == 304:
                return FetchResult(
                    requested_url=safe,
                    final_url=safe,
                    status_code=304,
                    content_type="",
                    body=b"",
                    retrieved_at=retrieved_at,
                    etag=etag,
                    not_modified=True,
                )
            retry_after = _retry_after(exc.headers)
            retryable = exc.code in RETRYABLE_STATUS
            raise FetchError(
                f"HTTP {exc.code} fetching {safe}",
                retryable=retryable,
                retry_after=retry_after,
                status_code=exc.code,
            ) from exc
        except URLError as exc:
            raise FetchError(
                f"Network error fetching {safe}: {exc.reason}",
                retryable=True,
            ) from exc
        except TimeoutError as exc:
            raise FetchError(f"Timeout fetching {safe}", retryable=True) from exc
        except OSError as exc:
            raise FetchError(f"I/O error fetching {safe}: {exc}", retryable=True) from exc


def _result_from_response(response: object, safe: str, retrieved_at: str, max_bytes: int, hosts: frozenset[str]) -> FetchResult:
    status_code = getattr(response, "status", 200) or 200
    headers = getattr(response, "headers", {})
    content_type = headers.get("Content-Type", "") if headers is not None else ""
    etag = headers.get("ETag") if headers is not None else None
    final_url = response.geturl()  # type: ignore[attr-defined]
    body = _read_bounded(response, max_bytes=max_bytes)
    final_safe = sanitize_https_url(final_url, hosts=hosts)
    if final_safe is None:
        raise UnsafeRedirectError(f"Final URL left allowlist: {final_url!r}")
    if status_code != 200:
        raise FetchError(f"HTTP {status_code} fetching {safe}", status_code=status_code)
    return FetchResult(
        requested_url=safe,
        final_url=final_safe,
        status_code=status_code,
        content_type=content_type.split(";")[0].strip().lower(),
        body=body,
        retrieved_at=retrieved_at,
        etag=etag,
        not_modified=False,
    )


def _retry_after(headers: object) -> float | None:
    if headers is None:
        return None
    raw = headers.get("Retry-After") if hasattr(headers, "get") else None
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        try:
            when = parsedate_to_datetime(raw)
            return max(0.0, (when.timestamp() - time.time()))
        except (TypeError, ValueError, OverflowError):
            return None


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
        self.calls: list[tuple[str, str | None]] = []

    def get(
        self,
        url: str,
        *,
        max_bytes: int,
        etag: str | None = None,
    ) -> FetchResult:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise FetchError("MapFetcher only accepts https URLs")
        self.calls.append((url, etag))
        if url not in self._mapping:
            raise FetchError(f"No fixture for {url}")
        result = self._mapping[url]
        if isinstance(result, Exception):
            raise result
        if result.not_modified:
            return result
        if len(result.body) > max_bytes:
            raise FetchError(f"Response exceeded max bytes {max_bytes}")
        return result


class ScriptedFetcher:
    """Test double: queued responses per URL, including retryable failures."""

    def __init__(self, mapping: dict[str, list[FetchResult | Exception]]) -> None:
        self._mapping = {key: list(value) for key, value in mapping.items()}
        self.calls: list[tuple[str, str | None]] = []

    def get(
        self,
        url: str,
        *,
        max_bytes: int,
        etag: str | None = None,
    ) -> FetchResult:
        self.calls.append((url, etag))
        queue = self._mapping.get(url)
        if not queue:
            raise FetchError(f"No fixture remaining for {url}")
        result = queue.pop(0)
        if isinstance(result, Exception):
            raise result
        if len(result.body) > max_bytes and not result.not_modified:
            raise FetchError(f"Response exceeded max bytes {max_bytes}")
        return result


class RetryingFetcher:
    """Apply retry/backoff around any Fetcher (used in tests with ScriptedFetcher)."""

    def __init__(
        self,
        inner: Fetcher,
        *,
        max_attempts: int = 3,
        backoff_seconds: float = 0.0,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._inner = inner
        self._max_attempts = max(1, max_attempts)
        self._backoff_seconds = backoff_seconds
        self._sleep = sleep or (lambda _delay: None)

    def get(
        self,
        url: str,
        *,
        max_bytes: int,
        etag: str | None = None,
    ) -> FetchResult:
        last_error: FetchError | None = None
        for attempt in range(self._max_attempts):
            try:
                return self._inner.get(url, max_bytes=max_bytes, etag=etag)
            except FetchError as exc:
                last_error = exc
                if not exc.retryable or attempt + 1 >= self._max_attempts:
                    raise
                delay = exc.retry_after
                if delay is None:
                    delay = self._backoff_seconds * (2**attempt)
                self._sleep(max(0.0, delay))
        raise last_error or FetchError(f"Failed fetching {url}")
