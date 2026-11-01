"""Observe the public GitHub Pages manifest without treating job status as proof.

CDN and Pages propagation can serve a previous snapshot after deploy-pages
succeeds. A mismatch or timeout is unconfirmed visibility, not a silent
success and not a reason to overwrite newer published state.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from silastron_pulse.constants import USER_AGENT
from silastron_pulse.sanitize import sanitize_https_url

PAGES_OBSERVE_HOSTS = frozenset(
    {
        "pulse.silastron.com",
        "mehrn0ush.github.io",
    }
)


def observe_pages_manifest(
    url: str,
    *,
    expected_snapshot_id: str,
    expected_digest: str | None = None,
    attempts: int = 4,
    timeout_seconds: float = 8.0,
    fetcher: Any | None = None,
) -> dict[str, Any]:
    safe = sanitize_https_url(url, hosts=PAGES_OBSERVE_HOSTS)
    if safe is None:
        return {
            "status": "refused",
            "visibility": "unconfirmed",
            "note": f"Refusing to observe non-allowlisted Pages URL {url!r}",
        }
    last_error = None
    seen_snapshot = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            payload = _get_json(safe, timeout_seconds=timeout_seconds, fetcher=fetcher)
        except Exception as exc:  # noqa: BLE001 - observation must never raise into persist
            last_error = str(exc)
            continue
        if not isinstance(payload, dict):
            last_error = "public manifest is not a JSON object"
            continue
        seen_snapshot = payload.get("snapshot_id")
        if seen_snapshot == expected_snapshot_id:
            digest = payload.get("content_sha256") or payload.get("digest")
            if expected_digest and digest and digest != expected_digest:
                return {
                    "status": "mismatch",
                    "visibility": "unconfirmed",
                    "attempt": attempt,
                    "observed_snapshot_id": seen_snapshot,
                    "note": "Public manifest snapshot matched but digest did not.",
                }
            return {
                "status": "visible",
                "visibility": "confirmed",
                "attempt": attempt,
                "observed_snapshot_id": seen_snapshot,
                "note": "Public Pages manifest matches the intended snapshot.",
            }
        last_error = (
            f"public manifest still serves {seen_snapshot!r}, not {expected_snapshot_id}"
        )
    return {
        "status": "unconfirmed",
        "visibility": "unconfirmed",
        "observed_snapshot_id": seen_snapshot,
        "error": last_error,
        "note": (
            "GitHub Pages deploy job success is not treated as proof of publicly "
            "visible content. CDN or Pages propagation may still serve the previous snapshot."
        ),
    }


def _get_json(url: str, *, timeout_seconds: float, fetcher: Any | None) -> dict[str, Any]:
    if fetcher is not None:
        raw = fetcher(url)
        if isinstance(raw, dict):
            return raw
        return json.loads(raw)
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - host allowlisted
            body = response.read(1_000_000)
    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} observing {url}") from exc
    except URLError as exc:
        raise RuntimeError(f"network error observing {url}: {exc.reason}") from exc
    return json.loads(body.decode("utf-8"))
