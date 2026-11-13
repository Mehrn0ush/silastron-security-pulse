"""Post-deploy smoke test: the live site must be the build we just made."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

USER_AGENT = "silastron-pulse-smoke/1"
BUILD_FIELDS = ("commit", "built_at", "snapshot_id", "manifest_sha256", "malware_state_commit")


def fetch_json(url: str) -> dict:
    if urlparse(url).scheme != "https":
        raise ValueError("only https URLs are fetched")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - https checked above
        return json.loads(response.read().decode("utf-8"))


def compare(built_build: dict, built_manifest: dict, live_build: dict, live_manifest: dict) -> list[str]:
    problems = []
    for field in BUILD_FIELDS:
        if live_build.get(field) != built_build.get(field):
            problems.append(f"build.json {field}: live {live_build.get(field)!r}, built {built_build.get(field)!r}")
    if live_manifest.get("snapshot_id") != built_manifest.get("snapshot_id"):
        problems.append(
            f"manifest snapshot_id: live {live_manifest.get('snapshot_id')!r}, built {built_manifest.get('snapshot_id')!r}"
        )
    return problems


def run(
    site_dir: Path,
    base_url: str,
    timeout: float = 300,
    interval: float = 15,
    fetch: Callable[[str], dict] = fetch_json,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> list[str]:
    """Poll until the live site matches the build or `timeout` seconds pass. Returns the last problems."""
    built_build = json.loads((site_dir / "build.json").read_text(encoding="utf-8"))
    built_manifest = json.loads((site_dir / "data" / "manifest.json").read_text(encoding="utf-8"))
    base_url = base_url.rstrip("/")
    deadline = clock() + timeout
    attempt = 0
    while True:
        attempt += 1
        stamp = time.time_ns()
        try:
            problems = compare(
                built_build,
                built_manifest,
                fetch(f"{base_url}/build.json?cb={stamp}"),
                fetch(f"{base_url}/data/manifest.json?cb={stamp}"),
            )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            problems = [f"could not read the live site: {exc}"]
        if not problems:
            log(f"ok after {attempt} attempt(s): live site is commit {str(built_build.get('commit'))[:12]}")
            return []
        log(f"attempt {attempt}: {len(problems)} difference(s), first: {problems[0]}")
        if clock() + interval > deadline:
            return problems
        sleep(interval)
