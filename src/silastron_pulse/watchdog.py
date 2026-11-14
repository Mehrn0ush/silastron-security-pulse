"""Watchdog: open one issue when the live site is stale or unhealthy, close it on recovery.

Decision logic is pure (`evaluate`); fetching and issue handling take injected callables so they are
tested without a network. Thresholds assume daily collection (KEV and malware).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from silastron_pulse.malware.weeks import parse_utc

KEV_MAX_AGE_HOURS = 48
MALWARE_MAX_AGE_HOURS = 48
BEHIND_HOURS = 6
FETCH_ATTEMPTS = 3
LABEL = "site-stale"
ISSUE_TITLE = "Live site is stale or unhealthy"
USER_AGENT = "silastron-pulse-watchdog/1"


@dataclass
class Observation:
    site_ok: bool
    site_error: str | None = None
    kev_verified_at: str | None = None
    malware_collected_at: str | None = None
    live_malware_commit: str | None = None
    malware_head_commit: str | None = None
    malware_head_date: str | None = None


@dataclass
class Problem:
    key: str
    detail: str


def _age_hours(value: str | None, now: datetime) -> float | None:
    parsed = parse_utc(value)
    return None if parsed is None else (now - parsed).total_seconds() / 3600


def evaluate(obs: Observation, now: datetime) -> list[Problem]:
    now = now.astimezone(timezone.utc)
    if not obs.site_ok:
        return [Problem("site-unreachable", f"The live site could not be fetched after {FETCH_ATTEMPTS} attempts: {obs.site_error}")]
    problems: list[Problem] = []
    kev_age = _age_hours(obs.kev_verified_at, now)
    if kev_age is None:
        problems.append(Problem("kev-unverified", "The live site has no readable KEV verification time (data/verification-status.json)."))
    elif kev_age > KEV_MAX_AGE_HOURS:
        problems.append(Problem("kev-stale", f"KEV data was last independently verified {kev_age:.0f} hours ago "
                                f"({obs.kev_verified_at}); the limit is {KEV_MAX_AGE_HOURS}. Check Collect and Publish."))
    if obs.malware_head_commit is not None:
        mal_age = _age_hours(obs.malware_collected_at, now)
        if mal_age is None:
            problems.append(Problem("malware-missing", "malware-state exists but the live site has no malware data. Run Publish or check the malware build."))
        elif mal_age > MALWARE_MAX_AGE_HOURS:
            problems.append(Problem("malware-stale", f"Malware data was collected {mal_age:.0f} hours ago ({obs.malware_collected_at}); "
                                    f"the limit is {MALWARE_MAX_AGE_HOURS}. Check Collect malware."))
        head_age = _age_hours(obs.malware_head_date, now)
        if (obs.live_malware_commit != obs.malware_head_commit and head_age is not None and head_age > BEHIND_HOURS):
            problems.append(Problem("malware-behind", f"malware-state moved {head_age:.0f} hours ago (to {obs.malware_head_commit[:12]}) but the live "
                                    f"site still serves {str(obs.live_malware_commit)[:12] or 'none'}; limit {BEHIND_HOURS} hours. "
                                    "Publish has not picked it up."))
    return problems


# ------------------------------------------------------------------ fetching


def http_json(url: str, token: str | None = None) -> Any:
    if urlparse(url).scheme != "https":
        raise ValueError("only https URLs are fetched")
    headers = {"User-Agent": USER_AGENT, "Cache-Control": "no-cache"}
    if token and urlparse(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _optional(fetch: Callable[[str], Any], url: str) -> Any:
    try:
        return fetch(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def observe(*, site_url: str, repo: str, fetch: Callable[[str], Any] = http_json,
            sleep: Callable[[float], None] = time.sleep, attempts: int = FETCH_ATTEMPTS, interval: float = 20.0) -> Observation:
    site_url = site_url.rstrip("/")
    error = "unknown"
    manifest = None
    for attempt in range(attempts):
        try:
            manifest = fetch(f"{site_url}/data/manifest.json?cb={time.time_ns()}")
            break
        except (OSError, ValueError, urllib.error.URLError) as exc:
            error = str(exc)
            if attempt + 1 < attempts:
                sleep(interval)
    if manifest is None:
        return Observation(site_ok=False, site_error=error)
    stamp = time.time_ns()
    verification = _optional(fetch, f"{site_url}/data/verification-status.json?cb={stamp}")
    status = _optional(fetch, f"{site_url}/malware/data/status.json?cb={stamp}")
    build = _optional(fetch, f"{site_url}/build.json?cb={stamp}")
    head = _optional(fetch, f"https://api.github.com/repos/{repo}/branches/malware-state")
    commit = (head or {}).get("commit") or {}
    return Observation(
        site_ok=True,
        kev_verified_at=(verification or {}).get("verified_at"),
        malware_collected_at=(status or {}).get("collected_at"),
        live_malware_commit=(build or {}).get("malware_state_commit"),
        malware_head_commit=commit.get("sha"),
        malware_head_date=((commit.get("commit") or {}).get("committer") or {}).get("date"),
    )


# ------------------------------------------------------------------ issue handling


def issue_body(problems: list[Problem], now: datetime) -> str:
    lines = [f"Checked {now.strftime('%Y-%m-%d %H:%M UTC')} by the watchdog workflow.", ""]
    lines += [f"- **{p.key}**: {p.detail}" for p in problems]
    lines += ["", "See docs/operations.md for what each alert means and how to recover. This issue closes itself when the site is healthy."]
    return "\n".join(lines)


def sync_issue(problems: list[Problem], now: datetime, run: Callable[[list[str], str | None], str], owner: str | None) -> str:
    """Create, update or close the single site-stale issue. `run(args, stdin)` wraps the gh CLI."""
    run(["label", "create", LABEL, "--color", "B60205", "--description", "The live site is stale or unhealthy", "--force"], None)
    number = run(["issue", "list", "--label", LABEL, "--state", "open", "--json", "number", "--jq", ".[0].number // empty"], None).strip()
    if problems:
        body = issue_body(problems, now)
        if number:
            run(["issue", "edit", number, "--body-file", "-"], body)
            return f"updated #{number}"
        args = ["issue", "create", "--title", ISSUE_TITLE, "--label", LABEL, "--body-file", "-"]
        if owner:
            args += ["--assignee", owner]
        run(args, body)
        return "opened"
    if number:
        run(["issue", "comment", number, "--body-file", "-"], "The live site is healthy again. Closing.")
        run(["issue", "close", number], None)
        return f"closed #{number}"
    return "healthy"
