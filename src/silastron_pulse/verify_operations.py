"""Read-only operational verification. Never writes, dispatches, or mutates."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from silastron_pulse.constants import USER_AGENT
from silastron_pulse.data_status import evaluate_data_status
from silastron_pulse.pages_observe import PAGES_OBSERVE_HOSTS
from silastron_pulse.sanitize import sanitize_https_url
from silastron_pulse.verification_status import validate_verification_status


def verify_operations(
    *,
    pages_url: str = "https://pulse.silastron.com",
    repository: str = "Mehrn0ush/silastron-security-pulse",
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    base = pages_url.rstrip("/")
    checks: dict[str, Any] = {}
    evidence_gaps: list[str] = []
    failures: list[str] = []
    manifest = _get_json(f"{base}/data/manifest.json", checks, "manifest")
    preview = _get_json(f"{base}/data/preview.json", checks, "preview")
    publication_status = _get_json(
        f"{base}/data/publication-status.json", checks, "publication_status", required=False
    )
    verification = _get_json(
        f"{base}/data/verification-status.json", checks, "verification_status", required=False
    )
    homepage = _get_text(f"{base}/", checks, "homepage")
    if verification is not None:
        try:
            validate_verification_status(verification)
        except Exception as exc:  # noqa: BLE001 - report-only
            failures.append(f"verification-status failed validation: {exc}")
            verification = None
    if manifest is None:
        failures.append("Public manifest is unavailable.")
    status = evaluate_data_status(
        snapshot=None,
        manifest=manifest,
        verification=verification,
        publication_status=publication_status,
        now=current,
        stale_after_hours=int((manifest or {}).get("stale_after_hours") or 36),
    )
    if homepage is not None:
        if "Stale snapshot" in homepage and "status-banner" in homepage:
            checks["homepage_stale_banner"] = "present_in_html_shell"
        checks["cve_deep_link_supported"] = "#cve/" in (homepage or "") or "parseCveHash" in (
            _get_text(f"{base}/app.js", checks, "app_js") or ""
        )
    if status.get("integrity_problem"):
        failures.append("Publication consistency is not consistent.")
    if verification is None:
        evidence_gaps.append(
            "Public verification-status.json is missing. A successful unchanged "
            "Collect cannot be confirmed from Pages alone."
        )
    if preview is None:
        evidence_gaps.append("Public preview.json is unavailable.")
    verdict = "verified_operational_success"
    if failures:
        verdict = "verified_operational_failure"
    elif evidence_gaps:
        verdict = "insufficient_evidence"
    return {
        "verdict": verdict,
        "pages_url": base,
        "repository": repository,
        "evaluated_at": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_status": status,
        "checks": checks,
        "failures": failures,
        "evidence_gaps": evidence_gaps,
        "owner_commands": [
            f"gh run list --repo {repository} --workflow collect.yml --limit 10",
            f"gh run list --repo {repository} --workflow publish.yml --limit 10",
            (
                f"gh api repos/{repository}/actions/workflows/collect.yml/runs"
                "?per_page=5 --jq '.workflow_runs[]|{id,event,conclusion,created_at}'"
            ),
            f"curl -sS {base}/data/manifest.json",
            f"curl -sS {base}/data/verification-status.json",
            f"curl -sS {base}/data/publication-status.json",
            "Do not dispatch Collect, Publish, or Deploy as part of this check.",
        ],
        "note": (
            "This command only reads public Pages documents. It does not inspect "
            "private Actions logs unless the repository owner runs the listed commands."
        ),
    }


def _get_json(url: str, checks: dict[str, Any], name: str, *, required: bool = True) -> dict[str, Any] | None:
    body, status = _fetch(url)
    checks[name] = {"url": url, "http_status": status, "available": body is not None}
    if body is None:
        if required:
            checks[name]["evidence"] = "missing"
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        checks[name]["evidence"] = "invalid_json"
        return None
    return payload if isinstance(payload, dict) else None


def _get_text(url: str, checks: dict[str, Any], name: str) -> str | None:
    body, status = _fetch(url)
    checks[name] = {"url": url, "http_status": status, "available": body is not None}
    if body is None:
        return None
    return body.decode("utf-8", "replace")


def _fetch(url: str) -> tuple[bytes | None, int | None]:
    safe = sanitize_https_url(url, hosts=PAGES_OBSERVE_HOSTS)
    if safe is None:
        return None, None
    request = Request(safe, headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html;q=0.9"})
    try:
        with urlopen(request, timeout=12) as response:  # noqa: S310 - allowlisted HTTPS
            return response.read(2_000_000), getattr(response, "status", 200)
    except HTTPError as exc:
        return None, exc.code
    except (URLError, TimeoutError, OSError, ValueError):
        return None, None
