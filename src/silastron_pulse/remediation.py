"""Assemble evidence-based remediation. Never infer a patch from CVSS or ranges."""

from __future__ import annotations

import re
from typing import Any

from silastron_pulse.models import CveRecord, KevRecord, RemediationItem
from silastron_pulse.sanitize import authoritative_kev_url, sanitize_public_https_url

MAX_REMEDIATION_ITEMS = 32
_HTTPS_URL = re.compile(r"https://[^\s<>\"']+", re.IGNORECASE)


def extract_https_urls(text: str | None) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for match in _HTTPS_URL.findall(text):
        cleaned = match.rstrip(").,;]}")
        safe = sanitize_public_https_url(cleaned)
        if safe and safe not in seen:
            seen.add(safe)
            found.append(safe)
        if len(found) >= 8:
            break
    return found


def assemble_remediation(*, kev: KevRecord, cve: CveRecord) -> dict[str, Any]:
    items: list[RemediationItem] = []
    if kev.required_action:
        items.append(
            RemediationItem(
                kind="required_action",
                source="cisa_kev",
                attribution="CISA KEV requiredAction",
                text=kev.required_action,
                url=authoritative_kev_url(),
            )
        )
        for url in extract_https_urls(kev.required_action):
            items.append(
                RemediationItem(
                    kind="reference",
                    source="cisa_kev",
                    attribution="CISA KEV requiredAction",
                    url=url,
                )
            )
    if kev.notes:
        items.append(
            RemediationItem(
                kind="reference",
                source="cisa_kev",
                attribution="CISA KEV notes",
                text=kev.notes,
            )
        )
        for url in extract_https_urls(kev.notes):
            items.append(
                RemediationItem(
                    kind="reference",
                    source="cisa_kev",
                    attribution="CISA KEV notes",
                    url=url,
                )
            )
    items.extend(cve.remediation_items)
    unique: list[RemediationItem] = []
    seen: set[tuple[object, ...]] = set()
    for item in items:
        key = (item.kind, item.source, item.attribution, item.text, item.url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
        if len(unique) >= MAX_REMEDIATION_ITEMS:
            break
    return {
        "status": "available" if unique else "unavailable",
        "items": [item.to_dict() for item in unique],
        "note": (
            "Remediation is copied from CISA KEV and CVE List V5 CNA fields. "
            "Verified Fix and Mitigation require CNA solutions or workarounds. "
            "CNA reference tags are classification hints, not proof of vendor "
            "ownership. No verified remediation data does not mean a fix is "
            "unavailable."
        ),
    }
