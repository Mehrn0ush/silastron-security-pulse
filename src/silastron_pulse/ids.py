"""Strict identifier handling. Never pad, coerce, or fuzzy-match CVE IDs."""

from __future__ import annotations

import re

from silastron_pulse.constants import CVE_ID_PATTERN, CWE_ID_PATTERN, CVE_LIST_V5_RAW_BASE
from silastron_pulse.errors import ValidationError

CVE_ID_RE = re.compile(CVE_ID_PATTERN)
CWE_ID_RE = re.compile(CWE_ID_PATTERN)


def parse_cve_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError("CVE ID must be a string")
    cve_id = value.strip().upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        raise ValidationError(f"Invalid CVE ID: {value!r}")
    return cve_id


def same_cve_id(left: str, right: str) -> bool:
    """Exact identifier equality after strict parse. No zero-padding."""
    return parse_cve_id(left) == parse_cve_id(right)


def cvelist_v5_relpath(cve_id: str) -> str:
    parsed = parse_cve_id(cve_id)
    _prefix, year, sequence = parsed.split("-")
    bucket = f"{int(sequence) // 1000}xxx"
    return f"cves/{year}/{bucket}/{parsed}.json"


def cvelist_v5_raw_url(cve_id: str) -> str:
    return CVE_LIST_V5_RAW_BASE + cvelist_v5_relpath(cve_id)


def parse_cwe_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    if not CWE_ID_RE.fullmatch(candidate):
        return None
    return candidate
