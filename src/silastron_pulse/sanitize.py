"""Treat all external data as untrusted."""

from __future__ import annotations

from urllib.parse import urlparse

from silastron_pulse.constants import ALLOWED_HTTPS_HOSTS, AUTHORITATIVE_LINK_HOSTS
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.constants import CVE_RECORD_PAGE_TEMPLATE, KEV_CATALOG_PAGE_URL


CONTROL_CHARS = dict.fromkeys(range(32))
CONTROL_CHARS.update({127: None})
# Preserve tab/newline as spaces rather than dropping silently.
CONTROL_CHARS[9] = ord(" ")
CONTROL_CHARS[10] = ord(" ")
CONTROL_CHARS[13] = ord(" ")


def clean_text_report(value: object, max_chars: int) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if not isinstance(value, str):
        return None, False
    text = value.translate(CONTROL_CHARS).strip()
    if not text:
        return None, False
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "…", True
    return text, False


def clean_text(value: object, max_chars: int) -> str | None:
    text, _truncated = clean_text_report(value, max_chars)
    return text


def require_text(value: object, field: str, max_chars: int) -> str:
    text, _truncated = require_text_report(value, field, max_chars)
    return text


def require_text_report(value: object, field: str, max_chars: int) -> tuple[str, bool]:
    text, truncated = clean_text_report(value, max_chars)
    if text is None:
        raise ValueError(f"Missing or empty field: {field}")
    return text, truncated


def is_safe_https_url(value: object, hosts: frozenset[str] | None = None) -> bool:
    return sanitize_https_url(value, hosts=hosts) is not None


def sanitize_https_url(
    value: object, hosts: frozenset[str] | None = None
) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or any(ch.isspace() for ch in raw) or "\\" in raw:
        return None
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme.lower() != "https":
        return None
    if parsed.username or parsed.password:
        return None
    host = (parsed.hostname or "").lower()
    if not host or host in {"localhost"} or host.endswith(".local"):
        return None
    if host.startswith("127.") or host == "::1" or host.startswith("0."):
        return None
    allowed = hosts if hosts is not None else ALLOWED_HTTPS_HOSTS
    if host not in allowed:
        return None
    if parsed.port not in (None, 443):
        return None
    return parsed.geturl()


def authoritative_cve_url(cve_id: str) -> str:
    parsed = parse_cve_id(cve_id)
    url = CVE_RECORD_PAGE_TEMPLATE.format(cve_id=parsed)
    safe = sanitize_https_url(url, hosts=AUTHORITATIVE_LINK_HOSTS)
    if safe is None:
        raise ValueError("Failed to construct authoritative CVE URL")
    return safe


def authoritative_kev_url() -> str:
    safe = sanitize_https_url(KEV_CATALOG_PAGE_URL, hosts=AUTHORITATIVE_LINK_HOSTS)
    if safe is None:
        raise ValueError("Failed to construct authoritative KEV URL")
    return safe
