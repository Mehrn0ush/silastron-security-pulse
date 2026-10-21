"""Authoritative outbound URL paths. Host allowlisting is not enough."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from silastron_pulse.ids import CVE_ID_RE
from silastron_pulse.sanitize import sanitize_https_url

_CVE_PATH = re.compile(r"^/CVERecord$")
_KEV_PATHS = {
    "/known-exploited-vulnerabilities-catalog",
}
_CVELIST_BLOB = re.compile(
    r"^/CVEProject/cvelistV5/blob/main/cves/[0-9]{4}/[0-9]+xxx/CVE-[0-9]{4}-[0-9]{4,}\.json$"
)


def authoritative_href(value: object) -> str | None:
    safe = sanitize_https_url(value)
    if safe is None:
        return None
    parsed = urlparse(safe)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if host in {"www.cisa.gov", "cisa.gov"}:
        if path.rstrip("/") in _KEV_PATHS or path in _KEV_PATHS:
            return safe
        return None
    if host in {"www.cve.org", "cve.org"}:
        if not _CVE_PATH.fullmatch(path):
            return None
        cve_id = (parse_qs(parsed.query).get("id") or [None])[0]
        if not cve_id or not CVE_ID_RE.fullmatch(cve_id):
            return None
        return safe
    if host == "github.com":
        if _CVELIST_BLOB.fullmatch(path):
            return safe
        return None
    return None
