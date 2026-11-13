"""Atom feeds (RFC 4287). Built with ElementTree so every value is escaped.

Entry ids are stable across rebuilds (derived from the record, never the build
time) and `updated` comes from the data, so rebuilding unchanged data produces
byte-identical feeds.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from silastron_pulse.ids import CVE_ID_RE

ATOM = "http://www.w3.org/2005/Atom"
ID_AUTHORITY = "tag:pulse.silastron.com,2026"
MAX_KEV_ENTRIES = 200
AUTHOR = "Silastron Security Pulse"


def _q(name: str) -> str:
    return f"{{{ATOM}}}{name}"


def _text(parent: ET.Element, name: str, value: str, **attrs: str) -> ET.Element:
    node = ET.SubElement(parent, _q(name), attrs)
    node.text = value
    return node


# Characters XML 1.0 cannot carry (ElementTree would write them out and break every reader).
_XML_ILLEGAL = re.compile("[^\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def _clip(value: Any, limit: int) -> str:
    text = " ".join(_XML_ILLEGAL.sub("", str(value or "")).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def kev_entries(rows: list[dict[str, Any]], base_url: str) -> list[dict[str, str]]:
    """One entry per CVE added to KEV, newest first, capped at MAX_KEV_ENTRIES."""
    dated = [
        row
        for row in rows
        if isinstance(row.get("cve_id"), str)
        and CVE_ID_RE.fullmatch(row["cve_id"])
        and isinstance(row.get("kev_date_added"), str)
        and len(row["kev_date_added"]) == 10
    ]
    dated.sort(key=lambda row: (row["kev_date_added"], row["cve_id"]), reverse=True)
    entries = []
    for row in dated[:MAX_KEV_ENTRIES]:
        cve_id = row["cve_id"]
        who = _clip(f"{row.get('vendor_project') or 'Unknown vendor'} {row.get('product') or ''}", 120)
        entries.append(
            {
                "id": f"{ID_AUTHORITY}:kev:{cve_id}",
                "title": _clip(f"{cve_id} added to CISA KEV: {who}", 200),
                "updated": row["kev_date_added"] + "T00:00:00Z",
                "link": f"{base_url}/cve/{cve_id}/",
                "summary": _clip(row.get("vulnerability_name") or "Added to the CISA Known Exploited Vulnerabilities catalog.", 300),
            }
        )
    return entries


def build_feed(*, title: str, feed_id: str, self_href: str, alternate_href: str, entries: list[dict[str, str]],
               empty_updated: str, rights: str) -> bytes:
    ET.register_namespace("", ATOM)
    feed = ET.Element(_q("feed"))
    _text(feed, "title", title)
    _text(feed, "id", feed_id)
    _text(feed, "updated", entries[0]["updated"] if entries else empty_updated)
    ET.SubElement(feed, _q("link"), {"rel": "self", "type": "application/atom+xml", "href": self_href})
    ET.SubElement(feed, _q("link"), {"rel": "alternate", "type": "text/html", "href": alternate_href})
    author = ET.SubElement(feed, _q("author"))
    _text(author, "name", AUTHOR)
    _text(feed, "rights", rights)
    for entry in entries:
        node = ET.SubElement(feed, _q("entry"))
        _text(node, "title", entry["title"])
        _text(node, "id", entry["id"])
        _text(node, "updated", entry["updated"])
        ET.SubElement(node, _q("link"), {"rel": "alternate", "type": "text/html", "href": entry["link"]})
        _text(node, "summary", entry["summary"], type="text")
    ET.indent(feed)
    return ET.tostring(feed, encoding="utf-8", xml_declaration=True) + b"\n"
