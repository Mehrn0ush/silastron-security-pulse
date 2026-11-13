"""Sitemap, robots.txt, Atom feeds and build.json for the deployed site."""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from silastron_pulse.feeds import build_feed, kev_entries, malware_entries
from silastron_pulse.home_page import parse_instant
from silastron_pulse.ids import CVE_ID_RE
from silastron_pulse.methodology_page import METHODOLOGY_REVISED

SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
# sitemaps.org: at most 50,000 URLs and 50 MB per file. Stay well inside both; above this
# the build fails rather than silently truncating, and a sitemap index must be added.
MAX_SITEMAP_URLS = 45_000
MAX_SITEMAP_BYTES = 40_000_000
BUILD_SCHEMA_VERSION = "1.0.0"
KEV_RIGHTS = "CISA KEV data is dedicated to the public domain (CC0 1.0). Page text: Silastron."


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _day(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if len(value) == 10 and value[4] == "-" and value[7] == "-":
        return value if parse_instant(value + "T00:00:00Z") else None
    parsed = parse_instant(value)
    return parsed.strftime("%Y-%m-%d") if parsed else None


def _latest_day(values: list[Any]) -> str | None:
    days = [d for d in (_day(v) for v in values) if d]
    return max(days) if days else None


def home_lastmod(published_dir: Path) -> str | None:
    manifest = _obj(_load(published_dir / "manifest.json"))
    verification = _obj(_load(published_dir / "verification-status.json"))
    return _latest_day([manifest.get("snapshot_generated_at"), verification.get("verified_at")])


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def cve_lastmod(row: dict[str, Any], detail: dict[str, Any]) -> str | None:
    """The newest date the CVE page itself shows: KEV added date or an upstream modified date."""
    sources = _obj(_obj(detail.get("intelligence")).get("sources"))
    values: list[Any] = [row.get("kev_date_added")]
    for source in sources.values():
        values.append(_obj(source).get("source_updated_at"))
    return _latest_day(values)


def sitemap_xml(urls: list[tuple[str, str | None]]) -> bytes:
    if len(urls) > MAX_SITEMAP_URLS:
        raise ValueError(f"{len(urls)} URLs exceed {MAX_SITEMAP_URLS}; add a sitemap index")
    ET.register_namespace("", SITEMAP_NS)
    root = ET.Element(f"{{{SITEMAP_NS}}}urlset")
    for loc, lastmod in urls:
        url = ET.SubElement(root, f"{{{SITEMAP_NS}}}url")
        ET.SubElement(url, f"{{{SITEMAP_NS}}}loc").text = loc
        if lastmod:
            ET.SubElement(url, f"{{{SITEMAP_NS}}}lastmod").text = lastmod
    ET.indent(root)
    data = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
    if len(data) > MAX_SITEMAP_BYTES:
        raise ValueError("sitemap exceeds the size bound; add a sitemap index")
    return data


def _malware_digests(site_dir: Path) -> list[dict[str, Any]]:
    weeks = site_dir / "malware" / "data" / "weeks"
    if not weeks.is_dir():
        return []
    out = []
    for path in sorted(weeks.glob("*.json")):
        if path.name == "index.json":
            continue
        doc = _load(path)
        if isinstance(doc, dict) and doc.get("week"):
            out.append(doc)
    return out


def build_site_files(
    *,
    published_dir: Path,
    site_dir: Path,
    base_url: str,
    commit: str,
    built_at: datetime,
    malware_state_commit: str | None = None,
) -> dict[str, int]:
    base_url = base_url.rstrip("/")
    index = _load(published_dir / "catalog-index.json")
    if not isinstance(index, dict):
        raise FileNotFoundError(f"{published_dir / 'catalog-index.json'} is missing or unreadable")
    rows = [r for r in index.get("records") or [] if isinstance(r, dict)]
    urls: list[tuple[str, str | None]] = [
        (f"{base_url}/", home_lastmod(published_dir)),
        (f"{base_url}/methodology/", METHODOLOGY_REVISED),
    ]
    for row in sorted(rows, key=lambda r: str(r.get("cve_id"))):
        cve_id = row.get("cve_id")
        if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
            continue
        if not (site_dir / "cve" / cve_id / "index.html").is_file():
            continue
        detail = _obj(_load(published_dir / "cve" / f"{cve_id}.json"))
        urls.append((f"{base_url}/cve/{cve_id}/", cve_lastmod(row, detail)))
    malware_data = site_dir / "malware" / "data"
    if (malware_data / "status.json").is_file():
        from silastron_pulse.malware.pages import page_manifest

        urls += [(f"{base_url}{path}", lastmod) for path, lastmod in page_manifest(malware_data)]
    (site_dir / "sitemap.xml").write_bytes(sitemap_xml(urls))
    (site_dir / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {base_url}/sitemap.xml\n", encoding="utf-8")

    entries = kev_entries(rows, base_url)
    empty = (home_lastmod(published_dir) or "1970-01-01") + "T00:00:00Z"
    digests = _malware_digests(site_dir)
    mal_entries = malware_entries(digests, base_url)
    (site_dir / "kev").mkdir(parents=True, exist_ok=True)
    (site_dir / "kev" / "feed.xml").write_bytes(
        build_feed(
            title="Silastron Security Pulse: CISA KEV additions",
            feed_id="tag:pulse.silastron.com,2026:feed:kev",
            self_href=f"{base_url}/kev/feed.xml",
            alternate_href=f"{base_url}/",
            entries=entries,
            empty_updated=empty,
            rights=KEV_RIGHTS,
        )
    )
    (site_dir / "feed.xml").write_bytes(
        build_feed(
            title="Silastron Security Pulse: all updates",
            feed_id="tag:pulse.silastron.com,2026:feed:all",
            self_href=f"{base_url}/feed.xml",
            alternate_href=f"{base_url}/",
            entries=sorted([*entries, *mal_entries], key=lambda e: (e["updated"], e["id"]), reverse=True),
            empty_updated=empty,
            rights=KEV_RIGHTS,
        )
    )
    (site_dir / "malware").mkdir(parents=True, exist_ok=True)
    (site_dir / "malware" / "feed.xml").write_bytes(
        build_feed(
            title="Silastron Security Pulse: malicious package digests",
            feed_id="tag:pulse.silastron.com,2026:feed:malware",
            self_href=f"{base_url}/malware/feed.xml",
            alternate_href=f"{base_url}/malware/",
            entries=mal_entries,
            empty_updated=empty,
            rights="Counts derived from OpenSSF Malicious Packages (Apache-2.0).",
        )
    )
    manifest_bytes = (published_dir / "manifest.json").read_bytes() if (published_dir / "manifest.json").is_file() else b""
    manifest = _obj(_load(published_dir / "manifest.json"))
    build = {
        "schema_version": BUILD_SCHEMA_VERSION,
        "commit": commit,
        "built_at": built_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "snapshot_id": manifest.get("snapshot_id"),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "malware_state_commit": malware_state_commit,
    }
    (site_dir / "build.json").write_text(json.dumps(build, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"sitemap_urls": len(urls), "feed_entries": len(entries)}
