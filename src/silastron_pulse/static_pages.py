"""Minimal static per-CVE pages, visible to search engines and non-JS clients.

Each page is generated from the same cve/{CVE_ID}.json detail file the
interactive dashboard fetches (see catalog_index.py). It carries only key
facts, source attribution, and a canonical link; it is not a copy of the
dashboard UI and has no interactivity beyond links. All source text is
HTML-escaped on render; nothing here trusts upstream text as markup.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import shutil
from pathlib import Path
from typing import Any

from silastron_pulse.ids import CVE_ID_RE
from silastron_pulse.sanitize import sanitize_public_https_url

CVE_PAGE_CSS = """\
:root { color-scheme: light dark; }
body { font: 16px/1.5 system-ui, sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem;
  color: #1a1a2e; background: #fff; }
@media (prefers-color-scheme: dark) { body { color: #e8e8f0; background: #11111c; } }
a { color: #3454d1; }
@media (prefers-color-scheme: dark) { a { color: #9db4ff; } }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #ccc; vertical-align: top; }
.unavailable { opacity: 0.7; font-style: italic; }
.notice { font-size: 0.9rem; opacity: 0.85; border-left: 3px solid #999; padding-left: 0.75rem; }
footer { margin-top: 2rem; font-size: 0.85rem; opacity: 0.8; }
"""


def _esc(value: Any) -> str:
    if value is None or value == "":
        return "unavailable"
    return html.escape(str(value), quote=True)


def _url(value: Any) -> str | None:
    return sanitize_public_https_url(value)


def _row(label: str, value: Any) -> str:
    cls = "" if value not in (None, "") else ' class="unavailable"'
    return f"<tr><th>{html.escape(label)}</th><td{cls}>{_esc(value)}</td></tr>"


def _json_ld_block(entry: dict[str, Any], *, base_url: str) -> tuple[str, str]:
    cve_id = entry["cve_id"]
    same_as = [
        url
        for url in (
            _url((entry.get("links") or {}).get("cve_record")),
            _url((entry.get("links") or {}).get("kev_catalog")),
            _url((entry.get("links") or {}).get("nvd")),
        )
        if url
    ]
    data = {
        "@context": "https://schema.org",
        "@type": "WebPage",
        "@id": f"{base_url}/cve/{cve_id}/",
        "url": f"{base_url}/cve/{cve_id}/",
        "name": f"{cve_id} — Silastron Security Pulse",
        "isPartOf": {"@type": "WebSite", "name": "Silastron Security Pulse", "url": base_url + "/"},
        "mainEntity": {
            "@type": "Thing",
            "identifier": cve_id,
            "name": entry.get("vulnerability_name") or cve_id,
            "description": entry.get("short_description") or entry.get("cve_description"),
            "sameAs": same_as,
        },
    }
    # No schema.org type exists for a vulnerability record; this is a WebPage
    # describing one, not a claim that CVE identity is schema.org-typed.
    payload = json.dumps(data, ensure_ascii=False, indent=None)
    safe_payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    digest = base64.b64encode(hashlib.sha256(safe_payload.encode("utf-8")).digest()).decode("ascii")
    return safe_payload, digest


def render_cve_page(entry: dict[str, Any], *, base_url: str) -> str:
    """Render one minimal static page from a cve/{CVE_ID}.json detail entry."""
    cve_id = entry["cve_id"]
    if not CVE_ID_RE.fullmatch(cve_id):
        raise ValueError(f"Refusing to render a page for an unsafe cve_id {cve_id!r}")
    canonical = f"{base_url}/cve/{cve_id}/"
    title = f"{cve_id} — Silastron Security Pulse"
    description = entry.get("short_description") or entry.get("cve_description") or (
        "CISA Known Exploited Vulnerabilities and CVE List V5 intelligence. No composite risk score."
    )
    json_ld, ld_hash = _json_ld_block(entry, base_url=base_url)
    csp = (
        "default-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src 'none'; style-src 'self'; "
        f"script-src 'sha256-{ld_hash}'; connect-src 'none'; font-src 'none'; object-src 'none'; "
        "upgrade-insecure-requests"
    )
    sources = entry.get("intelligence", {}).get("sources", {}) if isinstance(entry.get("intelligence"), dict) else {}
    links = entry.get("links") or {}
    remediation = entry.get("remediation") or {}
    # Distinct from the "Required action (CISA KEV)" row above: CNA-sourced
    # evidence only. "reference" items are bare URLs/titles already covered
    # by Authoritative sources below.
    cna_remediation_kinds = {"verified_fix", "mitigation"}
    remediation_text = None
    if remediation.get("status") == "available" and remediation.get("items"):
        remediation_text = "; ".join(
            str(item.get("text"))
            for item in remediation["items"]
            if item.get("text") and item.get("kind") in cna_remediation_kinds
        ) or None

    def _source_rows(name: str) -> str:
        meta = sources.get(name) if isinstance(sources, dict) else None
        meta = meta if isinstance(meta, dict) else {}
        return (
            f"<tr><th>{html.escape(name)}</th>"
            f"<td>{_esc(meta.get('status'))}</td>"
            f"<td>{_esc(meta.get('retrieved_at'))}</td>"
            f"<td>{_esc(meta.get('upstream_modified_at'))}</td>"
            f"<td>{_esc(meta.get('completeness'))}</td></tr>"
        )

    link_items = []
    for label, key in (
        ("CVE.org record", "cve_record"),
        ("CISA KEV catalog", "kev_catalog"),
        ("CVE List V5 (raw)", "cvelist_v5"),
        ("NVD", "nvd"),
    ):
        url = _url(links.get(key))
        if url:
            link_items.append(f'<li><a href="{html.escape(url, quote=True)}" rel="noopener noreferrer">{label}</a></li>')

    cwes = entry.get("cwes") or []
    # Not pre-escaped: _row()/_esc() below escapes this exactly once.
    cwe_text = ", ".join(str(c) for c in cwes) if cwes else None

    # CISA SSVC decision points: source-attributed facts, never a derived
    # score or priority. "unavailable" per point means CISA has not
    # published that decision point, not that it is low impact.
    ssvc_points = [
        (entry.get("ssvc_exploitation"), "Exploitation"),
        (entry.get("ssvc_automatable"), "Automatable"),
        (entry.get("ssvc_technical_impact"), "Technical impact"),
    ]
    ssvc_text = (
        "; ".join(f"{label}: {value}" for value, label in ssvc_points if value and value != "unavailable")
        or None
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<meta name="description" content="{_esc(description)}">
<link rel="canonical" href="{html.escape(canonical, quote=True)}">
<link rel="stylesheet" href="/cve-page.css">
<title>{html.escape(title)}</title>
</head>
<body>
<p class="notice">Published CISA KEV and CVE List V5 intelligence. Source-attributed only;
no composite risk score, and this is not a statement about Silastron.com or customer exposure.</p>
<h1>{html.escape(cve_id)}</h1>
<p>{_esc(entry.get('vulnerability_name'))}</p>
<table>
{_row("Vendor / project", entry.get("vendor_project"))}
{_row("Product", entry.get("product"))}
{_row("Added to CISA KEV", entry.get("kev_date_added"))}
{_row("CISA due date", entry.get("due_date"))}
{_row("Required action (CISA KEV)", entry.get("required_action"))}
{_row("Known ransomware campaign use", entry.get("known_ransomware_campaign_use"))}
{_row("CVSS base score", entry.get("cvss_base_score"))}
{_row("CVSS vector", entry.get("cvss_vector"))}
{_row("CWE", cwe_text)}
{_row("CISA SSVC decision points", ssvc_text)}
{_row("Extraction completeness", entry.get("completeness"))}
{_row("CNA-reported solution / mitigation", remediation_text)}
</table>
<h2>Sources and provenance</h2>
<table>
<tr><th>Source</th><th>Status</th><th>Retrieved</th><th>Upstream modified</th><th>Completeness</th></tr>
{_source_rows("cisa_kev")}
{_source_rows("cve_list_v5")}
{_source_rows("nvd")}
</table>
<h2>Authoritative sources</h2>
<ul>
{"".join(link_items) or '<li class="unavailable">No authoritative links available.</li>'}
</ul>
<p><a href="/#cve/{html.escape(cve_id, quote=True)}">View full source-attributed intelligence in the interactive explorer</a></p>
<script type="application/ld+json">{json_ld}</script>
<footer>
<p>A Silastron research dashboard. <a href="https://silastron.com" rel="noopener noreferrer">silastron.com</a></p>
<p>CVE is a registered trademark of The MITRE Corporation. KEV data is dedicated to the public
domain under CC0 1.0. This product uses the NVD API but is not endorsed or certified by the NVD.</p>
</footer>
</body>
</html>
"""


def build_static_cve_pages(*, published_dir: Path, site_dir: Path, base_url: str) -> int:
    """Render one page per published CVE plus sitemap.xml. Returns the page count.

    published_dir must already contain catalog-index.json and cve/*.json
    (written by store.promote_snapshot / catalog_index.py). Stale pages for a
    CVE no longer published are removed, mirroring the cve/*.json cleanup.
    """
    base_url = base_url.rstrip("/")
    index_path = published_dir / "catalog-index.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"{index_path} is missing; run promote before building static pages")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    cve_root = site_dir / "cve"
    cve_root.mkdir(parents=True, exist_ok=True)
    current_ids: set[str] = set()
    urls = [f"{base_url}/"]
    for row in index.get("records") or []:
        cve_id = row.get("cve_id")
        if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
            continue
        detail_path = published_dir / "cve" / f"{cve_id}.json"
        if not detail_path.is_file():
            continue
        entry = json.loads(detail_path.read_text(encoding="utf-8"))
        page_dir = cve_root / cve_id
        page_dir.mkdir(parents=True, exist_ok=True)
        (page_dir / "index.html").write_text(
            render_cve_page(entry, base_url=base_url), encoding="utf-8"
        )
        current_ids.add(cve_id)
        urls.append(f"{base_url}/cve/{cve_id}/")

    for path in cve_root.glob("CVE-*"):
        if path.is_symlink():
            raise PermissionError(f"Refusing to touch a symlinked CVE page directory {path.name}")
        if path.is_dir() and path.name not in current_ids:
            if any(child.is_symlink() for child in path.rglob("*")):
                raise PermissionError(f"Refusing to touch a symlink under {path.name}")
            shutil.rmtree(path)

    (site_dir / "cve-page.css").write_text(CVE_PAGE_CSS, encoding="utf-8")
    sitemap_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for url in urls:
        sitemap_lines.append(f"  <url><loc>{html.escape(url, quote=True)}</loc></url>")
    sitemap_lines.append("</urlset>")
    (site_dir / "sitemap.xml").write_text("\n".join(sitemap_lines) + "\n", encoding="utf-8")
    (site_dir / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {base_url}/sitemap.xml\n", encoding="utf-8"
    )
    return len(current_ids)
