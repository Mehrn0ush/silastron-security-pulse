"""Head tags, JSON-LD and the shared footer for every generated page."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from silastron_pulse.htmlbuild import Node, el, fragment

SITE_NAME = "Silastron Security Pulse"
REPO_URL = "https://github.com/Mehrn0ush/silastron-security-pulse"
FOOTER_LINKS = (
    ("Join the Orbit", "https://silastron.com/newsletter/"),
    ("pqc.silastron.com", "https://pqc.silastron.com"),
    ("silastron.com", "https://silastron.com"),
    ("Source repository", REPO_URL),
    ("Report an error", REPO_URL + "/issues"),
)
FEEDS = (
    ("Silastron Security Pulse: all updates", "/feed.xml"),
    ("Silastron Security Pulse: CISA KEV additions", "/kev/feed.xml"),
    ("Silastron Security Pulse: malicious package digests", "/malware/feed.xml"),
)
SUBSCRIBE = (
    ("All updates", "/feed.xml"),
    ("CISA KEV additions", "/kev/feed.xml"),
    ("Malicious package digests", "/malware/feed.xml"),
)


def csp(*, script_hash: str | None, self_scripts: bool, connect_self: bool, images: bool) -> str:
    scripts = []
    if self_scripts:
        scripts.append("'self'")
    if script_hash:
        scripts.append("'sha256-" + script_hash + "'")
    script_src = " ".join(scripts) if scripts else "'none'"
    img_src = "'self' data:" if images else "'none'"
    connect_src = "'self'" if connect_self else "'none'"
    return (
        "default-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src " + img_src + "; style-src 'self'; script-src " + script_src + "; "
        "connect-src " + connect_src + "; font-src 'none'; object-src 'none'; upgrade-insecure-requests"
    )


def json_ld(data: dict[str, Any]) -> tuple[Node, str]:
    """A JSON-LD data block with `<`, `>` and `&` escaped, and its CSP hash."""
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    safe = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    digest = base64.b64encode(hashlib.sha256(safe.encode("utf-8")).digest()).decode("ascii")
    return _RawScript(safe), digest  # type: ignore[return-value]


class _RawScript:
    """Script block whose body is pre-escaped JSON; the only raw text this module emits."""

    def __init__(self, body: str) -> None:
        self.body = body

    def html(self) -> str:
        return f'<script type="application/ld+json">{self.body}</script>'


def head_tags(
    *,
    base_url: str,
    path: str,
    title: str,
    description: str,
    og_type: str = "website",
    csp_value: str,
    ld_block: Any = None,
    extra_alternates: tuple[tuple[str, str], ...] = FEEDS,
) -> str:
    canonical = f"{base_url}{path}"
    nodes: list[Any] = [
        el("meta", {"http-equiv": "Content-Security-Policy", "content": csp_value}),
        el("meta", {"name": "referrer", "content": "no-referrer"}),
        el("meta", {"name": "description", "content": description}),
        el("title", None, title),
        el("link", {"rel": "canonical", "href": canonical}),
        el("meta", {"property": "og:title", "content": title}),
        el("meta", {"property": "og:description", "content": description}),
        el("meta", {"property": "og:type", "content": og_type}),
        el("meta", {"property": "og:url", "content": canonical}),
        el("meta", {"property": "og:site_name", "content": SITE_NAME}),
        el("meta", {"name": "twitter:card", "content": "summary"}),
    ]
    for label, href in extra_alternates:
        nodes.append(el("link", {"rel": "alternate", "type": "application/atom+xml", "title": label, "href": base_url + href}))
    if ld_block is not None:
        nodes.append(ld_block)
    return fragment(*nodes)


def subscribe_nav() -> Node:
    return el(
        "p",
        {"class": "subscribe"},
        "Subscribe: ",
        *[x for i, (label, href) in enumerate(SUBSCRIBE) for x in ((" · ",) if i else ()) + (el("a", {"href": href, "rel": "alternate", "type": "application/atom+xml"}, label),)],
    )


def footer(*, last_collected: str, last_published: str) -> Node:
    link_nodes: list[Any] = []
    for index, (label, href) in enumerate(FOOTER_LINKS):
        if index:
            link_nodes.append(" · ")
        link_nodes.append(el("a", {"href": href, "rel": "noopener noreferrer"}, label))
    return el(
        "footer",
        None,
        el("p", None, "A Silastron research dashboard."),
        el("p", {"class": "footer-links"}, *link_nodes),
        subscribe_nav(),
        el("p", {"class": "footer-times"}, f"Last collected: {last_collected}. Last published: {last_published}."),
        el(
            "p",
            None,
            "CVE is a registered trademark of The MITRE Corporation. KEV data is dedicated to the public domain "
            "under CC0 1.0. This product uses the NVD API but is not endorsed or certified by the NVD. This page "
            "does not modify or represent Silastron.com WordPress content.",
        ),
    )


def website_ld(base_url: str) -> dict[str, Any]:
    return {"@type": "WebSite", "@id": f"{base_url}/#website", "name": SITE_NAME, "url": f"{base_url}/"}


_SHELL_PRE = """<!DOCTYPE html>
<html lang="en" data-theme="system">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    {head}
    <script src="/theme.js"></script>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to content</a>
    <header class="site-header">
      <div class="brand-lockup">
        <p class="brand-name"><a class="brand-link" href="https://silastron.com" rel="noopener noreferrer">Silastron</a></p>
        <p class="product-name">Security Pulse</p>
      </div>
      <div class="header-tools">
        <div class="theme-switch" role="group" aria-label="Color theme">
          <button type="button" data-theme-choice="system" aria-pressed="true">System</button>
          <button type="button" data-theme-choice="light" aria-pressed="false">Light</button>
          <button type="button" data-theme-choice="dark" aria-pressed="false">Dark</button>
        </div>
      </div>
      <div class="header-copy"><h1>{h1}</h1></div>
      <nav class="page-nav" aria-label="Page">{nav}</nav>
    </header>
    <main id="main">
"""


def shell_page(*, head: str, h1: Node | str, nav_current: str, body: str, footer: Node, scripts: tuple[str, ...] = ()) -> str:
    """A whole page: shared header/nav/footer around an already-built, already-escaped body."""
    links = (("/", "Home"), ("/malware/", "Malicious packages"), ("/methodology/", "Methodology"))
    nav = fragment(
        *[el("a", {"href": href, "aria-current": "page" if href == nav_current else None}, label) for href, label in links]
    )
    return (
        _SHELL_PRE.replace("{head}", head).replace("{h1}", fragment(h1)).replace("{nav}", nav)
        + body
        + "\n    </main>\n    "
        + footer.html()
        + "".join(f'\n    <script src="{src}"></script>' for src in scripts)
        + "\n  </body>\n</html>\n"
    )
