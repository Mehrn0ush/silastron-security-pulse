"""Static /methodology/ page: how to read the signals, sources and limits.

The text is authored here (trusted); no upstream value is interpolated.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from silastron_pulse.htmlbuild import Node
from silastron_pulse.page_chrome import csp, head_tags, subscribe_nav

# Bump METHODOLOGY_REVISED when the text below changes (the sitemap lastmod comes from it);
# tests fail until the hash and the date are both updated.
METHODOLOGY_REVISED = "2026-11-14"
METHODOLOGY_BODY_SHA256 = "11722d7fe937428bf89281c407f5dafe02f5e7ab2951a7831ceac25837717255"
_SIGNALS = (Path(__file__).with_name("_signals_list.html")).read_text(encoding="utf-8")

_BODY = f"""
<h2 id="signals-heading">How to read these signals</h2>
{_SIGNALS}
<h2 id="sources-heading">Sources</h2>
<ul>
  <li>CISA Known Exploited Vulnerabilities catalog (public domain, CC0 1.0).</li>
  <li>CVE List V5 records, including the CISA ADP (Vulnrichment) container for CVSS and SSVC.</li>
  <li>NVD API 2.0 enrichment. This product uses the NVD API but is not endorsed or certified by the NVD.</li>
  <li>FIRST EPSS is <strong>not</strong> published, see the EPSS entry above.</li>
</ul>
<h2 id="provenance-heading">Collection, verification and publication</h2>
<p>
  Collect and Publish are separate steps. Collect gathers a candidate snapshot and
  never deploys. Publish decides, fails closed, and deploys only a verified
  candidate. The home page shows when sources were last independently verified,
  when the last collection succeeded, and when the published snapshot last
  changed. A snapshot that is old is not necessarily stale, and a recent one is
  not proof of a recent check.
</p>
<h2 id="limits-heading">Limits</h2>
<ul>
  <li>KEV and CVE records describe vulnerabilities, not your exposure.</li>
  <li>Extracted product and version inventories can be partial; the page says so per record.</li>
  <li>Enrichment can be missing; missing is shown as unavailable, never as zero.</li>
</ul>
<p>Only the latest two published snapshots are served on this site (<code>data/snapshots/</code>); older ones are kept in the repository, on the <code>pulse-state</code> branch.</p>
<p>Full documentation is in the
<a href="https://github.com/Mehrn0ush/silastron-security-pulse/tree/main/docs" rel="noopener noreferrer">docs folder</a>.</p>
"""

def body_sha256() -> str:
    return hashlib.sha256(_BODY.encode("utf-8")).hexdigest()


_PRE = """<!DOCTYPE html>
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
      <div class="header-copy"><h1>Methodology</h1></div>
      <nav class="page-nav" aria-label="Page"><a href="/">Home</a><a href="/methodology/" aria-current="page">Methodology</a></nav>
    </header>
    <main id="main">
"""


def build_methodology_page(site_dir: Path, *, base_url: str, footer: Node) -> None:
    base_url = base_url.rstrip("/")
    head = head_tags(
        base_url=base_url,
        path="/methodology/",
        title="Methodology - Silastron Security Pulse",
        description="How Silastron Security Pulse reads CISA KEV, CVE, CVSS and SSVC signals, what it publishes and what it does not.",
        csp_value=csp(script_hash=None, self_scripts=True, connect_self=True, images=True),
    )
    target = site_dir / "methodology"
    target.mkdir(parents=True, exist_ok=True)
    page = (
        _PRE.replace("{head}", head)
        + '<section aria-labelledby="signals-heading">'
        + _BODY
        + "</section>\n    </main>\n    "
        + footer.html()
        + '\n    <script src="/stale.js"></script>\n  </body>\n</html>\n'
    )
    (target / "index.html").write_text(page, encoding="utf-8")
