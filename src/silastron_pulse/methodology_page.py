"""Static /methodology/ page: how to read the signals, sources and limits.

The text is authored here (trusted); no upstream value is interpolated.
"""

from __future__ import annotations

from pathlib import Path

CSP = (
    "default-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; "
    "img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "font-src 'none'; object-src 'none'; upgrade-insecure-requests"
)
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

_HEAD = f"""<!DOCTYPE html>
<html lang="en" data-theme="system">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta http-equiv="Content-Security-Policy" content="{CSP}" />
    <meta name="referrer" content="no-referrer" />
    <meta name="description" content="How Silastron Security Pulse reads CISA KEV, CVE, CVSS and SSVC signals, what it publishes and what it does not." />
    <title>Methodology - Silastron Security Pulse</title>
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

_FOOT = """
    </main>
    <footer>
      <p>A Silastron research dashboard. <a href="https://silastron.com" rel="noopener noreferrer">silastron.com</a></p>
      <p>CVE is a registered trademark of The MITRE Corporation. This preview does not modify or represent Silastron.com WordPress content.</p>
    </footer>
  </body>
</html>
"""


def build_methodology_page(site_dir: Path) -> None:
    target = site_dir / "methodology"
    target.mkdir(parents=True, exist_ok=True)
    (target / "index.html").write_text(_HEAD + '<section aria-labelledby="signals-heading">' + _BODY + "</section>" + _FOOT, encoding="utf-8")
