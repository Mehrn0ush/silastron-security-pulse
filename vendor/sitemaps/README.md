# sitemaps.org XML schemas

`sitemap.xsd` and `siteindex.xsd` are the Sitemap protocol 0.9 schemas published at
<https://www.sitemaps.org/schemas/sitemap/0.9/>, retrieved 2026-11-13. CI validates the generated
`sitemap.xml` against them (`.github/scripts/validate_site_files.py`) so the check does not depend on
sitemaps.org being reachable.

Licence: the Sitemap protocol specification is licensed by its sponsors under the Creative Commons
Attribution-ShareAlike licence (sitemaps.org/terms.html, "Scope of Terms of Service; License"). The files are
unmodified. This repository only generates one sitemap (limits: 50,000 URLs and 50 MB per file; the generator
fails at 45,000 URLs or 40 MB and a sitemap index would then be needed), so `siteindex.xsd` is kept for that case.

SHA-256: `sitemap.xsd` `fbec77e84467050d5667394a57cc5cdfe1239d80aca1d61e9e0827173c3d9df9`,
`siteindex.xsd` `68d166ae92a07d5e8dbb0290d28c74aba24d896b721c0d3b1cee78c6aee9781e` (a test fails if either changes).
