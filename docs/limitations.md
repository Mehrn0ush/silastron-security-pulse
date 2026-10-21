# Known limitations

- EPSS scores are not published. **BLOCKED** pending redistribution clearance.
- CVE enrichment uses GitHub raw files from cvelistV5. Production rate-limit
  behavior at ~1,700 requests is **UNVERIFIED**. Excess failures fail the run.
- KEV `dateReleased` may include non-millisecond fractional seconds. The raw
  string is preserved; it is not rewritten.
- CVSS is CNA-only. Missing CNA metrics yield `severity.status=unavailable`
  even if a CISA ADP container has a score.
- Product affectedness is source text, not CPE matching or asset inventory.
- Deployment exposure is always `not_assessed`.
- Change detection requires a previously valid snapshot in `pulse-state`. The
  first snapshot shows recent KEV additions, not a diff. A missing previous
  snapshot after source state exists fails closed.
- GitHub Pages CSP is a meta tag; GitHub may not emit equivalent HTTP headers.
  **UNVERIFIED** on a live Pages hostname because Pages is not deployed.
- `cvelistV5` `deltaLog.json` was 29.8 MB on 2026-10-21 and exceeds the 15 MB
  fetch bound. Incremental catch-up then uses If-None-Match on the KEV CVE set.
  First live collect is therefore still ~1 KEV + 1 delta.json + 1 failed/large
  deltaLog + ~1,754 CVE GETs. **UNVERIFIED** in production.
- Synthetic fixtures use `CVE-2099-*` IDs and must never be presented as live
  intelligence. Upstream samples under `tests/fixtures/upstream/` are real
  public records used only in tests.
