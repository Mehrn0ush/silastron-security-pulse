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
- Change detection requires a previously published snapshot. The first
  snapshot shows recent KEV additions, not a diff.
- GitHub Pages CSP is a meta tag; GitHub may not emit equivalent HTTP headers.
  **UNVERIFIED** on a live Pages hostname because Pages is not deployed.
- The collector does not retry with backoff beyond a single request per URL.
- Synthetic fixtures use `CVE-2099-*` IDs and must never be presented as live
  intelligence.
