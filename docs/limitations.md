# Known limitations

- EPSS scores are not published. **BLOCKED** pending redistribution clearance.
- CVE enrichment uses GitHub raw files from cvelistV5. Initial-subset rate-limit
  behavior at ~1,754 requests is **UNVERIFIED** in Actions. Excess failures fail
  the run. Incremental runs do not repeat that poll.
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
- First live collect still performs ~1,754 CVE GETs for the KEV subset.
- If `deltaLog.json` exceeds 40 MB, collection fails closed instead of
  downloading it or polling every KEV CVE. Default HTTP timeout is 30s;
  the measured log GET was 17.94s.
- Synthetic fixtures use `CVE-2099-*` IDs and must never be presented as live
  intelligence. Upstream samples under `tests/fixtures/upstream/` are real
  public records used only in tests.
