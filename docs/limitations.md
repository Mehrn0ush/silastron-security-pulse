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
  `records[].completeness=complete` means the extracted CNA/KEV inventory was
  stored within bounds; it does not prove complete real-world product coverage.
- `snapshot.status` is collection outcome. A collect that finishes with some
  truncated version lists is `degraded`, not `failed`. Freshness is computed at
  viewing time and is independent of both.
- Deployment exposure is always `not_assessed`.
- Change detection requires a previously valid snapshot in `pulse-state`. The
  first snapshot shows recent KEV additions, not a diff. A missing previous
  snapshot after source state exists fails closed.
- `snapshot.changes` is a collect-time comparison against the previous
  available snapshot (published latest if present, otherwise the last
  candidate). The dashboard What's Changed section does **not** use that
  field. It uses `preview.publication_comparison`, computed at promote time
  against the previously published `latest.json`. The first published
  snapshot has no predecessor; the UI reports "No comparison available"
  rather than treating the catalog as newly added or showing zero changes.
  Newly extracted remediation is `enrichment_count`, not `updated_count`.
- GitHub Pages CSP is a meta tag; GitHub may not emit equivalent HTTP headers.
  **UNVERIFIED** on a live Pages hostname because Pages is not deployed.
- First live collect still performs ~1,754 CVE GETs for the KEV subset.
- If `deltaLog.json` exceeds 40 MB uncompressed (`HEAD` without gzip),
  collection fails closed instead of downloading it or polling every KEV CVE.
  GET uses `Accept-Encoding: gzip`; the live uncompressed transfer was
  ~228s / 29.88 MB, while gzip was ~4.2s / 1.73 MB on the wire. Incremental
  completeness is unchanged: the full log is still parsed when `fetchTime`
  advances.
- Storage bounds (200 products, 200 versions per product, 8,000-character
  descriptions, 3 MB CVE bodies) can still leave a record `partial` or
  `unavailable`. After the 2026-10-21 incremental recovery collect, these 18
  records remain `completeness=partial` because CNA version lists exceed 200
  entries. They must not be treated as complete affected-version inventories:
  CVE-2017-6736, CVE-2017-6737, CVE-2017-6738, CVE-2017-6743, CVE-2017-6744,
  CVE-2023-20109, CVE-2023-33063, CVE-2023-33107, CVE-2024-20399,
  CVE-2025-20333, CVE-2025-20352, CVE-2025-20362, CVE-2026-20122,
  CVE-2026-20127, CVE-2026-20245, CVE-2026-20262, CVE-2026-21385, and
  CVE-2026-76504 (up to 1,544 omitted versions on CVE-2017-6736). Each stores
  `omitted_version_count`, `truncated_fields=["versions"]`, and
  `product_affectedness.status=source_asserted_partial`. Preview tables show
  KEV vendor/product plus completeness, not the full CNA version list.
- Synthetic fixtures use `CVE-2099-*` IDs and must never be presented as live
  intelligence. Upstream samples under `tests/fixtures/upstream/` are real
  public records used only in tests.
