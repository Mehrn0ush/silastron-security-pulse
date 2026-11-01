# Architecture

Silastron Security Pulse is a deterministic, bounded collector that writes
versioned JSON. There is no database, queue, or WordPress integration.

```
CISA KEV JSON ──► KEV adapter ──► selected CVE IDs
                                      │
CVE List V5 delta.json / deltaLog / raw ─┴──► CVE adapter
                                      │
NVD CVE API 2.0 ──► optional NVD adapter ─┘
                                      │
FIRST EPSS ──► disabled adapter ──────┘
                                      │
                                      ▼
                         snapshot builder + change diff
                                      │
                    pulse-state source/ + candidates/
                                      │
                          candidate artifact (transfer only)
                                      │
                         promote guard (fail closed)
                                      │
                    pulse-state published/ + GitHub Pages
```

Persistent layout is documented in [collection-state.md](collection-state.md).

## Design decisions

1. **KEV is the event source.** CVE List V5 is enrichment for KEV identifiers
   only. The pipeline never invents CVE relationships.
2. **EPSS is implemented but disabled.** Public availability is not treated as
   a redistribution right.
3. **Stdlib-only runtime.** The collector uses Python 3.11+ with no third-party
   packages, reducing supply-chain surface.
4. **Collection and publication are separate workflows.** A failed collect
   cannot deploy Pages and cannot replace last-known-good source, candidate, or
   published state. A successful scheduled Collect may start Publish, still
   bound to that run's artifact. Manual Publish and frontend deploy stay
   independent. Rollback is an explicit CLI/workflow operation.
5. **Signals stay distinct.** Confirmed exploitation, EPSS probability, CVSS
   severity, product affectedness, and deployment exposure are separate objects.
   `composite_risk_score` is always `null`.
6. **External data is untrusted.** Strings are sanitized, JSON is size- and
   depth-bounded, URLs are HTTPS-allowlisted, and the preview never uses
   `innerHTML`.
7. **Authoritative links are constructed**, not copied from untrusted
   reference fields. Preview hyperlinks are path-restricted to the CISA KEV
   catalog page, CVE.org record pages, and CVE List V5 blob URLs.
8. **Collect-time KEV integrity is independent of publication binding.** The
   collector validates the documented CISA feed, compares parsed records to the
   original bytes, and stores the upstream digest. Publication still does not
   re-fetch CISA. HTTPS is not publisher authentication.
9. **Pages deploy and pulse-state persist are not atomic.** Intent is
   persisted before deploy. `publication-status.json` records pending,
   deployed, persisted, failed, and uncertain outcomes. Later publication
   and frontend deploy fail closed on unresolved publication. Recovery
   verifies the original artifact and never silently rolls back
   `published/latest`. A successful Actions job is not proof of CDN
   visibility.
10. **CVE history is published-to-published.** Compact indexes are generated
    from immutable snapshots at promote time and merged into a durable ledger
    so first-observed dates survive the 36-snapshot comparison window. The
    explorer loads one bounded CVE file on demand and never treats extraction
    enrichment as an upstream change. See [cve-history.md](cve-history.md).
11. **KEV integrity and CVE enrichment are separate.** Publication can accept
    bounded, classified CVE List V5 absence. Missing enrichment never drops
    a verified KEV row and never fabricates CNA fields. See
    [enrichment-policy.md](enrichment-policy.md).
12. **No large upstream datasets are committed.** Tests use synthetic fixtures
    plus small official samples (one KEV excerpt and CVE-2021-44228). Live
    snapshots stay on `pulse-state` and workflow artifacts until publication is
    approved.
13. **NVD enrichment is optional and source-attributed.** The official NVD
    CVE API 2.0 may add CVSS, CWE, product, and reference assertions. It is
    never a KEV publication dependency. CNA and NVD disagreements are
    preserved, not merged into a composite score. See
    [vulnerability-intelligence.md](vulnerability-intelligence.md).

## Runtime layout

| Path | Role |
| --- | --- |
| `src/silastron_pulse/` | Collector, adapters, validation, promote guard |
| `schemas/` | Versioned JSON schemas and URL allowlist |
| `preview/` | Static GitHub Pages UI |
| `public/data/` | Unpublished local placeholder only |
| `tests/fixtures/` | Synthetic source documents |
| `.github/workflows/` | CI, collect, publish |

## Snapshot identity

Each successful collection writes `candidate.json` with:

- `schema_version` `1.0.0`
- `snapshot_id` derived from KEV content hash and `generated_at`
  (`generated_at` is collection completion, not fetch start)
- `collection_started_at` / `collection_completed_at` on the snapshot
- `status`: collection outcome (`ok`, `degraded`, `failed`). `degraded` is a
  successful collect with incomplete extracted inventories or unavailable
  enrichments, not a failed collection and not a freshness flag.
- `records[].completeness` and `summary.complete_records` /
  `partial_records` / `unavailable_records`: extracted-inventory completeness.
  A complete extraction does not prove complete real-world product affectedness.
- source metadata: URL, retrieval time, publication/update time, revision,
  parser version, license, content hash
- sorted records keyed by exact CVE ID
- a change set against the previously published or candidate snapshot, including
  KEV removals
- `binding.collector_commit_sha` and `binding.source_state_revision`
