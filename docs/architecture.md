# Architecture

Silastron Security Pulse is a deterministic, bounded collector that writes
versioned JSON. There is no database, queue, or WordPress integration.

```
CISA KEV JSON ──► KEV adapter ──► selected CVE IDs
                                      │
CVE List V5 delta.json / ETag / raw ──┴──► CVE adapter
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
   published state. Rollback is an explicit CLI/workflow operation.
5. **Signals stay distinct.** Confirmed exploitation, EPSS probability, CVSS
   severity, product affectedness, and deployment exposure are separate objects.
   `composite_risk_score` is always `null`.
6. **External data is untrusted.** Strings are sanitized, JSON is size- and
   depth-bounded, URLs are HTTPS-allowlisted, and the preview never uses
   `innerHTML`.
7. **Authoritative links are constructed**, not copied from untrusted
   reference fields. Preview hyperlinks are path-restricted to the CISA KEV
   catalog page, CVE.org record pages, and CVE List V5 blob URLs.
8. **No large upstream datasets are committed.** Tests use synthetic fixtures
   plus small official samples (one KEV excerpt and CVE-2021-44228). Live
   snapshots stay on `pulse-state` and workflow artifacts until publication is
   approved.

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
- `snapshot_id` derived from KEV content hash and generation time
- source metadata: URL, retrieval time, publication/update time, revision,
  parser version, license, content hash
- sorted records keyed by exact CVE ID
- a change set against the previously published or candidate snapshot, including
  KEV removals
- `binding.collector_commit_sha` and `binding.source_state_revision`
