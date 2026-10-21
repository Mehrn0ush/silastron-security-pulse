# Data schemas

Runtime enforcement lives in `src/silastron_pulse/validate.py`. JSON Schema
files in `schemas/` document the public contract for WordPress or other
read-only consumers.

## Files a consumer should read

| File | Purpose |
| --- | --- |
| `data/manifest.json` | Latest pointer, stale/fresh flags, publication state |
| `data/latest.json` | Full snapshot |
| `data/preview.json` | Bounded table for the HTML preview |
| `data/snapshots/{id}.json` | Immutable historical snapshot after promote |

Until publication is approved, `preview/data/manifest.json` and
`public/data/manifest.json` are `status: unpublished` placeholders.

## Snapshot v1 required fields

- `schema_version`: `1.0.0`
- `snapshot_id`, `generated_at`, `status` (`ok` or `degraded`; `failed` is never promoted)
- `composite_risk_score`: always `null`
- `sources.kev|cve|epss`: status, parser version, license, retrieval and source timestamps, revision when the source provides one
- `records[]`: sorted unique `cve_id`
- `records[].kev.listed`: always `true` in this pipeline
- `records[].signals`: five independent objects
- `records[].links`: constructed HTTPS URLs to CVE.org, CISA KEV, and CVE List V5
- `changes`: new KEV, updated KEV, **removed KEV**, changed CVE information, EPSS changes
- `binding.collector_commit_sha`, `binding.source_state_revision`
- `sources.kev.retrieved_at` required on successful snapshots

Consumers must recompute freshness at viewing time from `snapshot_generated_at`
and `stale_after_hours`. Manifest `stale`/`fresh` are promote-time hints only.

## Manifest v1

- `stale` and `fresh` are opposites. Consumers **must** honor `stale=true`.
- `publication_state` is `published` or `not_published`.
- A missing or unpublished manifest means the feed is unavailable, not empty.

## Compatibility note for WordPress.com

Future theme consumption should fetch `manifest.json` first, refuse to render
records when `status` is `unpublished`/`failed` or `stale` is true without a
visible stale banner, and never compute a local risk score from these fields.
This repository does not deploy that theme.
