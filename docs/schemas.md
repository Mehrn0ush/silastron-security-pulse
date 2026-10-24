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

## Preview `publication_comparison`

Optional object written at promote time. It is **not** `snapshot.changes`.

- `available`: `true` only when the previously published `latest.json` exists,
  has a different `snapshot_id`, and can be rebuilt into comparable entries
- `reason`: present when unavailable (`no_previous_published_snapshot`,
  `incompatible_published_snapshot`, or `same_published_snapshot`)
- `compared_to_snapshot_id` / `compared_to_generated_at`: previous published
  snapshot identity
- `added_count` / `removed_count` / `updated_count`: integers when available,
  otherwise `null`. Unavailable must not be rendered as zero
- `updated_count` is KEV, CVE, CVSS, or completeness *field* changes only.
  Newly extracted remediation or other enrichment is `enrichment_count`, not a
  core update. Older published previews may still put enrichment-only rows in
  `rows` as `cve_update` with empty `changed_fields`; consumers must
  leave those rows unresolved instead of treating missing field-level evidence
  as confirmed enrichment or as zero core updates
- `enrichment_count` / `enrichment_sample`: optional. Absent on snapshots
  published before this field existed
- `rows`: bounded field-level before/after values for added, removed, and core
  updates. `added_count`, `removed_count`, `updated_count`, and
  `enrichment_count` are full-catalog totals computed before `rows` is
  truncated. Retrieval timestamps are ignored. EPSS is excluded while
  redistribution remains disabled. Empty `changed_fields` is not a reason to
  invent "Not applicable" values

## Snapshot v1 required fields

- `schema_version`: `1.0.0`
- `snapshot_id`, `collection_started_at`, `collection_completed_at`, `generated_at`, `status`
- `status` is **collection outcome only**: `ok`, `degraded`, or `failed`. `degraded` means the collect succeeded with incomplete extracted inventories or unavailable enrichments. It is not a failed collection and is not a freshness flag. `failed` is never promoted.
- `generated_at` equals `collection_completed_at` (snapshot identity time). `collection_started_at` is when fetches began.
- Record completeness is separate: `records[].completeness` (`complete`, `partial`, or `unavailable`) and `summary.complete_records` / `partial_records` / `unavailable_records`. `partial` is a truncated extracted product/version inventory. `unavailable` is a missing CVE enrichment. A `complete` extraction does not prove complete real-world product affectedness.
- `records[].cve.omitted_product_count` / `omitted_version_count` when storage bounds drop CNA entries
- `composite_risk_score`: always `null`
- `sources.kev|cve|epss`: status, parser version, license, retrieval and source timestamps, revision when the source provides one
- `records[]`: sorted unique `cve_id`
- `records[].kev.listed`: always `true` in this pipeline
- `records[].signals`: five independent objects
- `records[].links`: constructed HTTPS URLs to CVE.org, CISA KEV, and CVE List V5
- `records[].remediation`: optional evidence object. `status` is `available` or
  `unavailable`. Items are copied from CISA KEV `requiredAction`/`notes` (and
  HTTPS URLs found in those fields), CVE List V5 CNA `solutions` (CNA-Reported
  Solution; not independently verified),
  CNA `workarounds` (Mitigation), and CNA references tagged `vendor-advisory`
  (Reference). A missing object is valid for snapshots collected before this
  field existed. Absence of items is not proof that no vendor fix exists. The
  collector never infers a patch from CVSS, affected-version ranges,
  descriptions, or untagged CVE reference titles.
- `changes`: new KEV, updated KEV, **removed KEV**, changed CVE information, EPSS changes
- `binding.collector_commit_sha`, `binding.source_state_revision`
- `sources.kev.retrieved_at` required on successful snapshots

Consumers must recompute freshness at viewing time from `snapshot_generated_at`
and `stale_after_hours`. Manifest `stale`/`fresh` are promote-time hints only.
Do not derive freshness from `status` or from `records[].completeness`.

## Manifest v1

- `stale` and `fresh` are opposites. Consumers **must** honor `stale=true`.
- `publication_state` is `published` or `not_published`.
- A missing or unpublished manifest means the feed is unavailable, not empty.

## Compatibility note for WordPress.com

Future theme consumption should fetch `manifest.json` first, refuse to render
records when publication `status` is `unpublished`/`failed` or `stale` is true
without a visible stale banner, treat snapshot `status=degraded` as a successful
collect with incomplete records (not a failure), read completeness from
`records[].completeness` and the summary counts, and never compute a local risk
score from these fields. This repository does not deploy that theme.
