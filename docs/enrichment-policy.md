# Enrichment availability and publication eligibility

KEV source integrity and optional CVE List V5 / CNA enrichment are independent
dimensions. A verified KEV catalog is not invalidated by a missing CNA record.

This policy does not authorize republishing the rejected
`20261031T141620Z_c8b8ec309b66` artifact. See
[incident-2026-10-31-publication.md](incident-2026-10-31-publication.md).

## States

| `enrichment_availability.state` | Meaning | Publication effect |
| --- | --- | --- |
| `available` | Current CVE List V5 fetch succeeded and extraction is complete | Eligible |
| `partial` | Current fetch succeeded; extracted inventory is truncated | Eligible when bounded |
| `cvelist_v5_not_found` | Official constructed raw path returned HTTP 404 | Eligible only under absolute and proportional caps |
| `transient_failure` | Retryable timeout, 429, or 5xx after retries | Eligible only under a tighter cap |
| `unexpected_error` | Fetch failed without confirmed-absent evidence | Blocks |
| `unclassified` | Unavailable record lacks structured fetch evidence | Blocks |

HTTP 404 means the official CVE List V5 raw file is not served. It does **not**
prove the CVE is unpublished on CVE.org, reserved, rejected, or absent from
CISA. Historical error strings such as `HTTP 404 fetching …` stay
`unclassified`.

## Hard blockers (unchanged KEV contract)

- Invalid, corrupted, incomplete, or unverified KEV source data
- Candidate / Collect-time catalog mismatch
- Unexplained KEV ID set or material field substitution
- Older candidate than the published snapshot
- Unresolved deploy/persist divergence
- Systemic CVE List V5 source `failed` / `unavailable`
- Unexpected or unclassified enrichment loss
- Previously published current enrichment disappearing without a successful
  current fetch (cached 304 is not treated as loss)

## Bounded optional enrichment

A verified KEV catalog may publish when optional enrichment is unavailable
only when every condition holds:

- each gap has structured fetch evidence
- missing records remain in the catalog (`completeness=unavailable`)
- no CVSS, product, version, CWE, or remediation value is fabricated
- previously known enrichment is not presented as a current successful fetch
- source-specific status and timestamps stay visible
- the decision lists exact counts, CVE IDs, and reasons

## Thresholds

Observed production catalog on 2026-10-31: **1766** KEV IDs, **1** reserved
CVE List V5 file.

| Cap | Absolute | Ratio | Applies when |
| --- | --- | --- | --- |
| Confirmed CVE List V5 404 | 8 | 0.5% | Ratio only if catalog ≥ 200 records |
| Transient fetch failure | 2 | 0.2% | Ratio only if catalog ≥ 200 records |
| Unclassified | 0 | n/a | Always |
| Unexpected error | 0 | n/a | Always |
| Systemic unavailable mix | 12 | 5% | Both absolute floor and ratio |

The PUBLISH / SKIP / REJECT contract is unchanged. Eligible bounded
enrichment uses `publish` with reason `first_publish`, `eligible`, or
`enrichment_update`. Policy refusal uses `reject` / `degraded_blocked`.

`enrichment_update` is used when the KEV digest is unchanged and enrichment
availability or CVE content digest improves. That can republish after a later
successful CVE List V5 fetch.

## Residual heuristic risk

These caps are informed by one incident and the current KEV size. They are
not a proof that every 404 below the cap is a reserved ID. A coordinated
burst of reserved KEV identifiers at or below 8 records can publish without
CNA enrichment. Catalogs smaller than 200 records rely on absolute caps only.
