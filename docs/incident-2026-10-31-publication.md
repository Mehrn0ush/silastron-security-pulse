# Incident: 31 October 2026 publication rejection

Verification date: 2026-11-01. This document is an investigation record. It
does not authorize republication of the rejected artifact.

## Identifiers

| Item | Value |
| --- | --- |
| Collect | [41209169460](https://github.com/Mehrn0ush/silastron-security-pulse/actions/runs/41209169460) scheduled, conclusion success |
| Auto-publish | [41209374680](https://github.com/Mehrn0ush/silastron-security-pulse/actions/runs/41209374680) rejected on both attempts |
| Snapshot | `20261031T141620Z_c8b8ec309b66` |
| Digest | `c30a3b5b62bba04a9633e9c6e7ff71f10af983fda14fa6a95e2e4db24cb6dec0` |
| KEV | 1766 / 1766, catalogVersion `2026.10.30` |
| Decision | `reject` / `degraded_blocked` |

## Findings

1. **CVE List V5 path construction was correct.**
   `cvelist_v5_relpath("CVE-2026-118527")` is
   `cves/2026/118xxx/CVE-2026-118527.json` (`118527 // 1000 = 118`). Sibling
   `CVE-2026-111357` (same CISA add date) fetched successfully from
   `cves/2026/111xxx/`.
2. **The record was reserved, not a collector path bug.** On 2026-11-01,
   CVE.org still reported “This ID has been reserved by a CNA.” CISA KEV and
   the 30 October CISA alert name the ID. CVE List V5 raw still returned
   HTTP 404. A 404 is evidence that the official raw file is not served. It
   is **not** proof the CVE is unpublished elsewhere.
3. **The failure was persistent**, not a one-off timeout. Collect on 31
   October and observation on 1 November both saw 404 / reserved.
4. **KEV source integrity remained independently valid.** Catalog count
   matched records; publication binding matched the Collect-time catalog.
5. **Rejecting all 1766 KEV records was unnecessary.** The policy treated
   any unavailable CNA enrichment as a hard block. The KEV listing for
   `CVE-2026-118527` was verified; only optional CVE List V5 enrichment was
   missing.

## Policy change

Later Collects record structured `enrichment_availability`. Confirmed CVE
List V5 absence is bounded and publishable. Unclassified historical error
strings, including this artifact’s plain `HTTP 404 fetching …` field, remain
insufficient evidence. This rejected snapshot is not force-published.
