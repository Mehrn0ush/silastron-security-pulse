# Data status

The homepage no longer labels an old published snapshot as a stale collection.
GitHub Pages is static: an unchanged Collect that SKIPs does not create a new
vulnerability snapshot. Without a separate status document, the public site
cannot know that a later verification succeeded.

## Verification-status publication

`data/verification-status.json` is operational status, not a CVE snapshot.

- Collect still writes only `candidate.json` and related Collect artifacts.
- Publish writes verification status after a `publish` or `skip` decision.
- `skip` with `unchanged_upstream` or `already_published` may deploy the
  existing published tree plus the new status file. That is a Pages deploy of
  the current site, not a new snapshot and not a history rewrite.
- Failed or rejected decisions do not claim `verified`.
- `verified_at` is the Collect completion time of a validated artifact, never
  inferred from clock age or an HTTP 200.

GitHub Pages cannot patch one file without a deploy. Status-only publication is
the smallest safe way to expose a newer successful verification.

## What the homepage shows

| Field | Meaning |
| --- | --- |
| Last successful verification | Present only when `verification-status.json` validates and `verified` is true |
| Last successful collection | Collect completion from verification evidence, else the published snapshot |
| Last published snapshot | Immutable snapshot `generated_at` |
| Last upstream update | Source-provided KEV/CVE timestamps when present |
| Publication consistency | `publication-status.json` state |

Integrity failures still use the blocking banner. Unchanged verified catalogs
use neutral wording.
