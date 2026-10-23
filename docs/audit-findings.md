# Audit finding status F1–F14

Evidence date: 2026-10-21. Tests: `PYTHONPATH=src python3 -m unittest discover -s tests -v` → **74 passed**.

| ID | Severity | Status | Evidence |
| --- | --- | --- | --- |
| F1 | BLOCKER | **Resolved** | `origin/main` = `38b9ab55007bbf4211100d808c7f7103b9d5f6b7` (stub only). Feature branch was not merged into main. Default branch is `main`. |
| F2 | BLOCKER | **Resolved with owner follow-up** | PR #6 base is `main`. Main protection: 1 review, required checks `Test Python 3.11` / `Test Python 3.12`, no force push, no deletions. `pulse-state` now rejects force push and deletion. Pages environment still lacks required reviewers (`can_admins_bypass: true`) — owner action. |
| F3 | BLOCKER | **Resolved** | Incremental CVE strategy uses `delta.json` identity and a bounded `deltaLog.json` catch-up (40 MB). HEAD skips oversized logs; missed windows resync the KEV subset once; incomplete sync fails closed. Per-CVE polling of all KEV IDs is not the scheduled path. Evidence: [cve-sync.md](cve-sync.md), `tests/test_cve_sync.py`. |
| F4 | BLOCKER | **Resolved** | System of record is `pulse-state` (`docs/collection-state.md`). Artifacts are not the only persistence. Collect commits `source/` + `candidates/`. Publish persists `published/` after deploy. |
| F5 | HIGH | **Resolved** | `HttpsFetcher` retries retryable statuses including 429/5xx, honors `Retry-After`, exponential backoff, 304, and min-interval throttle. Tests: `test_rate_limit_and_transient_errors_retry`. |
| F6 | HIGH | **Resolved** | `ChangeSet.removed_kev_entries` and preview rows for removals. Tests: `test_kev_removals_are_recorded`, `test_removed_kev_entries_are_detected`. |
| F7 | HIGH | **Resolved** | Provided `--previous` path must exist and validate. Existing source state requires a previous snapshot. Tests: `test_missing_previous_snapshot_fails`, `test_source_state_without_snapshot_fails`. |
| F8 | HIGH | **Resolved** | CVE comparable fields include `date_updated` and content; delta/ETag refetch is independent of KEV identity. Test: `test_delta_forces_cve_refetch_independent_of_kev`. |
| F9 | HIGH | **Resolved** | Promote compares against actual `published/latest.json`, rejects older `generated_at`, and rejects superseded `snapshot_id` unless `rollback --confirm ROLLBACK`. Tests: `test_stale_candidate_replay_is_rejected`, `test_superseded_snapshot_id_cannot_be_replayed_without_rollback`. |
| F10 | HIGH | **Resolved** | Publish requires `collect_run_id`. `verify_collect_run` checks repository, Collect workflow, `main`, success, `workflow_dispatch` or `schedule`, SHA, artifact name/expiry, and digest. Tests: `test_unrelated_collection_artifact_is_rejected`, `test_artifact_integrity_mismatch_is_rejected`, `test_missing_digest_is_rejected`, `test_schedule_collect_run_is_acceptable_for_manual_publish`. |
| F11 | MEDIUM | **Resolved** | `sources.kev.retrieved_at` is required on successful snapshots. Per-CVE `retrieved_at` is preserved across HTTP 304. Tests: `test_retrieval_timestamps_are_required_and_preserved_on_304`. |
| F12 | MEDIUM | **Resolved** | Preview recomputes freshness with `Date.now()` from `snapshot_generated_at`. Path-restricted outbound links in `preview/app.js` and `links.py`. Tests: `test_preview_computes_freshness_at_viewing_time`, `test_path_restricted_links`. |
| F13 | MEDIUM | **Resolved** | Product and CWE truncation is recorded on `truncated_fields` / `cwes_incomplete`. Tests: `test_product_truncation_is_explicit`, `test_cwe_truncation_is_explicit`. |
| F14 | LOW | **Resolved** | Retries, backoff, and Retry-After as F5. Incomplete enrichment is `degraded`/`unavailable` with an explicit error string, not silent reuse of unverified cache. |

## Owner actions still required

1. Add required reviewers to the `github-pages` environment and disable
   `can_admins_bypass` if the plan allows.
2. Optionally enable `enforce_admins` on `main`.
3. Do not enable scheduled collection until after a successful supervised
   live collect.
4. Do not run Publish until source-contract review is accepted.

## Remote changes made during this correction

- Confirmed `main` default at stub `38b9ab5`; PR #6 already retargeted to `main`.
- Applied `pulse-state` branch protection: `allow_force_pushes=false`,
  `allow_deletions=false`, no required reviews (so Collect/Publish can
  fast-forward state). `enforce_admins` remains false.
- PUT `github-pages` environment with empty `reviewers` did **not** add
  required reviewers. No Pages deploy was performed.
