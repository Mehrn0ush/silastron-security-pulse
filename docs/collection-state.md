# Collection-state architecture

Persistent intelligence state lives on the dedicated Git branch `pulse-state`.
GitHub Actions artifacts are a transfer mechanism for publication, not the
system of record.

## Why a Git branch, not a database

The collector is a bounded, deterministic batch job. State is a small set of
versioned JSON documents. A dedicated branch gives:

- atomic updates via a single fast-forward commit
- recoverable history without introducing an external database
- reviewable diffs of source and snapshot revisions
- no secrets and no hosted service to operate

## Layout on `pulse-state`

```
source/manifest.json          # committed last; presence means source state exists
source/kev/meta.json
source/kev/catalog.json
source/cve/index.json         # delta fetchTime, log ETag/size/skip, per-CVE etags
source/cve/records/CVE-*.json
candidates/latest.json        # last successful candidate snapshot
candidates/latest.meta.json   # collector SHA, source revision, content sha256
published/latest.json         # last promoted snapshot (publication only)
published/preview.json
published/manifest.json
published/history.json
published/snapshots/{id}.json
```

Source, candidate, and published trees are separate. A failed collection does
not rewrite candidate or published files. The source manifest is written last so
a crash mid-write does not claim that source state is complete.

## Lifecycle

1. **Collect** (`workflow_dispatch` or daily `schedule` at 08:00 UTC on `main`)
   checks out collector code and `pulse-state`, takes a filesystem lock, loads
   the previous valid snapshot from `published/latest.json` or
   `candidates/latest.json`, fetches KEV, incrementally enriches CVE List V5
   (`delta.json` / `deltaLog.json`, not a per-CVE poll of the full KEV set),
   writes `dist/candidate.json`, copies the Collect-time KEV catalog into the
   `pulse-candidate` artifact, commits `source/` and `candidates/` to
   `pulse-state`, and uploads that artifact. It never writes `published/`.
   See [cve-sync.md](cve-sync.md).
2. **Publish** binds one Collect run. A successful scheduled Collect on `main`
   starts Publish via `workflow_run` with that exact run ID. Manual dispatch
   remains the fallback and still requires `collect_run_id`. It verifies
   repository, Collect workflow path **and** name, `main`, success, allowed
   event, head SHA, artifact name, expiry, SHA-256 digest, and that candidate
   KEV records equal the bundled Collect-time catalog. Automated publication
   accepts only `schedule`; manual dispatch still accepts `workflow_dispatch`
   or `schedule`. The selected run is never the newest Collect. Fail-closed
   `decide-publication` skips unchanged upstream data and rejects stale,
   catalog-mismatched, or degraded-beyond-policy candidates. It copies the
   actual last published snapshot from `pulse-state` into the promote directory
   so stale replay is compared against real published state, then deploys Pages
   and commits `published/` only after a successful deploy job. Pages and
   pulse-state persist are sequential; a persist failure after deploy is a
   recorded divergence, not a silent success.
3. **Rollback** is `silastron-pulse rollback --confirm ROLLBACK --snapshot-id …`.
   It is the only operation allowed to re-promote a superseded snapshot.

## Concurrency and recovery

- Workflow `concurrency: collect` with `cancel-in-progress: false`.
- Process lock `.collect.lock` (exclusive `flock`) around a local state dir.
- `pulse-state` rejects force pushes and deletions.
- Push is fast-forward only. A rejected push fails the collect job.
- Failed collects write `collection-status.json` in the job workspace only.

## Binding

Every candidate includes:

```json
"binding": {
  "collector_commit_sha": "<GITHUB_SHA of the Collect commit>",
  "source_state_revision": "<KEV catalogVersion>:<CVE revision>"
}
```

`candidate.meta.json` repeats those fields plus `content_sha256`. Publication
rejects a missing, mismatched, or unbound artifact.
