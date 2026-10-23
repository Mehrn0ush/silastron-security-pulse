# Workflow operation

All GitHub Actions are SHA-pinned. Workflows default to `contents: read`.
Pull requests never collect live intelligence and never deploy Pages.

## `ci.yml`

- Triggers: pull request, push to `main`, workflow_dispatch
- Permissions: `contents: read`
- Runs unit tests on Python 3.11 and 3.12
- Validates unpublished manifests and schema JSON

## `collect.yml`

- Triggers: **workflow_dispatch** and **schedule** `0 8 * * *` (08:00 UTC)
- Runs only from `main`
- `concurrency: collect` with `cancel-in-progress: false` so overlapping runs
  queue instead of cancelling in-progress collection
- Permissions: `contents: write` (fast-forward `pulse-state` only), `actions: read`
- Checks out collector code and `pulse-state`
- Writes `dist/candidate.json` + `candidate.meta.json`, uploads `pulse-candidate`
- On success, commits `source/` and `candidates/` to `pulse-state`
- Refuses to commit if `published/` is dirty or staged
- Does not deploy Pages and does not write `published/`
- If collection fails, the job fails before persist; last-known-good pulse-state
  is left in place
- HTTP 429/5xx retries remain in `HttpsFetcher`; this workflow does not publish

A successful scheduled Collect is a candidate only. Publication still requires
an explicit Publish dispatch with that run's `collect_run_id`.

## `publish.yml`

- Trigger: workflow_dispatch with `confirm=PUBLISH` and **required** `collect_run_id`
- No schedule. A newer Collect run is not selected automatically.
- Accepts Collect runs whose event is `workflow_dispatch` or `schedule`
- Runs only from `main`
- Verifies Collect run repository, workflow identity, branch, success, SHA, artifact
  name, expiry, and `candidate.json` content SHA-256 (against `candidate.meta.json`,
  `SHA256SUMS`, and the expected content digest). GitHub `artifact.digest` is the
  zip archive hash and is not compared to `candidate.json`.
- `persist-published` needs `[build, deploy]` so `needs.build.outputs.snapshot_id`
  is written into the pulse-state commit message after a successful deploy
- Copies actual `pulse-state/published` into the promote directory so replay is
  compared against last published state
- Deploy job permissions: `pages: write`, `id-token: write`
- Uses the `github-pages` environment (required reviewers are an owner action)
- After a successful deploy, commits `published/` to `pulse-state`
- Untrusted pull requests cannot dispatch this on `main`

Do **not** run this workflow until publication is explicitly approved.

Runners are pinned to `ubuntu-24.04` so `ubuntu-latest` cannot silently move
to Ubuntu 26.

## Action pins (verified 2026-10-23 via GitHub git refs API)

| Action | Tag | SHA |
| --- | --- | --- |
| actions/checkout | v5.1.0 | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` |
| actions/setup-python | v6.3.0 | `ece7cb06caefa5fff74198d8649806c4678c61a1` |
| actions/upload-artifact | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| actions/download-artifact | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| actions/upload-pages-artifact | v3.0.1 | `56afc609e74202658d3ffba0e8f6dda462b719fa` |
| actions/configure-pages | v5.0.0 | `983d7736d9b0ae728b81ab479565c72886d7745b` |
| actions/deploy-pages | v4.0.5 | `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e` |

`configure-pages` is listed for operators who later add it; the current publish
workflow uses the Pages artifact + deploy-pages pair.
