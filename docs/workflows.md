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

A successful **scheduled** Collect may start automated Publish via
`workflow_run`. The Publish workflow still binds that exact Collect `run_id`
and never selects the newest candidate. Manual Collect remains a candidate
only until an operator dispatches Publish with that run ID.

## `publish.yml`

- Triggers: `workflow_run` (Collect completed) **and** `workflow_dispatch`
  with `confirm=PUBLISH` and **required** `collect_run_id`
- No independent Publish cron. Automated runs use `run-name`
  `Auto-publish Collect <id>`
- Automated publication requires Collect `event=schedule`, `conclusion=success`,
  `head_branch=main`, workflow name `Collect`, and the same-repository head.
  `workflow_run.branches: [main]` prevents other branches from starting Publish.
  Ineligible Collect completions write a skip summary instead of promoting.
- Manual dispatch still accepts Collect `workflow_dispatch` or `schedule`
- A newer Collect run is not selected automatically
- Runs only from `main`
- `decide-publication` runs after artifact download and fail-closes before
  promote. Unchanged upstream KEV/CVE identity is a successful skip
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
- After a successful deploy, verifies that `publication_comparison` still
  names the live `pulse-state/published/latest.json`, then commits `published/`
  to `pulse-state`. A stale baseline is refused even if another Publish run
  already persisted. Workflow `concurrency: pages` is not the only guard.
- Untrusted pull requests cannot dispatch this on `main` and cannot start Collect
  on `main`, so they cannot start automated publication

Scheduled Collect plus automated Publish is the daily production path. Manual
Publish remains the explicit fallback.

## `deploy-frontend.yml`

- Trigger: workflow_dispatch with `confirm=DEPLOY_FRONTEND` from `main` only
- No schedule, no Collect, no Promote, and no `pulse-state` write
- Shares `concurrency: pages` / `cancel-in-progress: false` with Publish so
  the two cannot interleave Pages artifacts
- Copies `pulse-state/published/` byte-for-byte into `_site/data/`, then copies
  current `preview/` HTML/CSS/JS
- `verify-published-site` fails closed if published JSON is missing, invalid,
  inconsistent, or mutated during the copy
- Does not recompute `publication_comparison` or change publication timestamps
- Deploy uses the same `github-pages` environment and `deploy-pages` action as
  Publish. A failed build does not deploy, so the last-known-good Pages site
  remains. Because this workflow never persists `published/`, pulse-state is
  unchanged on success or failure

Use this when UI on `main` should ship against the currently published
snapshot. Intelligence updates still require Publish.

Runners are pinned to `ubuntu-24.04` so `ubuntu-latest` cannot silently move
to Ubuntu 26.

## Action pins (verified 2026-10-24 via GitHub git refs API)

Artifact and Pages actions below run on Node.js 24. The previous v4
artifact pins ran on Node 20 and were being forced onto Node 24.

| Action | Tag | SHA |
| --- | --- | --- |
| actions/checkout | v5.1.0 | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` |
| actions/setup-python | v6.3.0 | `ece7cb06caefa5fff74198d8649806c4678c61a1` |
| actions/upload-artifact | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| actions/download-artifact | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| actions/upload-pages-artifact | v5.0.0 | `fc324d3547104276b827a68afc52ff2a11cc49c9` |
| actions/configure-pages | v5.0.0 | `983d7736d9b0ae728b81ab479565c72886d7745b` |
| actions/deploy-pages | v5.0.1 | `368f82528645a54fb793d4d04e342629a3f51346` |

`configure-pages` is listed for operators who later add it; the current publish
workflow uses the Pages artifact + deploy-pages pair.

Custom domain `pulse.silastron.com` is a repository Pages setting. Actions
workflow publishes ignore a `CNAME` file. Neither Publish nor Deploy
frontend writes Pages DNS settings; see docs/deployment.md.
