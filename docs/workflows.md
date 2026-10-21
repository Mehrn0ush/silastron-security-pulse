# Workflow operation

All GitHub Actions are SHA-pinned. Workflows default to `contents: read`.
Pull requests never collect live intelligence and never deploy Pages.

## `ci.yml`

- Triggers: pull request, push to `main`, workflow_dispatch
- Permissions: `contents: read`
- Runs unit tests on Python 3.11 and 3.12
- Validates unpublished manifests and schema JSON

## `collect.yml`

- Trigger: **workflow_dispatch only**
- Schedule is present only as a commented example and is **not enabled**
- Runs only from `main`
- Permissions: `contents: read`
- Writes `dist/candidate.json` and uploads artifact `pulse-candidate`
- Does not commit, does not deploy, and does not update `public/data`
- If collection fails, the job fails and no candidate artifact is uploaded

Do not enable the cron schedule until the repository owner approves source
contracts and security review.

## `publish.yml`

- Trigger: workflow_dispatch with `confirm=PUBLISH`
- Optional `collect_run_id`
- Runs only from `main`
- Downloads a successful collect artifact, validates, promotes into `_site/data`,
  copies the static preview, then deploys GitHub Pages
- Deploy job permissions: `pages: write`, `id-token: write`
- Uses the `github-pages` environment so branch protection / reviewers can be added
- Untrusted pull requests cannot dispatch this on `main`

Do **not** run this workflow until publication is explicitly approved.

## Action pins (verified 2026-10-21 via GitHub git refs API)

| Action | Tag | SHA |
| --- | --- | --- |
| actions/checkout | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| actions/setup-python | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| actions/upload-artifact | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| actions/download-artifact | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| actions/upload-pages-artifact | v3.0.1 | `56afc609e74202658d3ffba0e8f6dda462b719fa` |
| actions/configure-pages | v5.0.0 | `983d7736d9b0ae728b81ab479565c72886d7745b` |
| actions/deploy-pages | v4.0.5 | `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e` |

`configure-pages` is listed for operators who later add it; the current publish
workflow uses the Pages artifact + deploy-pages pair.
