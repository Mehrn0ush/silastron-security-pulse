# Deployment and rollback

GitHub Pages is the only deployment target. WordPress is out of scope.

## Current readiness

**Not ready for public intelligence deployment.** The publish workflow exists
but must not be run until the owner approves source contracts and security
review. The checked-in preview manifest is `unpublished`.

## Intended publication path (after approval)

1. Enable GitHub Pages: Settings → Pages → Source = GitHub Actions.
2. Protect the `github-pages` environment with required reviewers.
3. Run `Collect` from `main` via workflow_dispatch.
4. Inspect the `pulse-candidate` artifact.
5. Run `Publish GitHub Pages` from `main` with `confirm=PUBLISH`.
6. Confirm `manifest.json` `status` is `ok` or `degraded` and `stale` is false.

## Rollback

Promote never deletes previous snapshot files under `snapshots/`. Rollback is:

1. Choose a known-good `snapshots/{id}.json`.
2. Run promote against that file, or re-deploy a previous Pages artifact.
3. Do not hand-edit `latest.json`.
4. If a bad deploy occurred, disable Pages or redeploy the unpublished
   placeholder until a good snapshot is available.

Failed collections leave the last promoted snapshot in place.

## WordPress.com later

Point a future theme at the Pages URLs for `manifest.json` and `latest.json`.
Use GET only. Do not cache a stale snapshot as fresh. This repository will not
push into WordPress.
