# Deployment and rollback

GitHub Pages is the only deployment target. WordPress is out of scope.

## Current readiness

**Not ready for public intelligence deployment.** The publish workflow exists
but must not be run until the owner approves source contracts and security
review. The checked-in preview manifest is `unpublished`.

## Intended publication path (after approval)

1. Enable GitHub Pages: Settings → Pages → Source = GitHub Actions.
2. Protect the `github-pages` environment with required reviewers.
3. Collect runs daily at 08:00 UTC and can also be started from `main` via
   workflow_dispatch. Inspect the `pulse-candidate` artifact from the Collect
   run you intend to publish.
4. Run `Publish GitHub Pages` from `main` with `confirm=PUBLISH` and that
   Collect run's `collect_run_id`. A newer Collect does not replace the bound
   artifact.
6. Confirm `manifest.json` `status` is `ok` or `degraded` and `stale` is false.

## Rollback

Promote never deletes previous snapshot files under `snapshots/`. Replaying a
superseded snapshot through ordinary promote is rejected. Rollback is explicit:

```bash
PYTHONPATH=src python3 -m silastron_pulse rollback \
  --published-dir published \
  --snapshot-id '<id>' \
  --confirm ROLLBACK
```

Do not hand-edit `latest.json`. If a bad deploy occurred, disable Pages or
redeploy the unpublished placeholder until a good snapshot is available.

Failed collections leave the last promoted snapshot in place.

## WordPress.com later

Point a future theme at the Pages URLs for `manifest.json` and `latest.json`.
Use GET only. Do not cache a stale snapshot as fresh. This repository will not
push into WordPress.
