# Operations

## What runs when

| Workflow | Trigger | Does | Writes |
| --- | --- | --- | --- |
| Collect | daily 08:00 UTC (starts late), manual | Collects KEV/CVE/NVD into a candidate | `pulse-state` (source, candidates) |
| Collect malware | daily 03:15 UTC, manual | Ingests OpenSSF Malicious Packages, applies gates | `malware-state` |
| Publish GitHub Pages | after a scheduled Collect or Collect malware; manual (`confirm=PUBLISH` + Collect run id) | Decides, builds the whole site from each source's last-good snapshot, deploys, smoke-tests | Pages, `pulse-state` receipts |
| Deploy frontend | manual (`confirm=DEPLOY_FRONTEND`) | Rebuilds pages and scripts against the current snapshot | Pages |
| Watchdog | every 6 hours; after Collect, Collect malware, Publish | Reads the live site and opens or closes one `site-stale` issue | issues only |
| CI | pull requests, pushes | Unit tests, browser tests, feed/sitemap validation, size budget | nothing |

Publish runs no unit tests, so a code change cannot block a data publish. A manual Collect is never published
automatically: run Publish with its run id.

## What the visitor sees

Pages are rebuilt only when Publish runs. Every page footer carries `data-collected` and `data-built` stamps and
`stale.js` (same origin, 72 hours, three times the daily interval) adds a "Possibly out of date" notice when the
collected stamp is older. The home page also recomputes its status banner in the browser (`app.js`). With
JavaScript off the footer still shows the last collected and last published times.

## Alerts (issue `site-stale`, assigned to the repository owner)

| Finding | Meaning | Limit |
| --- | --- | --- |
| `site-unreachable` | `/data/manifest.json` failed three times in a row, 20 s apart | 3 attempts |
| `kev-unverified` | The live site has no readable `verified_at` | n/a |
| `kev-stale` | KEV last independently verified too long ago | 48 h |
| `malware-missing` | `malware-state` exists but the live site has no malware data | n/a |
| `malware-stale` | Malware collected too long ago | 48 h |
| `malware-behind` | `malware-state` has a newer commit than the one the live site serves (`build.json`) | 6 h |

The issue is edited in place while problems persist and closes itself on recovery. Thresholds live in
`src/silastron_pulse/watchdog.py`. To be told, keep GitHub notifications on for issues assigned to you (Settings,
Notifications, Participating and @mentions); that is a setting on the owner's account, not on the repository.

**Scheduled workflows are disabled by GitHub in a public repository after 60 days without repository activity**
(documented GitHub rule). If Collect, Collect malware and Watchdog all go quiet, check the Actions tab for a
"disabled" banner and re-enable them; a commit or manual run restarts the clock.

## Runbooks

**Collect fails** (red run, banner "Collection failed" on the site). Open the failed run's log. Typical causes:
an upstream file crossed a size cap (`max_delta_bytes`, `max_snapshot_bytes`: raise in `constants.py`, see
`docs/limitations.md`), an upstream outage (re-run later), or a code error (fix and re-run). The published site keeps
serving the last good snapshot and says when it was last verified. Then run Publish with the new Collect run id if it
was a manual run.

**Publish fails or is skipped.** Skipped: the `confirm` input was not exactly `PUBLISH`. 404 on "Verify collect run
identity": the Collect run id is wrong. Failed after build: read the failing step; the persisted state is untouched
until deploy succeeds. The smoke-test job failing means Pages did not serve the build yet: re-run it, or run Deploy
frontend. Nothing is rolled back automatically; see `docs/deployment.md` for the explicit rollback command.

**Site stale (watchdog issue).** `kev-stale`: check Collect, then run Publish as above. `malware-stale` or
`malware-behind`: check Collect malware; if it succeeded, run Publish (or Deploy frontend) so the site picks up the
new `malware-state` commit. `site-unreachable`: check githubstatus.com and the Pages settings, then Deploy frontend.
A malware gate failure keeps the last good malware snapshot and is expected to alert after 48 h.

**Re-run Publish for a manual Collect.** Actions, Publish GitHub Pages, Run workflow on `main`, `confirm` = `PUBLISH`,
`collect_run_id` = the numeric id from the Collect run URL.

## Not applicable here (from the PQC tracker hardening)

Pulse commits no collected data to the repository (state is on `pulse-state` and `malware-state`), so the suite
cannot break when Collect runs; `tests/test_hygiene.py` keeps it that way and limits wall-clock reads to a reviewed
list. Publish runs no tests, so a publish gate is not needed. Collect clocks are injected (`silastron_pulse.clock`).
