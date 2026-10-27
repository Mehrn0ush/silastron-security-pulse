# Deployment and rollback

GitHub Pages is the only deployment target. WordPress is out of scope.

## Custom domain (`pulse.silastron.com`)

Production hostname is the `pulse` subdomain of `silastron.com`. The apex
site and `www` stay on WordPress.com Premium. Do not edit the WordPress
theme, database, content, or site settings to host Pulse.

### What the repository already does

Pages is published by GitHub Actions (`build_type: workflow`), not from a
branch. Official GitHub docs: when the publishing source is a custom Actions
workflow, **a `CNAME` file is ignored and is not required**. The custom
domain is stored in repository Pages settings and is not rewritten by
`Publish GitHub Pages` or `Deploy frontend`. Both workflows upload the same
root files (`index.html`, `styles.css`, `app.js`) plus `_site/data/`. Those
paths are relative, so `https://pulse.silastron.com/data/manifest.json` and
same-origin `connect-src 'self'` keep working after the hostname change.

Do not add a committed `CNAME` file. Do not point workflows at a different
host. Do not change Collect / Publish isolation to ship the domain.

### Required DNS record

Add **only** this record in WordPress.com **Domains → silastron.com → DNS
records**. Nameservers for `silastron.com` are WordPress.com; this is DNS
for the subdomain, not a WordPress site change.

| Field | Value |
| --- | --- |
| Type | `CNAME` |
| Host / name | `pulse` |
| Target / value | `mehrn0ush.github.io` |
| Trailing dot | optional (`mehrn0ush.github.io.`) |

Confirmed from GitHub Pages health (`is_cname_to_github_user_domain: true`)
and live `CNAME` lookup: `pulse.silastron.com` → `mehrn0ush.github.io`.
GitHub's documented target for a user project site is
`USERNAME.github.io` with **no repository name**. Do not CNAME to
`silastron-security-pulse.github.io` or a `*.pages.github.io` host.

Do not add `A` / `AAAA` records for `pulse`. Do not change `@` or `www`.
Do not add a wildcard record. Do not proxy the hostname through Cloudflare
or another CDN.

### Required GitHub settings (manual)

Repository **Settings → Pages** for `Mehrn0ush/silastron-security-pulse`:

1. Source = **GitHub Actions** (already set).
2. Custom domain = `pulse.silastron.com` (already set; certificate
   approved).
3. After DNS shows as valid, enable **Enforce HTTPS**. It is currently
   off, so `http://pulse.silastron.com/` still serves the site and
   `https://mehrn0ush.github.io/silastron-security-pulse/` redirects to
   HTTP.
4. Do not switch the source to a branch. A branch publish would commit a
   `CNAME` file and bypass the Actions artifact path.

Account **Settings → Pages** (profile, not the repository):

5. Verify `silastron.com` to lock immediate subdomains against takeover.
   GitHub shows a one-time TXT name
   `_github-pages-challenge-Mehrn0ush.silastron.com` and a token. Copy
   that token from the UI. Do not invent it. Add the TXT in WordPress.com
   DNS, wait for propagation, then click **Verify**. Keep the TXT record.

Optional: set the repository homepage to `https://pulse.silastron.com`.

### Operator checks after DNS

```bash
dig pulse.silastron.com +nostats +nocomments +nocmd CNAME
# expect: pulse.silastron.com.  …  CNAME  mehrn0ush.github.io.

dig silastron.com +nostats +nocomments +nocmd A
dig www.silastron.com +nostats +nocomments +nocmd CNAME
# apex and www must still be WordPress, unchanged
```

Then open `https://pulse.silastron.com/` and confirm the lock icon, that
HTTP redirects to HTTPS after Enforce HTTPS is on, and that
`/styles.css`, `/app.js`, `/data/manifest.json`, and `/data/preview.json`
load from the same host.

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
4. A successful **scheduled** Collect starts `Publish GitHub Pages`
   automatically, bound to that Collect run ID. Manual Collect does not
   auto-publish. To publish a manual Collect, run `Publish GitHub Pages`
   from `main` with `confirm=PUBLISH` and that run's `collect_run_id`. A
   newer Collect does not replace the bound artifact. Unchanged upstream
   data is a normal skip, not a failed publish.
5. To ship UI from `main` without republishing intelligence, run
   `Deploy frontend` with `confirm=DEPLOY_FRONTEND`. It copies the current
   published snapshot as-is and does not run Collect or Promote.
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
