# Source integration contracts

Verification date: 2026-10-21. Statements are marked **VERIFIED**,
**UNVERIFIED**, or **BLOCKED**.

## 1. CISA Known Exploited Vulnerabilities — VERIFIED primary source

| Item | Value | Status |
| --- | --- | --- |
| Catalog page | https://www.cisa.gov/resources-tools/resources/kev-catalog | VERIFIED |
| JSON feed | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | VERIFIED live HTTP 200 on 2026-10-21 |
| JSON schema | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json | VERIFIED |
| License | CC0 1.0, https://www.cisa.gov/sites/default/files/licenses/kev/license.txt | VERIFIED |
| Git mirror | https://github.com/cisagov/kev-data | VERIFIED as a convenience copy, not used |
| Observed catalogVersion | `2026.10.20` | VERIFIED sample |
| Observed count | `1754` | VERIFIED sample |
| dateReleased sample | `2026-10-20T19:00:31.8765Z` | VERIFIED; fractional seconds are not strictly millisecond |

### Operational constraints — VERIFIED or observed

- Unauthenticated HTTPS GET.
- CISA typically updates weekdays during US Eastern business hours; the Git
  mirror documents hourly polling. **VERIFIED** from cisagov/kev-data README.
- `count` must equal `vulnerabilities.length`. Empty catalogs are rejected.
- `notes` and descriptions are untrusted text and may contain URLs.
- License does **not** authorize use of the CISA logo or DHS seal and is not
  an endorsement.

### Integration

Adapter: `src/silastron_pulse/adapters/kev.py`  
Parser version: `1.0.0`  
Revision stored: `catalogVersion`  
Publication time stored: `dateReleased`

## 2. CVE List V5 — VERIFIED enrichment source

| Item | Value | Status |
| --- | --- | --- |
| Official list | https://github.com/CVEProject/cvelistV5 | VERIFIED README: “This repository is the official CVE List” |
| Record format | CVE Record Format 5.x via `dataVersion` | VERIFIED; 5.0/5.1/5.2 coexist |
| Schema repo | https://github.com/CVEProject/cve-schema | VERIFIED |
| Terms of use | https://www.cve.org/Legal/TermsOfUse | VERIFIED |
| Single-record fetch | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{n}xxx/{CVE-ID}.json` | VERIFIED live fetch of CVE-2021-44228 on 2026-10-21 |
| Official download methods | git clone or large release zips | VERIFIED; not used because they are large upstream datasets |
| Latest change window | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json` | VERIFIED 2026-10-21 HTTP 200, **4,123 bytes**; current ~7-minute window only |
| Official catch-up log | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json` | VERIFIED 2026-10-21 HEAD Content-Length **29,863,282**; GET 17.94s; ~30-day rolling windows. Fetched when ≤ 40 MB after HEAD |

### License — VERIFIED

MITRE grants a copyright license to reproduce, prepare derivative works of,
publicly display, publicly perform, sublicense, and distribute CVE, provided
copies reproduce MITRE's copyright designation and the license text. Snapshots
embed that attribution. The CC0 pull request on cvelistV5 is **not merged**.

### Operational constraints

- Records update about every 7 minutes in cvelistV5. **VERIFIED** from README.
- Path layout is `cves/{year}/{sequence//1000}xxx/{CVE-ID}.json`. **VERIFIED**.
- Enrichment is bounded to KEV CVE IDs, max 3000 records, max 1 MB each.
- The fetched `cveMetadata.cveId` must equal the requested ID exactly. No
  zero-padding or fuzzy match.
- CVSS is taken only from the CNA container. ADP scores are not substituted.
- GitHub raw rate limits for 1,700+ sequential fetches are **UNVERIFIED** in
  production. Collection retries 429/5xx with exponential backoff and
  Retry-After, then fails closed on excess failures.
- Incremental strategy **VERIFIED** against official distribution on 2026-10-21.
  See [cve-sync.md](cve-sync.md). git clone ≈ 3.02 GB and midnight zip =
  639.61 MB are rejected for a KEV-only subset. `delta.json` is the current
  window only. `deltaLog.json` (29.86 MB, ~30-day catch-up) is HEADed then
  fetched when it fits 40 MB; KEV ∩ 24h was 7 IDs. Oversized logs are not
  re-downloaded. Incomplete catch-up fails closed. A gap older than the log
  triggers a one-time KEV-subset resync. Per-CVE If-None-Match of the full
  KEV set is not the scheduled incremental path.

### CVE Services API — not used

Live `GET https://cveawg.mitre.org/api/cve/CVE-2021-44228` on 2026-10-21 returned
HTTP 200, 18,335 bytes, `RateLimit-Limit: 25000`. Bulk `GET /cve` is
Secretariat-only. The API is therefore still one request per KEV ID and adds a
host this pipeline does not allowlist. It is not used.

## 3. FIRST EPSS — BLOCKED for publication

| Item | Value | Status |
| --- | --- | --- |
| Home | https://www.first.org/epss | VERIFIED |
| Data page | https://www.first.org/epss/data | VERIFIED |
| API | https://api.first.org/data/v1/epss | VERIFIED documentation |
| Daily CSV | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | VERIFIED documentation |
| Usage agreement | Grants public *use* of scores and requests attribution | VERIFIED via FIRST usage text captured by ScanCode LicenseDB |
| Explicit redistribution license for derived public JSON feeds | Not found | BLOCKED |

FIRST says scores are free to use with requested attribution. That is **not**
treated as permission to republish scores in a public GitHub Pages JSON
snapshot that third parties, including a future WordPress theme, will consume.

Adapter: `src/silastron_pulse/adapters/epss.py`  
`REDISTRIBUTION_CLEARED = False`  
Parser helpers are tested against fixtures only.

To enable later, the repository owner must document a written determination
that displaying and redistributing EPSS scores in this public JSON feed is
permitted, then change the blocker in code through a reviewed pull request.
Do not enable by environment variable.

## Correlation policy

- Join key: exact CVE ID string after `CVE-YYYY-NNNN+` validation.
- `CVE-2099-0001` is never treated as `CVE-2099-00001`.
- KEV is the only confirmed-exploitation signal.
- Missing CVE enrichment marks that record `unavailable`; it does not drop the
  KEV event and does not invent CVE fields.
