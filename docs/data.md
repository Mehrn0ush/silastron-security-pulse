# Published data files

Every file under the site root, its source, licence and attribution. Sizes are budgeted by
`ops/site-budget.json` (see `docs/deployment.md`).

## KEV / CVE side (`/data/`)

| File | What | Source and licence |
| --- | --- | --- |
| `latest.json`, `snapshots/<id>.json` (latest two) | Published snapshot | CISA KEV (CC0 1.0), CVE List V5 (CVE Program terms; "CVE" is a registered trademark of MITRE), NVD (see attribution below), CISA ADP. Structure by Silastron. |
| `manifest.json`, `preview.json`, `publication-status.json`, `verification-status.json`, `history.json` | Status and comparison documents | Silastron-generated from the above |
| `catalog-index.json`, `cve/<ID>.json` | Explorer index and per-CVE detail | Derived from the snapshot |
| `history/**` | Per-CVE history and ledger | Derived from retained snapshots |
| `/cve/<ID>/`, `/`, `/methodology/` | Pages | Text by Silastron; data as above |
| `/sitemap.xml`, `/robots.txt`, `/feed.xml`, `/kev/feed.xml`, `/build.json` | Discovery and build identity | Silastron |

Attribution: "This product uses the NVD API but is not endorsed or certified by the NVD." EPSS is not published.

## Malicious packages (`/malware/`)

Source: OpenSSF Malicious Packages (github.com/ossf/malicious-packages), **Apache-2.0**, no NOTICE file
(`docs/malware-source.md`). Attribution line on every page and in `status.json`:
"Source: OpenSSF Malicious Packages (github.com/ossf/malicious-packages), Apache-2.0. Reduced and re-indexed by
Silastron: counts, short summaries and lookup rows only; not endorsed by the OpenSSF."
We state that the data is changed (reduced to the fields below) and ship the licence at `/malware/LICENSE.txt`.

| File | What |
| --- | --- |
| `data/status.json` | `collected_at`, upstream commit, counts, flags, `stale_after_hours`, attribution |
| `data/summary.json` | Weekly new-report counts per ecosystem, weekly withdrawals, yearly totals, `spikes` (more than 5x the 12-week median and at least 50), undated count |
| `data/weeks/<ISO-week>.json` and `.csv` | Digest: totals, by ecosystem, withdrawn that week, the list of new reports (id, ecosystem, name, published, modified, reporting origin, upstream path, summary of at most 200 characters), `updated` |
| `data/weeks/index.json` | Weeks available |
| `data/index/manifest.json` | Ecosystems, counts, normalisation rule, shard list |
| `data/index/<ecosystem>/<prefix>.json` | Lookup shards (each at most 500 KB) keyed by normalised-name prefix |
| `data/quarantine.json` | Records set aside (id or path, reason, first seen), linked from the methodology page |
| `LICENSE.txt` | Apache License 2.0 |

Never published: upstream `details` text, indicators (IPs, URLs, domains, hashes), credits, payloads, install commands,
registry links. Classification is not published: upstream has no structured field for it.
