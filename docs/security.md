# Security controls

## Trust boundaries

- CISA, CVE List V5, and (if later enabled) FIRST are untrusted data sources.
- GitHub Actions `pull_request` workflows are untrusted for publication.
- The static preview treats snapshot JSON as untrusted.

## Controls

| Control | Implementation |
| --- | --- |
| HTTPS only | `sanitize_https_url` rejects other schemes |
| Host allowlist | Hardcoded; not configurable via environment |
| Redirects | Max 3; off-allowlist redirects fail |
| Timeouts and size limits | HTTP timeout, KEV/CVE/delta byte caps, max JSON depth, max records |
| Oversized deltaLog | HEAD first; GET skipped when Content-Length exceeds `max_delta_bytes` |
| No secrets | No API keys; no WordPress credentials |
| No third-party JS | Preview uses local `app.js` / `styles.css` only |
| XSS | Preview uses `textContent` and `createElement`; CSP meta tag |
| Unsafe URLs | `javascript:`, `data:`, credentials, localhost, and non-allowlisted hosts are dropped |
| Identifier integrity | Exact CVE ID match; mismatch is a correlation failure |
| Fail closed | Failed collect writes `collection-status.json` and does not rewrite pulse-state |
| Artifact identity | Publish binds one Collect run ID, workflow path **and** name, digest, and SHA. Auto-publish accepts only scheduled Collect on main |
| KEV catalog binding | Candidate CVE IDs and material KEV fields must match the Collect-time catalog in the same artifact. Candidate hashes are not independent proof |
| Untrusted interpolation | Artifact `snapshot_id` cannot enter a shell command; run IDs must be numeric; copies refuse symlinks |
| Path-restricted links | Preview and `authoritative_href` allow only KEV catalog, CVE.org record, and cvelistV5 blob paths |
| Least privilege | Collect may write `pulse-state` only; Pages write only on the deploy job |
| SHA-pinned actions | See docs/workflows.md |
| No custom crypto | SHA-256 via hashlib only, for content hashing |
| No PR deploy | Publish and collect ignore pull requests |

## Explicit non-goals

- This pipeline does not scan Silastron assets.
- It does not assert that a product in KEV is deployed anywhere.
- It does not produce a 0–10 “Pulse score”.
