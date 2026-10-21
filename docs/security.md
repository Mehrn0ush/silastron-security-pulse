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
| Timeouts and size limits | HTTP timeout, max bytes, max JSON depth, max records |
| No secrets | No API keys; no WordPress credentials |
| No third-party JS | Preview uses local `app.js` / `styles.css` only |
| XSS | Preview uses `textContent` and `createElement`; CSP meta tag |
| Unsafe URLs | `javascript:`, `data:`, credentials, localhost, and non-allowlisted hosts are dropped |
| Identifier integrity | Exact CVE ID match; mismatch is a correlation failure |
| Fail closed | Failed collect writes `collection-status.json` and does not promote |
| Least privilege | Default `contents: read`; Pages write only on the deploy job |
| SHA-pinned actions | See docs/workflows.md |
| No custom crypto | SHA-256 via hashlib only, for content hashing |
| No PR deploy | Publish and collect ignore pull requests |

## Explicit non-goals

- This pipeline does not scan Silastron assets.
- It does not assert that a product in KEV is deployed anywhere.
- It does not produce a 0–10 “Pulse score”.
