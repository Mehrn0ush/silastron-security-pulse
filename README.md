# Silastron Security Pulse

Public, read-only vulnerability intelligence pipeline for later consumption by
Silastron.com. This repository does **not** access, modify, or deploy WordPress.

The pipeline collects CISA Known Exploited Vulnerabilities (KEV) as the primary
event source, enriches those CVE identifiers from the official CVE List V5, and
keeps FIRST EPSS **disabled** until redistribution terms are approved.

This preview never collapses confirmed exploitation, estimated probability,
severity, product affectedness, and deployment exposure into a risk score.

## Status

- Collection workflow: daily at 08:00 UTC plus manual `workflow_dispatch`.
  Collect does not publish.
- Frontend-only Pages deploy is a separate manual workflow; it does not Collect or Promote.
- GitHub Pages publication: a successful scheduled Collect auto-starts Publish
  bound to that run ID. Manual `confirm=PUBLISH` with an explicit
  `collect_run_id` remains the fallback. Unchanged upstream data is a skip.
- EPSS: **BLOCKED** for publication. See [docs/source-contracts.md](docs/source-contracts.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Collection-state architecture](docs/collection-state.md)
- [CVE List V5 synchronization](docs/cve-sync.md)
- [Audit finding status](docs/audit-findings.md)
- [Source integration contracts](docs/source-contracts.md)
- [Data schemas](docs/schemas.md)
- [Local development](docs/local-development.md)
- [Workflow operation](docs/workflows.md)
- [Security controls](docs/security.md)
- [Deployment and rollback](docs/deployment.md)
- [Known limitations](docs/limitations.md)

## Quick local test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

No third-party Python runtime dependencies are required.

## License

Original source code is Apache-2.0. CVE and KEV data remain under their own
terms. See [LICENSE](LICENSE) and [docs/licenses](docs/licenses).
