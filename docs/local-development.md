# Local development

Requires Python 3.11 or newer. There are no runtime package dependencies.

```bash
cd silastron-security-pulse
export PYTHONPATH=src
python3 -m unittest discover -s tests -v
python3 -m silastron_pulse validate preview/data/manifest.json
```

## Offline collection against fixtures

The unit tests inject a `MapFetcher`. There is no live-network default in
tests. To collect from the real CISA and CVE List V5 endpoints:

```bash
export PYTHONPATH=src
python3 -m silastron_pulse collect --output-dir dist
```

That command performs live HTTPS GETs. Do not run it against production
publication directories until source contracts are approved.

## Local preview

```bash
python3 -m http.server 8080 --directory preview
```

Open `http://127.0.0.1:8080/`. The checked-in `preview/data/manifest.json` is
an unpublished placeholder, so the UI must show an unavailable state.

## Commands

| Command | Effect |
| --- | --- |
| `python3 -m silastron_pulse collect --output-dir dist` | Write `candidate.json` |
| `python3 -m silastron_pulse validate dist/candidate.json` | Schema/semantic validation |
| `python3 -m silastron_pulse promote --candidate dist/candidate.json --published-dir public/data` | Atomic replace of published files |
| `python3 -m silastron_pulse write-unpublished --published-dir public/data` | Restore unpublished placeholders |

`promote` refuses empty, failed, older, or sharply shrunken snapshots.
