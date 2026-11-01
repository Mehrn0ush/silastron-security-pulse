#!/usr/bin/env python3
"""Build a local fixture site and serve it for Playwright. No live sources."""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from silastron_pulse.pipeline import collect  # noqa: E402
from silastron_pulse.store import promote_snapshot  # noqa: E402
from silastron_pulse.validate import validate_snapshot  # noqa: E402
from tests.support import frozen_clock, test_config, valid_fetcher  # noqa: E402


def build_site(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in ("index.html", "app.js", "styles.css", "theme.js"):
        shutil.copy2(ROOT / "preview" / name, out / name)
    data = out / "data"
    collect_dir = out / "_collect"
    published = out / "_published"
    result = collect(
        config=test_config(collect_dir),
        fetcher=valid_fetcher(),
        clock=frozen_clock(),
        collector_commit_sha="abc",
    )
    if result.status != "ok" or result.snapshot is None:
        raise SystemExit("fixture collection failed")
    snapshot = _expand_snapshot(result.snapshot)
    validate_snapshot(snapshot)
    from datetime import datetime, timezone

    promote_snapshot(
        snapshot,
        published,
        now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
        stale_after_hours=36,
        max_bytes=8_000_000,
        max_depth=32,
    )
    shutil.copytree(published, data)
    _write_history(data)
    (out / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")


def _expand_snapshot(snapshot: dict) -> dict:
    payload = copy.deepcopy(snapshot)
    template = copy.deepcopy(payload["records"][0])
    extras = []
    for index in range(28):
        record = copy.deepcopy(template)
        cve_id = f"CVE-2099-{1000 + index:04d}"
        record["cve_id"] = cve_id
        record["kev"]["cve_id"] = cve_id
        record["cve"]["cve_id"] = cve_id
        record["links"]["cve_record"] = f"https://www.cve.org/CVERecord?id={cve_id}"
        record["links"]["cvelist_v5"] = (
            f"https://github.com/CVEProject/cvelistV5/blob/main/cves/2099/"
            f"{(1000 + index) // 1000:d}xxx/{cve_id}.json"
        )
        if index == 0:
            record["kev"]["vendor_project"] = "=1+1"
            record["kev"]["product"] = "Formula Product"
            record["kev"]["date_added"] = "2099-02-01"
            record["kev"]["cwes"] = ["CWE-94"]
            record["cve"]["severity"]["base_score"] = 9.8
            record["cve"]["severity"]["base_severity"] = "CRITICAL"
        elif index == 1:
            record["kev"]["vendor_project"] = "Acme"
            record["kev"]["product"] = "Widget"
            record["kev"]["date_added"] = "2098-12-15"
            record["kev"]["cwes"] = []
            record["cve"]["severity"] = None
            record["cve"]["status"] = "unavailable"
            record["cve"]["error"] = "unavailable fixture"
            record["completeness"] = "unavailable"
            record["remediation"] = {"status": "unavailable", "items": []}
        elif index == 2:
            record["kev"]["vendor_project"] = "Acme"
            record["kev"]["product"] = "Gadget"
            record["kev"]["date_added"] = "2099-03-01"
            record["cve"]["omitted_version_count"] = 1
            record["cve"]["truncated_fields"] = ["versions"]
            record["completeness"] = "partial"
            record["cve"]["severity"]["base_score"] = 4.3
            record["cve"]["severity"]["base_severity"] = "MEDIUM"
        else:
            record["kev"]["vendor_project"] = "OtherCo"
            record["kev"]["product"] = f"App {index}"
            record["kev"]["date_added"] = f"2097-01-{(index % 28) + 1:02d}"
            record["cve"]["severity"]["base_score"] = 2.0
            record["cve"]["severity"]["base_severity"] = "LOW"
        extras.append(record)
    payload["records"] = sorted(payload["records"] + extras, key=lambda item: item["cve_id"])
    summary = payload["summary"]
    summary["kev_records"] = len(payload["records"])
    summary["complete_records"] = sum(1 for item in payload["records"] if item["completeness"] == "complete")
    summary["partial_records"] = sum(1 for item in payload["records"] if item["completeness"] == "partial")
    summary["unavailable_records"] = sum(
        1 for item in payload["records"] if item["completeness"] == "unavailable"
    )
    payload["snapshot_id"] = "e2e-fixture-1"
    return payload


def _write_history(data: Path) -> None:
    history_dir = data / "history" / "cves"
    history_dir.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": "1.1.0",
        "cve_id": "CVE-2099-0001",
        "coverage": "durable",
        "first_observed_snapshot_id": "e2e-old-1",
        "first_observed_generated_at": "2098-12-01T00:00:00Z",
        "first_observed_may_be_incomplete": False,
        "kev_date_added": "2099-01-01",
        "durable_event_count": 3,
        "event_count": 3,
        "events_truncated": False,
        "events": [
            {
                "kind": "first_observed",
                "classification": "published_observation",
                "snapshot_id": "e2e-old-1",
                "generated_at": "2098-12-01T00:00:00Z",
                "note": "First verifiable published observation. This is not CISA KEV dateAdded.",
            },
            {
                "kind": "kev_field_change",
                "classification": "upstream_kev",
                "snapshot_id": "e2e-mid-1",
                "generated_at": "2099-01-01T00:00:00Z",
                "changes": [{"field": "required_action", "before": "old", "after": "new"}],
                "note": "CISA KEV field values changed between published snapshots.",
            },
            {
                "kind": "cvss_change",
                "classification": "upstream_cvss",
                "snapshot_id": "e2e-new-1",
                "generated_at": "2099-01-10T12:00:00Z",
                "changes": [{"field": "base_score", "before": 5.0, "after": 7.5}],
                "note": "CVSS score or severity changed between published snapshots.",
            },
        ],
    }
    (history_dir / "CVE-2099-0001.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    index = {
        "schema_version": "1.1.0",
        "cves": [
            {
                "cve_id": "CVE-2099-0001",
                "first_observed_snapshot_id": "e2e-old-1",
                "first_observed_generated_at": "2098-12-01T00:00:00Z",
                "path": "cves/CVE-2099-0001.json",
            }
        ],
    }
    (data / "history" / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "tests" / "e2e" / ".site")
    parser.add_argument("--port", type=int, default=4173)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    build_site(args.out)
    if args.build_only:
        print(args.out)
        return 0
    import os

    os.chdir(args.out)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), SimpleHTTPRequestHandler)
    print(f"serving {args.out} on http://127.0.0.1:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
