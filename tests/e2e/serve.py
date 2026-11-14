#!/usr/bin/env python3
"""Build a local fixture site and serve it for Playwright. No live sources."""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE_URL = "https://pulse.silastron.com"
# The fixture is a normal, recent, verified publication; browser tests fix their clock to
# FIXTURE_NOW (tests/e2e/clock.js) so ages never depend on the real time.
FIXTURE_COLLECTED = "2026-11-01T12:00:00+00:00"
FIXTURE_PUBLISHED = "2026-11-01T14:00:00+00:00"
FIXTURE_NOW = "2026-11-01T15:00:00+00:00"
SRC = ROOT / "src"
for path in (ROOT, SRC, ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from silastron_pulse.pipeline import collect  # noqa: E402
from silastron_pulse.store import promote_snapshot  # noqa: E402
from silastron_pulse.validate import validate_snapshot  # noqa: E402
from tests.support import FrozenClock, test_config, valid_fetcher  # noqa: E402


def build_site(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in ("app.js", "styles.css", "theme.js", "malware-check.js", "stale.js"):
        shutil.copy2(ROOT / "preview" / name, out / name)
    data = out / "data"
    collect_dir = out / "_collect"
    published = out / "_published"
    result = collect(
        config=test_config(collect_dir),
        fetcher=valid_fetcher(),
        clock=FrozenClock(datetime.fromisoformat(FIXTURE_COLLECTED)),
        collector_commit_sha="abc",
    )
    if result.status != "ok" or result.snapshot is None:
        raise SystemExit("fixture collection failed")
    snapshot = _expand_snapshot(result.snapshot)
    validate_snapshot(snapshot)

    promote_snapshot(
        snapshot,
        published,
        now=datetime.fromisoformat(FIXTURE_PUBLISHED),
        stale_after_hours=36,
        max_bytes=8_000_000,
        max_depth=32,
    )
    shutil.copytree(published, data)
    from silastron_pulse.verification_status import build_verification_status

    status = build_verification_status(
        candidate=snapshot,
        decision_outcome="publish",
        decision_reason="first_publish",
        collect_run_id="1",
        collect_event="workflow_dispatch",
        published=snapshot,
        publication_state="consistent",
        candidate_digest="a" * 64,
    )
    (data / "verification-status.json").write_text(
        json.dumps(status, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (data / "publication-status.json").write_text(
        json.dumps(
            {
                "state": "consistent",
                "classification": "persistence_succeeded_and_consistent",
                "snapshot_id": snapshot["snapshot_id"],
                "collect_run_id": "1",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_history(data)

    import tempfile

    from silastron_pulse.malware.collect import collect_malware
    from silastron_pulse.malware.site_data import build_malware_site_data
    from support_malware import write_fixture_clone  # noqa: E402

    with tempfile.TemporaryDirectory() as malware_tmp:
        clone = write_fixture_clone(Path(malware_tmp) / "clone")
        state = Path(malware_tmp) / "state"
        state.mkdir()
        outcome = collect_malware(clone_dir=clone, state_dir=state, upstream_sha="f" * 40, now=datetime.fromisoformat(FIXTURE_COLLECTED))
        if not outcome.ok:
            raise SystemExit(f"fixture malware collection failed: {outcome.problems}")
        build_malware_site_data(state_dir=state, site_dir=out, licence_file=ROOT / "vendor" / "openssf-malicious-packages" / "LICENSE")

    from silastron_pulse.home_page import build_home_page  # noqa: E402
    from silastron_pulse.methodology_page import build_methodology_page  # noqa: E402

    build_home_page(
        published_dir=data,
        template_path=ROOT / "preview" / "index.html",
        site_dir=out,
        now=datetime.fromisoformat(FIXTURE_NOW),
    )
    from silastron_pulse import page_chrome
    from silastron_pulse.home_page import footer_for
    from silastron_pulse.site_files import build_site_files
    from silastron_pulse.static_pages import build_static_cve_pages

    build_methodology_page(
        out,
        base_url=BASE_URL,
        footer=footer_for(data),
    )
    from silastron_pulse.malware.pages import build_malware_pages

    build_malware_pages(
        data_dir=out / "malware" / "data",
        site_dir=out,
        base_url=BASE_URL,
        footer=footer_for(data),
        now=datetime.fromisoformat(FIXTURE_NOW),
    )
    build_static_cve_pages(published_dir=data, site_dir=out, base_url=BASE_URL)
    build_site_files(
        published_dir=data,
        site_dir=out,
        base_url=BASE_URL,
        commit="0" * 40,
        built_at=datetime.fromisoformat(FIXTURE_NOW),
    )


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
        record["links"]["nvd"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        _sync_intelligence_id(record)
        if index == 0:
            record["kev"]["vendor_project"] = "=1+1"
            record["kev"]["product"] = "Formula Product"
            record["kev"]["date_added"] = "2099-02-01"
            record["kev"]["cwes"] = ["CWE-94"]
            record["cve"]["severity"]["base_score"] = 9.8
            record["cve"]["severity"]["base_severity"] = "CRITICAL"
            _set_intel(
                record,
                assessments=[
                    {
                        "source": "cve_cna",
                        "cvss_version": "3.1",
                        "base_score": 7.5,
                        "severity": "HIGH",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "metrics": {
                            "attackVector": "NETWORK",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                        },
                    },
                    {
                        "source": "nvd",
                        "cvss_version": "3.1",
                        "base_score": 9.8,
                        "severity": "CRITICAL",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "metrics": {
                            "attackVector": "NETWORK",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                        },
                    },
                ],
                cwes=[{"cwe_id": "CWE-94", "name": "Code Injection", "source": "cve_cna"}],
                fixed=False,
                nvd_status="ok",
                conflicts=[{"kind": "cvss", "note": "CNA and NVD CVSS 3.1 scores differ."}],
            )
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
            _set_intel(
                record,
                assessments=[],
                cwes=[],
                fixed=False,
                nvd_status="unavailable",
                descriptions=[
                    {
                        "text": "<img src=x onerror=alert(1)>",
                        "source": "nvd",
                    }
                ],
            )
        elif index == 2:
            record["kev"]["vendor_project"] = "Acme"
            record["kev"]["product"] = "Gadget"
            record["kev"]["date_added"] = "2099-03-01"
            record["cve"]["omitted_version_count"] = 1
            record["cve"]["truncated_fields"] = ["versions"]
            record["completeness"] = "partial"
            record["cve"]["severity"]["base_score"] = 4.3
            record["cve"]["severity"]["base_severity"] = "MEDIUM"
            _set_intel(
                record,
                assessments=[
                    {
                        "source": "cve_cna",
                        "cvss_version": "3.1",
                        "base_score": 4.3,
                        "severity": "MEDIUM",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
                        "metrics": {
                            "attackVector": "NETWORK",
                            "privilegesRequired": "LOW",
                            "userInteraction": "REQUIRED",
                        },
                    }
                ],
                cwes=[{"cwe_id": "CWE-79", "name": "XSS", "source": "nvd"}],
                fixed=True,
                nvd_status="ok",
                advisories=[
                    {
                        "url": "https://vendor.example/advisory/CVE-2099-1002",
                        "title": "Vendor advisory",
                        "classification": "vendor_advisory",
                        "source": "cve_cna",
                    }
                ],
            )
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
    for record in payload["records"]:
        _sync_intelligence_id(record)
    return payload


def _sync_intelligence_id(record: dict) -> None:
    intel = record.get("intelligence")
    if not isinstance(intel, dict):
        return
    identity = intel.setdefault("identity", {})
    identity["cve_id"] = record["cve_id"]


def _set_intel(
    record: dict,
    *,
    assessments: list,
    cwes: list,
    fixed: bool,
    nvd_status: str,
    conflicts: list | None = None,
    descriptions: list | None = None,
    references: list | None = None,
    advisories: list | None = None,
) -> None:
    intel = record.setdefault("intelligence", {})
    intel["schema_version"] = "1.0.0"
    intel.setdefault("identity", {})["cve_id"] = record["cve_id"]
    intel["descriptions"] = descriptions or []
    intel["cvss"] = {
        "assessments": assessments,
        "display_preference_note": (
            "Display preference is a deterministic UI order, not a correctness ranking."
        ),
    }
    intel["cwes"] = {"assertions": cwes}
    intel["affected"] = {
        "products": [
            {
                "vendor": record["kev"]["vendor_project"],
                "product": record["kev"]["product"],
                "source": "cve_cna",
                "ranges": [
                    {
                        "status": "affected",
                        "version": "1.0",
                        "less_than": "2.0",
                        "less_than_or_equal": None,
                        "greater_than": None,
                        "greater_than_or_equal": None,
                        "version_type": "semver",
                    }
                ],
            }
        ],
        "note": "Affected ranges are not merged across sources.",
    }
    intel["remediation"] = {
        "fixed_versions": (
            [
                {
                    "vendor": record["kev"]["vendor_project"],
                    "product": record["kev"]["product"],
                    "version": "2.0.0",
                    "source": "cve_cna",
                    "evidence": "cna_changes_status_fixed",
                }
            ]
            if fixed
            else []
        ),
        "vendor_advisories": advisories or [],
        "note": "Fixed versions appear only from explicit CNA fixed evidence.",
    }
    intel["references"] = (advisories or []) + (references or [])
    intel["sources"] = {
        "cisa_kev": {"status": "ok", "completeness": "available"},
        "cve_list_v5": {
            "status": record["cve"].get("status") or "ok",
            "completeness": "unavailable" if record["completeness"] == "unavailable" else "available",
        },
        "nvd": {"status": nvd_status, "completeness": "available" if nvd_status == "ok" else "unavailable"},
    }
    intel["conflicts"] = conflicts or []
    intel["coverage"] = {
        "has_cvss": bool(assessments),
        "has_cwe": bool(cwes),
        "has_affected_versions": True,
        "has_fixed_version": fixed,
        "has_vendor_advisory": bool(advisories),
        "nvd_available": nvd_status == "ok",
    }


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
