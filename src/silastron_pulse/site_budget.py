"""Size budget for the deployed site. Fails the build; never trims anything."""

from __future__ import annotations

import json
from pathlib import Path


def load_budget(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check_site_budget(site_dir: Path, budget: dict) -> tuple[list[str], dict[str, int]]:
    """Return (problems, stats). Symlinks are refused."""
    problems: list[str] = []
    total = 0
    malware_total = 0
    largest: list[tuple[int, str]] = []
    growth = 1 + float(budget["max_growth_fraction"])
    allow: dict[str, int] = budget["allowlist"]
    snap_prefix = budget["snapshot_glob"]
    snap_limit = int(allow[budget["snapshot_baseline"]] * growth)
    malware_prefix = budget["malware_prefix"]
    for path in sorted(site_dir.rglob("*")):
        if path.is_symlink():
            problems.append(f"symlink in site tree: {path.relative_to(site_dir)}")
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(site_dir).as_posix()
        size = path.stat().st_size
        total += size
        if rel.startswith(malware_prefix):
            malware_total += size
        largest.append((size, rel))
        if rel in allow:
            if size > int(allow[rel] * growth):
                problems.append(f"{rel} is {size} bytes, more than {budget['max_growth_fraction']:.0%} above its recorded {allow[rel]}")
        elif rel.startswith(snap_prefix) and rel.endswith(".json"):
            if size > snap_limit:
                problems.append(f"{rel} is {size} bytes, above the {snap_limit} bound for deployed snapshots")
        elif size > budget["max_file_bytes"]:
            problems.append(f"{rel} is {size} bytes, above the {budget['max_file_bytes']} per-file limit")
    if total > budget["max_site_bytes"]:
        problems.append(f"site is {total} bytes, above the {budget['max_site_bytes']} limit")
    if malware_total > budget["max_malware_bytes"]:
        problems.append(f"{malware_prefix} is {malware_total} bytes, above the {budget['max_malware_bytes']} limit")
    largest.sort(reverse=True)
    stats = {"total_bytes": total, "malware_bytes": malware_total, "files": len(largest)}
    return problems, stats
