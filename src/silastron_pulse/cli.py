"""Command-line interface for collection, validation, and promotion."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from silastron_pulse.config import PulseConfig
from silastron_pulse.errors import PulseError
from silastron_pulse.pipeline import collect
from silastron_pulse.store import (
    load_snapshot,
    promote_snapshot,
    unpublished_status,
    atomic_write_json,
)
from silastron_pulse.validate import validate_manifest, validate_snapshot
from silastron_pulse.clock import SystemClock, format_datetime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="silastron-pulse",
        description="Silastron Security Pulse collection pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect_parser = sub.add_parser("collect", help="Collect a candidate snapshot")
    collect_parser.add_argument("--output-dir", type=Path, required=True)
    collect_parser.add_argument("--previous", type=Path, default=None)
    collect_parser.add_argument(
        "--promote",
        action="store_true",
        help="Promote the candidate into the output published directory",
    )

    validate_parser = sub.add_parser("validate", help="Validate a snapshot JSON file")
    validate_parser.add_argument("path", type=Path)

    promote_parser = sub.add_parser("promote", help="Atomically publish a candidate snapshot")
    promote_parser.add_argument("--candidate", type=Path, required=True)
    promote_parser.add_argument("--published-dir", type=Path, required=True)

    unpublished = sub.add_parser("write-unpublished", help="Write the unpublished status documents")
    unpublished.add_argument("--published-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            config = PulseConfig.from_env(args.output_dir)
            result = collect(
                config=config,
                previous_snapshot_path=args.previous,
                promote=args.promote,
            )
            if result.status == "failed":
                print(f"collection failed: {result.error}", file=sys.stderr)
                return 1
            print(f"collection {result.status}: {result.snapshot['snapshot_id']}")
            return 0
        if args.command == "validate":
            config = PulseConfig.from_env(Path("."))
            payload = json.loads(args.path.read_text(encoding="utf-8"))
            if "records" in payload:
                validate_snapshot(payload)
            else:
                validate_manifest(payload)
            print("valid")
            return 0
        if args.command == "promote":
            config = PulseConfig.from_env(args.published_dir)
            candidate = load_snapshot(
                args.candidate,
                max_bytes=config.max_kev_bytes,
                max_depth=config.max_json_depth,
            )
            promote_snapshot(
                candidate,
                args.published_dir,
                now=SystemClock().now(),
                stale_after_hours=config.stale_after_hours,
                max_bytes=config.max_kev_bytes,
                max_depth=config.max_json_depth,
            )
            print("promoted")
            return 0
        if args.command == "write-unpublished":
            clock = SystemClock()
            payload = unpublished_status(generated_at=format_datetime(clock.now()))
            atomic_write_json(args.published_dir / "manifest.json", payload)
            atomic_write_json(args.published_dir / "status.json", payload)
            print("unpublished status written")
            return 0
    except PulseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
