"""Command-line interface for collection, validation, and promotion."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from silastron_pulse.clock import SystemClock, format_datetime
from silastron_pulse.config import PulseConfig
from silastron_pulse.errors import PulseError
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.pipeline import collect
from silastron_pulse.store import (
    assert_site_data_matches_published,
    atomic_write_json,
    load_snapshot,
    promote_snapshot,
    rollback_snapshot,
    unpublished_status,
    verify_publication_transition,
    verify_published_site,
)
from silastron_pulse.validate import validate_manifest, validate_snapshot
from silastron_pulse.verify_run import verify_collect_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="silastron-pulse",
        description="Silastron Security Pulse collection pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect_parser = sub.add_parser("collect", help="Collect a candidate snapshot")
    collect_parser.add_argument("--output-dir", type=Path, required=True)
    collect_parser.add_argument("--previous", type=Path, default=None)
    collect_parser.add_argument("--state-dir", type=Path, default=None)
    collect_parser.add_argument("--collector-sha", type=str, default=None)
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
    promote_parser.add_argument("--expected-digest", type=str, default=None)
    promote_parser.add_argument("--expected-collector-sha", type=str, default=None)
    promote_parser.add_argument("--expected-source-revision", type=str, default=None)

    rollback_parser = sub.add_parser("rollback", help="Explicitly restore an archived snapshot")
    rollback_parser.add_argument("--published-dir", type=Path, required=True)
    rollback_parser.add_argument("--snapshot-id", required=True)
    rollback_parser.add_argument("--confirm", required=True)

    verify = sub.add_parser("verify-run", help="Verify a collect workflow run and artifact")
    verify.add_argument("--run-json", type=Path, required=True)
    verify.add_argument("--artifact-json", type=Path, required=True)
    verify.add_argument("--candidate", type=Path, required=True)
    verify.add_argument("--expected-repository", required=True)
    verify.add_argument("--expected-branch", required=True)
    verify.add_argument("--expected-head-sha", default=None)
    verify.add_argument("--expected-digest", default=None)

    unpublished = sub.add_parser("write-unpublished", help="Write the unpublished status documents")
    unpublished.add_argument("--published-dir", type=Path, required=True)

    verify_pub = sub.add_parser(
        "verify-publication",
        help="Refuse persist when the comparison baseline is stale",
    )
    verify_pub.add_argument("--incoming", type=Path, required=True)
    verify_pub.add_argument("--current", type=Path, required=True)

    verify_site = sub.add_parser(
        "verify-published-site",
        help="Validate published Pages data without promoting",
    )
    verify_site.add_argument("--published-dir", type=Path, required=True)
    verify_site.add_argument("--site-data", type=Path, default=None)

    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            config = PulseConfig.from_env(args.output_dir)
            result = collect(
                config=config,
                previous_snapshot_path=args.previous,
                promote=args.promote,
                state_dir=args.state_dir,
                collector_commit_sha=args.collector_sha,
            )
            if result.status == "failed":
                print(f"collection failed: {result.error}", file=sys.stderr)
                return 1
            print(f"collection {result.status}: {result.snapshot['snapshot_id']}")
            return 0
        if args.command == "validate":
            payload = json.loads(args.path.read_text(encoding="utf-8"))
            if "records" in payload:
                validate_snapshot(payload)
            else:
                validate_manifest(payload)
            print("valid")
            return 0
        if args.command == "promote":
            config = PulseConfig.from_env(args.published_dir)
            raw = args.candidate.read_bytes()
            if args.expected_digest and sha256_bytes(raw) != args.expected_digest:
                raise PulseError("Candidate digest does not match --expected-digest")
            candidate = load_snapshot(
                args.candidate,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            binding = candidate.get("binding") or {}
            if args.expected_collector_sha:
                actual = binding.get("collector_commit_sha")
                if actual != args.expected_collector_sha:
                    raise PulseError(
                        f"Candidate collector SHA {actual} does not match {args.expected_collector_sha}"
                    )
            if args.expected_source_revision:
                actual_rev = binding.get("source_state_revision")
                if actual_rev != args.expected_source_revision:
                    raise PulseError(
                        "Candidate source-state revision does not match metadata"
                    )
            promote_snapshot(
                candidate,
                args.published_dir,
                now=SystemClock().now(),
                stale_after_hours=config.stale_after_hours,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            print("promoted")
            return 0
        if args.command == "rollback":
            config = PulseConfig.from_env(args.published_dir)
            rollback_snapshot(
                args.published_dir,
                args.snapshot_id,
                now=SystemClock().now(),
                stale_after_hours=config.stale_after_hours,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
                confirm=args.confirm,
            )
            print("rolled back")
            return 0
        if args.command == "verify-run":
            run = json.loads(args.run_json.read_text(encoding="utf-8"))
            artifact = json.loads(args.artifact_json.read_text(encoding="utf-8"))
            candidate_bytes = args.candidate.read_bytes()
            result = verify_collect_run(
                run,
                expected_repository=args.expected_repository,
                expected_branch=args.expected_branch,
                expected_head_sha=args.expected_head_sha,
                artifact=artifact,
                candidate_bytes=candidate_bytes,
                expected_digest=args.expected_digest,
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "verify-publication":
            config = PulseConfig.from_env(args.incoming)
            verify_publication_transition(
                incoming_dir=args.incoming,
                current_dir=args.current,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            print("publication transition ok")
            return 0
        if args.command == "verify-published-site":
            config = PulseConfig.from_env(args.published_dir)
            result = verify_published_site(
                args.published_dir,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            if args.site_data is not None:
                assert_site_data_matches_published(args.site_data, args.published_dir)
            print(json.dumps(result, indent=2))
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
