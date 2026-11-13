"""Command-line interface for collection, validation, and promotion."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from silastron_pulse.clock import SystemClock, format_datetime, parse_generated_at
from silastron_pulse.config import PulseConfig
from silastron_pulse.errors import PulseError, ValidationError
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.pipeline import collect
from silastron_pulse.auto_publish import (
    attach_verification_status,
    evaluate_publication,
    write_decision_outputs,
)
from silastron_pulse.pages_observe import observe_pages_manifest
from silastron_pulse.reconciliation import (
    RECONCILE_CONFIRM,
    assert_intent_matches,
    assert_publication_consistent,
    build_publication_intent,
    build_publication_status,
    classify_workflow_outcome,
    publication_status_path,
    reconcile_publication,
    write_publication_intent,
    write_publication_status,
)
from silastron_pulse.verify_operations import verify_operations
from silastron_pulse.verification_status import record_failed_attempt, validate_verification_status
from silastron_pulse.safe_fs import (
    assert_artifact_tree,
    copy_tree_without_symlinks,
    require_run_id,
)
from silastron_pulse.store import (
    assert_site_data_matches_published,
    atomic_write_json,
    load_snapshot,
    promote_snapshot,
    rebuild_catalog_index,
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

    rebuild_index = sub.add_parser(
        "build-catalog-index",
        help="Regenerate catalog-index.json and cve/*.json from an existing latest.json",
    )
    rebuild_index.add_argument("--published-dir", type=Path, required=True)

    static_pages = sub.add_parser(
        "build-static-cve-pages",
        help="Render one minimal static page per published CVE, plus sitemap.xml",
    )
    static_pages.add_argument("--published-dir", type=Path, required=True)
    static_pages.add_argument("--site-dir", type=Path, required=True)
    static_pages.add_argument("--base-url", required=True)

    site_files = sub.add_parser(
        "build-site-files", help="Write sitemap.xml, robots.txt, Atom feeds and build.json"
    )
    site_files.add_argument("--published-dir", type=Path, required=True)
    site_files.add_argument("--site-dir", type=Path, required=True)
    site_files.add_argument("--base-url", required=True)
    site_files.add_argument("--commit", required=True)
    site_files.add_argument("--malware-state-commit")
    site_files.add_argument("--now", help="ISO 8601 build instant (default: current time)")

    budget = sub.add_parser("check-site-budget", help="Fail if the site tree exceeds the size budget")
    budget.add_argument("--site-dir", type=Path, required=True)
    budget.add_argument("--budget", type=Path, default=Path("ops/site-budget.json"))

    smoke = sub.add_parser("smoke-test", help="Poll the live site until it matches the build")
    smoke.add_argument("--site-dir", type=Path, required=True)
    smoke.add_argument("--url", required=True)
    smoke.add_argument("--timeout", type=float, default=300)
    smoke.add_argument("--interval", type=float, default=15)
    prune = sub.add_parser(
        "prune-deployed-snapshots",
        help="Drop all but the current and newest other snapshot from a site data copy",
    )
    prune.add_argument("--data-dir", type=Path, required=True)

    mal_collect = sub.add_parser(
        "malware-collect", help="Ingest a clone of ossf/malicious-packages into the malware-state tree"
    )
    mal_collect.add_argument("--clone-dir", type=Path, required=True)
    mal_collect.add_argument("--state-dir", type=Path, required=True)
    mal_collect.add_argument("--upstream-sha", required=True)
    mal_collect.add_argument("--now", help="ISO 8601 instant (default: current time)")
    mal_collect.add_argument("--summary-file", type=Path)

    mal_site = sub.add_parser("build-malware-data", help="Write /malware/data from the malware-state tree")
    mal_site.add_argument("--state-dir", type=Path, required=True)
    mal_site.add_argument("--site-dir", type=Path, required=True)
    mal_site.add_argument("--licence", type=Path, default=Path("vendor/openssf-malicious-packages/LICENSE"))

    home = sub.add_parser(
        "build-home-page",
        help="Pre-render the home page sections and the methodology page",
    )
    home.add_argument("--published-dir", type=Path, required=True)
    home.add_argument("--template", type=Path, required=True)
    home.add_argument("--site-dir", type=Path, required=True)
    home.add_argument("--now", help="ISO 8601 instant used for ages (default: current time)")
    home.add_argument("--base-url", default="https://pulse.silastron.com")

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

    decide = sub.add_parser(
        "decide-publication",
        help="Fail-closed eligibility decision for a bound Collect artifact",
    )
    decide.add_argument("--mode", choices=("auto", "manual"), required=True)
    decide.add_argument("--run-json", type=Path, required=True)
    decide.add_argument("--artifact-json", type=Path, required=True)
    decide.add_argument("--candidate", type=Path, required=True)
    decide.add_argument("--metadata-json", type=Path, required=True)
    decide.add_argument("--sha256sums", type=Path, required=True)
    decide.add_argument("--published-dir", type=Path, required=True)
    decide.add_argument("--expected-repository", required=True)
    decide.add_argument("--expected-branch", default="main")
    decide.add_argument("--github-output", type=Path, default=None)
    decide.add_argument("--summary-path", type=Path, default=None)
    decide.add_argument("--now", default=None, help="RFC3339 evaluation time (tests)")
    decide.add_argument("--kev-catalog", type=Path, required=True)
    decide.add_argument("--kev-meta", type=Path, required=True)
    decide.add_argument("--expected-run-id", default=None)
    decide.add_argument("--expected-event", default=None)
    decide.add_argument("--expected-head-sha", default=None)
    decide.add_argument("--artifact-dir", type=Path, default=None)
    decide.add_argument("--verification-status-out", type=Path, default=None)

    artifact_dir = sub.add_parser(
        "verify-artifact-dir",
        help="Refuse unexpected files or symlinks in a Collect artifact tree",
    )
    artifact_dir.add_argument("--path", type=Path, required=True)

    copy_tree = sub.add_parser(
        "safe-copy",
        help="Copy published JSON without following symlinks",
    )
    copy_tree.add_argument("--src", type=Path, required=True)
    copy_tree.add_argument("--dst", type=Path, required=True)

    verify_status = sub.add_parser(
        "verify-publication-status",
        help="Refuse publication or frontend deploy when Pages and pulse-state diverged",
    )
    verify_status.add_argument("--published-dir", type=Path, required=True)
    verify_status.add_argument("--require", default="consistent")

    write_status = sub.add_parser(
        "write-publication-status",
        help="Record deploy/persist reconciliation state",
    )
    write_status.add_argument("--published-dir", type=Path, required=True)
    write_status.add_argument("--state", required=True)
    write_status.add_argument("--classification", default="")
    write_status.add_argument("--snapshot-id", default=None)
    write_status.add_argument("--collect-run-id", default=None)
    write_status.add_argument("--deployment-run-id", default=None)
    write_status.add_argument("--manifest-digest", default=None)
    write_status.add_argument("--persisted-snapshot-id", default=None)
    write_status.add_argument("--persisted-manifest-digest", default=None)
    write_status.add_argument("--page-url", default=None)
    write_status.add_argument("--note", default=None)
    write_status.add_argument("--deploy-result", default=None)
    write_status.add_argument("--persist-result", default=None)

    reconcile = sub.add_parser(
        "reconcile-publication",
        help="Idempotent recovery after a successful deploy and failed persist",
    )
    reconcile.add_argument("--incoming", type=Path, required=True)
    reconcile.add_argument("--current", type=Path, required=True)
    reconcile.add_argument("--expected-snapshot-id", required=True)
    reconcile.add_argument("--expected-digest", required=True)
    reconcile.add_argument("--expected-collect-run-id", required=True)
    reconcile.add_argument("--confirm", required=True)
    reconcile.add_argument("--deployment-run-id", default=None)

    write_intent = sub.add_parser(
        "write-publication-intent",
        help="Persist publication intent before Pages deploy",
    )
    write_intent.add_argument("--published-dir", type=Path, required=True)
    write_intent.add_argument("--snapshot-id", required=True)
    write_intent.add_argument("--collect-run-id", required=True)
    write_intent.add_argument("--candidate-digest", required=True)
    write_intent.add_argument("--deployment-run-id", required=True)
    write_intent.add_argument("--expected-previous-snapshot-id", default="")
    write_intent.add_argument("--state", default="pending_deploy")

    verify_intent = sub.add_parser(
        "verify-publication-intent",
        help="Refuse deploy when the recorded intent does not match the validated candidate",
    )
    verify_intent.add_argument("--published-dir", type=Path, required=True)
    verify_intent.add_argument("--snapshot-id", required=True)
    verify_intent.add_argument("--collect-run-id", required=True)
    verify_intent.add_argument("--candidate-digest", required=True)

    write_verification = sub.add_parser(
        "write-verification-status",
        help="Write a validated operational verification-status document",
    )
    write_verification.add_argument("--candidate", type=Path, required=True)
    write_verification.add_argument("--published-dir", type=Path, required=True)
    write_verification.add_argument("--decision", required=True)
    write_verification.add_argument("--reason", required=True)
    write_verification.add_argument("--collect-run-id", default=None)
    write_verification.add_argument("--collect-event", default=None)
    write_verification.add_argument("--candidate-digest", default=None)
    write_verification.add_argument("--output", type=Path, required=True)

    record_failure = sub.add_parser(
        "record-failed-collect",
        help="Attach a failed Collect attempt to the persisted verification-status",
    )
    record_failure.add_argument("--published-dir", type=Path, required=True)
    record_failure.add_argument("--collect-run-id", required=True)
    record_failure.add_argument("--conclusion", required=True)
    record_failure.add_argument("--attempted-at", required=True)

    verify_ops = sub.add_parser(
        "verify-operations",
        help="Read-only operational verification. Never writes or dispatches.",
    )
    verify_ops.add_argument("--pages-url", default="https://pulse.silastron.com")
    verify_ops.add_argument("--repository", default="Mehrn0ush/silastron-security-pulse")

    observe = sub.add_parser(
        "observe-pages-manifest",
        help="Observe the public Pages manifest without treating job status as proof",
    )
    observe.add_argument("--url", required=True)
    observe.add_argument("--expected-snapshot-id", required=True)
    observe.add_argument("--expected-digest", default=None)
    observe.add_argument("--attempts", type=int, default=3)

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
            if payload.get("kind") == "verification_status":
                validate_verification_status(payload)
            elif "records" in payload:
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
        if args.command == "verify-artifact-dir":
            assert_artifact_tree(args.path)
            print("artifact tree ok")
            return 0
        if args.command == "safe-copy":
            copy_tree_without_symlinks(args.src, args.dst)
            print("copied")
            return 0
        if args.command == "verify-publication-status":
            if args.require != "consistent":
                raise PulseError("verify-publication-status only supports --require consistent")
            config = PulseConfig.from_env(args.published_dir)
            status = assert_publication_consistent(
                args.published_dir,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            print(json.dumps(status, indent=2, default=str))
            return 0
        if args.command == "write-publication-status":
            classification = args.classification or classify_workflow_outcome(
                deploy_result=args.deploy_result,
                persist_result=args.persist_result,
            )
            payload = build_publication_status(
                state=args.state,
                classification=classification,
                now=SystemClock().now(),
                snapshot_id=args.snapshot_id,
                collect_run_id=args.collect_run_id,
                deployment_run_id=args.deployment_run_id,
                manifest_digest=args.manifest_digest,
                persisted_snapshot_id=args.persisted_snapshot_id,
                persisted_manifest_digest=args.persisted_manifest_digest,
                page_url=args.page_url,
                note=args.note,
            )
            written = write_publication_status(args.published_dir, payload)
            print(json.dumps(written, indent=2, default=str))
            return 0
        if args.command == "reconcile-publication":
            if args.confirm != RECONCILE_CONFIRM:
                raise PulseError("Reconciliation requires --confirm RECONCILE")
            config = PulseConfig.from_env(args.incoming)
            result = reconcile_publication(
                incoming_dir=args.incoming,
                current_dir=args.current,
                expected_snapshot_id=args.expected_snapshot_id,
                expected_digest=args.expected_digest,
                expected_collect_run_id=args.expected_collect_run_id,
                confirm=args.confirm,
                now=SystemClock().now(),
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
                deployment_run_id=args.deployment_run_id,
            )
            if result.get("copy_required"):
                copy_tree_without_symlinks(args.incoming, args.current)
                write_publication_status(args.current, result["publication_status"])
            print(json.dumps(result, indent=2, default=str))
            return 0
        if args.command == "write-publication-intent":
            payload = build_publication_intent(
                now=SystemClock().now(),
                snapshot_id=args.snapshot_id,
                collect_run_id=args.collect_run_id,
                candidate_digest=args.candidate_digest,
                expected_previous_snapshot_id=args.expected_previous_snapshot_id or None,
                deployment_run_id=args.deployment_run_id,
                state=args.state,
            )
            written = write_publication_intent(args.published_dir, payload)
            print(json.dumps(written, indent=2, default=str))
            return 0
        if args.command == "verify-publication-intent":
            config = PulseConfig.from_env(args.published_dir)
            intent = assert_intent_matches(
                args.published_dir,
                snapshot_id=args.snapshot_id,
                collect_run_id=args.collect_run_id,
                candidate_digest=args.candidate_digest,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            print(json.dumps(intent, indent=2, default=str))
            return 0
        if args.command == "observe-pages-manifest":
            result = observe_pages_manifest(
                args.url,
                expected_snapshot_id=args.expected_snapshot_id,
                expected_digest=args.expected_digest,
                attempts=args.attempts,
            )
            print(json.dumps(result, indent=2, default=str))
            return 0
        if args.command == "decide-publication":
            config = PulseConfig.from_env(args.published_dir)
            if args.artifact_dir is not None:
                assert_artifact_tree(args.artifact_dir)
            run = json.loads(args.run_json.read_text(encoding="utf-8"))
            artifact = json.loads(args.artifact_json.read_text(encoding="utf-8"))
            metadata = json.loads(args.metadata_json.read_text(encoding="utf-8"))
            kev_catalog = json.loads(args.kev_catalog.read_text(encoding="utf-8"))
            kev_meta = json.loads(args.kev_meta.read_text(encoding="utf-8"))
            extra_files = {
                "source-kev-catalog.json": args.kev_catalog.read_bytes(),
                "source-kev-meta.json": args.kev_meta.read_bytes(),
            }
            provenance_path = args.kev_catalog.with_name("source-kev-provenance.json")
            if provenance_path.is_file() and not provenance_path.is_symlink():
                extra_files["source-kev-provenance.json"] = provenance_path.read_bytes()
            decision = evaluate_publication(
                mode=args.mode,
                run=run,
                expected_repository=args.expected_repository,
                expected_branch=args.expected_branch,
                artifact=artifact,
                candidate_bytes=args.candidate.read_bytes(),
                metadata=metadata,
                sha256sums_text=args.sha256sums.read_text(encoding="utf-8"),
                published_dir=args.published_dir,
                now=parse_generated_at(args.now) if args.now else SystemClock().now(),
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
                stale_after_hours=config.stale_after_hours,
                expected_head_sha=args.expected_head_sha or None,
                expected_run_id=require_run_id(args.expected_run_id or run.get("id")),
                expected_event=args.expected_event or None,
                kev_catalog=kev_catalog,
                kev_meta=kev_meta,
                extra_files=extra_files,
            )
            write_decision_outputs(
                decision,
                output_path=args.github_output,
                summary_path=args.summary_path,
            )
            if args.verification_status_out is not None and decision.outcome in {"publish", "skip"}:
                published = None
                latest = args.published_dir / "latest.json"
                if latest.exists():
                    published = load_snapshot(
                        latest,
                        max_bytes=config.max_snapshot_bytes,
                        max_depth=config.max_json_depth,
                        compatible=True,
                    )
                publication_state = None
                status_file = publication_status_path(args.published_dir)
                if status_file.exists():
                    publication_state = json.loads(status_file.read_text(encoding="utf-8")).get("state")
                candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
                payload = attach_verification_status(
                    decision,
                    candidate=candidate,
                    published=published,
                    publication_state=publication_state,
                )
                atomic_write_json(args.verification_status_out, payload)
            print(json.dumps(
                {
                    "outcome": decision.outcome,
                    "reason": decision.reason,
                    "snapshot_id": decision.snapshot_id,
                    "collect_run_id": decision.collect_run_id,
                    "digest": decision.digest,
                    "details": decision.details,
                },
                indent=2,
                default=str,
            ))
            return 0 if decision.outcome in {"publish", "skip"} else 1
        if args.command == "write-verification-status":
            config = PulseConfig.from_env(args.published_dir)
            candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
            published = None
            latest = args.published_dir / "latest.json"
            if latest.exists():
                published = load_snapshot(
                    latest,
                    max_bytes=config.max_snapshot_bytes,
                    max_depth=config.max_json_depth,
                    compatible=True,
                )
            publication_state = None
            status_file = publication_status_path(args.published_dir)
            if status_file.exists():
                publication_state = json.loads(status_file.read_text(encoding="utf-8")).get("state")
            from silastron_pulse.auto_publish import PublicationDecision

            decision = PublicationDecision(
                outcome=args.decision,
                reason=args.reason,
                snapshot_id=candidate.get("snapshot_id"),
                collect_run_id=args.collect_run_id,
                digest=args.candidate_digest,
                details={"collect_event": args.collect_event},
            )
            payload = attach_verification_status(
                decision,
                candidate=candidate,
                published=published,
                publication_state=publication_state,
            )
            atomic_write_json(args.output, payload)
            print("verification status written")
            return 0
        if args.command == "record-failed-collect":
            target = args.published_dir / "verification-status.json"
            if not target.is_file():
                raise ValidationError("No persisted verification-status to annotate")
            payload = record_failed_attempt(
                json.loads(target.read_text(encoding="utf-8")),
                collect_run_id=args.collect_run_id,
                conclusion=args.conclusion,
                attempted_at=_normalized_instant(args.attempted_at),
            )
            atomic_write_json(target, payload)
            print("failed collect attempt recorded")
            return 0
        if args.command == "verify-operations":
            report = verify_operations(
                pages_url=args.pages_url,
                repository=args.repository,
            )
            print(json.dumps(report, indent=2, default=str))
            if report.get("verdict") == "verified_operational_failure":
                return 1
            return 0
        if args.command == "write-unpublished":
            clock = SystemClock()
            payload = unpublished_status(generated_at=format_datetime(clock.now()))
            atomic_write_json(args.published_dir / "manifest.json", payload)
            atomic_write_json(args.published_dir / "status.json", payload)
            print("unpublished status written")
            return 0
        if args.command == "build-catalog-index":
            config = PulseConfig.from_env(args.published_dir)
            count = rebuild_catalog_index(
                args.published_dir,
                max_bytes=config.max_snapshot_bytes,
                max_depth=config.max_json_depth,
            )
            print(f"rebuilt catalog index for {count} records")
            return 0
        if args.command == "build-site-files":
            from datetime import datetime, timezone

            from silastron_pulse.home_page import parse_instant
            from silastron_pulse.site_files import build_site_files

            built_at = parse_instant(args.now) if args.now else datetime.now(timezone.utc)
            if built_at is None:
                raise PulseError(f"invalid --now: {args.now}")
            stats = build_site_files(
                published_dir=args.published_dir,
                site_dir=args.site_dir,
                base_url=args.base_url,
                commit=args.commit,
                built_at=built_at,
                malware_state_commit=args.malware_state_commit or None,
            )
            print(f"wrote sitemap ({stats['sitemap_urls']} URLs), feeds ({stats['feed_entries']} entries), build.json")
            return 0
        if args.command == "check-site-budget":
            from silastron_pulse.site_budget import check_site_budget, load_budget

            problems, stats = check_site_budget(args.site_dir, load_budget(args.budget))
            print(f"site: {stats['total_bytes']} bytes in {stats['files']} files; malware/: {stats['malware_bytes']} bytes")
            for problem in problems:
                print(f"BUDGET: {problem}", file=sys.stderr)
            return 1 if problems else 0
        if args.command == "smoke-test":
            from silastron_pulse.smoke import run as smoke_run

            problems = smoke_run(args.site_dir, args.url, timeout=args.timeout, interval=args.interval)
            for problem in problems:
                print(f"SMOKE: {problem}", file=sys.stderr)
            return 1 if problems else 0
        if args.command == "prune-deployed-snapshots":
            from silastron_pulse.store import prune_deployed_snapshots

            removed = prune_deployed_snapshots(args.data_dir)
            print(f"pruned {len(removed)} snapshot(s) from the deployed copy")
            return 0
        if args.command == "malware-collect":
            from datetime import datetime, timezone

            from silastron_pulse.home_page import parse_instant
            from silastron_pulse.malware.collect import collect_malware

            now = parse_instant(args.now) if args.now else datetime.now(timezone.utc)
            if now is None:
                raise PulseError(f"invalid --now: {args.now}")
            outcome = collect_malware(
                clone_dir=args.clone_dir, state_dir=args.state_dir, upstream_sha=args.upstream_sha, now=now
            )
            print(outcome.summary_markdown)
            if args.summary_file:
                args.summary_file.write_text(outcome.summary_markdown, encoding="utf-8")
            return 0 if outcome.ok else 1
        if args.command == "build-malware-data":
            from silastron_pulse.malware.site_data import build_malware_site_data

            status = build_malware_site_data(
                state_dir=args.state_dir, site_dir=args.site_dir, licence_file=args.licence
            )
            print(f"wrote /malware/data: {status['active']} active reports, collected {status['collected_at']}")
            return 0
        if args.command == "build-home-page":
            from datetime import datetime, timezone

            from silastron_pulse.home_page import build_home_page, parse_instant
            from silastron_pulse.methodology_page import build_methodology_page

            now = parse_instant(args.now) if args.now else datetime.now(timezone.utc)
            if now is None:
                raise PulseError(f"invalid --now: {args.now}")
            build_home_page(
                published_dir=args.published_dir,
                template_path=args.template,
                site_dir=args.site_dir,
                now=now,
                base_url=args.base_url,
            )
            from silastron_pulse import page_chrome
            from silastron_pulse.home_page import footer_times

            collected, published = footer_times(args.published_dir)
            build_methodology_page(
                args.site_dir,
                base_url=args.base_url,
                footer=page_chrome.footer(last_collected=collected, last_published=published),
            )
            print("wrote index.html and methodology/index.html")
            return 0
        if args.command == "build-static-cve-pages":
            from silastron_pulse.static_pages import build_static_cve_pages

            count = build_static_cve_pages(
                published_dir=args.published_dir,
                site_dir=args.site_dir,
                base_url=args.base_url,
            )
            print(f"wrote {count} static CVE pages")
            return 0
    except PulseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())


def _normalized_instant(value: str) -> str:
    try:
        return format_datetime(parse_generated_at(value))
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
