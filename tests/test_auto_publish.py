"""Fail-closed automated publication eligibility."""

from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.auto_publish import evaluate_publication
from silastron_pulse.cli import main
from silastron_pulse.jsonutil import dump_bytes, sha256_bytes
from silastron_pulse.kev_integrity import catalog_from_snapshot
from silastron_pulse.pipeline import collect
from silastron_pulse.store import promote_snapshot
from silastron_pulse.verify_run import verify_collect_run
from tests.support import frozen_clock, test_config, valid_fetcher

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2099, 1, 10, 14, tzinfo=timezone.utc)
REPO = "Mehrn0ush/silastron-security-pulse"


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _run(**overrides: object) -> dict:
    payload = {
        "id": 99,
        "repository_full_name": REPO,
        "path": ".github/workflows/collect.yml",
        "name": "Collect",
        "head_branch": "main",
        "conclusion": "success",
        "event": "schedule",
        "head_sha": "abc",
    }
    payload.update(overrides)
    return payload


class AutoPublishHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = test_config(self.root / "collect")
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
            collector_commit_sha="abc",
        )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        self.snapshot = result.snapshot
        self.published = self.root / "published"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _bundle(self, snapshot: dict, *, event: str = "schedule") -> dict:
        raw = dump_bytes(snapshot)
        digest = sha256_bytes(raw)
        catalog, meta = catalog_from_snapshot(snapshot)
        catalog_bytes = dump_bytes(catalog)
        meta_bytes = dump_bytes(meta)
        binding = snapshot.get("binding") or {}
        metadata = {
            "content_sha256": digest,
            "source_state_revision": binding.get("source_state_revision"),
        }
        files = {
            "candidate.json": raw,
            "source-kev-catalog.json": catalog_bytes,
            "source-kev-meta.json": meta_bytes,
        }
        sha256sums = "".join(
            f"{sha256_bytes(body)}  {name}\n" for name, body in files.items()
        )
        return {
            "raw": raw,
            "digest": digest,
            "metadata": metadata,
            "catalog": catalog,
            "kev_meta": meta,
            "catalog_bytes": catalog_bytes,
            "meta_bytes": meta_bytes,
            "sha256sums": sha256sums,
            "run": _run(event=event, head_sha=binding.get("collector_commit_sha") or "abc"),
            "artifact": {"name": "pulse-candidate", "expired": False},
        }

    def _decide(
        self,
        snapshot: dict,
        *,
        mode: str = "auto",
        event: str = "schedule",
        catalog: dict | None = None,
        kev_meta: dict | None = None,
        **overrides: object,
    ):
        bundle = self._bundle(snapshot, event=event)
        kwargs = {
            "mode": mode,
            "run": bundle["run"],
            "expected_repository": REPO,
            "expected_branch": "main",
            "artifact": bundle["artifact"],
            "candidate_bytes": bundle["raw"],
            "metadata": bundle["metadata"],
            "sha256sums_text": bundle["sha256sums"],
            "published_dir": self.published,
            "now": NOW,
            "max_bytes": self.config.max_snapshot_bytes,
            "max_depth": self.config.max_json_depth,
            "stale_after_hours": 36,
            "kev_catalog": catalog if catalog is not None else bundle["catalog"],
            "kev_meta": kev_meta if kev_meta is not None else bundle["kev_meta"],
            "extra_files": {
                "source-kev-catalog.json": bundle["catalog_bytes"],
                "source-kev-meta.json": bundle["meta_bytes"],
            },
        }
        kwargs.update(overrides)
        return evaluate_publication(**kwargs), bundle

    def _promote(self, snapshot: dict) -> None:
        promote_snapshot(
            snapshot,
            self.published,
            now=NOW,
            stale_after_hours=36,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )

    def test_first_scheduled_collect_is_eligible(self) -> None:
        decision, _ = self._decide(self.snapshot)
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "first_publish")
        self.assertEqual(decision.snapshot_id, self.snapshot["snapshot_id"])

    def test_unchanged_upstream_is_a_normal_skip(self) -> None:
        self._promote(self.snapshot)
        later = deepcopy(self.snapshot)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["collection_completed_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "20990110T130000Z_unchanged"
        decision, _ = self._decide(later)
        self.assertEqual(decision.outcome, "skip")
        self.assertEqual(decision.reason, "unchanged_upstream")

    def test_already_published_snapshot_is_skipped(self) -> None:
        self._promote(self.snapshot)
        decision, _ = self._decide(self.snapshot)
        self.assertEqual(decision.outcome, "skip")
        self.assertEqual(decision.reason, "already_published")

    def test_degraded_partial_extraction_is_allowed_when_kev_verified(self) -> None:
        degraded = deepcopy(self.snapshot)
        degraded["status"] = "degraded"
        degraded["sources"]["cve"]["status"] = "degraded"
        degraded["summary"]["partial_records"] = 1
        degraded["summary"]["truncated_records"] = 1
        degraded["summary"]["complete_records"] = degraded["summary"]["complete_records"] - 1
        record = degraded["records"][0]
        record["completeness"] = "partial"
        record["cve"]["truncated_fields"] = ["description"]
        decision, _ = self._decide(degraded)
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "first_publish")

    def test_degraded_unavailable_enrichment_is_blocked(self) -> None:
        degraded = deepcopy(self.snapshot)
        degraded["status"] = "degraded"
        degraded["summary"]["unavailable_records"] = 1
        degraded["summary"]["partial_records"] = 1
        degraded["summary"]["truncated_records"] = 1
        record = degraded["records"][0]
        record["completeness"] = "unavailable"
        record["cve"]["status"] = "failed"
        decision, _ = self._decide(degraded)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "degraded_blocked")

    def test_invalid_digest_is_rejected(self) -> None:
        bundle = self._bundle(self.snapshot)
        bundle["metadata"]["content_sha256"] = "0" * 64
        decision = evaluate_publication(
            mode="auto",
            run=bundle["run"],
            expected_repository=REPO,
            expected_branch="main",
            artifact=bundle["artifact"],
            candidate_bytes=bundle["raw"],
            metadata=bundle["metadata"],
            sha256sums_text=bundle["sha256sums"],
            published_dir=self.published,
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "collect_run_untrusted")

    def test_missing_kev_digest_is_rejected(self) -> None:
        broken = deepcopy(self.snapshot)
        broken["sources"]["kev"]["content_sha256"] = None
        decision, _ = self._decide(broken)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "kev_unverified")

    def test_unexplained_small_kev_removal_is_rejected(self) -> None:
        self._promote(self.snapshot)
        dropped = deepcopy(self.snapshot)
        dropped["generated_at"] = "2099-01-10T13:00:00Z"
        dropped["collection_completed_at"] = "2099-01-10T13:00:00Z"
        dropped["snapshot_id"] = "drop-1"
        dropped["records"] = dropped["records"][:1]
        dropped["summary"]["kev_records"] = 1
        dropped["summary"]["complete_records"] = 1
        catalog, meta = catalog_from_snapshot(self.snapshot)
        decision, _ = self._decide(dropped, catalog=catalog, kev_meta=meta, extra_files=None)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "kev_catalog_mismatch")

    def test_catalog_explained_kev_shrink_is_eligible(self) -> None:
        self._promote(self.snapshot)
        dropped = deepcopy(self.snapshot)
        dropped["generated_at"] = "2099-01-10T13:00:00Z"
        dropped["collection_completed_at"] = "2099-01-10T13:00:00Z"
        dropped["snapshot_id"] = "drop-ok"
        dropped["records"] = dropped["records"][:1]
        dropped["summary"]["kev_records"] = 1
        dropped["summary"]["complete_records"] = 1
        dropped["sources"]["kev"]["content_sha256"] = "b" * 64
        dropped["sources"]["kev"]["source_revision"] = "2099.01.10"
        decision, _ = self._decide(dropped)
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "eligible")

    def test_same_count_substitution_matching_catalog_is_eligible(self) -> None:
        self._promote(self.snapshot)
        mutated = deepcopy(self.snapshot)
        mutated["generated_at"] = "2099-01-10T13:00:00Z"
        mutated["collection_completed_at"] = "2099-01-10T13:00:00Z"
        mutated["snapshot_id"] = "swap-ok"
        mutated["sources"]["kev"]["content_sha256"] = "d" * 64
        mutated["sources"]["kev"]["source_revision"] = "2099.01.11"
        record = mutated["records"][-1]
        record["cve_id"] = "CVE-2099-9999"
        record["kev"]["cve_id"] = "CVE-2099-9999"
        record["cve"]["cve_id"] = "CVE-2099-9999"
        decision, _ = self._decide(mutated)
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "eligible")

    def test_same_count_substitution_without_catalog_support_is_rejected(self) -> None:
        self._promote(self.snapshot)
        mutated = deepcopy(self.snapshot)
        mutated["generated_at"] = "2099-01-10T13:00:00Z"
        mutated["collection_completed_at"] = "2099-01-10T13:00:00Z"
        mutated["snapshot_id"] = "swap-bad"
        record = mutated["records"][-1]
        record["cve_id"] = "CVE-2099-9999"
        record["kev"]["cve_id"] = "CVE-2099-9999"
        record["cve"]["cve_id"] = "CVE-2099-9999"
        catalog, meta = catalog_from_snapshot(self.snapshot)
        decision, _ = self._decide(mutated, catalog=catalog, kev_meta=meta, extra_files=None)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "kev_catalog_mismatch")

    def test_same_digest_id_rewrite_is_rejected(self) -> None:
        self._promote(self.snapshot)
        mutated = deepcopy(self.snapshot)
        mutated["generated_at"] = "2099-01-10T13:00:00Z"
        mutated["collection_completed_at"] = "2099-01-10T13:00:00Z"
        mutated["snapshot_id"] = "missing-id"
        record = mutated["records"][-1]
        record["cve_id"] = "CVE-2099-9999"
        record["kev"]["cve_id"] = "CVE-2099-9999"
        record["cve"]["cve_id"] = "CVE-2099-9999"
        decision, _ = self._decide(mutated)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "unexplained_kev_change")

    def test_completeness_regression_with_unchanged_kev_is_rejected(self) -> None:
        self._promote(self.snapshot)
        later = deepcopy(self.snapshot)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["collection_completed_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "regressed"
        later["summary"]["complete_records"] = 0
        later["summary"]["partial_records"] = later["summary"]["kev_records"]
        decision, _ = self._decide(later)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "completeness_regression")

    def test_expired_or_missing_artifact_is_rejected(self) -> None:
        bundle = self._bundle(self.snapshot)
        expired = evaluate_publication(
            mode="auto",
            run=bundle["run"],
            expected_repository=REPO,
            expected_branch="main",
            artifact={**bundle["artifact"], "expired": True},
            candidate_bytes=bundle["raw"],
            metadata=bundle["metadata"],
            sha256sums_text=bundle["sha256sums"],
            published_dir=self.published,
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(expired.outcome, "reject")
        self.assertEqual(expired.reason, "collect_run_untrusted")
        missing = evaluate_publication(
            mode="auto",
            run=bundle["run"],
            expected_repository=REPO,
            expected_branch="main",
            artifact={"name": "other"},
            candidate_bytes=bundle["raw"],
            metadata=bundle["metadata"],
            sha256sums_text=bundle["sha256sums"],
            published_dir=self.published,
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(missing.outcome, "reject")
        self.assertEqual(missing.reason, "collect_run_untrusted")

    def test_stale_candidate_is_rejected(self) -> None:
        stale = deepcopy(self.snapshot)
        stale["generated_at"] = "2099-01-01T00:00:00Z"
        stale["collection_started_at"] = "2099-01-01T00:00:00Z"
        stale["collection_completed_at"] = "2099-01-01T00:00:00Z"
        decision, _ = self._decide(stale)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "stale_candidate")

    def test_older_collect_cannot_replace_newer_published(self) -> None:
        self._promote(self.snapshot)
        older = deepcopy(self.snapshot)
        older["generated_at"] = "2099-01-10T11:00:00Z"
        older["snapshot_id"] = "older-1"
        older["sources"]["kev"]["content_sha256"] = "c" * 64
        decision, _ = self._decide(older)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "older_than_published")

    def test_auto_mode_rejects_manual_collect_event(self) -> None:
        decision, _ = self._decide(self.snapshot, mode="auto", event="workflow_dispatch")
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "collect_run_untrusted")

    def test_manual_mode_still_accepts_workflow_dispatch_collect(self) -> None:
        decision, _ = self._decide(self.snapshot, mode="manual", event="workflow_dispatch")
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "first_publish")

    def test_epss_scores_are_rejected(self) -> None:
        scored = deepcopy(self.snapshot)
        scored["records"][0]["epss"]["score"] = 0.9
        decision, _ = self._decide(scored)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "epss_forbidden")

    def test_duplicate_cve_ids_are_rejected(self) -> None:
        dup = deepcopy(self.snapshot)
        dup["records"] = dup["records"] + dup["records"]
        dup["summary"]["kev_records"] = len(dup["records"])
        decision, _ = self._decide(dup)
        self.assertEqual(decision.outcome, "reject")
        self.assertIn(decision.reason, {"snapshot_invalid", "source_inconsistent"})

    def test_corrupted_catalog_is_rejected(self) -> None:
        decision, _ = self._decide(
            self.snapshot,
            catalog={"records": "nope"},
            extra_files=None,
        )
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "kev_catalog_mismatch")

    def test_catalog_digest_inconsistent_with_candidate_is_rejected(self) -> None:
        catalog, meta = catalog_from_snapshot(self.snapshot)
        meta = dict(meta)
        meta["content_sha256"] = "e" * 64
        decision, _ = self._decide(self.snapshot, catalog=catalog, kev_meta=meta, extra_files=None)
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "kev_catalog_mismatch")

    def test_forged_workflow_identity_is_rejected(self) -> None:
        decision, _ = self._decide(
            self.snapshot,
            run=_run(path=".github/workflows/ci.yml", name="Collect"),
            extra_files=None,
        )
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "collect_run_untrusted")

    def test_unsafe_sha256sums_path_is_rejected(self) -> None:
        bundle = self._bundle(self.snapshot)
        digest = bundle["digest"]
        decision, _ = self._decide(
            self.snapshot,
            sha256sums_text=f"{digest}  ../candidate.json\n",
            extra_files=None,
        )
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "collect_run_untrusted")

    def test_remediation_only_change_is_eligible(self) -> None:
        self._promote(self.snapshot)
        later = deepcopy(self.snapshot)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["collection_completed_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "remediation-1"
        later["sources"]["cve"]["content_sha256"] = "f" * 64
        later["records"][0]["cve"]["description"] = "Updated remediation text"
        decision, _ = self._decide(later)
        self.assertEqual(decision.outcome, "publish")
        self.assertEqual(decision.reason, "eligible")

    def test_cli_writes_skip_outputs_for_unchanged_data(self) -> None:
        self._promote(self.snapshot)
        later = deepcopy(self.snapshot)
        later["generated_at"] = "2099-01-10T13:00:00Z"
        later["collection_completed_at"] = "2099-01-10T13:00:00Z"
        later["snapshot_id"] = "cli-unchanged"
        bundle = self._bundle(later)
        files = self.root / "cli"
        files.mkdir()
        (files / "run.json").write_text(json.dumps(bundle["run"]), encoding="utf-8")
        (files / "artifact.json").write_text(json.dumps(bundle["artifact"]), encoding="utf-8")
        (files / "candidate.json").write_bytes(bundle["raw"])
        (files / "meta.json").write_text(json.dumps(bundle["metadata"]), encoding="utf-8")
        (files / "source-kev-catalog.json").write_bytes(bundle["catalog_bytes"])
        (files / "source-kev-meta.json").write_bytes(bundle["meta_bytes"])
        (files / "SHA256SUMS").write_text(bundle["sha256sums"], encoding="utf-8")
        output = files / "github-output"
        summary = files / "summary.md"
        self.assertEqual(
            main(
                [
                    "decide-publication",
                    "--mode",
                    "auto",
                    "--run-json",
                    str(files / "run.json"),
                    "--artifact-json",
                    str(files / "artifact.json"),
                    "--candidate",
                    str(files / "candidate.json"),
                    "--metadata-json",
                    str(files / "meta.json"),
                    "--sha256sums",
                    str(files / "SHA256SUMS"),
                    "--kev-catalog",
                    str(files / "source-kev-catalog.json"),
                    "--kev-meta",
                    str(files / "source-kev-meta.json"),
                    "--published-dir",
                    str(self.published),
                    "--expected-repository",
                    REPO,
                    "--github-output",
                    str(output),
                    "--summary-path",
                    str(summary),
                    "--now",
                    "2099-01-10T14:00:00Z",
                ]
            ),
            0,
        )
        text = output.read_text(encoding="utf-8")
        self.assertIn("decision=skip", text)
        self.assertIn("reason=unchanged_upstream", text)
        self.assertIn("Unchanged upstream", summary.read_text(encoding="utf-8"))

    def test_cli_rejects_invalid_artifacts(self) -> None:
        bundle = self._bundle(self.snapshot)
        files = self.root / "cli-reject"
        files.mkdir()
        (files / "run.json").write_text(json.dumps(bundle["run"]), encoding="utf-8")
        (files / "artifact.json").write_text(json.dumps(bundle["artifact"]), encoding="utf-8")
        (files / "candidate.json").write_bytes(bundle["raw"])
        (files / "meta.json").write_text(
            json.dumps({"content_sha256": "0" * 64}), encoding="utf-8"
        )
        (files / "source-kev-catalog.json").write_bytes(bundle["catalog_bytes"])
        (files / "source-kev-meta.json").write_bytes(bundle["meta_bytes"])
        (files / "SHA256SUMS").write_text(bundle["sha256sums"], encoding="utf-8")
        self.assertEqual(
            main(
                [
                    "decide-publication",
                    "--mode",
                    "auto",
                    "--run-json",
                    str(files / "run.json"),
                    "--artifact-json",
                    str(files / "artifact.json"),
                    "--candidate",
                    str(files / "candidate.json"),
                    "--metadata-json",
                    str(files / "meta.json"),
                    "--sha256sums",
                    str(files / "SHA256SUMS"),
                    "--kev-catalog",
                    str(files / "source-kev-catalog.json"),
                    "--kev-meta",
                    str(files / "source-kev-meta.json"),
                    "--published-dir",
                    str(self.published),
                    "--expected-repository",
                    REPO,
                ]
            ),
            1,
        )


class AutoPublishWorkflowTests(unittest.TestCase):
    def test_event_driven_publish_keeps_manual_and_frontend_paths(self) -> None:
        publish = _workflow("publish.yml")
        collect = _workflow("collect.yml")
        frontend = _workflow("deploy-frontend.yml")
        self.assertIn("workflow_run:", publish)
        self.assertIn("branches: [main]", publish)
        self.assertIn("Auto-publish Collect", publish)
        self.assertIn("PUBLISH_MODE", publish)
        self.assertIn("head_repository.full_name == github.repository", publish)
        self.assertIn("persist-credentials: false", publish)
        self.assertIn("verify-artifact-dir", publish)
        self.assertIn("safe-copy", publish)
        self.assertIn("git commit -F /tmp/publish-commit-msg", publish)
        self.assertIn("warn-pages-state-divergence:", publish)
        self.assertIn("source-kev-catalog.json", collect)
        self.assertIn("collect_run_id must be a numeric", publish)
        self.assertIn("group: pages", publish)
        self.assertIn("cancel-in-progress: false", publish)
        self.assertNotIn("pull_request:", publish)
        self.assertNotIn("schedule:", publish)
        self.assertIn("group: pages", frontend)
        self.assertIn("DEPLOY_FRONTEND", frontend)
        self.assertNotIn("workflow_run:", frontend)
        self.assertNotIn("deploy-pages", collect)
        self.assertNotIn("decide-publication", collect)
        self.assertIn("git add source candidates", collect)
        self.assertIn("contents: read", publish)
        self.assertIn("actions: read", publish)
        self.assertNotIn("pages: write", collect)

    def test_auto_verify_rejects_untrusted_collect_events(self) -> None:
        snapshot = {
            "snapshot_id": "x",
            "binding": {"collector_commit_sha": "abc", "source_state_revision": "r"},
        }
        payload = json.dumps(snapshot).encode("utf-8")
        digest = sha256_bytes(payload)
        with self.assertRaises(Exception):
            verify_collect_run(
                _run(event="workflow_dispatch"),
                expected_repository=REPO,
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate"},
                candidate_bytes=payload,
                expected_digest=digest,
                metadata={"content_sha256": digest, "source_state_revision": "r"},
                sha256sums_text=f"{digest}  candidate.json\n",
                allowed_events=frozenset({"schedule"}),
            )


if __name__ == "__main__":
    unittest.main()
