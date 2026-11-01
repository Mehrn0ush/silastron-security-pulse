"""Deploy/persist reconciliation state machine."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from shutil import copytree

from silastron_pulse.auto_publish import evaluate_publication
from silastron_pulse.cli import main
from silastron_pulse.errors import PublishGuardError
from silastron_pulse.jsonutil import dump_bytes, sha256_bytes
from silastron_pulse.pipeline import collect
from silastron_pulse.reconciliation import (
    CONSISTENT,
    DEPLOYED_UNPERSISTED,
    UNKNOWN,
    assert_publication_consistent,
    build_publication_status,
    classify_workflow_outcome,
    reconcile_publication,
    write_publication_status,
)
from silastron_pulse.kev_integrity import catalog_from_snapshot
from silastron_pulse.store import promote_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher
from tests.test_auto_publish import REPO, _run

NOW = datetime(2099, 1, 10, 14, tzinfo=timezone.utc)


class ReconciliationTests(unittest.TestCase):
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
        self.incoming = self.root / "incoming"
        promote_snapshot(
            self.snapshot,
            self.incoming,
            now=NOW,
            stale_after_hours=36,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.digest = sha256_bytes((self.incoming / "latest.json").read_bytes())
        self.snapshot_id = self.snapshot["snapshot_id"]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _status(self, state: str, **overrides: object) -> dict:
        payload = build_publication_status(
            state=state,
            classification="deployment_succeeded_persist_failed",
            now=NOW,
            snapshot_id=self.snapshot_id,
            collect_run_id="99",
            deployment_run_id="100",
            manifest_digest=self.digest,
        )
        payload.update(overrides)
        return write_publication_status(self.published, payload)

    def _decide(self) -> object:
        raw = dump_bytes(self.snapshot)
        catalog, meta = catalog_from_snapshot(self.snapshot)
        catalog_bytes = dump_bytes(catalog)
        meta_bytes = dump_bytes(meta)
        extra = {
            "source-kev-catalog.json": catalog_bytes,
            "source-kev-meta.json": meta_bytes,
        }
        sha256sums = "".join(f"{sha256_bytes(body)}  {name}\n" for name, body in extra.items())
        sha256sums = f"{sha256_bytes(raw)}  candidate.json\n" + sha256sums
        return evaluate_publication(
            mode="auto",
            run=_run(head_sha="abc"),
            expected_repository=REPO,
            expected_branch="main",
            artifact={"name": "pulse-candidate", "expired": False},
            candidate_bytes=raw,
            metadata={"content_sha256": sha256_bytes(raw)},
            sha256sums_text=sha256sums,
            published_dir=self.published,
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
            kev_catalog=catalog,
            kev_meta=meta,
            extra_files=extra,
        )

    def test_successful_deploy_failed_persist_blocks_later_publish(self) -> None:
        self._status(DEPLOYED_UNPERSISTED)
        decision = self._decide()
        self.assertEqual(decision.outcome, "reject")
        self.assertEqual(decision.reason, "publication_diverged")
        self.assertIn(self.snapshot_id, decision.details["message"])
        self.assertIn("99", decision.details["message"])
        self.assertIn(self.digest, decision.details["message"])

    def test_unknown_deployment_outcome_blocks(self) -> None:
        write_publication_status(
            self.published,
            build_publication_status(
                state=UNKNOWN,
                classification="deployment_outcome_unknown",
                now=NOW,
                snapshot_id=self.snapshot_id,
                collect_run_id="99",
                deployment_run_id="100",
                manifest_digest=self.digest,
            ),
        )
        decision = self._decide()
        self.assertEqual(decision.outcome, "reject")
        self.assertIn("unknown", decision.details["message"])

    def test_duplicate_recovery_is_idempotent(self) -> None:
        copytree(self.incoming, self.published)
        first = reconcile_publication(
            incoming_dir=self.incoming,
            current_dir=self.published,
            expected_snapshot_id=self.snapshot_id,
            expected_digest=self.digest,
            expected_collect_run_id="99",
            confirm="RECONCILE",
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
            deployment_run_id="100",
        )
        self.assertEqual(first["status"], "already_consistent")
        second = reconcile_publication(
            incoming_dir=self.incoming,
            current_dir=self.published,
            expected_snapshot_id=self.snapshot_id,
            expected_digest=self.digest,
            expected_collect_run_id="99",
            confirm="RECONCILE",
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
            deployment_run_id="100",
        )
        self.assertEqual(second["status"], "already_consistent")
        self.assertTrue(second["publication_status"].get("recovery", {}).get("duplicate"))

    def test_stale_or_conflicting_recovery_is_refused(self) -> None:
        copytree(self.incoming, self.published)
        self._status(DEPLOYED_UNPERSISTED, snapshot_id=self.snapshot_id)
        with self.assertRaises(PublishGuardError):
            reconcile_publication(
                incoming_dir=self.incoming,
                current_dir=self.published,
                expected_snapshot_id="other-snapshot",
                expected_digest=self.digest,
                expected_collect_run_id="99",
                confirm="RECONCILE",
                now=NOW,
                max_bytes=self.config.max_snapshot_bytes,
                max_depth=self.config.max_json_depth,
            )

    def test_repair_after_failed_persist_preserves_history(self) -> None:
        copytree(self.incoming, self.published)
        older = json.loads((self.published / "latest.json").read_text(encoding="utf-8"))
        self.assertTrue((self.published / "history.json").exists())
        self._status(DEPLOYED_UNPERSISTED)
        result = reconcile_publication(
            incoming_dir=self.incoming,
            current_dir=self.published,
            expected_snapshot_id=self.snapshot_id,
            expected_digest=self.digest,
            expected_collect_run_id="99",
            confirm="RECONCILE",
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertIn(result["status"], {"already_consistent", "repaired"})
        current = json.loads((self.published / "latest.json").read_text(encoding="utf-8"))
        self.assertEqual(current["snapshot_id"], older["snapshot_id"])
        self.assertTrue((self.published / "history.json").exists())
        self.assertTrue((self.published / "snapshots" / f"{self.snapshot_id}.json").exists())

    def test_frontend_deploy_blocked_during_divergence(self) -> None:
        self._status(DEPLOYED_UNPERSISTED)
        with self.assertRaises(PublishGuardError):
            assert_publication_consistent(
                self.published,
                max_bytes=self.config.max_snapshot_bytes,
                max_depth=self.config.max_json_depth,
            )
        self.assertEqual(
            main(
                [
                    "verify-publication-status",
                    "--published-dir",
                    str(self.published),
                    "--require",
                    "consistent",
                ]
            ),
            1,
        )

    def test_consistent_legacy_missing_status_allows_publish(self) -> None:
        copytree(self.incoming, self.published)
        (self.published / "publication-status.json").unlink(missing_ok=True)
        status = assert_publication_consistent(
            self.published,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(status["state"], CONSISTENT)
        self.assertTrue(status.get("legacy_missing_status"))

    def test_classify_outcomes(self) -> None:
        self.assertEqual(
            classify_workflow_outcome(deploy_result="failure", persist_result="skipped"),
            "deployment_failed_before_publication",
        )
        self.assertEqual(
            classify_workflow_outcome(deploy_result="success", persist_result="failure"),
            "deployment_succeeded_persist_failed",
        )
        self.assertEqual(
            classify_workflow_outcome(deploy_result="success", persist_result="success"),
            "persistence_succeeded_and_consistent",
        )
        self.assertEqual(
            classify_workflow_outcome(deploy_result="cancelled", persist_result="skipped"),
            "deployment_failed_before_publication",
        )
        self.assertEqual(
            classify_workflow_outcome(deploy_result="", persist_result=""),
            "deployment_outcome_unknown",
        )

    def test_concurrent_manual_and_scheduled_see_divergence(self) -> None:
        self._status(DEPLOYED_UNPERSISTED)
        scheduled = self._decide()
        self.assertEqual(scheduled.reason, "publication_diverged")
        raw = dump_bytes(self.snapshot)
        catalog, meta = catalog_from_snapshot(self.snapshot)
        extra = {
            "source-kev-catalog.json": dump_bytes(catalog),
            "source-kev-meta.json": dump_bytes(meta),
        }
        sha256sums = f"{sha256_bytes(raw)}  candidate.json\n" + "".join(
            f"{sha256_bytes(body)}  {name}\n" for name, body in extra.items()
        )
        manual = evaluate_publication(
            mode="manual",
            run=_run(event="workflow_dispatch", head_sha="abc"),
            expected_repository=REPO,
            expected_branch="main",
            artifact={"name": "pulse-candidate", "expired": False},
            candidate_bytes=raw,
            metadata={"content_sha256": sha256_bytes(raw)},
            sha256sums_text=sha256sums,
            published_dir=self.published,
            now=NOW,
            max_bytes=self.config.max_snapshot_bytes,
            max_depth=self.config.max_json_depth,
            kev_catalog=catalog,
            kev_meta=meta,
            extra_files=extra,
        )
        self.assertEqual(manual.reason, "publication_diverged")


if __name__ == "__main__":
    unittest.main()
