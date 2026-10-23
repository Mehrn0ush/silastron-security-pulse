"""Regression tests for scheduled Collect, isolation, and EPSS-off daily ops."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.adapters.epss import REDISTRIBUTION_CLEARED
from silastron_pulse.constants import KEV_JSON_URL
from silastron_pulse.errors import ArtifactVerifyError, FetchError, ValidationError
from silastron_pulse.http import RETRYABLE_STATUS
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.lock import CollectionLock
from silastron_pulse.pipeline import collect
from silastron_pulse.verify_run import verify_collect_run
from tests.support import frozen_clock, test_config, valid_fetcher

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


class CollectWorkflowContractTests(unittest.TestCase):
    def test_daily_schedule_and_manual_dispatch_are_both_enabled(self) -> None:
        text = _workflow("collect.yml")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("schedule:", text)
        self.assertIn('cron: "0 8 * * *"', text)
        self.assertIn("github.event_name == 'schedule'", text)
        self.assertIn("github.event_name == 'workflow_dispatch'", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)

    def test_overlapping_collect_runs_wait_instead_of_cancelling(self) -> None:
        text = _workflow("collect.yml")
        self.assertIn("group: collect", text)
        self.assertIn("cancel-in-progress: false", text)

    def test_collect_does_not_publish_or_touch_published_tree(self) -> None:
        text = _workflow("collect.yml")
        self.assertNotIn("deploy-pages", text)
        self.assertNotIn("github-pages", text)
        self.assertIn("git add source candidates", text)
        self.assertIn("Collect must not modify published/", text)
        self.assertNotIn("git add published", text)
        self.assertNotIn("--promote", text)

    def test_collect_permissions_remain_contents_write_and_actions_read(self) -> None:
        text = _workflow("collect.yml")
        self.assertIn("contents: write", text)
        self.assertIn("actions: read", text)
        self.assertNotIn("pages: write", text)
        self.assertNotIn("id-token: write", text)


class PublishIsolationTests(unittest.TestCase):
    def test_publish_stays_manual_and_binds_an_explicit_collect_run(self) -> None:
        text = _workflow("publish.yml")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("schedule:", text)
        self.assertIn("collect_run_id:", text)
        self.assertIn("required: true", text)
        self.assertIn("confirm == 'PUBLISH'", text)
        self.assertIn("run-id: ${{ github.event.inputs.collect_run_id }}", text)
        self.assertNotIn("run-id: ${{ github.run_id }}", text)

    def test_publish_does_not_select_the_latest_collect_implicitly(self) -> None:
        text = _workflow("publish.yml")
        self.assertIn("github.event.inputs.collect_run_id", text)
        self.assertNotIn("gh run list", text)


class VerifyScheduledCollectTests(unittest.TestCase):
    def _run(self, **overrides: object) -> dict:
        payload = {
            "id": 1,
            "repository_full_name": "Mehrn0ush/silastron-security-pulse",
            "path": ".github/workflows/collect.yml",
            "name": "Collect",
            "head_branch": "main",
            "conclusion": "success",
            "event": "schedule",
            "head_sha": "abc",
        }
        payload.update(overrides)
        return payload

    def _candidate(self) -> tuple[bytes, str, dict, str]:
        snapshot = {
            "snapshot_id": "sched-1",
            "binding": {
                "collector_commit_sha": "abc",
                "source_state_revision": "kev:cve",
            },
        }
        payload = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")
        digest = sha256_bytes(payload)
        metadata = {"content_sha256": digest, "source_state_revision": "kev:cve"}
        return payload, digest, metadata, f"{digest}  candidate.json\n"

    def test_schedule_collect_run_is_acceptable_for_manual_publish(self) -> None:
        payload, digest, metadata, sha256sums = self._candidate()
        result = verify_collect_run(
            self._run(),
            expected_repository="Mehrn0ush/silastron-security-pulse",
            expected_branch="main",
            expected_head_sha="abc",
            artifact={"name": "pulse-candidate", "expired": False},
            candidate_bytes=payload,
            expected_digest=digest,
            metadata=metadata,
            sha256sums_text=sha256sums,
        )
        self.assertEqual(result["snapshot_id"], "sched-1")

    def test_push_and_pull_request_collect_events_are_rejected(self) -> None:
        payload, digest, metadata, sha256sums = self._candidate()
        for event in ("push", "pull_request", "repository_dispatch"):
            with self.assertRaises(ArtifactVerifyError):
                verify_collect_run(
                    self._run(event=event),
                    expected_repository="Mehrn0ush/silastron-security-pulse",
                    expected_branch="main",
                    expected_head_sha="abc",
                    artifact={"name": "pulse-candidate"},
                    candidate_bytes=payload,
                    expected_digest=digest,
                    metadata=metadata,
                    sha256sums_text=sha256sums,
                )


class ConcurrentAndFailureTests(unittest.TestCase):
    def test_collection_lock_refuses_a_second_holder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".collect.lock"
            with CollectionLock(path):
                with self.assertRaises(ValidationError) as raised:
                    with CollectionLock(path):
                        pass
                self.assertIn("refusing concurrent update", str(raised.exception))

    def test_failed_collection_does_not_replace_last_known_good_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=state,
            )
            self.assertEqual(first.status, "ok")
            candidate = (state / "candidates" / "latest.json").read_bytes()
            source_manifest = (state / "source" / "manifest.json").read_bytes()
            failed = collect(
                config=test_config(root / "two"),
                fetcher=valid_fetcher(**{KEV_JSON_URL: FetchError("500")}),
                clock=frozen_clock(),
                state_dir=state,
            )
            self.assertEqual(failed.status, "failed")
            self.assertEqual((state / "candidates" / "latest.json").read_bytes(), candidate)
            self.assertEqual((state / "source" / "manifest.json").read_bytes(), source_manifest)
            self.assertFalse((state / "published" / "latest.json").exists())

    def test_http_429_remains_retryable_for_github_raw_limits(self) -> None:
        self.assertIn(429, RETRYABLE_STATUS)


class SnapshotIntegrityAndEpssTests(unittest.TestCase):
    def test_candidate_has_no_epss_scores_and_epss_stays_disabled(self) -> None:
        self.assertFalse(REDISTRIBUTION_CLEARED)
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(
                config=test_config(Path(tmp)),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
        assert result.snapshot is not None
        self.assertFalse(result.snapshot["summary"]["epss_enabled"])
        self.assertEqual(result.snapshot["sources"]["epss"]["status"], "disabled")
        self.assertIsNone(result.snapshot["composite_risk_score"])
        for record in result.snapshot["records"]:
            self.assertIsNone(record["epss"]["score"])
            self.assertIsNone(record["epss"]["percentile"])
            self.assertNotEqual(record["epss"]["status"], "ok")
            self.assertIsNone(record["signals"]["estimated_exploitation_probability"]["value"])

    def test_collect_and_publish_workflows_do_not_enable_epss(self) -> None:
        combined = _workflow("collect.yml") + _workflow("publish.yml")
        self.assertNotIn("REDISTRIBUTION_CLEARED", combined)
        self.assertNotIn("enabled=True", combined)
        self.assertNotIn("EPSS_ENABLED", combined)
        self.assertIn("validate dist/candidate.json", _workflow("collect.yml"))

    def test_identical_second_collection_is_an_empty_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            second = collect(
                config=test_config(root / "two"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
        assert first.snapshot is not None
        assert second.snapshot is not None
        self.assertEqual(second.snapshot["changes"]["new_kev_entries"], [])
        self.assertEqual(second.snapshot["changes"]["removed_kev_entries"], [])
        self.assertEqual(second.snapshot["changes"]["changed_cve_information"], [])
        self.assertEqual(second.snapshot["changes"]["epss_changes"], [])
        self.assertEqual(second.snapshot["changes"]["source_metadata_changes"], [])
        self.assertEqual(first.snapshot["changes"]["new_kev_entries"], [])


if __name__ == "__main__":
    unittest.main()
