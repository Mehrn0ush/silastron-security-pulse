from __future__ import annotations

import unittest
from datetime import datetime, timezone

from silastron_pulse.data_status import evaluate_data_status
from silastron_pulse.verification_status import build_verification_status


NOW = datetime(2099, 1, 12, 12, tzinfo=timezone.utc)


def _candidate(**overrides: object) -> dict:
    payload = {
        "snapshot_id": "20990110T120000Z_abc",
        "generated_at": "2099-01-10T12:00:00Z",
        "collection_started_at": "2099-01-10T11:59:00Z",
        "collection_completed_at": "2099-01-10T12:00:00Z",
        "status": "ok",
        "sources": {
            "kev": {
                "status": "ok",
                "retrieved_at": "2099-01-10T12:00:00Z",
                "source_published_at": "2099-01-09T00:00:00Z",
                "content_sha256": "k" * 64,
            },
            "cve": {"status": "ok", "retrieved_at": "2099-01-10T12:00:00Z"},
            "nvd": {"status": "unavailable", "retrieved_at": None},
        },
        "summary": {},
    }
    payload.update(overrides)
    return payload


class DataStatusTests(unittest.TestCase):
    def test_unchanged_verified_kev_is_not_stale(self) -> None:
        candidate = _candidate()
        verification = build_verification_status(
            candidate=candidate,
            decision_outcome="skip",
            decision_reason="unchanged_upstream",
            collect_run_id="22",
            collect_event="schedule",
            published=candidate,
            publication_state="consistent",
            candidate_digest="d" * 64,
        )
        status = evaluate_data_status(
            snapshot=candidate,
            manifest={"snapshot_generated_at": "2099-01-08T00:00:00Z", "stale_after_hours": 36, "status": "ok"},
            verification=verification,
            publication_status={"state": "consistent"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertTrue(status["verified"])
        self.assertEqual(status["headline"], "Unchanged catalog, independently verified")
        self.assertNotIn("stale", status["headline"].lower())
        self.assertEqual(status["last_successful_verification_at"], "2099-01-10T12:00:00Z")

    def test_old_snapshot_with_recent_collect_uses_verification(self) -> None:
        published = _candidate(generated_at="2099-01-01T00:00:00Z")
        later = _candidate(
            snapshot_id="20990112T080000Z_def",
            generated_at="2099-01-12T08:00:00Z",
            collection_completed_at="2099-01-12T08:00:00Z",
        )
        verification = build_verification_status(
            candidate=later,
            decision_outcome="skip",
            decision_reason="unchanged_upstream",
            collect_run_id="33",
            collect_event="schedule",
            published=published,
            publication_state="consistent",
            candidate_digest="e" * 64,
        )
        status = evaluate_data_status(
            snapshot=published,
            manifest={"snapshot_generated_at": "2099-01-01T00:00:00Z", "status": "ok"},
            verification=verification,
            publication_status={"state": "consistent"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertEqual(status["last_published_snapshot_at"], "2099-01-01T00:00:00Z")
        self.assertEqual(status["last_successful_verification_at"], "2099-01-12T08:00:00Z")
        self.assertTrue(status["snapshot_age_is_not_verification"])

    def test_failed_collect_after_last_successful_verification_is_not_fresh(self) -> None:
        published = _candidate()
        failed = _candidate(
            snapshot_id="20990112T080000Z_fail",
            generated_at="2099-01-12T08:00:00Z",
            collection_completed_at="2099-01-12T08:00:00Z",
            status="failed",
        )
        failed["sources"]["kev"]["status"] = "failed"
        failed["sources"]["kev"]["content_sha256"] = None
        failed["sources"]["kev"]["retrieved_at"] = None
        verification = build_verification_status(
            candidate=failed,
            decision_outcome="reject",
            decision_reason="kev_unverified",
            collect_run_id="45",
            collect_event="schedule",
            published=published,
            publication_state="consistent",
            candidate_digest=None,
        )
        status = evaluate_data_status(
            snapshot=published,
            manifest={"snapshot_generated_at": "2099-01-10T12:00:00Z", "status": "ok"},
            verification=verification,
            publication_status={"state": "consistent"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertFalse(status["verified"])
        self.assertIsNone(status["last_successful_verification_at"])
        self.assertEqual(status["last_successful_collection_at"], "2099-01-10T12:00:00Z")
        self.assertEqual(status["last_published_snapshot_at"], "2099-01-10T12:00:00Z")
        self.assertIn("reject", status["headline"].lower() + status["message"].lower())

    def test_failed_collect_is_not_presented_as_verified(self) -> None:
        candidate = _candidate()
        candidate["sources"]["kev"]["status"] = "failed"
        candidate["sources"]["kev"]["content_sha256"] = None
        verification = build_verification_status(
            candidate=candidate,
            decision_outcome="reject",
            decision_reason="kev_unverified",
            collect_run_id="44",
            collect_event="schedule",
            published=candidate,
            publication_state="consistent",
            candidate_digest=None,
        )
        status = evaluate_data_status(
            snapshot=candidate,
            manifest={"snapshot_generated_at": "2099-01-10T12:00:00Z", "status": "ok"},
            verification=verification,
            publication_status={"state": "consistent"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertFalse(status["verified"])
        self.assertIsNone(status["last_successful_verification_at"])
        combined = (status["headline"] + " " + status["message"]).lower()
        self.assertTrue("reject" in combined or "failed" in combined or "not independently validated" in combined)

    def test_missing_verification_is_insufficient_evidence(self) -> None:
        status = evaluate_data_status(
            snapshot=_candidate(),
            manifest={"snapshot_generated_at": "2099-01-10T12:00:00Z", "status": "ok"},
            verification=None,
            publication_status={"state": "consistent"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertFalse(status["verified"])
        self.assertEqual(status["headline"], "Verification evidence unavailable")
        self.assertIsNone(status["last_successful_verification_at"])

    def test_stale_upstream_is_shown_separately_from_collection(self) -> None:
        candidate = _candidate()
        verification = build_verification_status(
            candidate=candidate,
            decision_outcome="skip",
            decision_reason="already_published",
            collect_run_id="55",
            collect_event="schedule",
            published=candidate,
            publication_state="consistent",
            candidate_digest="f" * 64,
        )
        status = evaluate_data_status(
            snapshot=candidate,
            manifest={"snapshot_generated_at": "2099-01-10T12:00:00Z", "status": "ok"},
            verification=verification,
            publication_status={"state": "consistent"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertEqual(status["last_upstream_kev_update_at"], "2099-01-09T00:00:00Z")
        self.assertEqual(status["kev_retrieved_at"], "2099-01-10T12:00:00Z")
        self.assertTrue(status["verified"])

    def test_publication_divergence_stays_visible(self) -> None:
        status = evaluate_data_status(
            snapshot=_candidate(),
            manifest={"snapshot_generated_at": "2099-01-10T12:00:00Z", "status": "ok"},
            verification=None,
            publication_status={"state": "deployed_unpersisted", "classification": "deployment_succeeded_persist_failed"},
            now=NOW,
            stale_after_hours=36,
        )
        self.assertTrue(status["integrity_problem"])
        self.assertEqual(status["tone"], "unavailable")
        self.assertIn("diverged", status["message"])


if __name__ == "__main__":
    unittest.main()
