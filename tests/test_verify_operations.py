from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from silastron_pulse.verify_operations import verify_operations


NOW = datetime(2099, 1, 12, 12, tzinfo=timezone.utc)


def _manifest() -> dict:
    return {
        "snapshot_generated_at": "2099-01-10T12:00:00Z",
        "generated_at": "2099-01-10T14:00:00Z",
        "status": "ok",
        "stale_after_hours": 36,
        "record_count": 2,
    }


class VerifyOperationsTests(unittest.TestCase):
    def test_missing_verification_is_insufficient_evidence(self) -> None:
        responses = {
            "https://pulse.silastron.com/data/manifest.json": (
                json.dumps(_manifest()).encode("utf-8"),
                200,
            ),
            "https://pulse.silastron.com/data/preview.json": (json.dumps({"status": "ok"}).encode("utf-8"), 200),
            "https://pulse.silastron.com/data/publication-status.json": (
                json.dumps({"state": "consistent"}).encode("utf-8"),
                200,
            ),
            "https://pulse.silastron.com/data/verification-status.json": (None, 404),
            "https://pulse.silastron.com/": (b'<html id="status-banner">Pulse</html>', 200),
            "https://pulse.silastron.com/app.js": (b"function parseCveHash(){}", 200),
        }

        def fake_fetch(url: str):
            return responses.get(url, (None, None))

        with patch("silastron_pulse.verify_operations._fetch", side_effect=fake_fetch):
            report = verify_operations(now=NOW)
        self.assertEqual(report["verdict"], "insufficient_evidence")
        self.assertTrue(report["evidence_gaps"])
        self.assertFalse(report["failures"])
        self.assertIn("Do not dispatch", " ".join(report["owner_commands"]))

    def test_publication_divergence_is_verified_failure(self) -> None:
        responses = {
            "https://pulse.silastron.com/data/manifest.json": (
                json.dumps(_manifest()).encode("utf-8"),
                200,
            ),
            "https://pulse.silastron.com/data/preview.json": (json.dumps({"status": "ok"}).encode("utf-8"), 200),
            "https://pulse.silastron.com/data/publication-status.json": (
                json.dumps({"state": "unknown", "classification": "deployment_outcome_unknown"}).encode("utf-8"),
                200,
            ),
            "https://pulse.silastron.com/data/verification-status.json": (None, 404),
            "https://pulse.silastron.com/": (b"<html>Pulse</html>", 200),
        }

        def fake_fetch(url: str):
            return responses.get(url, (None, None))

        with patch("silastron_pulse.verify_operations._fetch", side_effect=fake_fetch):
            report = verify_operations(now=NOW)
        self.assertEqual(report["verdict"], "verified_operational_failure")
        self.assertTrue(report["failures"])
