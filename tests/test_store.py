from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.errors import PublishGuardError
from silastron_pulse.pipeline import collect
from silastron_pulse.store import load_snapshot, promote_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = test_config(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _snapshot(self):
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        self.assertEqual(result.status, "ok")
        assert result.snapshot is not None
        return result.snapshot

    def test_promote_then_rollback_invalid_candidate(self) -> None:
        snapshot = self._snapshot()
        published = self.root / "published"
        promote_snapshot(
            snapshot,
            published,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        latest = load_snapshot(
            published / "latest.json",
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        bad = dict(snapshot)
        bad["records"] = []
        bad["status"] = "ok"
        with self.assertRaises(PublishGuardError):
            promote_snapshot(
                bad,
                published,
                now=datetime(2099, 1, 10, 13, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=self.config.max_kev_bytes,
                max_depth=self.config.max_json_depth,
            )
        unchanged = load_snapshot(
            published / "latest.json",
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        self.assertEqual(unchanged["snapshot_id"], latest["snapshot_id"])

    def test_refuses_stale_older_snapshot(self) -> None:
        snapshot = self._snapshot()
        published = self.root / "published"
        promote_snapshot(
            snapshot,
            published,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=self.config.max_kev_bytes,
            max_depth=self.config.max_json_depth,
        )
        older = dict(snapshot)
        older["generated_at"] = "2099-01-01T00:00:00Z"
        older["snapshot_id"] = "older"
        with self.assertRaises(PublishGuardError):
            promote_snapshot(
                older,
                published,
                now=datetime(2099, 1, 10, 13, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=self.config.max_kev_bytes,
                max_depth=self.config.max_json_depth,
            )

    def test_failed_snapshot_is_not_published(self) -> None:
        snapshot = self._snapshot()
        snapshot["status"] = "failed"
        with self.assertRaises(PublishGuardError):
            promote_snapshot(
                snapshot,
                self.root / "published",
                now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=self.config.max_kev_bytes,
                max_depth=self.config.max_json_depth,
            )


if __name__ == "__main__":
    unittest.main()
