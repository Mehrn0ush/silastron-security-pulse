from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from silastron_pulse.errors import ValidationError
from silastron_pulse.pipeline import collect
from silastron_pulse.validate import validate_manifest, validate_snapshot
from tests.support import frozen_clock, test_config, valid_fetcher


class ValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config = test_config(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_valid_snapshot(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        assert result.snapshot is not None
        validate_snapshot(result.snapshot)

    def test_rejects_risk_score(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        assert result.snapshot is not None
        result.snapshot["composite_risk_score"] = 9.9
        with self.assertRaises(ValidationError):
            validate_snapshot(result.snapshot)

    def test_rejects_unsorted_or_duplicate_records(self) -> None:
        result = collect(
            config=self.config,
            fetcher=valid_fetcher(),
            clock=frozen_clock(),
        )
        assert result.snapshot is not None
        result.snapshot["records"] = list(reversed(result.snapshot["records"]))
        with self.assertRaises(ValidationError):
            validate_snapshot(result.snapshot)

    def test_manifest_cannot_be_fresh_and_stale(self) -> None:
        with self.assertRaises(ValidationError):
            validate_manifest(
                {
                    "schema_version": "1.0.0",
                    "generated_at": "2099-01-01T00:00:00Z",
                    "status": "ok",
                    "latest_snapshot": "x.json",
                    "latest_ok_snapshot": "x.json",
                    "stale": True,
                    "fresh": True,
                }
            )


if __name__ == "__main__":
    unittest.main()
