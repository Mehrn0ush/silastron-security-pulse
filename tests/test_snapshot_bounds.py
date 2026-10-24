from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from silastron_pulse.errors import ValidationError
from silastron_pulse.store import load_json_file
from tests.support import test_config

# Collect 40099136792 candidate.json was rejected by Publish at the KEV cap.
LIVE_CANDIDATE_BYTES = 17_277_697


class SnapshotBoundTests(unittest.TestCase):
    def test_snapshot_load_bound_is_above_kev_catalog_and_live_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
        self.assertGreater(config.max_snapshot_bytes, config.max_kev_bytes)
        self.assertGreaterEqual(config.max_snapshot_bytes, LIVE_CANDIDATE_BYTES)
        self.assertEqual(config.max_kev_bytes, 15_000_000)

    def test_payload_between_kev_and_snapshot_caps_is_loadable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            object.__setattr__(config, "max_kev_bytes", 80)
            object.__setattr__(config, "max_snapshot_bytes", 200)
            payload = b"{" + (b" " * 100) + b"}"
            path = Path(tmp) / "between.json"
            path.write_bytes(payload)
            with self.assertRaises(ValidationError) as raised:
                load_json_file(
                    path, max_bytes=config.max_kev_bytes, max_depth=config.max_json_depth
                )
            self.assertIn("exceeded max bytes 80", str(raised.exception))
            loaded = load_json_file(
                path, max_bytes=config.max_snapshot_bytes, max_depth=config.max_json_depth
            )
            self.assertEqual(loaded, {})

    def test_promote_cli_uses_snapshot_byte_limit(self) -> None:
        text = Path(__file__).resolve().parents[1].joinpath(
            "src/silastron_pulse/cli.py"
        ).read_text(encoding="utf-8")
        self.assertIn("max_bytes=config.max_snapshot_bytes", text)
        self.assertNotIn(
            "load_snapshot(\n                args.candidate,\n                max_bytes=config.max_kev_bytes",
            text,
        )


if __name__ == "__main__":
    unittest.main()
