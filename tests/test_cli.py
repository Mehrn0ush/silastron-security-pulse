from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.cli import main
from silastron_pulse.pipeline import collect
from tests.support import frozen_clock, test_config, valid_fetcher


class CliTests(unittest.TestCase):
    def test_validate_and_unpublished(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = test_config(root)
            result = collect(
                config=config,
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
            )
            assert result.snapshot is not None
            snapshot_path = root / "snap.json"
            snapshot_path.write_text(json.dumps(result.snapshot), encoding="utf-8")
            self.assertEqual(main(["validate", str(snapshot_path)]), 0)
            unpublished = root / "public"
            self.assertEqual(
                main(["write-unpublished", "--published-dir", str(unpublished)]),
                0,
            )
            manifest = json.loads((unpublished / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "unpublished")


if __name__ == "__main__":
    unittest.main()
