"""Symlink and path-safety guards for privileged publication copies."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silastron_pulse.errors import ArtifactVerifyError, PublishGuardError
from silastron_pulse.safe_fs import (
    ARTIFACT_FILES,
    assert_artifact_tree,
    copy_tree_without_symlinks,
    require_run_id,
    require_safe_token,
)
from silastron_pulse.cli import main


class SafeFsTests(unittest.TestCase):
    def test_run_id_and_tokens_reject_interpolation_payloads(self) -> None:
        self.assertEqual(require_run_id(12345), "12345")
        with self.assertRaises(ArtifactVerifyError):
            require_run_id("12;rm")
        with self.assertRaises(ArtifactVerifyError):
            require_safe_token("$(id)", label="snapshot_id")
        with self.assertRaises(ArtifactVerifyError):
            require_safe_token("a/b", label="snapshot_id")

    def test_artifact_tree_rejects_symlinks_and_unknown_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            for name in ARTIFACT_FILES:
                (dist / name).write_text("{}", encoding="utf-8")
            assert_artifact_tree(dist)
            (dist / "evil.sh").write_text("hi", encoding="utf-8")
            with self.assertRaises(ArtifactVerifyError):
                assert_artifact_tree(dist)
            (dist / "evil.sh").unlink()
            (dist / "link.json").symlink_to(dist / "candidate.json")
            with self.assertRaises(ArtifactVerifyError):
                assert_artifact_tree(dist)

    def test_copy_tree_refuses_symlinks_and_keeps_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            dst = Path(tmp) / "dst"
            src.mkdir()
            (src / "latest.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
            nested = src / "snapshots"
            nested.mkdir()
            (nested / "one.json").write_text("{}", encoding="utf-8")
            copy_tree_without_symlinks(src, dst)
            self.assertEqual((dst / "latest.json").read_text(encoding="utf-8"), '{"ok": true}')
            self.assertFalse((dst / "latest.json").is_symlink())
            (src / "sneak").symlink_to(Path("/etc/passwd"))
            with self.assertRaises(PublishGuardError):
                copy_tree_without_symlinks(src, Path(tmp) / "dst2")
            self.assertEqual(main(["safe-copy", "--src", str(src / "missing"), "--dst", str(dst)]), 1)
