import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCRIPT = ROOT / ".github" / "scripts" / "push-with-retry.sh"
ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
}


def git(cwd, *args, check=True):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, capture_output=True, text=True, check=check)


class PushWithRetryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.origin = root / "origin.git"
        git(root, "init", "-q", "--bare", "-b", "main", str(self.origin))
        self.a, self.b = root / "a", root / "b"
        git(root, "clone", "-q", str(self.origin), str(self.a))
        git(self.a, "checkout", "-q", "-b", "main")
        (self.a / "data").mkdir()
        (self.a / "data/x.json").write_text("{}\n")
        (self.a / "data/y.json").write_text("{}\n")
        git(self.a, "add", "-A")
        git(self.a, "commit", "-q", "-m", "init")
        git(self.a, "push", "-q", "origin", "main")
        git(root, "clone", "-q", str(self.origin), str(self.b))

    def run_script(self):
        return subprocess.run([str(SCRIPT), "main"], cwd=self.a, env=ENV, capture_output=True, text=True)

    def commit(self, repo, name, text, message):
        (repo / "data" / name).write_text(text)
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", message)

    def origin_log(self):
        return git(self.origin, "log", "--format=%s", "main").stdout.split("\n")[:-1]

    def test_plain_push_works(self):
        self.commit(self.a, "x.json", '{"a": 1}\n', "collect")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.origin_log()[0], "collect")

    def test_concurrent_push_to_another_file_is_rebased_over(self):
        self.commit(self.a, "x.json", '{"a": 1}\n', "collect")
        self.commit(self.b, "y.json", '{"b": 1}\n', "someone else")
        git(self.b, "push", "-q", "origin", "main")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.origin_log()[:2], ["collect", "someone else"])

    def test_conflicting_change_fails_at_once_and_leaves_a_clean_tree(self):
        self.commit(self.a, "x.json", '{"a": 1}\n', "collect")
        self.commit(self.b, "x.json", '{"b": 1}\n', "someone else")
        git(self.b, "push", "-q", "origin", "main")
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(git(self.a, "status", "--porcelain").stdout, "")
        self.assertEqual(self.origin_log()[0], "someone else")

    def test_gives_up_after_three_rejected_pushes(self):
        counter = Path(self.origin.parent / "count")
        hook = self.origin / "hooks" / "pre-receive"
        hook.write_text(f'#!/bin/sh\necho x >> "{counter}"\nexit 1\n')
        hook.chmod(0o755)
        self.commit(self.a, "x.json", '{"a": 1}\n', "collect")
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(counter.read_text().split()), 3)
        self.assertIn("giving up after 3 attempts", r.stderr)

    def test_recovers_when_the_first_push_loses_a_race(self):
        """A reject on the first attempt, success on the second, with a new upstream commit in between."""
        counter = Path(self.origin.parent / "count")
        hook = self.origin / "hooks" / "pre-receive"
        hook.write_text(
            f'#!/bin/sh\nif [ ! -s "{counter}" ]; then echo x > "{counter}"; exit 1; fi\nexit 0\n'
        )
        hook.chmod(0o755)
        self.commit(self.a, "x.json", '{"a": 1}\n', "collect")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.origin_log()[0], "collect")

    def shallow_clone(self):
        c = self.a.parent / "shallow"
        git(self.a.parent, "clone", "-q", "--depth", "1", f"file://{self.origin}", str(c))
        self.assertEqual(git(c, "rev-parse", "--is-shallow-repository").stdout.strip(), "true")
        git(c, "checkout", "-q", "main")
        return c

    def test_shallow_clone_pushes_after_main_moved_on(self):
        """Collect's checkout used to be shallow: the rebase must still work when main has new commits."""
        c = self.shallow_clone()
        self.commit(self.b, "y.json", '{"b": 1}\n', "someone else 1")
        self.commit(self.b, "y.json", '{"b": 2}\n', "someone else 2")
        git(self.b, "push", "-q", "origin", "main")
        self.commit(c, "x.json", '{"a": 1}\n', "collect")
        r = subprocess.run([str(SCRIPT), "main"], cwd=c, env=ENV, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.origin_log()[:3], ["collect", "someone else 2", "someone else 1"])

    def test_shallow_clone_plain_push_and_conflict(self):
        c = self.shallow_clone()
        self.commit(c, "x.json", '{"a": 1}\n', "collect")
        r = subprocess.run([str(SCRIPT), "main"], cwd=c, env=ENV, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        c2 = self.a.parent / "shallow2"
        git(self.a.parent, "clone", "-q", "--depth", "1", f"file://{self.origin}", str(c2))
        self.commit(c2, "y.json", '{"mine": 1}\n', "collect 2")
        self.commit(self.b, "y.json", '{"theirs": 1}\n', "someone else")
        git(self.b, "pull", "-q", "--rebase", "origin", "main")
        git(self.b, "push", "-q", "origin", "main")
        r = subprocess.run([str(SCRIPT), "main"], cwd=c2, env=ENV, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(git(c2, "status", "--porcelain").stdout, "")

    def test_malware_collect_checks_out_full_history(self):
        text = (ROOT / ".github/workflows/collect-malware.yml").read_text()
        self.assertIn("fetch-depth: 0", text)

    def test_malware_workflow_pushes_through_the_script_and_never_forces(self):
        text = (ROOT / ".github/workflows/collect-malware.yml").read_text()
        self.assertEqual(text.count(".github/scripts/push-with-retry.sh\" malware-state"), 1)
        self.assertNotIn("--force", text)
        self.assertNotIn("push -f", text)
        self.assertNotIn("git push", text)
