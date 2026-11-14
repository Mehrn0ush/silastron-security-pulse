"""Watchdog decision logic, fetching and issue handling, with no network."""

from __future__ import annotations

import io
import re
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

from silastron_pulse.watchdog import (
    BEHIND_HOURS,
    FETCH_ATTEMPTS,
    ISSUE_TITLE,
    KEV_MAX_AGE_HOURS,
    LABEL,
    MALWARE_MAX_AGE_HOURS,
    Observation,
    evaluate,
    observe,
    sync_issue,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def iso(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def healthy(**over) -> Observation:
    base = dict(site_ok=True, kev_verified_at=iso(5), malware_collected_at=iso(5), live_malware_commit="a" * 40,
                malware_head_commit="a" * 40, malware_head_date=iso(5))
    base.update(over)
    return Observation(**base)


def keys(obs: Observation) -> list[str]:
    return [p.key for p in evaluate(obs, NOW)]


class EvaluateTests(unittest.TestCase):
    def test_healthy_site_has_no_problems(self) -> None:
        self.assertEqual(keys(healthy()), [])

    def test_unreachable_site_is_the_only_finding(self) -> None:
        self.assertEqual(keys(Observation(site_ok=False, site_error="timeout")), ["site-unreachable"])

    def test_kev_staleness_threshold(self) -> None:
        self.assertEqual(keys(healthy(kev_verified_at=iso(KEV_MAX_AGE_HOURS - 1))), [])
        self.assertEqual(keys(healthy(kev_verified_at=iso(KEV_MAX_AGE_HOURS + 1))), ["kev-stale"])

    def test_missing_or_garbled_kev_time(self) -> None:
        self.assertEqual(keys(healthy(kev_verified_at=None)), ["kev-unverified"])
        self.assertEqual(keys(healthy(kev_verified_at="yesterday")), ["kev-unverified"])

    def test_malware_staleness_threshold(self) -> None:
        self.assertEqual(keys(healthy(malware_collected_at=iso(MALWARE_MAX_AGE_HOURS - 1))), [])
        self.assertEqual(keys(healthy(malware_collected_at=iso(MALWARE_MAX_AGE_HOURS + 1))), ["malware-stale"])

    def test_malware_behind_main_state_by_more_than_six_hours(self) -> None:
        behind = healthy(live_malware_commit="b" * 40, malware_head_date=iso(BEHIND_HOURS + 1))
        self.assertEqual(keys(behind), ["malware-behind"])
        recent = healthy(live_malware_commit="b" * 40, malware_head_date=iso(BEHIND_HOURS - 1))
        self.assertEqual(keys(recent), [])

    def test_live_site_without_malware_data_when_the_branch_exists(self) -> None:
        self.assertIn("malware-missing", keys(healthy(malware_collected_at=None, live_malware_commit=None)))

    def test_no_malware_branch_means_no_malware_alerts(self) -> None:
        self.assertEqual(keys(healthy(malware_head_commit=None, malware_head_date=None, malware_collected_at=None,
                                      live_malware_commit=None)), [])

    def test_both_sources_can_alert_independently(self) -> None:
        both = healthy(kev_verified_at=iso(100), malware_collected_at=iso(100))
        self.assertEqual(sorted(keys(both)), ["kev-stale", "malware-stale"])


class ObserveTests(unittest.TestCase):
    def test_three_failed_fetches_mean_unreachable(self) -> None:
        calls, sleeps = [], []

        def fetch(url: str):
            calls.append(url)
            raise OSError("boom")

        obs = observe(site_url="https://x.example", repo="o/r", fetch=fetch, sleep=sleeps.append, attempts=FETCH_ATTEMPTS)
        self.assertFalse(obs.site_ok)
        self.assertEqual(len(calls), FETCH_ATTEMPTS)
        self.assertEqual(len(sleeps), FETCH_ATTEMPTS - 1)

    def test_one_transient_failure_is_not_an_alert(self) -> None:
        state = {"n": 0}

        def fetch(url: str):
            if "manifest.json" in url:
                state["n"] += 1
                if state["n"] == 1:
                    raise OSError("blip")
                return {"snapshot_id": "s"}
            if "verification-status" in url:
                return {"verified_at": iso(1)}
            raise urllib.error.HTTPError(url, 404, "nf", {}, io.BytesIO(b""))  # type: ignore[arg-type]

        obs = observe(site_url="https://x.example", repo="o/r", fetch=fetch, sleep=lambda s: None)
        self.assertTrue(obs.site_ok)
        self.assertEqual(obs.kev_verified_at, iso(1))
        self.assertIsNone(obs.malware_collected_at)
        self.assertIsNone(obs.malware_head_commit)

    def test_reads_malware_head_and_live_commit(self) -> None:
        def fetch(url: str):
            if "manifest.json" in url:
                return {}
            if "verification-status" in url:
                return {"verified_at": iso(1)}
            if "malware/data/status.json" in url:
                return {"collected_at": iso(2)}
            if "build.json" in url:
                return {"malware_state_commit": "c" * 40}
            if "branches/malware-state" in url:
                return {"commit": {"sha": "d" * 40, "commit": {"committer": {"date": iso(9)}}}}
            raise AssertionError(url)

        obs = observe(site_url="https://x.example", repo="o/r", fetch=fetch, sleep=lambda s: None)
        self.assertEqual((obs.live_malware_commit, obs.malware_head_commit, obs.malware_head_date), ("c" * 40, "d" * 40, iso(9)))


class Gh:
    def __init__(self, open_issue: str = "") -> None:
        self.open_issue, self.calls = open_issue, []

    def __call__(self, args, stdin):
        self.calls.append((args, stdin))
        if args[:2] == ["issue", "list"]:
            return self.open_issue
        return ""

    def verbs(self):
        return [" ".join(a[:2]) for a, _ in self.calls]


class IssueTests(unittest.TestCase):
    problems = evaluate(healthy(kev_verified_at=iso(100)), NOW)

    def test_opens_one_labelled_assigned_issue(self) -> None:
        gh = Gh()
        self.assertEqual(sync_issue(self.problems, NOW, gh, "Mehrn0ush"), "opened")
        create = next(a for a, _ in gh.calls if a[:2] == ["issue", "create"])
        self.assertIn(ISSUE_TITLE, create)
        self.assertEqual(create[create.index("--label") + 1], LABEL)
        self.assertEqual(create[create.index("--assignee") + 1], "Mehrn0ush")
        self.assertIn("kev-stale", gh.calls[-1][1])
        self.assertEqual(gh.verbs()[0], "label create")  # the label is ensured first

    def test_updates_the_existing_issue_instead_of_opening_another(self) -> None:
        gh = Gh("12")
        self.assertEqual(sync_issue(self.problems, NOW, gh, "o"), "updated #12")
        self.assertNotIn("issue create", gh.verbs())
        self.assertIn("issue edit", gh.verbs())

    def test_closes_on_recovery_and_is_silent_when_nothing_is_open(self) -> None:
        gh = Gh("12")
        self.assertEqual(sync_issue([], NOW, gh, "o"), "closed #12")
        self.assertEqual(gh.verbs()[-2:], ["issue comment", "issue close"])
        quiet = Gh()
        self.assertEqual(sync_issue([], NOW, quiet, "o"), "healthy")
        self.assertNotIn("issue create", quiet.verbs())

    def test_omits_the_assignee_when_none_is_given(self) -> None:
        gh = Gh()
        sync_issue(self.problems, NOW, gh, None)
        create = next(a for a, _ in gh.calls if a[:2] == ["issue", "create"])
        self.assertNotIn("--assignee", create)


class WorkflowContractTests(unittest.TestCase):
    wf = (ROOT / ".github" / "workflows" / "watchdog.yml").read_text(encoding="utf-8")

    def test_permissions_are_issues_write_and_contents_read_only(self) -> None:
        block = re.search(r"^permissions:\n((?:  .+\n)+)", self.wf, re.M).group(1)
        self.assertEqual(sorted(line.strip() for line in block.splitlines()), ["contents: read", "issues: write"])

    def test_triggers_name_real_workflows(self) -> None:
        names = {re.search(r"^name: (.+)$", (ROOT / ".github" / "workflows" / f).read_text(), re.M).group(1)
                 for f in ("collect.yml", "collect-malware.yml", "publish.yml")}
        listed = set(re.findall(r'"([^"]+)"', re.search(r"workflows: \[(.+)\]", self.wf).group(1)))
        self.assertEqual(listed, names)
        self.assertIn("schedule:", self.wf)
        self.assertIn('cron: "17 */6 * * *"', self.wf)

    def test_no_secrets_and_no_repository_writes(self) -> None:
        self.assertNotIn("secrets.", self.wf)
        self.assertNotIn("git push", self.wf)


if __name__ == "__main__":
    unittest.main()
