"""Official delta.json / deltaLog.json fetchTime and window-boundary semantics."""

from __future__ import annotations

import json
import unittest

from silastron_pulse.adapters.delta import compare_fetch_times, parse_delta_log, parse_delta_window
from tests.support import fixture_bytes


class FetchTimeTests(unittest.TestCase):
    def test_official_fractional_fetch_time_equals_padded_form(self) -> None:
        self.assertEqual(
            compare_fetch_times("2026-10-21T09:40:14.219Z", "2026-10-21T09:40:14.219000Z"),
            "equal",
        )

    def test_newer_and_older_windows(self) -> None:
        self.assertEqual(
            compare_fetch_times("2099-01-09T00:00:00Z", "2099-01-08T00:00:00Z"),
            "newer",
        )
        self.assertEqual(
            compare_fetch_times("2099-01-07T00:00:00Z", "2099-01-08T00:00:00Z"),
            "older",
        )

    def test_unparseable_fetch_time_is_invalid(self) -> None:
        self.assertEqual(compare_fetch_times("not-a-time", "2099-01-08T00:00:00Z"), "invalid")


class DeltaLogBoundaryTests(unittest.TestCase):
    def test_stored_window_is_excluded_later_windows_included(self) -> None:
        parsed = parse_delta_log(
            [
                {"fetchTime": "2099-01-10T00:00:00Z", "updated": [{"cveId": "CVE-2099-0003"}]},
                {"fetchTime": "2099-01-09T00:00:00Z", "updated": [{"cveId": "CVE-2099-0002"}]},
                {"fetchTime": "2099-01-08T00:00:00Z", "updated": [{"cveId": "CVE-2099-0001"}]},
            ],
            since="2099-01-08T00:00:00Z",
            retrieved_at="2099-01-10T12:00:00Z",
        )
        self.assertTrue(parsed.complete_since)
        self.assertEqual(parsed.changed_ids, frozenset({"CVE-2099-0002", "CVE-2099-0003"}))
        self.assertNotIn("CVE-2099-0001", parsed.changed_ids)

    def test_duplicate_fetch_times_after_since_are_all_included(self) -> None:
        parsed = parse_delta_log(
            [
                {
                    "fetchTime": "2099-01-09T00:00:00.000Z",
                    "updated": [{"cveId": "CVE-2099-0001"}],
                },
                {
                    "fetchTime": "2099-01-09T00:00:00Z",
                    "new": [{"cveId": "CVE-2099-0002"}],
                },
                {"fetchTime": "2099-01-08T00:00:00Z", "updated": [{"cveId": "CVE-2099-0003"}]},
            ],
            since="2099-01-08T00:00:00Z",
            retrieved_at="2099-01-10T12:00:00Z",
        )
        self.assertEqual(parsed.changed_ids, frozenset({"CVE-2099-0001", "CVE-2099-0002"}))
        self.assertNotIn("CVE-2099-0003", parsed.changed_ids)

    def test_duplicate_fetch_times_at_watermark_are_skipped(self) -> None:
        parsed = parse_delta_log(
            [
                {"fetchTime": "2099-01-08T00:00:00Z", "updated": [{"cveId": "CVE-2099-0001"}]},
                {"fetchTime": "2099-01-08T00:00:00.000Z", "updated": [{"cveId": "CVE-2099-0002"}]},
            ],
            since="2099-01-08T00:00:00Z",
            retrieved_at="2099-01-10T12:00:00Z",
        )
        self.assertEqual(parsed.changed_ids, frozenset())
        self.assertTrue(parsed.complete_since)

    def test_gap_when_earliest_window_is_after_since(self) -> None:
        parsed = parse_delta_log(
            [{"fetchTime": "2099-01-20T00:00:00Z", "updated": [{"cveId": "CVE-2099-0001"}]}],
            since="2099-01-08T00:00:00Z",
            retrieved_at="2099-01-10T12:00:00Z",
        )
        self.assertFalse(parsed.complete_since)
        self.assertEqual(parsed.changed_ids, frozenset({"CVE-2099-0001"}))

    def test_upstream_delta_window_shape(self) -> None:
        payload = json.loads(fixture_bytes("upstream/delta.json"))
        self.assertEqual(payload["fetchTime"], "2026-10-21T09:40:14.219Z")
        self.assertEqual(parse_delta_window(payload), {"CVE-2021-44228"})


if __name__ == "__main__":
    unittest.main()
