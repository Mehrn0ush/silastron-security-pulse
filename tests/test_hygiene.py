"""Guards that keep the suite independent of live data and of the wall clock.

Pulse keeps no collected data in the repository (state lives on the pulse-state and malware-state branches),
so unlike a repo with a committed data directory the suite cannot be broken by a Collect run. These static
checks keep it that way and keep clock reads at a short, reviewed list of boundaries.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "silastron_pulse"
CLOCK_CALL = re.compile(r"datetime\.now\(|date\.today\(|time\.time\(\)|time\.time_ns\(|utcnow\(")

# Every place production code may read the wall clock, with why. Everything else must take an injected
# `now`/clock. A new entry needs a reason here.
ALLOWED_CLOCK_READS = {
    "clock.py": "the system clock implementation",
    "cli.py": "command-line default when --now is not given",
    "http.py": "Retry-After arithmetic",
    "smoke.py": "cache-busting query stamp",
    "watchdog.py": "cache-busting query stamp",
    "adapters/nvd.py": "default when the caller passes no instant",
    "verify_operations.py": "default when the caller passes no instant",
    "malware/collect.py": "default when the caller passes no instant",
    "malware/pages.py": "default when the caller passes no instant",
}


class ClockHygieneTests(unittest.TestCase):
    def test_wall_clock_reads_stay_at_the_reviewed_boundaries(self) -> None:
        found = {
            p.relative_to(SRC).as_posix()
            for p in SRC.rglob("*.py")
            if CLOCK_CALL.search(p.read_text(encoding="utf-8"))
        }
        self.assertEqual(found, set(ALLOWED_CLOCK_READS), "a clock read was added or removed; update ALLOWED_CLOCK_READS with a reason")

    def test_tests_never_read_the_wall_clock(self) -> None:
        offenders = []
        for p in [*sorted((ROOT / "tests").glob("*.py")), ROOT / "tests" / "e2e" / "serve.py"]:
            if p.name == "test_hygiene.py":
                continue
            if CLOCK_CALL.search(p.read_text(encoding="utf-8")):
                offenders.append(p.name)
        self.assertEqual(offenders, [])


class LiveDataHygieneTests(unittest.TestCase):
    def test_no_collected_data_is_committed(self) -> None:
        names = {p.name for p in (ROOT / "data").iterdir()} if (ROOT / "data").is_dir() else set()
        self.assertEqual(names, {"commentary"})

    def test_no_test_reads_the_repository_data_directory(self) -> None:
        pattern = re.compile(r'ROOT\s*/\s*"data"')
        offenders = [p.name for p in sorted((ROOT / "tests").glob("*.py")) if p.name != "test_hygiene.py"
                     and pattern.search(p.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [])

    def test_no_test_opens_the_network(self) -> None:
        pattern = re.compile(r"urlopen\(|requests\.get|http\.client\.HTTPSConnection")
        offenders = [p.name for p in sorted((ROOT / "tests").glob("*.py")) if p.name != "test_hygiene.py"
                     and pattern.search(p.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
