from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.clock import FrozenClock, SteppingClock
from silastron_pulse.config import PulseConfig
from silastron_pulse.constants import CVE_DELTA_JSON_URL, KEV_JSON_URL
from silastron_pulse.http import FetchResult, MapFetcher
from silastron_pulse.ids import cvelist_v5_raw_url

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2099, 1, 10, 12, 0, tzinfo=timezone.utc)


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_config(output_dir: Path) -> PulseConfig:
    return PulseConfig.from_env(output_dir)


def fetch_result(url: str, name: str, retrieved_at: str = "2099-01-10T12:00:00Z") -> FetchResult:
    body = fixture_bytes(name)
    return FetchResult(
        requested_url=url,
        final_url=url,
        status_code=200,
        content_type="application/json",
        body=body,
        retrieved_at=retrieved_at,
    )


def valid_fetcher(**overrides: FetchResult | Exception) -> MapFetcher:
    mapping: dict[str, FetchResult | Exception] = {
        KEV_JSON_URL: fetch_result(KEV_JSON_URL, "kev_valid.json"),
        cvelist_v5_raw_url("CVE-2099-0001"): fetch_result(
            cvelist_v5_raw_url("CVE-2099-0001"), "cve_2099_0001.json"
        ),
        cvelist_v5_raw_url("CVE-2099-0002"): fetch_result(
            cvelist_v5_raw_url("CVE-2099-0002"), "cve_2099_0002.json"
        ),
        CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta_initial.json"),
    }
    mapping.update(overrides)
    return MapFetcher(mapping)


def frozen_clock() -> FrozenClock:
    return FrozenClock(NOW)


def stepping_clock(*, step_seconds: float = 1.0) -> SteppingClock:
    return SteppingClock(NOW, step_seconds=step_seconds)


def load_fixture_json(name: str) -> object:
    return json.loads(fixture_bytes(name))
