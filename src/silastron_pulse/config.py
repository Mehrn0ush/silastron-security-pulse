"""Validated runtime configuration. Host allowlists are not configurable."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from silastron_pulse.constants import DEFAULT_LIMITS


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = int(raw, 10)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class PulseConfig:
    http_timeout_seconds: int
    max_redirects: int
    max_kev_bytes: int
    max_snapshot_bytes: int
    max_delta_bytes: int
    max_cve_bytes: int
    max_json_depth: int
    max_kev_records: int
    max_cve_enrichments: int
    max_string_chars: int
    max_description_chars: int
    max_products: int
    max_versions_per_product: int
    max_preview_changes: int
    max_preview_recent: int
    cve_workers: int
    cve_min_interval_ms: int
    http_max_attempts: int
    http_backoff_seconds: int
    max_cwes: int
    stale_after_hours: int
    max_cve_failures_ratio: float
    max_cve_failures_absolute: int
    output_dir: Path

    @classmethod
    def from_env(cls, output_dir: Path) -> "PulseConfig":
        defaults = DEFAULT_LIMITS
        return cls(
            http_timeout_seconds=_int_env(
                "PULSE_HTTP_TIMEOUT_SECONDS",
                defaults["http_timeout_seconds"],
                minimum=1,
                maximum=120,
            ),
            max_redirects=_int_env(
                "PULSE_MAX_REDIRECTS",
                defaults["max_redirects"],
                minimum=0,
                maximum=5,
            ),
            max_kev_bytes=_int_env(
                "PULSE_MAX_KEV_BYTES",
                defaults["max_kev_bytes"],
                minimum=1024,
                maximum=30_000_000,
            ),
            max_snapshot_bytes=_int_env(
                "PULSE_MAX_SNAPSHOT_BYTES",
                defaults["max_snapshot_bytes"],
                minimum=1024,
                maximum=80_000_000,
            ),
            max_delta_bytes=_int_env(
                "PULSE_MAX_DELTA_BYTES",
                defaults["max_delta_bytes"],
                minimum=1024,
                maximum=80_000_000,
            ),
            max_cve_bytes=_int_env(
                "PULSE_MAX_CVE_BYTES",
                defaults["max_cve_bytes"],
                minimum=1024,
                maximum=5_000_000,
            ),
            max_json_depth=_int_env(
                "PULSE_MAX_JSON_DEPTH",
                defaults["max_json_depth"],
                minimum=4,
                maximum=64,
            ),
            max_kev_records=_int_env(
                "PULSE_MAX_KEV_RECORDS",
                defaults["max_kev_records"],
                minimum=1,
                maximum=5000,
            ),
            max_cve_enrichments=_int_env(
                "PULSE_MAX_CVE_ENRICHMENTS",
                defaults["max_cve_enrichments"],
                minimum=0,
                maximum=5000,
            ),
            max_string_chars=_int_env(
                "PULSE_MAX_STRING_CHARS",
                defaults["max_string_chars"],
                minimum=32,
                maximum=20_000,
            ),
            max_description_chars=_int_env(
                "PULSE_MAX_DESCRIPTION_CHARS",
                defaults["max_description_chars"],
                minimum=32,
                maximum=10_000,
            ),
            max_products=_int_env(
                "PULSE_MAX_PRODUCTS",
                defaults["max_products"],
                minimum=1,
                maximum=500,
            ),
            max_versions_per_product=_int_env(
                "PULSE_MAX_VERSIONS_PER_PRODUCT",
                defaults["max_versions_per_product"],
                minimum=1,
                maximum=500,
            ),
            max_preview_changes=_int_env(
                "PULSE_MAX_PREVIEW_CHANGES",
                defaults["max_preview_changes"],
                minimum=1,
                maximum=200,
            ),
            max_preview_recent=_int_env(
                "PULSE_MAX_PREVIEW_RECENT",
                defaults["max_preview_recent"],
                minimum=1,
                maximum=100,
            ),
            cve_workers=_int_env(
                "PULSE_CVE_WORKERS",
                defaults["cve_workers"],
                minimum=1,
                maximum=8,
            ),
            cve_min_interval_ms=_int_env(
                "PULSE_CVE_MIN_INTERVAL_MS",
                defaults["cve_min_interval_ms"],
                minimum=0,
                maximum=2000,
            ),
            http_max_attempts=_int_env(
                "PULSE_HTTP_MAX_ATTEMPTS",
                defaults["http_max_attempts"],
                minimum=1,
                maximum=8,
            ),
            http_backoff_seconds=_int_env(
                "PULSE_HTTP_BACKOFF_SECONDS",
                defaults["http_backoff_seconds"],
                minimum=0,
                maximum=60,
            ),
            max_cwes=_int_env(
                "PULSE_MAX_CWES",
                defaults["max_cwes"],
                minimum=1,
                maximum=64,
            ),
            stale_after_hours=_int_env(
                "PULSE_STALE_AFTER_HOURS",
                defaults["stale_after_hours"],
                minimum=1,
                maximum=168,
            ),
            max_cve_failures_ratio=defaults["max_cve_failures_ratio"],
            max_cve_failures_absolute=defaults["max_cve_failures_absolute"],
            output_dir=output_dir,
        )
