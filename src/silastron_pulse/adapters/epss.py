"""FIRST EPSS adapter.

Production collection is BLOCKED. Public availability of scores is not treated
as a redistribution license. Parsing helpers exist so enablement can be tested
against fixtures without publishing EPSS data.
"""

from __future__ import annotations

from dataclasses import dataclass

from silastron_pulse.constants import (
    EPSS_ATTRIBUTION,
    EPSS_HOME_URL,
    EPSS_PARSER_VERSION,
    EPSS_USAGE_AGREEMENT_URL,
)
from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import parse_cve_id
from silastron_pulse.models import EpssRecord, SourceMeta

# Hard blocker. Do not flip this without documented owner approval of
# FIRST EPSS usage AND redistribution terms for a public JSON snapshot.
REDISTRIBUTION_CLEARED = False

EPSS_BLOCKER = (
    "EPSS is disabled because FIRST grants public use of scores with requested "
    "attribution, but does not publish an explicit redistribution license for "
    "derived public datasets. Silastron Security Pulse would republish scores "
    "in GitHub Pages JSON consumed by third parties. That exceeds verified "
    f"rights. See {EPSS_USAGE_AGREEMENT_URL}"
)


@dataclass(frozen=True)
class EpssResult:
    meta: SourceMeta
    records: dict[str, EpssRecord]


def collect_epss(cve_ids: list[str], *, enabled: bool = False) -> EpssResult:
    del cve_ids
    if enabled and not REDISTRIBUTION_CLEARED:
        enabled = False
    if not enabled:
        meta = SourceMeta(
            id="first-epss",
            name="FIRST Exploit Prediction Scoring System",
            status="disabled",
            url=EPSS_HOME_URL,
            retrieved_at=None,
            source_published_at=None,
            source_updated_at=None,
            source_revision=None,
            parser_version=EPSS_PARSER_VERSION,
            schema_version=None,
            license="FIRST EPSS Usage Agreement (redistribution unverified)",
            content_sha256=None,
            notes=EPSS_ATTRIBUTION,
            error=EPSS_BLOCKER,
        )
        return EpssResult(meta=meta, records={})
    raise ValidationError("EPSS enablement is blocked by REDISTRIBUTION_CLEARED=False")


def unavailable_record(cve_id: str) -> EpssRecord:
    return EpssRecord(
        status="unavailable",
        cve_id=parse_cve_id(cve_id),
        notes=EPSS_BLOCKER,
    )


def parse_epss_api_payload(payload: object, expected_cve_id: str) -> EpssRecord:
    """Parse a FIRST EPSS API-shaped document. Not used in production collection."""
    expected = parse_cve_id(expected_cve_id)
    if not isinstance(payload, dict):
        raise ValidationError("EPSS payload must be an object")
    rows = payload.get("data")
    if not isinstance(rows, list) or not rows:
        raise ValidationError("EPSS payload has no data rows")
    if len(rows) != 1:
        raise ValidationError("EPSS payload must contain exactly one row for a CVE lookup")
    row = rows[0]
    if not isinstance(row, dict):
        raise ValidationError("EPSS row must be an object")
    actual = parse_cve_id(row.get("cve"))
    if actual != expected:
        raise ValidationError(
            f"EPSS row CVE {actual} does not match requested {expected}"
        )
    score = _parse_unit_interval(row.get("epss"), "epss")
    percentile = _parse_unit_interval(row.get("percentile"), "percentile")
    date = row.get("date")
    if not isinstance(date, str) or not date:
        raise ValidationError("EPSS row is missing date")
    return EpssRecord(
        status="ok",
        cve_id=expected,
        score=score,
        percentile=percentile,
        score_date=date,
        notes=EPSS_ATTRIBUTION,
    )


def _parse_unit_interval(value: object, field: str) -> float:
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError as exc:
            raise ValidationError(f"EPSS {field} is not a number") from exc
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValidationError(f"EPSS {field} is not a number")
    number = float(value)
    if number < 0.0 or number > 1.0:
        raise ValidationError(f"EPSS {field} must be between 0 and 1")
    return number
