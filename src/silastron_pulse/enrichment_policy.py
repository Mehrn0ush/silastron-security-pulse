"""Evidence-based CVE/CNA enrichment availability for publication.

KEV source integrity and optional CVE List V5 enrichment are independent.
A missing CNA record must not, by itself, invalidate a verified KEV catalog.

HTTP 404 on the constructed CVE List V5 path means that official raw file
is not served. It does not prove the CVE is unpublished on CVE.org, NVD,
or CISA. Records without structured fetch evidence stay unclassified and
are not treated as confirmed-absent.
"""

from __future__ import annotations

from typing import Any

from silastron_pulse.errors import FetchError
from silastron_pulse.ids import cvelist_v5_raw_url, parse_cve_id
from silastron_pulse.http import RETRYABLE_STATUS

AVAILABLE = "available"
PARTIAL = "partial"
CVELIST_V5_NOT_FOUND = "cvelist_v5_not_found"
TRANSIENT_FAILURE = "transient_failure"
UNEXPECTED_ERROR = "unexpected_error"
UNCLASSIFIED = "unclassified"

# Observed 2026-10-31: 1 of 1766 KEV IDs had no CVE List V5 file (reserved on
# CVE.org). Absolute and ratio caps stay far above that single-record case
# and far below a systemic outage. Ratio caps apply only at production-sized
# catalogs so a 2-record fixture cannot look like a 50% outage. Residual risk:
# a coordinated burst of reserved KEV IDs below the absolute cap can publish
# without CNA records, and catalogs smaller than MIN_POLICY_POPULATION rely
# on absolute caps only.
MAX_CONFIRMED_ABSENT = 8
MAX_CONFIRMED_ABSENT_RATIO = 0.005
MAX_TRANSIENT = 2
MAX_TRANSIENT_RATIO = 0.002
MAX_UNCLASSIFIED = 0
SYSTEMIC_UNAVAILABLE_RATIO = 0.05
SYSTEMIC_UNAVAILABLE_MIN = 12
MIN_POLICY_POPULATION = 200

NOT_FOUND_NOTE = (
    "CVE List V5 returned HTTP 404 for the constructed official path. "
    "This does not prove the CVE is unpublished on CVE.org, NVD, or CISA."
)


def classify_fetch_failure(cve_id: str, url: str, exc: BaseException) -> dict[str, Any]:
    status = getattr(exc, "status_code", None)
    retryable = bool(getattr(exc, "retryable", False))
    constructed = cvelist_v5_raw_url(cve_id)
    path_valid = url == constructed
    message = str(exc)
    if (
        status == 404
        and path_valid
        and isinstance(exc, FetchError)
        and not retryable
    ):
        return {
            "state": CVELIST_V5_NOT_FOUND,
            "http_status": 404,
            "requested_url": url,
            "constructed_path_valid": True,
            "retryable": False,
            "note": NOT_FOUND_NOTE,
        }
    transient = retryable or status in RETRYABLE_STATUS or _looks_transient(message)
    return {
        "state": TRANSIENT_FAILURE if transient else UNEXPECTED_ERROR,
        "http_status": status,
        "requested_url": url,
        "constructed_path_valid": path_valid,
        "retryable": transient,
        "note": (
            "Retryable CVE List V5 fetch failure. Previously published enrichment "
            "must not be treated as a current successful fetch."
            if transient
            else "CVE List V5 fetch failed without confirmed-absent evidence."
        ),
        "error": message,
    }


def record_availability(record: dict[str, Any]) -> dict[str, Any]:
    cve = record.get("cve") if isinstance(record.get("cve"), dict) else {}
    structured = cve.get("enrichment_availability")
    completeness = record.get("completeness")
    if isinstance(structured, dict) and structured.get("state"):
        state = structured["state"]
        if completeness == "unavailable" and state in {AVAILABLE, PARTIAL}:
            return {
                "cve_id": record.get("cve_id"),
                "state": UNCLASSIFIED,
                "error": cve.get("error"),
                "note": (
                    "Record completeness is unavailable but enrichment_availability "
                    "still claims a successful fetch. Treating as unclassified."
                ),
            }
        if state in {AVAILABLE, PARTIAL, CVELIST_V5_NOT_FOUND, TRANSIENT_FAILURE, UNEXPECTED_ERROR}:
            return {
                "cve_id": record.get("cve_id"),
                "state": state,
                "http_status": structured.get("http_status"),
                "requested_url": structured.get("requested_url"),
                "note": structured.get("note"),
                "error": structured.get("error") or cve.get("error"),
            }
    status = cve.get("status")
    if status == "ok" and completeness == "complete":
        return {"cve_id": record.get("cve_id"), "state": AVAILABLE}
    if status == "ok" and completeness == "partial":
        return {"cve_id": record.get("cve_id"), "state": PARTIAL}
    if completeness == "unavailable" or status in {"unavailable", "failed"}:
        return {
            "cve_id": record.get("cve_id"),
            "state": UNCLASSIFIED,
            "error": cve.get("error"),
            "note": (
                "Unavailable enrichment lacks structured fetch evidence. "
                "HTTP 404 text in an error string is not treated as confirmed absence."
            ),
        }
    return {"cve_id": record.get("cve_id"), "state": AVAILABLE}


def evaluate_enrichment_policy(
    candidate: dict[str, Any],
    *,
    published: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = [item for item in (candidate.get("records") or []) if isinstance(item, dict)]
    classified = [record_availability(item) for item in records]
    counts = {
        AVAILABLE: 0,
        PARTIAL: 0,
        CVELIST_V5_NOT_FOUND: 0,
        TRANSIENT_FAILURE: 0,
        UNEXPECTED_ERROR: 0,
        UNCLASSIFIED: 0,
    }
    by_state: dict[str, list[str]] = {key: [] for key in counts}
    for item in classified:
        state = str(item.get("state") or UNCLASSIFIED)
        counts[state] = counts.get(state, 0) + 1
        cve_id = item.get("cve_id")
        if isinstance(cve_id, str):
            by_state.setdefault(state, []).append(cve_id)
    total = max(len(records), 1)
    report = {
        "counts": counts,
        "affected": {
            "cvelist_v5_not_found": by_state.get(CVELIST_V5_NOT_FOUND, []),
            "transient_failure": by_state.get(TRANSIENT_FAILURE, []),
            "unexpected_error": by_state.get(UNEXPECTED_ERROR, []),
            "unclassified": by_state.get(UNCLASSIFIED, []),
        },
        "thresholds": {
            "max_confirmed_absent": MAX_CONFIRMED_ABSENT,
            "max_confirmed_absent_ratio": MAX_CONFIRMED_ABSENT_RATIO,
            "max_transient": MAX_TRANSIENT,
            "max_transient_ratio": MAX_TRANSIENT_RATIO,
            "max_unclassified": MAX_UNCLASSIFIED,
            "systemic_unavailable_ratio": SYSTEMIC_UNAVAILABLE_RATIO,
            "systemic_unavailable_min": SYSTEMIC_UNAVAILABLE_MIN,
            "min_policy_population": MIN_POLICY_POPULATION,
        },
        "heuristic_risk": (
            "Confirmed-absent caps are informed by the 2026-10-31 incident "
            "(1/1766 reserved CVE List V5 file) and are not a proof that every "
            "404 below the cap is a reserved ID. Ratio caps apply only when "
            f"the catalog has at least {MIN_POLICY_POPULATION} records."
        ),
    }
    reason = _block_reason(candidate, counts, total, published, by_state)
    report["eligible"] = reason is None
    report["block_reason"] = reason
    return report


def _block_reason(
    candidate: dict[str, Any],
    counts: dict[str, int],
    total: int,
    published: dict[str, Any] | None,
    by_state: dict[str, list[str]],
) -> str | None:
    cve_source = ((candidate.get("sources") or {}).get("cve") or {})
    if cve_source.get("status") in {"failed", "unavailable"}:
        return (
            f"Systemic CVE List V5 source status {cve_source.get('status')!r} "
            "blocks publication. KEV records are not removed, but enrichment "
            "cannot be represented as current."
        )
    unavailable = (
        counts[CVELIST_V5_NOT_FOUND]
        + counts[TRANSIENT_FAILURE]
        + counts[UNEXPECTED_ERROR]
        + counts[UNCLASSIFIED]
    )
    if unavailable >= SYSTEMIC_UNAVAILABLE_MIN and unavailable / total > SYSTEMIC_UNAVAILABLE_RATIO:
        return (
            f"Systemic enrichment loss: {unavailable} of {total} records are "
            f"unavailable ({unavailable / total:.1%}), above "
            f"{SYSTEMIC_UNAVAILABLE_RATIO:.1%} and {SYSTEMIC_UNAVAILABLE_MIN} records."
        )
    if counts[UNCLASSIFIED] > MAX_UNCLASSIFIED:
        ids = ", ".join(by_state.get(UNCLASSIFIED, [])[:8]) or "unknown"
        return (
            f"{counts[UNCLASSIFIED]} unavailable enrichment(s) lack structured "
            f"fetch evidence ({ids}). Historical error strings are not treated "
            "as confirmed CVE List V5 absence."
        )
    if counts[UNEXPECTED_ERROR]:
        ids = ", ".join(by_state.get(UNEXPECTED_ERROR, [])[:8])
        return f"Unexpected CVE List V5 errors block publication: {ids}"
    if _exceeds(counts[TRANSIENT_FAILURE], total, MAX_TRANSIENT, MAX_TRANSIENT_RATIO):
        ids = ", ".join(by_state.get(TRANSIENT_FAILURE, [])[:8])
        return (
            f"{counts[TRANSIENT_FAILURE]} transient CVE List V5 failure(s) "
            f"exceed the cap of {MAX_TRANSIENT} and {MAX_TRANSIENT_RATIO:.2%} "
            f"({ids})."
        )
    if _exceeds(counts[CVELIST_V5_NOT_FOUND], total, MAX_CONFIRMED_ABSENT, MAX_CONFIRMED_ABSENT_RATIO):
        ids = ", ".join(by_state.get(CVELIST_V5_NOT_FOUND, [])[:8])
        return (
            f"{counts[CVELIST_V5_NOT_FOUND]} CVE List V5 files were not found, "
            f"exceeding {MAX_CONFIRMED_ABSENT} and {MAX_CONFIRMED_ABSENT_RATIO:.2%} "
            f"({ids})."
        )
    loss = _previous_enrichment_loss(candidate, published)
    if loss:
        return loss
    if candidate.get("status") == "degraded":
        summary = candidate.get("summary") or {}
        partial = summary.get("partial_records") or 0
        truncated = summary.get("truncated_records") or 0
        if (
            not counts[CVELIST_V5_NOT_FOUND]
            and not counts[TRANSIENT_FAILURE]
            and not partial
            and not truncated
        ):
            return "Degraded snapshot has no bounded partial extraction or classified enrichment gap"
    return None


def _previous_enrichment_loss(
    candidate: dict[str, Any],
    published: dict[str, Any] | None,
) -> str | None:
    if not published:
        return None
    previous = {
        item.get("cve_id"): item
        for item in (published.get("records") or [])
        if isinstance(item, dict)
    }
    lost = []
    for item in candidate.get("records") or []:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cve_id")
        prior = previous.get(cve_id) if isinstance(cve_id, str) else None
        if not prior:
            continue
        prior_cve = prior.get("cve") if isinstance(prior.get("cve"), dict) else {}
        current_cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
        if prior_cve.get("status") == "ok" and current_cve.get("status") != "ok":
            if current_cve.get("cached"):
                continue
            lost.append(cve_id)
    if lost:
        return (
            "Previously published CVE List V5 enrichment is missing for "
            f"{', '.join(lost[:8])}. Refusing to represent that loss as current "
            "upstream data."
        )
    return None


def kev_digest(snapshot: dict[str, Any]) -> object:
    return ((snapshot.get("sources") or {}).get("kev") or {}).get("content_sha256")


def enrichment_improved(published: dict[str, Any], candidate: dict[str, Any]) -> bool:
    if kev_digest(published) != kev_digest(candidate):
        return False
    pub = evaluate_enrichment_policy(published)["counts"]
    cand = evaluate_enrichment_policy(candidate)["counts"]
    pub_ok = pub[AVAILABLE] + pub[PARTIAL]
    cand_ok = cand[AVAILABLE] + cand[PARTIAL]
    pub_missing = pub[UNCLASSIFIED] + pub[CVELIST_V5_NOT_FOUND] + pub[TRANSIENT_FAILURE] + pub[UNEXPECTED_ERROR]
    cand_missing = cand[UNCLASSIFIED] + cand[CVELIST_V5_NOT_FOUND] + cand[TRANSIENT_FAILURE] + cand[UNEXPECTED_ERROR]
    return cand_ok > pub_ok or cand_missing < pub_missing


def _exceeds(count: int, total: int, absolute: int, ratio: float) -> bool:
    if count > absolute:
        return True
    return total >= MIN_POLICY_POPULATION and count / total > ratio


def _looks_transient(message: str) -> bool:
    text = message.lower()
    return any(
        token in text
        for token in (
            "timeout",
            "temporarily unavailable",
            "connection reset",
            "connection aborted",
            "429",
            "http 502",
            "http 503",
            "http 504",
        )
    )


def parse_optional_cve_id(value: object) -> str | None:
    try:
        return parse_cve_id(value)
    except Exception:
        return None
