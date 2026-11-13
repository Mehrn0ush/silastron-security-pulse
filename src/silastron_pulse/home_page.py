"""Pre-render the home page sections that do not need JavaScript.

The data status, overview, "What's changed" and "Recently added to CISA KEV"
sections are rendered at build time from the published JSON documents, so they
are indexable and readable without JavaScript. The browser script only refreshes
the time-dependent status (banner and ages) and runs the explorer.

The status wording mirrors preview/app.js `evaluateDataStatus`; a browser test
compares the two at a frozen clock.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from silastron_pulse.htmlbuild import Node, Text, el, fragment
from silastron_pulse.ids import CVE_ID_RE
from silastron_pulse.links import authoritative_href

MARKER = re.compile(r"<!--prerender:([a-z-]+)-->")
FAILED_ATTEMPT_CONCLUSIONS = ("failure", "timed_out", "cancelled", "startup_failure")
FIELD_LABELS = {
    "vendor_project": "Vendor",
    "product": "Product",
    "vulnerability_name": "Vulnerability name",
    "kev_date_added": "KEV added",
    "required_action": "Required action",
    "due_date": "Due date",
    "cve_state": "CVE state",
    "cve_title": "CVE title",
    "cve_description": "CVE description",
    "cve_date_updated": "CVE date updated",
    "cve_assigner": "CVE assigner",
    "cve_status": "CVE extraction status",
    "affected_products": "Affected products",
    "cvss_base_score": "CVSS base score",
    "cvss_base_severity": "CVSS severity",
    "completeness": "Extraction completeness",
    "remediation_item_count": "Extracted remediation items",
}
CATEGORY_LABELS = {
    "added_kev": "Newly added KEV entries",
    "removed_kev": "Removed KEV entries",
    "kev_update": "KEV record updates",
    "cve_update": "CVE information updates",
    "cvss_change": "CVSS changes",
    "completeness_change": "Extraction completeness changes",
    "enrichment_update": "Extracted remediation evidence",
}
CORE_CATEGORIES = {"kev_update", "cvss_change", "completeness_change"}
ENRICHMENT_CATEGORIES = {"enrichment_update", "remediation_update"}


# ---------------------------------------------------------------- formatting


def js_number(value: float) -> str:
    """Format like JavaScript's String(number)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if math.isfinite(value) and value == int(value):
            return str(int(value))
        return repr(value)
    return str(value)


def as_text(value: Any) -> str:
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return js_number(value)
    return str(value)


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def parse_instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_instant(value: Any) -> str:
    parsed = parse_instant(value)
    if parsed is None:
        return as_text(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_age(hours: float | None) -> str:
    if hours is None or not math.isfinite(hours):
        return "Unavailable"
    if abs(hours) < 1:
        return f"{_round_half_up(hours * 60)} minutes"
    if hours < 48:
        return f"{js_number(_round_half_up(hours * 10) / 10)} hours"
    return f"{js_number(_round_half_up(hours / 24 * 10) / 10)} days"


def format_count(value: Any) -> str:
    if value is None or value == "" or isinstance(value, bool):
        return as_text(value)
    try:
        number = float(value)
    except (TypeError, ValueError):
        return as_text(value)
    if not math.isfinite(number):
        return as_text(value)
    return f"{int(number):,}" if number == int(number) else as_text(value)


def hours_since(value: Any, now: datetime) -> float | None:
    parsed = parse_instant(value)
    return None if parsed is None else (now - parsed).total_seconds() / 3600


def format_instant_with_age(value: Any, now: datetime) -> str:
    hours = hours_since(value, now)
    if hours is None or hours < 0:
        return format_instant(value)
    return f"{format_instant(value)} ({format_age(hours)} ago)"


# ---------------------------------------------------------------- data status


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def attempt_is_valid(attempt: Any) -> bool:
    if attempt is None:
        return True
    return bool(
        isinstance(attempt, dict)
        and attempt.get("conclusion") in FAILED_ATTEMPT_CONCLUSIONS
        and re.fullmatch(r"[0-9]+", str(attempt.get("collect_run_id") or ""))
        and parse_instant(attempt.get("attempted_at")) is not None
    )


def attempt_outcome(attempt: dict[str, Any]) -> str:
    conclusion = str(attempt.get("conclusion"))
    return "failed" if conclusion == "failure" else conclusion.replace("_", " ")


def verification_is_valid(doc: Any) -> bool:
    if not isinstance(doc, dict) or not attempt_is_valid(doc.get("last_attempt")):
        return False
    if doc.get("kind") != "verification_status" or doc.get("schema_version") != "1.0.0":
        return False
    if doc.get("verified") is True:
        kev = _obj(doc.get("kev"))
        return bool(
            doc.get("verification_state") == "verified"
            and doc.get("verified_at")
            and kev.get("status") == "ok"
            and kev.get("content_sha256")
            and kev.get("retrieved_at")
        )
    return doc.get("verification_state") in ("failed", "rejected", "insufficient")


def source_validation_summary(verification: dict[str, Any]) -> str:
    validated: list[str] = []
    not_validated: list[str] = []
    for key, label in (("kev", "KEV"), ("cve", "CVE List V5"), ("nvd", "NVD")):
        view = _obj(verification.get(key))
        if view.get("validated") is True:
            validated.append(label)
        else:
            not_validated.append(f"{label} ({as_text(view.get('status'))})")
    text = f"Independently validated: {', '.join(validated) if validated else 'none'}."
    if not_validated:
        text += f" Not independently validated: {', '.join(not_validated)}."
    return text


def known_gaps(preview: Any, manifest: Any, verification: dict[str, Any] | None) -> list[str]:
    sources = _obj(_obj(preview).get("sources")) or _obj(_obj(manifest).get("sources"))
    gaps: list[str] = []
    for key in ("kev", "cve"):
        source = _obj(sources.get(key))
        if source.get("status") == "degraded" and source.get("error"):
            gaps.append(str(source["error"]))
    metrics = _obj((verification or {}).get("nvd_metrics"))
    total = _obj(manifest).get("record_count")
    if metrics and isinstance(metrics.get("ok"), (int, float)) and isinstance(total, (int, float)):
        if metrics["ok"] < total:
            gap = f"NVD enrichment covers {format_count(metrics['ok'])} of {format_count(total)} records"
            pending = metrics.get("pending_backfill")
            if isinstance(pending, (int, float)) and pending > 0:
                gap += f" ({format_count(pending)} pending backfill)"
            gaps.append(gap)
    return gaps


def evaluate_data_status(
    manifest: Any, preview: Any, publication_status: Any, verification: Any, now: datetime
) -> dict[str, Any]:
    manifest = _obj(manifest)
    preview_doc = _obj(preview)
    publication = _obj(publication_status)
    expected_hours = float(manifest.get("stale_after_hours") or 36)
    pub_state = publication.get("state")
    integrity = bool(pub_state and pub_state != "consistent")
    valid = verification if verification_is_valid(verification) else None
    verified = bool(valid and valid.get("verified") is True)
    outcome = preview_doc.get("status") or manifest.get("status")
    headline = "Verification evidence unavailable"
    message = (
        "Timestamps below come from the last published snapshot only. A later "
        "successful Collect that skipped publication is not visible here."
    )
    tone = "neutral"
    label = None
    verified_age = hours_since(valid.get("verified_at"), now) if verified and valid else None
    attempt = valid.get("last_attempt") if valid else None
    failed_attempt = None
    if attempt:
        attempted = parse_instant(attempt.get("attempted_at"))
        baseline = parse_instant(valid.get("verified_at")) if valid else None
        if attempted and (baseline is None or attempted > baseline):
            failed_attempt = attempt
    if integrity:
        headline = "Publication consistency problem"
        message = (
            "Published Pages data and persisted pulse-state may have diverged. Do not "
            "treat this page as an authoritative publication until an operator "
            "reconciles. " + as_text(publication.get("classification"))
        )
        tone = "unavailable"
    elif verification and not valid:
        headline = "Verification evidence is invalid"
        message = (
            "A verification-status document was present but failed validation. Do not "
            "treat snapshot age as proof of a recent successful collection."
        )
        tone = "unavailable"
    elif valid and valid.get("verification_state") == "failed":
        headline = "Collection verification failed"
        message = (
            valid.get("note") and as_text(valid.get("note"))
        ) or "The latest recorded collection did not independently validate KEV."
        tone = "unavailable"
    elif valid and valid.get("verification_state") == "rejected":
        headline = "Publication rejected"
        message = (valid.get("note") and as_text(valid.get("note"))) or "The latest Collect artifact was not published."
        tone = "unavailable"
    elif verified and failed_attempt and valid:
        headline = "Latest scheduled collection failed"
        label = "Collection failed"
        message = (
            f"Collect run {as_text(failed_attempt.get('collect_run_id'))} "
            f"{attempt_outcome(failed_attempt)} at {format_instant(failed_attempt.get('attempted_at'))}. "
            f"The data below was last independently verified "
            f"{format_instant_with_age(valid.get('verified_at'), now)} and has not been re-checked since."
        )
        tone = "stale"
    elif verified and valid and verified_age is not None and verified_age > expected_hours:
        headline = "Verification overdue"
        label = "Verification overdue"
        message = (
            f"No successful verification for {format_age(verified_age)} "
            f"(last {format_instant(valid.get('verified_at'))}). Collection is scheduled daily, "
            "so upstream changes since then may be missing."
        )
        tone = "stale"
    elif verified and valid:
        status_only = bool(valid.get("status_only"))
        headline = (
            "Unchanged catalog, independently verified"
            if status_only
            else "Published snapshot, independently verified"
        )
        prefix = ""
        if status_only:
            prefix = "Published snapshot content is unchanged. This is not a new vulnerability snapshot. "
        elif valid.get("publication_decision") == "publish":
            prefix = "A new snapshot was published. "
        message = prefix + source_validation_summary(valid)
        tone = "warn" if outcome == "degraded" else "ok"
        if tone == "warn":
            gaps = known_gaps(preview_doc, manifest, valid)
            if gaps:
                message += " Known gaps: " + "; ".join(gaps) + "."
    elif not valid and outcome == "degraded":
        headline = "Published snapshot"
        message = (
            "Collection of this snapshot succeeded with incomplete extracted inventories "
            "or unavailable enrichments. " + message
        )
        tone = "warn"
    last_collection = None
    if valid and (
        verified or valid.get("collection_outcome") in ("ok", "degraded")
    ):
        last_collection = valid.get("collection_completed_at")
    elif preview_doc.get("status") in ("ok", "degraded"):
        last_collection = preview_doc.get("collection_completed_at")
    return {
        "headline": headline,
        "message": message,
        "tone": tone,
        "label": label,
        "failed_attempt": failed_attempt,
        "verified": verified,
        "verification": valid,
        "last_verification_at": valid.get("verified_at") if verified and valid else None,
        "last_collection_at": last_collection,
    }


def banner_label(tone: str) -> str:
    return {
        "ok": "Data status",
        "neutral": "Data status",
        "stale": "Data status",
        "warn": "Degraded collection",
        "failed": "Failed",
    }.get(tone, "Unavailable")


def banner_node(tone: str, message: str, label: str | None = None) -> Node:
    return el(
        "p",
        {"id": "status-banner", "class": f"banner {tone}", "role": "status", "aria-live": "polite"},
        el("strong", {"class": "banner-label"}, label or banner_label(tone)),
        " " + message,
    )


# ---------------------------------------------------------------- row helpers


def meta_rows(items: list[tuple[str, Any]]) -> list[Node]:
    out: list[Node] = []
    for term, value in items:
        out.append(el("dt", None, term))
        out.append(el("dd", None, as_text(value)))
    return out


def card(term: str, value: Any, hint: str | None = None) -> Node:
    children: list[Node] = [el("h3", None, term), el("p", {"class": "value"}, as_text(value))]
    if hint:
        children.append(el("p", {"class": "hint"}, hint))
    return el("article", {"class": "card"}, *children)


def cve_link(value: Any) -> list[Node | str]:
    cve_id = value if isinstance(value, str) else ""
    if CVE_ID_RE.fullmatch(cve_id):
        return [el("a", {"href": f"#cve/{cve_id}"}, cve_id)]
    return [as_text(value)]


def source_links(links: Any) -> list[Node | str]:
    links = _obj(links)
    out: list[Node | str] = []
    for key, label in (
        ("cve_record", "CVE record"),
        ("kev_catalog", "KEV catalog"),
        ("cvelist_v5", "CVE List V5"),
        ("nvd", "NVD"),
    ):
        href = authoritative_href(links.get(key))
        if not href:
            out.append(el("span", None, f"{label} unavailable"))
            continue
        if out:
            out.append(" · ")
        out.append(
            el("a", {"href": href, "rel": "noopener noreferrer", "target": "_blank"}, label)
        )
    return out


def td(label: str, *children: Any, cls: str | None = None) -> Node:
    return el("td", {"data-label": label, "class": cls}, *children)


def completeness_label(row: dict[str, Any]) -> str:
    if row.get("completeness") == "unavailable":
        return "Unavailable enrichment"
    if row.get("completeness") == "partial" or row.get("partial"):
        omitted = []
        if row.get("omitted_product_count"):
            omitted.append(f"{as_text(row['omitted_product_count'])} products omitted")
        if row.get("omitted_version_count"):
            omitted.append(f"{as_text(row['omitted_version_count'])} versions omitted")
        if omitted:
            return f"Partial extracted inventory ({', '.join(omitted)})"
        return "Partial extracted inventory"
    return "Complete extracted inventory"


def cvss_band(row: dict[str, Any]) -> str | None:
    score = row.get("cvss_base_score")
    if row.get("severity_status") != "available" or score is None:
        return None
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(numeric):
        return None
    if numeric >= 9:
        return "critical"
    if numeric >= 7:
        return "high"
    if numeric >= 4:
        return "medium"
    return "low" if numeric > 0 else None


def epss_label(row: dict[str, Any], epss_disabled: bool) -> str:
    if epss_disabled or row.get("epss_status") == "disabled":
        return "Disabled"
    if row.get("epss_status") == "ok" and row.get("epss_score") is not None:
        return "Estimated " + as_text(row.get("epss_score"))
    return "Unavailable"


def recent_row(row: dict[str, Any], epss_disabled: bool) -> Node:
    pill = "pill ok"
    if row.get("completeness") == "partial" or row.get("partial"):
        pill = "pill warn"
    elif row.get("completeness") == "unavailable":
        pill = "pill danger"
    band = cvss_band(row)
    cvss_label = (
        as_text(row.get("cvss_base_score"))
        if row.get("severity_status") == "available" and row.get("cvss_base_score") is not None
        else "Unavailable"
    )
    product_children: list[Any] = [f"{as_text(row.get('vendor_project'))} / {as_text(row.get('product'))}"]
    if row.get("vulnerability_name"):
        product_children.append(el("div", {"class": "product-name"}, as_text(row.get("vulnerability_name"))))
    cvss_children: list[Any] = [cvss_label]
    if band:
        cvss_children.append(el("span", {"class": "severity-text"}, " " + band))
    return el(
        "tr",
        None,
        td("CVE", *cve_link(row.get("cve_id"))),
        td("Vendor / product", *product_children),
        td("KEV added", as_text(row.get("kev_date_added"))),
        td("Completeness", el("span", {"class": pill}, completeness_label(row))),
        td("CVSS", *cvss_children, cls=f"severity-{band}" if band else None),
        td("EPSS", epss_label(row, epss_disabled)),
        td("Sources", *source_links(row.get("links"))),
    )


# ---------------------------------------------------------------- comparison


def _side(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def field_pair(before: Any, after: Any, key: str) -> dict[str, Any] | None:
    b, a = _side(before), _side(after)
    has_b = bool(b is not None and key in b)
    has_a = bool(a is not None and key in a)
    if not has_b and not has_a:
        return None
    if has_b and has_a and b[key] == a[key]:
        return None
    return {
        "field": FIELD_LABELS.get(key, key),
        "previous": b[key] if has_b else "Not in previous published snapshot",
        "current": a[key] if has_a else "Removed from current published snapshot",
    }


def displayable_fields(row: dict[str, Any]) -> list[str]:
    before, after = _side(row.get("before")), _side(row.get("after"))
    declared = list(row["changed_fields"]) if isinstance(row.get("changed_fields"), list) else []
    keys = declared
    if not keys:
        for side in (before, after):
            for key in side or {}:
                if key not in keys:
                    keys.append(key)
    return [key for key in keys if field_pair(before, after, key) is not None]


def classify_comparison(comparison: Any) -> dict[str, Any]:
    empty = {"available": False, "added_count": None, "removed_count": None, "updated_count": None,
             "enrichment_count": None, "unresolved_count": None, "field_evidence": None,
             "added_rows": [], "removed_rows": [], "core_rows": [], "enrichment_rows": [],
             "unresolved_rows": [], "enrichment_sample": []}
    if not isinstance(comparison, dict) or comparison.get("available") is not True:
        return empty
    added, removed, core, enrichment_rows, unresolved = [], [], [], [], []
    for row in comparison.get("rows") or []:
        if not isinstance(row, dict):
            continue
        cats = row.get("categories") or []
        if "added_kev" in cats:
            added.append(row)
            continue
        if "removed_kev" in cats:
            removed.append(row)
            continue
        fields = displayable_fields(row)
        has_core = any(item in CORE_CATEGORIES for item in cats)
        enrichment_only = (
            any(item in ENRICHMENT_CATEGORIES for item in cats) and not has_core and "cve_update" not in cats
        )
        if enrichment_only:
            enrichment_rows.append(row)
        elif has_core or fields:
            core.append(row)
        else:
            unresolved.append(row)
    published_updated = comparison.get("updated_count")
    published_enrichment = comparison.get("enrichment_count")
    is_num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)  # noqa: E731
    if is_num(published_enrichment):
        updated = published_updated if is_num(published_updated) else len(core)
        enrichment, unresolved_count, evidence = published_enrichment, 0, "stored"
    elif is_num(published_updated) and published_updated == 0 and not unresolved:
        updated, enrichment, unresolved_count, evidence = 0, 0, 0, "stored"
    else:
        updated, enrichment = None, None
        unresolved_count = published_updated if is_num(published_updated) else len(unresolved)
        evidence = "unavailable"
    if isinstance(comparison.get("enrichment_sample"), list):
        sample = [item for item in comparison["enrichment_sample"] if isinstance(item, str)]
    else:
        sample = [str(row.get("cve_id")) for row in enrichment_rows]
    return {
        "available": True, "added_count": comparison.get("added_count"),
        "removed_count": comparison.get("removed_count"), "updated_count": updated,
        "enrichment_count": enrichment, "unresolved_count": unresolved_count,
        "field_evidence": evidence, "added_rows": added, "removed_rows": removed,
        "core_rows": core, "enrichment_rows": enrichment_rows, "unresolved_rows": unresolved,
        "enrichment_sample": sample[:8],
    }


def changed_fields_label(row: dict[str, Any]) -> str:
    cats = row.get("categories") or []
    if "added_kev" in cats:
        return "New in current published snapshot"
    if "removed_kev" in cats:
        return "Removed from current published snapshot"
    fields = displayable_fields(row)
    if not fields:
        return "Stored values are unchanged"
    return ", ".join(FIELD_LABELS.get(item, item) for item in fields)


def before_after(row: dict[str, Any]) -> Node | None:
    keys = row["changed_fields"] if isinstance(row.get("changed_fields"), list) and row["changed_fields"] else displayable_fields(row)
    pairs = [p for p in (field_pair(row.get("before"), row.get("after"), k) for k in keys) if p]
    if not pairs:
        return None
    body = [
        el("tr", None, el("th", {"scope": "row"}, p["field"]), el("td", None, as_text(p["previous"])),
           el("td", None, as_text(p["current"])))
        for p in pairs
    ]
    return el(
        "details", None, el("summary", None, "Before and after"),
        el("table", {"class": "diff-table"},
           el("caption", {"class": "visually-hidden"}, f"Published values before and after for {as_text(row.get('cve_id'))}"),
           el("thead", None, el("tr", None, *[el("th", {"scope": "col"}, h) for h in ("Field", "Previous published", "Current published")])),
           el("tbody", None, *body)),
    )


def change_group(title: str, rows: list[dict[str, Any]]) -> Node | None:
    if not rows:
        return None
    body = []
    for row in rows:
        ba = before_after(row)
        body.append(
            el("tr", None,
               td("CVE", *cve_link(row.get("cve_id"))),
               td("Categories", "; ".join(CATEGORY_LABELS.get(c, c) for c in (row.get("categories") or []))),
               td("Changed fields", changed_fields_label(row)),
               td("Sources", *source_links(row.get("links"))),
               td("Details", ba if ba else changed_fields_label(row)))
        )
    return el(
        "details", None, el("summary", None, f"{title} ({len(rows)})"),
        el("div", {"class": "table-wrap"},
           el("table", None, el("caption", {"class": "visually-hidden"}, title),
              el("thead", None, el("tr", None, *[el("th", {"scope": "col"}, h) for h in ("CVE", "Categories", "Changed fields", "Sources", "Details")])),
              el("tbody", None, *body))),
    )


def _count_item(label: str, value: Any) -> Node:
    return el("li", None, el("strong", None, "Unavailable" if value is None else js_number(value)), " " + label)


def comparison_section(comparison: Any) -> tuple[str, list[Node]]:
    classified = classify_comparison(comparison)
    if not classified["available"]:
        return (
            "No comparison available. Baseline unavailable because no immediately preceding "
            "published snapshot was retained or the previous published snapshot is incompatible.",
            [el("p", {"class": "empty-state"}, "No comparison available")],
        )
    comparison = _obj(comparison)
    note = (
        f"Published-to-published comparison against snapshot {as_text(comparison.get('compared_to_snapshot_id'))} "
        f"generated {format_instant(comparison.get('compared_to_generated_at'))}. Retrieval timestamps are not "
        "treated as vulnerability updates. Collect-time candidate diffs are not shown here. Newly extracted "
        "remediation is not counted as a KEV, CVE, CVSS, or completeness update."
    )
    if comparison.get("truncated"):
        note += (
            " Record-level rows are a bounded subset. Truncation is not proof that omitted updates "
            "are enrichment or that core field changes are absent."
        )
    items = [
        _count_item("newly added to KEV", classified["added_count"]),
        _count_item("removed from KEV", classified["removed_count"]),
    ]
    if classified["field_evidence"] == "unavailable":
        items.append(_count_item(
            "confirmed KEV, CVE, CVSS, or completeness field changes. This published comparison listed updates "
            "without stored field-level before/after values, so that count is unavailable rather than zero.",
            classified["updated_count"]))
        items.append(_count_item(
            "confirmed newly extracted remediation changes. Missing field-level diffs are not treated as enrichment.",
            classified["enrichment_count"]))
    else:
        items.append(_count_item("records with KEV, CVE, CVSS, or completeness field changes", classified["updated_count"]))
        items.append(_count_item(
            "existing records that now include extracted remediation evidence. That is not a change to those "
            "CVEs' upstream vulnerability facts.", classified["enrichment_count"]))
    body: list[Node] = [el("ul", {"class": "change-summary"}, *items)]
    for title, key in (("Newly added KEV entries", "added_rows"), ("Removed KEV entries", "removed_rows"),
                       ("Records with field-level updates", "core_rows")):
        group = change_group(title, classified[key])
        if group:
            body.append(group)
    if classified["unresolved_count"]:
        body.append(el("p", {"class": "empty-state"},
            f"{js_number(classified['unresolved_count'])} listed updates have no stored field-level before/after "
            "values. They are not shown as individual rows, and missing values are not treated as remediation "
            "enrichment or as confirmed core vulnerability changes."))
    if classified["enrichment_count"]:
        parts: list[Node] = [
            el("summary", None, f"Extracted remediation evidence newly present ({js_number(classified['enrichment_count'])})"),
            el("p", None, "These IDs were already in the previous published snapshot. The collector now extracts CNA "
               "solutions, workarounds, vendor advisories, or KEV required actions. That enrichment is not a newly "
               "changed upstream KEV/CVE/CVSS fact."),
        ]
        if classified["enrichment_sample"]:
            parts.append(el("p", None, "Examples: " + ", ".join(classified["enrichment_sample"])))
        body.append(el("details", None, *parts))
    if not (classified["added_rows"] or classified["removed_rows"] or classified["core_rows"]
            or classified["unresolved_count"] or classified["enrichment_count"]):
        body.append(el("p", {"class": "empty-state"}, "No published-to-published record changes."))
    return note, body


# ---------------------------------------------------------------- sections


def _epss_note(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    if "#Usage-Agreement" not in value and "FIRST EPSS Usage Agreement" not in value:
        return value
    return (
        "EPSS is disabled in this snapshot. FIRST currently publishes scores for public use "
        "with requested attribution (https://www.first.org/epss/faq). That is not a "
        "redistribution license for this public JSON feed. The published snapshot still "
        "contains a historic Usage Agreement URL that FIRST removed."
    )


def render_sections(
    *, manifest: Any, preview: Any, publication_status: Any, verification: Any, now: datetime
) -> dict[str, str]:
    """Return the HTML for each prerender slot, keyed by slot name."""
    empty_recent = el("tr", None, el("td", {"colspan": 7}, "No rows to display."))
    slots: dict[str, str] = {}

    def finish(**kw: Any) -> dict[str, str]:
        for key, value in kw.items():
            slots[key] = fragment(value)
        return slots

    base = {
        "data-status-summary": "Waiting for published data status.",
        "data-status-details": [],
        "overview-cards": [],
        "changes-note": "",
        "changes-body": [],
        "recent-note": "",
        "recent-body": [],
        "status-details": [],
        "technical-details": [],
    }
    note, body = comparison_section(None)
    if not isinstance(manifest, dict):
        return finish(**{**base,
            "status-banner": banner_node("unavailable", "No published snapshot is available. This preview is not a live intelligence feed."),
            "recent-note": "Snapshot unavailable.", "recent-body": [empty_recent],
            "changes-note": note, "changes-body": body})
    publication = manifest.get("publication_state") or manifest.get("status")
    if publication == "not_published" or manifest.get("status") == "unpublished":
        return finish(**{**base,
            "status-banner": banner_node("unavailable", as_text(manifest.get("message")) if manifest.get("message") else
                "Publication is disabled until source contracts and security review are approved."),
            "status-details": meta_rows([("Status", "Not published"), ("Generated at", manifest.get("generated_at")),
                                         ("Information state", "unavailable")]),
            "recent-note": "No approved snapshot has been published.",
            "recent-body": [el("tr", None, el("td", {"colspan": 7}, "No rows to display."))],
            "changes-note": note, "changes-body": body})

    preview_doc = _obj(preview)
    generated = manifest.get("snapshot_generated_at") or manifest.get("generated_at")
    generated_at = parse_instant(generated)
    age_hours = (now - generated_at).total_seconds() / 3600 if generated_at else None
    invalid_time = generated_at is None or (age_hours is not None and age_hours < 0)
    outcome = manifest.get("status")
    status = evaluate_data_status(manifest, preview, publication_status, verification, now)
    if invalid_time:
        banner = banner_node("unavailable", "Snapshot timestamps are invalid. Do not treat this page as intelligence.")
    elif outcome == "failed":
        banner = banner_node("unavailable", "Collection failed. No successful snapshot is shown.")
    else:
        banner = banner_node(status["tone"], status["message"], status["label"])

    summary = _obj(preview_doc.get("summary"))
    sources = _obj(preview_doc.get("sources")) or _obj(manifest.get("sources"))
    kev, cve, epss = _obj(sources.get("kev")), _obj(sources.get("cve")), _obj(sources.get("epss"))
    epss_disabled = bool(summary.get("epss_enabled") is False or epss.get("status") == "disabled")
    comparison = preview_doc.get("publication_comparison")
    classified = classify_comparison(comparison)
    available = classified["available"]
    no_cmp = "No comparison available"
    cards = [
        card("Known Exploited CVEs", manifest.get("record_count"),
             "CISA KEV entries in this published snapshot. Not a count of exposed systems."),
        card("New in KEV", no_cmp if not available or classified["added_count"] in (None, "") else classified["added_count"],
             "Added since the previous published snapshot. Not CISA dateAdded recency." if available
             else "Baseline unavailable. This is not zero new entries."),
    ]
    if not available:
        upd_value, upd_hint = no_cmp, "Baseline unavailable. This is not zero updates."
    elif classified["field_evidence"] == "unavailable":
        upd_value = "Field-level evidence not stored"
        upd_hint = ("This published comparison lists updates but did not store displayable before/after field "
                    "diffs. That is not zero updates and is not confirmed enrichment.")
    else:
        upd_value = no_cmp if classified["updated_count"] in (None, "") else classified["updated_count"]
        upd_hint = ("KEV, CVE, CVSS, or completeness field changes versus the previous published snapshot. "
                    "Newly extracted remediation is counted separately.")
    cards.append(card("Vulnerability Updates", upd_value, upd_hint))
    cards.append(card("Published snapshot", format_instant(manifest.get("snapshot_generated_at")),
        "This is the last published snapshot time, not last verification. Snapshot age is not proof that "
        "collection stopped or succeeded."))

    ver = status["verification"]
    attempt = status["failed_attempt"]
    kev_status = _obj(ver.get("kev") if ver else None) or kev
    cve_status = _obj(ver.get("cve") if ver else None) or cve
    nvd_status = _obj(ver.get("nvd") if ver else None) or _obj(sources.get("nvd"))
    data_rows: list[tuple[str, Any]] = [
        ("Last successful verification",
         format_instant_with_age(status["last_verification_at"], now) if status["verified"] else "Unavailable"),
    ]
    if attempt:
        data_rows.append(("Latest collection attempt",
            f"Collection {attempt_outcome(attempt)} {format_instant_with_age(attempt.get('attempted_at'), now)}, "
            f"run {as_text(attempt.get('collect_run_id'))}"))
    data_rows += [
        ("Last successful collection",
         format_instant_with_age(status["last_collection_at"], now) if status["last_collection_at"] else "Unavailable"),
        ("Last published snapshot", format_instant_with_age(manifest.get("snapshot_generated_at"), now)),
        ("Publication consistency", _obj(publication_status).get("state") or "Unavailable"),
        ("Publication decision", as_text(ver.get("publication_decision")) if ver else "Unavailable"),
        ("KEV source status", kev_status.get("status")),
        ("KEV retrieved at", format_instant(kev_status.get("retrieved_at"))),
        ("KEV upstream update", format_instant(kev_status.get("source_updated_at") or kev.get("source_published_at"))),
        ("CVE List V5 status", cve_status.get("status")),
        ("CVE retrieved at", format_instant(cve_status.get("retrieved_at"))),
        ("NVD status", nvd_status.get("status") or "unavailable"),
        ("NVD retrieved at", format_instant(nvd_status.get("retrieved_at"))),
    ]
    meta: list[tuple[str, Any]] = []
    pub_doc = _obj(publication_status)
    if pub_doc.get("state") and pub_doc.get("state") != "consistent":
        meta += [("Publication state", pub_doc.get("state")), ("Collect run ID", pub_doc.get("collect_run_id")),
                 ("Snapshot ID", pub_doc.get("snapshot_id")), ("Manifest digest", pub_doc.get("manifest_digest")),
                 ("Deployment run", pub_doc.get("deployment_run_id"))]
    meta += [
        ("Collection outcome", outcome),
        ("Published snapshot age", format_age(age_hours)),
        ("Snapshot age is not verification",
         "Age shows when snapshot content last changed, not when sources were last checked."),
        ("Snapshot generated at", format_instant(manifest.get("snapshot_generated_at"))),
        ("Published at", format_instant(manifest.get("generated_at"))),
        ("Collection started at", format_instant(preview_doc.get("collection_started_at"))),
        ("Collection completed at", format_instant(preview_doc.get("collection_completed_at"))),
        ("Record count", format_count(manifest.get("record_count"))),
        ("Complete extracted inventories", format_count(summary.get("complete_records"))),
        ("Partial extracted inventories", format_count(summary.get("partial_records"))),
        ("Unavailable enrichments", format_count(summary.get("unavailable_records"))),
        ("KEV source published at", format_instant(kev.get("source_published_at"))),
        ("CVE source updated at", format_instant(cve.get("source_updated_at"))),
        ("EPSS source status", epss.get("status")),
        ("EPSS source note", _epss_note(epss.get("error") or epss.get("notes"))),
        ("EPSS redistribution", "Disabled is not a zero probability." if epss_disabled else epss.get("status")),
    ]
    if preview_doc.get("note"):
        meta.append(("Consumer note", preview_doc.get("note")))
    technical = [
        ("Snapshot ID", manifest.get("snapshot_id")), ("Schema version", manifest.get("schema_version")),
        ("Preview schema version", preview_doc.get("schema_version")),
        ("KEV content digest", kev.get("content_sha256")), ("KEV source revision", kev.get("source_revision")),
        ("CVE content digest", cve.get("content_sha256")), ("CVE source revision", cve.get("source_revision")),
        ("CVE strategy", summary.get("cve_strategy")),
        ("Compared to published snapshot", _obj(comparison).get("compared_to_snapshot_id")),
        ("Changes recorded at collection", "yes" if preview_doc.get("changes_available") else "no"),
    ]
    common = {
        "status-banner": banner,
        "data-status-summary": f"{status['headline']}. {status['message']}",
        "data-status-details": meta_rows(data_rows),
        "overview-cards": cards,
        "status-details": meta_rows(meta),
        "technical-details": meta_rows(technical),
    }
    if not preview_doc:
        return finish(**{**base, **common, "recent-note": "Preview document unavailable.",
                         "recent-body": [el("tr", None, el("td", {"colspan": 7}, "No rows to display."))],
                         "changes-note": note, "changes-body": body})
    cmp_note, cmp_body = comparison_section(comparison)
    recent = [r for r in preview_doc.get("recent_kev_additions") or [] if isinstance(r, dict)]
    recent_note = (
        "CISA dateAdded recency for this published snapshot, not a published-to-published diff. KEV added is the "
        "CISA date_added, not collection or publication time. EPSS: "
        + ("disabled" if epss_disabled else as_text(epss.get("status")))
    )
    rows = [recent_row(r, epss_disabled) for r in recent] or [
        el("tr", None, el("td", {"colspan": 7}, "No recently added KEV entries are available in this snapshot."))
    ]
    return finish(**{**base, **common, "changes-note": cmp_note, "changes-body": cmp_body,
                     "recent-note": recent_note, "recent-body": rows})


# ---------------------------------------------------------------- build


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def fill_template(template: str, slots: dict[str, str]) -> str:
    seen: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in slots:
            raise ValueError(f"unknown prerender slot: {name}")
        seen.add(name)
        return slots[name]

    out = MARKER.sub(replace, template)
    missing = sorted(set(slots) - seen)
    if missing:
        raise ValueError(f"template has no marker for slots: {', '.join(missing)}")
    return out


def build_home_page(*, published_dir: Path, template_path: Path, site_dir: Path, now: datetime) -> None:
    slots = render_sections(
        manifest=_load(published_dir / "manifest.json"),
        preview=_load(published_dir / "preview.json"),
        publication_status=_load(published_dir / "publication-status.json"),
        verification=_load(published_dir / "verification-status.json"),
        now=now,
    )
    slots["built-at"] = fragment(Text(now.strftime("%Y-%m-%d %H:%M:%S UTC")))
    page = fill_template(template_path.read_text(encoding="utf-8"), slots)
    (site_dir / "index.html").write_text(page, encoding="utf-8")
