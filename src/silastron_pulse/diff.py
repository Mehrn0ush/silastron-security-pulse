"""Meaningful change detection. Retrieval timestamps alone are not changes."""

from __future__ import annotations

from typing import Any, Mapping

from silastron_pulse.adapters.cve import cve_record_from_dict
from silastron_pulse.models import (
    ChangeSet,
    EpssRecord,
    KevRecord,
    PulseEntry,
    Signals,
)

SOURCE_IDENTITY_KEYS = (
    "id",
    "status",
    "source_revision",
    "content_sha256",
    "license",
    "parser_version",
    "schema_version",
)
COMPARED_SOURCES = ("kev", "cve")


def source_identity(meta: Mapping[str, Any] | None) -> dict[str, Any]:
    payload = meta or {}
    return {key: payload.get(key) for key in SOURCE_IDENTITY_KEYS}


def detect_source_metadata_changes(
    previous_sources: Mapping[str, Any] | None,
    current_sources: Mapping[str, Any] | None,
) -> list[str]:
    previous = previous_sources or {}
    current = current_sources or {}
    changed: list[str] = []
    for name in COMPARED_SOURCES:
        previous_meta = previous.get(name) if isinstance(previous.get(name), dict) else {}
        current_meta = current.get(name) if isinstance(current.get(name), dict) else {}
        if source_identity(previous_meta) != source_identity(current_meta):
            changed.append(name)
    return changed


def detect_changes(
    previous_entries: dict[str, PulseEntry],
    current_entries: dict[str, PulseEntry],
    *,
    previous_sources: Mapping[str, Any] | None = None,
    current_sources: Mapping[str, Any] | None = None,
) -> ChangeSet:
    changes = ChangeSet()
    for cve_id, current in sorted(current_entries.items()):
        previous = previous_entries.get(cve_id)
        if previous is None:
            changes.new_kev_entries.append(cve_id)
            continue
        if previous.kev.comparable() != current.kev.comparable():
            changes.updated_kev_entries.append(cve_id)
        if previous.cve.comparable() != current.cve.comparable():
            changes.changed_cve_information.append(cve_id)
        if previous.epss.comparable() != current.epss.comparable():
            if current.epss.status == "ok" or previous.epss.status == "ok":
                changes.epss_changes.append(cve_id)
    for cve_id in sorted(previous_entries):
        if cve_id not in current_entries:
            changes.removed_kev_entries.append(cve_id)
    if previous_sources is not None or current_sources is not None:
        changes.source_metadata_changes = detect_source_metadata_changes(
            previous_sources, current_sources
        )
    return changes


DISPLAY_FIELD_KEYS = (
    "vendor_project",
    "product",
    "vulnerability_name",
    "kev_date_added",
    "required_action",
    "due_date",
    "cve_state",
    "cve_title",
    "cve_description",
    "cve_date_updated",
    "cve_assigner",
    "cve_status",
    "affected_products",
    "cvss_base_score",
    "cvss_base_severity",
    "completeness",
    "remediation_item_count",
)

CORE_ROW_CATEGORIES = frozenset({"kev_update", "cvss_change", "completeness_change"})
ENRICHMENT_ROW_CATEGORIES = frozenset({"enrichment_update", "remediation_update"})
ENRICHMENT_SAMPLE_LIMIT = 8

NO_PREVIOUS_PUBLISHED = "no_previous_published_snapshot"
INCOMPATIBLE_PUBLISHED = "incompatible_published_snapshot"
SAME_SNAPSHOT = "same_published_snapshot"


def entries_from_snapshot(payload: Mapping[str, Any]) -> dict[str, PulseEntry]:
    """Rebuild comparable entries from snapshot JSON. Retrieval times are ignored."""
    entries: dict[str, PulseEntry] = {}
    records = payload.get("records")
    if not isinstance(records, list):
        raise TypeError("snapshot records must be a list")
    for item in records:
        if not isinstance(item, dict):
            raise TypeError("snapshot record must be an object")
        kev = item["kev"]
        cve = item["cve"]
        epss = item["epss"]
        if not isinstance(kev, dict) or not isinstance(cve, dict) or not isinstance(epss, dict):
            raise TypeError("snapshot record kev, cve, and epss must be objects")
        kev_record = KevRecord(
            cve_id=kev["cve_id"],
            vendor_project=kev["vendor_project"],
            product=kev["product"],
            vulnerability_name=kev["vulnerability_name"],
            date_added=kev["date_added"],
            short_description=kev["short_description"],
            required_action=kev["required_action"],
            due_date=kev["due_date"],
            known_ransomware_campaign_use=kev.get("known_ransomware_campaign_use"),
            forensic_triage=kev.get("forensic_triage"),
            notes=kev.get("notes"),
            cwes=list(kev.get("cwes") or []),
            source_url=kev.get("source_url") or "",
            record_sha256=kev.get("record_sha256") or "",
            truncated_fields=tuple(kev.get("truncated_fields") or ()),
            cwes_incomplete=bool(kev.get("cwes_incomplete")),
        )
        cve_record = cve_record_from_dict(cve, cached=bool(cve.get("cached")))
        epss_record = EpssRecord(
            status=epss.get("status") or "unavailable",
            cve_id=epss.get("cve_id") or item["cve_id"],
            score=epss.get("score"),
            percentile=epss.get("percentile"),
            score_date=epss.get("score_date"),
            notes=epss.get("notes"),
        )
        signals_raw = item.get("signals") or {}
        if not isinstance(signals_raw, dict):
            signals_raw = {}
        entries[item["cve_id"]] = PulseEntry(
            cve_id=item["cve_id"],
            kev=kev_record,
            cve=cve_record,
            epss=epss_record,
            signals=Signals(
                confirmed_exploitation=signals_raw.get("confirmed_exploitation") or {},
                estimated_exploitation_probability=signals_raw.get(
                    "estimated_exploitation_probability"
                )
                or {},
                vulnerability_severity=signals_raw.get("vulnerability_severity") or {},
                product_affectedness=signals_raw.get("product_affectedness") or {},
                deployment_exposure=signals_raw.get("deployment_exposure") or {},
            ),
            links=item.get("links") or {},
        )
    return entries


def affected_products_label(entry: PulseEntry) -> str | None:
    products = entry.cve.products
    if not products:
        return None
    parts: list[str] = []
    limit = 8
    for item in products[:limit]:
        name = "/".join(part for part in (item.vendor, item.product) if part) or "unspecified product"
        versions = list(item.versions or [])
        if versions:
            shown = ", ".join(versions[:4])
            extra = f" (+{len(versions) - 4} versions)" if len(versions) > 4 else ""
            parts.append(f"{name} [{shown}{extra}]")
        else:
            parts.append(name)
    if len(products) > limit:
        parts.append(f"+{len(products) - limit} more products")
    return "; ".join(parts)


def display_fields(entry: PulseEntry) -> dict[str, Any]:
    severity = entry.cve.severity
    return {
        "vendor_project": entry.kev.vendor_project,
        "product": entry.kev.product,
        "vulnerability_name": entry.kev.vulnerability_name,
        "kev_date_added": entry.kev.date_added,
        "required_action": entry.kev.required_action,
        "due_date": entry.kev.due_date,
        "cve_state": entry.cve.state,
        "cve_title": entry.cve.title,
        "cve_description": entry.cve.description,
        "cve_date_updated": entry.cve.date_updated,
        "cve_assigner": entry.cve.assigner_short_name,
        "cve_status": entry.cve.status,
        "affected_products": affected_products_label(entry),
        "cvss_base_score": severity.base_score if severity else None,
        "cvss_base_severity": severity.base_severity if severity else None,
        "completeness": entry.completeness(),
        "remediation_item_count": len(entry.cve.remediation_items),
    }


def _changed_display_fields(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    keys = list(DISPLAY_FIELD_KEYS)
    for key in before.keys() | after.keys():
        if key not in keys:
            keys.append(key)
    return [key for key in keys if before.get(key) != after.get(key)]


def _side_dict(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _row_displayable_fields(row: Mapping[str, Any]) -> list[str]:
    before = _side_dict(row.get("before"))
    after = _side_dict(row.get("after"))
    declared = row.get("changed_fields") if isinstance(row.get("changed_fields"), list) else []
    keys = [key for key in declared if isinstance(key, str)]
    if not keys:
        keys = list(dict.fromkeys([*(before or {}), *(after or {})]))
    changed: list[str] = []
    for key in keys:
        has_before = before is not None and key in before
        has_after = after is not None and key in after
        if not has_before and not has_after:
            continue
        if has_before and has_after and before[key] == after[key]:
            continue
        changed.append(key)
    return changed


def _empty_presentation() -> dict[str, Any]:
    return {
        "available": False,
        "added_count": None,
        "removed_count": None,
        "updated_count": None,
        "enrichment_count": None,
        "unresolved_count": None,
        "field_evidence": None,
        "added_rows": [],
        "removed_rows": [],
        "core_rows": [],
        "enrichment_rows": [],
        "unresolved_rows": [],
        "enrichment_sample": [],
    }


def interpret_publication_comparison(
    comparison: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Derive presentation counts from a stored published comparison.

    Missing field-level diffs are not treated as confirmed enrichment. A
    truncated legacy comparison cannot prove the unpublished remainder is
    remediation-only or that core updates are absent.
    """
    if not comparison or comparison.get("available") is not True:
        return _empty_presentation()
    added_rows: list[dict[str, Any]] = []
    removed_rows: list[dict[str, Any]] = []
    core_rows: list[dict[str, Any]] = []
    enrichment_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    for raw in comparison.get("rows") or []:
        if not isinstance(raw, dict):
            continue
        cats = {item for item in (raw.get("categories") or []) if isinstance(item, str)}
        if "added_kev" in cats:
            added_rows.append(dict(raw))
            continue
        if "removed_kev" in cats:
            removed_rows.append(dict(raw))
            continue
        fields = _row_displayable_fields(raw)
        has_core_cat = bool(cats & CORE_ROW_CATEGORIES)
        enrichment_only = (
            bool(cats & ENRICHMENT_ROW_CATEGORIES)
            and not has_core_cat
            and "cve_update" not in cats
        )
        if enrichment_only:
            enrichment_rows.append(dict(raw))
        elif has_core_cat or fields:
            core_rows.append(dict(raw))
        else:
            unresolved_rows.append(dict(raw))
    published_updated = comparison.get("updated_count")
    published_enrichment = comparison.get("enrichment_count")
    if isinstance(published_enrichment, int):
        updated = published_updated if isinstance(published_updated, int) else len(core_rows)
        enrichment = published_enrichment
        unresolved_count = 0
        field_evidence = "stored"
    elif isinstance(published_updated, int) and published_updated == 0 and not unresolved_rows:
        updated = 0
        enrichment = 0
        unresolved_count = 0
        field_evidence = "stored"
    else:
        updated = None
        enrichment = None
        unresolved_count = (
            published_updated if isinstance(published_updated, int) else len(unresolved_rows)
        )
        field_evidence = "unavailable"
    sample = comparison.get("enrichment_sample")
    if not isinstance(sample, list):
        sample = [row.get("cve_id") for row in enrichment_rows]
    return {
        "available": True,
        "added_count": comparison.get("added_count"),
        "removed_count": comparison.get("removed_count"),
        "updated_count": updated,
        "enrichment_count": enrichment,
        "unresolved_count": unresolved_count,
        "field_evidence": field_evidence,
        "added_rows": added_rows,
        "removed_rows": removed_rows,
        "core_rows": core_rows,
        "enrichment_rows": enrichment_rows,
        "unresolved_rows": unresolved_rows,
        "enrichment_sample": [item for item in sample if isinstance(item, str)][:ENRICHMENT_SAMPLE_LIMIT],
    }


def _unavailable_publication_comparison(
    current: Mapping[str, Any] | None,
    *,
    reason: str,
    compared_to_snapshot_id: str | None = None,
    compared_to_generated_at: str | None = None,
) -> dict[str, Any]:
    current = current or {}
    return {
        "available": False,
        "reason": reason,
        "compared_to_snapshot_id": compared_to_snapshot_id,
        "compared_to_generated_at": compared_to_generated_at,
        "current_snapshot_id": current.get("snapshot_id"),
        "current_generated_at": current.get("generated_at"),
        "added_count": None,
        "removed_count": None,
        "updated_count": None,
        "enrichment_count": None,
        "enrichment_sample": [],
        "truncated": False,
        "rows": [],
    }


def _change_row(
    *,
    cve_id: str,
    categories: list[str],
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    changed_fields: list[str],
    links: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "categories": list(categories),
        "changed_fields": list(changed_fields),
        "before": before,
        "after": after,
        "links": {
            "cve_record": (links or {}).get("cve_record"),
            "kev_catalog": (links or {}).get("kev_catalog"),
            "cvelist_v5": (links or {}).get("cvelist_v5"),
        },
    }


def publication_comparison(
    previous_published: Mapping[str, Any] | None,
    current_published: Mapping[str, Any],
    *,
    max_rows: int = 50,
) -> dict[str, Any]:
    """Published-to-published field diff. Never reads collect-time changes."""
    if previous_published is None:
        return _unavailable_publication_comparison(
            current_published, reason=NO_PREVIOUS_PUBLISHED
        )
    previous_id = previous_published.get("snapshot_id")
    current_id = current_published.get("snapshot_id")
    if not previous_id or previous_id == current_id:
        return _unavailable_publication_comparison(
            current_published,
            reason=SAME_SNAPSHOT,
            compared_to_snapshot_id=previous_id if isinstance(previous_id, str) else None,
            compared_to_generated_at=previous_published.get("generated_at")
            if isinstance(previous_published.get("generated_at"), str)
            else None,
        )
    try:
        previous_entries = entries_from_snapshot(previous_published)
        current_entries = entries_from_snapshot(current_published)
    except (KeyError, TypeError, ValueError):
        return _unavailable_publication_comparison(
            current_published,
            reason=INCOMPATIBLE_PUBLISHED,
            compared_to_snapshot_id=previous_id if isinstance(previous_id, str) else None,
            compared_to_generated_at=previous_published.get("generated_at")
            if isinstance(previous_published.get("generated_at"), str)
            else None,
        )
    changes = detect_changes(
        previous_entries,
        current_entries,
        previous_sources=previous_published.get("sources"),
        current_sources=current_published.get("sources"),
    )
    added_count = len(changes.new_kev_entries)
    removed_count = len(changes.removed_kev_entries)
    core_count = 0
    rows: list[dict[str, Any]] = []
    for cve_id in changes.new_kev_entries:
        current = current_entries[cve_id]
        rows.append(
            _change_row(
                cve_id=cve_id,
                categories=["added_kev"],
                before=None,
                after=display_fields(current),
                changed_fields=[],
                links=current.links,
            )
        )
    for cve_id in changes.removed_kev_entries:
        previous = previous_entries[cve_id]
        rows.append(
            _change_row(
                cve_id=cve_id,
                categories=["removed_kev"],
                before=display_fields(previous),
                after=None,
                changed_fields=[],
                links=previous.links,
            )
        )
    updated_ids = sorted(
        set(changes.updated_kev_entries) | set(changes.changed_cve_information)
    )
    enrichment_ids: list[str] = []
    for cve_id in updated_ids:
        previous = previous_entries[cve_id]
        current = current_entries[cve_id]
        kev_changed = previous.kev.comparable() != current.kev.comparable()
        cve_core_changed = previous.cve.core_comparable() != current.cve.core_comparable()
        rem_changed = [item.to_dict() for item in previous.cve.remediation_items] != [
            item.to_dict() for item in current.cve.remediation_items
        ]
        if not kev_changed and not cve_core_changed:
            if rem_changed:
                enrichment_ids.append(cve_id)
            continue
        before = display_fields(previous)
        after = display_fields(current)
        changed_fields = _changed_display_fields(before, after)
        categories: list[str] = []
        if kev_changed:
            categories.append("kev_update")
        if cve_core_changed:
            categories.append("cve_update")
        if before["cvss_base_score"] != after["cvss_base_score"] or (
            before["cvss_base_severity"] != after["cvss_base_severity"]
        ):
            categories.append("cvss_change")
        if before["completeness"] != after["completeness"]:
            categories.append("completeness_change")
        if not categories:
            if rem_changed:
                enrichment_ids.append(cve_id)
            continue
        rows.append(
            _change_row(
                cve_id=cve_id,
                categories=categories,
                before=before,
                after=after,
                changed_fields=changed_fields,
                links=current.links,
            )
        )
        core_count += 1
    # Aggregate counts cover every record. The display window is applied after.
    limit = max(0, int(max_rows))
    return {
        "available": True,
        "reason": None,
        "compared_to_snapshot_id": previous_id,
        "compared_to_generated_at": previous_published.get("generated_at"),
        "current_snapshot_id": current_id,
        "current_generated_at": current_published.get("generated_at"),
        "added_count": added_count,
        "removed_count": removed_count,
        "updated_count": core_count,
        "enrichment_count": len(enrichment_ids),
        "enrichment_sample": enrichment_ids[:ENRICHMENT_SAMPLE_LIMIT],
        "truncated": len(rows) > limit,
        "rows": rows[:limit],
    }
