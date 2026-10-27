"""Evidence-based KEV catalog checks for publication.

Publication does not re-fetch CISA. It re-parses the KEV catalog persisted
during the bound Collect run and requires candidate records to match that
catalog exactly. Candidate metadata hashes are not independent proof.

A change versus the previously published snapshot is legitimate only when the
candidate still matches its Collect-time catalog. Same-digest KEV identity
with ID or material field drift is treated as corruption, not a CISA update.
"""

from __future__ import annotations

from typing import Any

from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import CVE_ID_RE

MATERIAL_KEV_FIELDS = (
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "short_description",
    "required_action",
    "due_date",
    "known_ransomware_campaign_use",
    "notes",
    "cwes",
)


def verify_catalog_structure(catalog: object, meta: object) -> dict[str, Any]:
    """Return a normalized catalog after structural and digest checks."""
    if not isinstance(catalog, dict):
        raise ValidationError("KEV catalog must be a JSON object")
    if not isinstance(meta, dict):
        raise ValidationError("KEV catalog meta must be a JSON object")
    if meta.get("status") != "ok":
        raise ValidationError(f"KEV catalog meta status {meta.get('status')!r} is not ok")
    if not meta.get("content_sha256"):
        raise ValidationError("KEV catalog meta is missing content_sha256")
    if not meta.get("source_revision"):
        raise ValidationError("KEV catalog meta is missing catalogVersion/source_revision")
    if not meta.get("retrieved_at"):
        raise ValidationError("KEV catalog meta is missing retrieved_at")
    catalog_meta = catalog.get("meta") if isinstance(catalog.get("meta"), dict) else {}
    if catalog_meta.get("content_sha256") and catalog_meta.get("content_sha256") != meta.get(
        "content_sha256"
    ):
        raise ValidationError("KEV catalog.json meta digest does not match kev meta.json")
    records = catalog.get("records")
    if not isinstance(records, list) or not records:
        raise ValidationError("KEV catalog records are missing")
    ids: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            raise ValidationError(f"KEV catalog records[{index}] must be an object")
        cve_id = item.get("cve_id")
        if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
            raise ValidationError(f"KEV catalog records[{index}] has an invalid cve_id")
        if cve_id in seen:
            raise ValidationError(f"KEV catalog contains duplicate CVE ID {cve_id}")
        seen.add(cve_id)
        ids.append(cve_id)
        if item.get("listed") is not True:
            raise ValidationError(f"{cve_id} is not marked listed in the KEV catalog")
    declared = catalog.get("count")
    if declared is not None and declared != len(records):
        raise ValidationError(
            f"KEV catalog declared count {declared!r} does not match {len(records)} records"
        )
    return {
        "ids": ids,
        "id_set": seen,
        "records": {item["cve_id"]: item for item in records},
        "content_sha256": meta.get("content_sha256"),
        "source_revision": meta.get("source_revision"),
        "count": len(records),
    }


def verify_candidate_matches_catalog(
    candidate: dict[str, Any],
    *,
    catalog: object,
    meta: object,
) -> dict[str, Any]:
    """Require candidate KEV records to equal the Collect-time catalog."""
    normalized = verify_catalog_structure(catalog, meta)
    kev = (candidate.get("sources") or {}).get("kev") or {}
    if kev.get("content_sha256") != normalized["content_sha256"]:
        raise ValidationError(
            "Candidate KEV digest does not match the Collect-time catalog digest"
        )
    if kev.get("source_revision") and kev.get("source_revision") != normalized["source_revision"]:
        raise ValidationError(
            "Candidate KEV catalogVersion does not match the Collect-time catalog"
        )
    records = candidate.get("records") or []
    candidate_ids = [item.get("cve_id") for item in records]
    if candidate_ids != normalized["ids"]:
        missing = sorted(normalized["id_set"] - {item for item in candidate_ids if item})
        extra = sorted({item for item in candidate_ids if item} - normalized["id_set"])
        raise ValidationError(
            "Candidate CVE IDs do not match the Collect-time KEV catalog"
            + (f"; missing {missing[:8]}" if missing else "")
            + (f"; extra {extra[:8]}" if extra else "")
        )
    if (candidate.get("summary") or {}).get("kev_records") != normalized["count"]:
        raise ValidationError(
            "summary.kev_records does not match the Collect-time KEV catalog count"
        )
    for item in records:
        cve_id = item.get("cve_id")
        catalog_record = normalized["records"][cve_id]
        candidate_kev = item.get("kev") or {}
        changed = _material_field_changes(catalog_record, candidate_kev)
        if changed:
            raise ValidationError(
                f"{cve_id} KEV fields {changed} do not match the Collect-time catalog"
            )
    return normalized


def kev_publication_diff(
    published: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Describe KEV ID and material-field changes versus the live published snapshot."""
    published_ids = [
        item.get("cve_id") for item in published.get("records") or [] if item.get("cve_id")
    ]
    candidate_ids = [
        item.get("cve_id") for item in candidate.get("records") or [] if item.get("cve_id")
    ]
    published_set = set(published_ids)
    candidate_set = set(candidate_ids)
    added = sorted(candidate_set - published_set)
    removed = sorted(published_set - candidate_set)
    published_records = {
        item.get("cve_id"): item.get("kev") or {}
        for item in published.get("records") or []
        if item.get("cve_id")
    }
    field_changes: list[str] = []
    for item in candidate.get("records") or []:
        cve_id = item.get("cve_id")
        previous = published_records.get(cve_id)
        if previous is None:
            continue
        changed = _material_field_changes(previous, item.get("kev") or {})
        if changed:
            field_changes.append(f"{cve_id}:{','.join(changed)}")
    published_digest = ((published.get("sources") or {}).get("kev") or {}).get("content_sha256")
    candidate_digest = ((candidate.get("sources") or {}).get("kev") or {}).get("content_sha256")
    return {
        "added": added,
        "removed": removed,
        "field_changes": field_changes[:16],
        "same_digest": bool(published_digest and published_digest == candidate_digest),
        "substitution": bool(added and removed),
    }


def unexplained_kev_change_reason(diff: dict[str, Any]) -> tuple[str, str] | None:
    """Reject ID or material KEV drift when the upstream digest did not change."""
    if not diff.get("same_digest"):
        return None
    if diff.get("added") or diff.get("removed"):
        return (
            "unexplained_kev_change",
            "KEV digest is unchanged but the CVE-ID set changed"
            + (f"; added {diff['added'][:8]}" if diff.get("added") else "")
            + (f"; removed {diff['removed'][:8]}" if diff.get("removed") else ""),
        )
    if diff.get("field_changes"):
        return (
            "unexplained_kev_change",
            "KEV digest is unchanged but material KEV fields changed: "
            + "; ".join(diff["field_changes"][:8]),
        )
    return None


def catalog_from_snapshot(snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a Collect-time catalog pair from a snapshot for tests and local simulation."""
    meta = dict((snapshot.get("sources") or {}).get("kev") or {})
    records = [dict(item.get("kev") or {}) for item in snapshot.get("records") or []]
    catalog = {"meta": meta, "records": records, "count": len(records)}
    return catalog, meta


def _material_field_changes(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    for field in MATERIAL_KEV_FIELDS:
        if left.get(field) != right.get(field):
            changed.append(field)
    return changed
