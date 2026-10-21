"""CISA Known Exploited Vulnerabilities adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass

from silastron_pulse.constants import (
    CISA_KEV_ATTRIBUTION,
    KEV_JSON_URL,
    KEV_LICENSE_ID,
    KEV_PARSER_VERSION,
    KEV_SCHEMA_URL,
)
from silastron_pulse.config import PulseConfig
from silastron_pulse.errors import FetchError, ValidationError
from silastron_pulse.http import Fetcher
from silastron_pulse.ids import parse_cve_id, parse_cwe_id
from silastron_pulse.jsonutil import load_bounded_json, sha256_bytes
from silastron_pulse.models import KevRecord, SourceMeta
from silastron_pulse.sanitize import authoritative_kev_url, clean_text, require_text


@dataclass(frozen=True)
class KevCatalog:
    meta: SourceMeta
    records: list[KevRecord]


def fetch_kev_catalog(fetcher: Fetcher, config: PulseConfig) -> KevCatalog:
    try:
        response = fetcher.get(KEV_JSON_URL, max_bytes=config.max_kev_bytes)
    except FetchError as exc:
        raise FetchError(f"KEV collection failed: {exc}") from exc
    payload = load_bounded_json(
        response.body,
        max_bytes=config.max_kev_bytes,
        max_depth=config.max_json_depth,
        source="CISA KEV",
    )
    return parse_kev_catalog(payload, raw=response.body, retrieved_at=response.retrieved_at, config=config)


def parse_kev_catalog(
    payload: object,
    *,
    raw: bytes,
    retrieved_at: str,
    config: PulseConfig,
) -> KevCatalog:
    if not isinstance(payload, dict):
        raise ValidationError("KEV payload must be a JSON object")
    catalog_version = clean_text(payload.get("catalogVersion"), config.max_string_chars)
    date_released = clean_text(payload.get("dateReleased"), 64)
    count = payload.get("count")
    vulnerabilities = payload.get("vulnerabilities")
    if not catalog_version:
        raise ValidationError("KEV catalogVersion is missing")
    if not date_released:
        raise ValidationError("KEV dateReleased is missing")
    if not isinstance(count, int) or isinstance(count, bool):
        raise ValidationError("KEV count must be an integer")
    if not isinstance(vulnerabilities, list):
        raise ValidationError("KEV vulnerabilities must be an array")
    if len(vulnerabilities) > config.max_kev_records:
        raise ValidationError(
            f"KEV catalog has {len(vulnerabilities)} records; max is {config.max_kev_records}"
        )
    if count != len(vulnerabilities):
        raise ValidationError(
            f"KEV count {count} does not match vulnerabilities length {len(vulnerabilities)}"
        )
    if len(vulnerabilities) == 0:
        raise ValidationError("KEV catalog is empty; refusing to treat this as a valid snapshot")

    records: list[KevRecord] = []
    seen: dict[str, KevRecord] = {}
    for index, item in enumerate(vulnerabilities):
        record = _parse_item(item, index=index, config=config)
        previous = seen.get(record.cve_id)
        if previous is not None:
            if previous.comparable() != record.comparable():
                raise ValidationError(
                    f"Conflicting duplicate KEV records for {record.cve_id}"
                )
            continue
        seen[record.cve_id] = record
        records.append(record)

    records.sort(key=lambda item: item.cve_id)
    meta = SourceMeta(
        id="cisa-kev",
        name="CISA Known Exploited Vulnerabilities Catalog",
        status="ok",
        url=KEV_JSON_URL,
        retrieved_at=retrieved_at,
        source_published_at=date_released,
        source_updated_at=date_released,
        source_revision=catalog_version,
        parser_version=KEV_PARSER_VERSION,
        schema_version=KEV_SCHEMA_URL,
        license=KEV_LICENSE_ID,
        content_sha256=sha256_bytes(raw),
        notes=CISA_KEV_ATTRIBUTION,
    )
    return KevCatalog(meta=meta, records=records)


def _parse_item(item: object, *, index: int, config: PulseConfig) -> KevRecord:
    if not isinstance(item, dict):
        raise ValidationError(f"KEV vulnerabilities[{index}] must be an object")
    try:
        cve_id = parse_cve_id(item.get("cveID"))
    except ValidationError as exc:
        raise ValidationError(f"KEV vulnerabilities[{index}] {exc}") from exc
    try:
        vendor = require_text(item.get("vendorProject"), "vendorProject", config.max_string_chars)
        product = require_text(item.get("product"), "product", config.max_string_chars)
        name = require_text(
            item.get("vulnerabilityName"), "vulnerabilityName", config.max_string_chars
        )
        date_added = require_text(item.get("dateAdded"), "dateAdded", 32)
        description = require_text(
            item.get("shortDescription"), "shortDescription", config.max_description_chars
        )
        action = require_text(
            item.get("requiredAction"), "requiredAction", config.max_description_chars
        )
        due_date = require_text(item.get("dueDate"), "dueDate", 32)
    except ValueError as exc:
        raise ValidationError(f"KEV {cve_id}: {exc}") from exc

    cwes_raw = item.get("cwes") or []
    if cwes_raw is None:
        cwes_raw = []
    if not isinstance(cwes_raw, list):
        raise ValidationError(f"KEV {cve_id}: cwes must be an array")
    cwes: list[str] = []
    for cwe in cwes_raw:
        parsed = parse_cwe_id(cwe)
        if parsed:
            cwes.append(parsed)
    cwes = sorted(set(cwes))

    comparable = {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": name,
        "dateAdded": date_added,
        "shortDescription": description,
        "requiredAction": action,
        "dueDate": due_date,
        "knownRansomwareCampaignUse": clean_text(
            item.get("knownRansomwareCampaignUse"), 32
        ),
        "forensicTriage": clean_text(item.get("forensicTriage"), 32),
        "notes": clean_text(item.get("notes"), config.max_description_chars),
        "cwes": cwes,
    }
    return KevRecord(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        vulnerability_name=name,
        date_added=date_added,
        short_description=description,
        required_action=action,
        due_date=due_date,
        known_ransomware_campaign_use=comparable["knownRansomwareCampaignUse"],
        forensic_triage=comparable["forensicTriage"],
        notes=comparable["notes"],
        cwes=cwes,
        source_url=authoritative_kev_url(),
        record_sha256=sha256_bytes(json.dumps(comparable, sort_keys=True).encode("utf-8")),
    )
