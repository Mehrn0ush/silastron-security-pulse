"""Snapshot dataclasses. Signals stay distinct; there is no composite risk score."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

SourceStatus = Literal["ok", "failed", "disabled", "unavailable", "degraded"]
CollectionStatus = Literal["ok", "failed", "degraded"]
RemediationKind = Literal["required_action", "verified_fix", "mitigation", "reference"]
RemediationSource = Literal["cisa_kev", "cve_list_v5"]


def _omit_none(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


@dataclass(frozen=True)
class SourceMeta:
    id: str
    name: str
    status: SourceStatus
    url: str | None
    retrieved_at: str | None
    source_published_at: str | None
    source_updated_at: str | None
    source_revision: str | None
    parser_version: str
    schema_version: str | None
    license: str
    content_sha256: str | None
    notes: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "url": self.url,
            "retrieved_at": self.retrieved_at,
            "source_published_at": self.source_published_at,
            "source_updated_at": self.source_updated_at,
            "source_revision": self.source_revision,
            "parser_version": self.parser_version,
            "schema_version": self.schema_version,
            "license": self.license,
            "content_sha256": self.content_sha256,
            "notes": self.notes,
            "error": self.error,
        }


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str | None
    forensic_triage: str | None
    notes: str | None
    cwes: list[str]
    source_url: str
    record_sha256: str
    truncated_fields: tuple[str, ...] = ()
    cwes_incomplete: bool = False

    def comparable(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
            "forensic_triage": self.forensic_triage,
            "notes": self.notes,
            "cwes": list(self.cwes),
            "truncated_fields": list(self.truncated_fields),
            "cwes_incomplete": self.cwes_incomplete,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "listed": True,
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
            "forensic_triage": self.forensic_triage,
            "notes": self.notes,
            "cwes": list(self.cwes),
            "source_url": self.source_url,
            "record_sha256": self.record_sha256,
            "truncated_fields": list(self.truncated_fields),
            "cwes_incomplete": self.cwes_incomplete,
        }


@dataclass(frozen=True)
class RemediationItem:
    kind: RemediationKind
    source: RemediationSource
    attribution: str
    text: str | None = None
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "kind": self.kind,
            "source": self.source,
            "attribution": self.attribution,
            "text": self.text,
            "url": self.url,
        }
        return {key: value for key, value in payload.items() if value is not None}


@dataclass(frozen=True)
class CveProduct:
    vendor: str | None
    product: str | None
    status: str | None
    versions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "status": self.status,
            "versions": list(self.versions),
        }


@dataclass(frozen=True)
class CveSeverity:
    source: str
    cvss_version: str
    base_score: float
    base_severity: str | None
    vector: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "cvss_version": self.cvss_version,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "vector": self.vector,
        }


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    state: str
    data_version: str | None
    date_published: str | None
    date_updated: str | None
    assigner_short_name: str | None
    title: str | None
    description: str | None
    severity: CveSeverity | None
    products: list[CveProduct]
    source_url: str
    record_page_url: str
    record_sha256: str
    status: SourceStatus = "ok"
    error: str | None = None
    retrieved_at: str | None = None
    last_checked_at: str | None = None
    etag: str | None = None
    truncated_fields: tuple[str, ...] = ()
    omitted_product_count: int = 0
    omitted_version_count: int = 0
    cached: bool = False
    remediation_items: tuple[RemediationItem, ...] = ()

    def comparable(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "state": self.state,
            "data_version": self.data_version,
            "date_published": self.date_published,
            "date_updated": self.date_updated,
            "assigner_short_name": self.assigner_short_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.to_dict() if self.severity else None,
            "products": [item.to_dict() for item in self.products],
            "status": self.status,
            "truncated_fields": list(self.truncated_fields),
            "omitted_product_count": self.omitted_product_count,
            "omitted_version_count": self.omitted_version_count,
            "remediation_items": [item.to_dict() for item in self.remediation_items],
        }

    def core_comparable(self) -> dict[str, Any]:
        payload = self.comparable()
        payload.pop("remediation_items", None)
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "cve_id": self.cve_id,
            "state": self.state,
            "data_version": self.data_version,
            "date_published": self.date_published,
            "date_updated": self.date_updated,
            "assigner_short_name": self.assigner_short_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.to_dict() if self.severity else None,
            "products": [item.to_dict() for item in self.products],
            "source_url": self.source_url,
            "record_page_url": self.record_page_url,
            "record_sha256": self.record_sha256,
            "error": self.error,
            "retrieved_at": self.retrieved_at,
            "last_checked_at": self.last_checked_at,
            "etag": self.etag,
            "truncated_fields": list(self.truncated_fields),
            "omitted_product_count": self.omitted_product_count,
            "omitted_version_count": self.omitted_version_count,
            "cached": self.cached,
            "remediation_items": [item.to_dict() for item in self.remediation_items],
        }


@dataclass(frozen=True)
class EpssRecord:
    status: SourceStatus
    cve_id: str
    score: float | None = None
    percentile: float | None = None
    score_date: str | None = None
    notes: str | None = None

    def comparable(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "cve_id": self.cve_id,
            "score": self.score,
            "percentile": self.percentile,
            "score_date": self.score_date,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "cve_id": self.cve_id,
            "score": self.score,
            "percentile": self.percentile,
            "score_date": self.score_date,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Signals:
    confirmed_exploitation: dict[str, Any]
    estimated_exploitation_probability: dict[str, Any]
    vulnerability_severity: dict[str, Any]
    product_affectedness: dict[str, Any]
    deployment_exposure: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed_exploitation": self.confirmed_exploitation,
            "estimated_exploitation_probability": self.estimated_exploitation_probability,
            "vulnerability_severity": self.vulnerability_severity,
            "product_affectedness": self.product_affectedness,
            "deployment_exposure": self.deployment_exposure,
            "composite_risk_score": None,
            "note": (
                "These signals are independent. They are never collapsed into "
                "a single risk score."
            ),
        }


@dataclass(frozen=True)
class PulseEntry:
    cve_id: str
    kev: KevRecord
    cve: CveRecord
    epss: EpssRecord
    signals: Signals
    links: dict[str, str]

    def completeness(self) -> str:
        return record_completeness(kev=self.kev, cve=self.cve)

    def to_dict(self) -> dict[str, Any]:
        from silastron_pulse.remediation import assemble_remediation

        return {
            "cve_id": self.cve_id,
            "completeness": self.completeness(),
            "kev": self.kev.to_dict(),
            "cve": self.cve.to_dict(),
            "epss": self.epss.to_dict(),
            "signals": self.signals.to_dict(),
            "links": dict(self.links),
            "remediation": assemble_remediation(kev=self.kev, cve=self.cve),
        }


def record_completeness(*, kev: KevRecord, cve: CveRecord) -> str:
    """Record-level completeness: complete, partial, or unavailable."""
    if cve.status != "ok":
        return "unavailable"
    if (
        cve.truncated_fields
        or kev.truncated_fields
        or kev.cwes_incomplete
        or cve.omitted_product_count
        or cve.omitted_version_count
    ):
        return "partial"
    return "complete"


@dataclass
class ChangeSet:
    new_kev_entries: list[str] = field(default_factory=list)
    updated_kev_entries: list[str] = field(default_factory=list)
    removed_kev_entries: list[str] = field(default_factory=list)
    changed_cve_information: list[str] = field(default_factory=list)
    epss_changes: list[str] = field(default_factory=list)
    source_metadata_changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_kev_entries": list(self.new_kev_entries),
            "updated_kev_entries": list(self.updated_kev_entries),
            "removed_kev_entries": list(self.removed_kev_entries),
            "changed_cve_information": list(self.changed_cve_information),
            "epss_changes": list(self.epss_changes),
            "source_metadata_changes": list(self.source_metadata_changes),
        }

    def is_empty(self) -> bool:
        return not (
            self.new_kev_entries
            or self.updated_kev_entries
            or self.removed_kev_entries
            or self.changed_cve_information
            or self.epss_changes
            or self.source_metadata_changes
        )
