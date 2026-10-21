"""Keep exploitation, probability, severity, affectedness, and exposure distinct."""

from __future__ import annotations

from silastron_pulse.models import CveRecord, EpssRecord, KevRecord, Signals


def build_signals(kev: KevRecord, cve: CveRecord, epss: EpssRecord) -> Signals:
    confirmed = {
        "value": True,
        "basis": "cisa_kev",
        "status": "confirmed_by_source",
        "source": "CISA Known Exploited Vulnerabilities catalog",
        "date_added": kev.date_added,
        "note": (
            "CISA listed this CVE in KEV. This is source-asserted evidence of "
            "known exploitation, not a statement about Silastron systems."
        ),
    }
    if epss.status == "ok" and epss.score is not None:
        probability = {
            "value": epss.score,
            "percentile": epss.percentile,
            "basis": "first_epss",
            "status": "estimated",
            "score_date": epss.score_date,
            "note": (
                "EPSS is an estimated probability of exploitation in the next "
                "30 days. It is not confirmation of exploitation."
            ),
        }
    else:
        probability = {
            "value": None,
            "percentile": None,
            "basis": "first_epss",
            "status": epss.status,
            "note": epss.notes
            or "EPSS is unavailable. No estimated probability is published.",
        }

    if cve.severity is not None:
        severity = {
            "status": "available",
            "source": cve.severity.source,
            "cvss_version": cve.severity.cvss_version,
            "base_score": cve.severity.base_score,
            "base_severity": cve.severity.base_severity,
            "vector": cve.severity.vector,
            "note": (
                "CVSS measures vulnerability severity, not exploitation or "
                "deployment exposure."
            ),
        }
    else:
        severity = {
            "status": "unavailable",
            "source": None,
            "cvss_version": None,
            "base_score": None,
            "base_severity": None,
            "vector": None,
            "note": "No CVSS vector was present in the CNA container of the CVE record.",
        }

    products = [
        {
            "vendor": item.vendor,
            "product": item.product,
            "status": item.status,
            "versions": list(item.versions),
            "source": "cve_cna",
        }
        for item in cve.products
    ]
    omitted = cve.omitted_product_count or cve.omitted_version_count
    affectedness = {
        "status": "source_asserted_partial" if omitted else "source_asserted",
        "kev_vendor_project": kev.vendor_project,
        "kev_product": kev.product,
        "cve_products": products,
        "omitted_product_count": cve.omitted_product_count,
        "omitted_version_count": cve.omitted_version_count,
        "note": (
            "Product affectedness is copied from KEV and the CVE CNA container. "
            "It does not mean a Silastron or customer system is exposed."
            + (
                f" {cve.omitted_product_count} additional CNA product entries and "
                f"{cve.omitted_version_count} additional version entries exceeded "
                "the storage bound and were not stored."
                if omitted
                else ""
            )
        ),
    }
    exposure = {
        "status": "not_assessed",
        "value": None,
        "note": (
            "Deployment exposure requires an asset inventory and is out of "
            "scope for this public intelligence snapshot."
        ),
    }
    return Signals(
        confirmed_exploitation=confirmed,
        estimated_exploitation_probability=probability,
        vulnerability_severity=severity,
        product_affectedness=affectedness,
        deployment_exposure=exposure,
    )
