"""Pinned source contracts, parser versions, and resource limits."""

from __future__ import annotations

PACKAGE_VERSION = "1.0.0"
SNAPSHOT_SCHEMA_VERSION = "1.0.0"
MANIFEST_SCHEMA_VERSION = "1.0.0"
PREVIEW_SCHEMA_VERSION = "1.0.0"

KEV_PARSER_VERSION = "1.0.0"
CVE_PARSER_VERSION = "1.0.0"
EPSS_PARSER_VERSION = "1.0.0"

USER_AGENT = (
    "SilastronSecurityPulse/1.0 "
    "(+https://github.com/Mehrn0ush/silastron-security-pulse)"
)

# Official CISA KEV JSON feed and schema, verified 2026-10-21 from
# https://www.cisa.gov/resources-tools/resources/kev-catalog
KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_SCHEMA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities_schema.json"
)
KEV_CATALOG_PAGE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
KEV_LICENSE_URL = "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt"
KEV_LICENSE_ID = "CC0-1.0"

# Official CVE List V5, verified 2026-10-21 from
# https://github.com/CVEProject/cvelistV5
CVE_LIST_V5_RAW_BASE = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
)
CVE_LIST_V5_BLOB_BASE = (
    "https://github.com/CVEProject/cvelistV5/blob/main/"
)
CVE_RECORD_PAGE_TEMPLATE = "https://www.cve.org/CVERecord?id={cve_id}"
CVE_TERMS_OF_USE_URL = "https://www.cve.org/Legal/TermsOfUse"
CVE_SCHEMA_DOCS_URL = "https://github.com/CVEProject/cve-schema"

# FIRST EPSS — adapter remains disabled pending redistribution clearance.
EPSS_HOME_URL = "https://www.first.org/epss"
EPSS_DATA_URL = "https://www.first.org/epss/data"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_USAGE_AGREEMENT_URL = "https://www.first.org/epss/#Usage-Agreement"

ALLOWED_HTTPS_HOSTS = frozenset(
    {
        "www.cisa.gov",
        "cisa.gov",
        "www.cve.org",
        "cve.org",
        "github.com",
        "raw.githubusercontent.com",
        "www.first.org",
        "api.first.org",
        "epss.empiricalsecurity.com",
    }
)

AUTHORITATIVE_LINK_HOSTS = frozenset(
    {
        "www.cisa.gov",
        "cisa.gov",
        "www.cve.org",
        "cve.org",
        "github.com",
        "www.first.org",
    }
)

DEFAULT_LIMITS = {
    "http_timeout_seconds": 30,
    "connect_timeout_seconds": 10,
    "max_redirects": 3,
    "max_kev_bytes": 15_000_000,
    "max_cve_bytes": 1_000_000,
    "max_epss_bytes": 2_000_000,
    "max_json_depth": 32,
    "max_kev_records": 3000,
    "max_cve_enrichments": 3000,
    "max_string_chars": 4000,
    "max_description_chars": 1200,
    "max_products": 8,
    "max_preview_changes": 50,
    "max_preview_recent": 25,
    "cve_workers": 4,
    "cve_min_interval_ms": 50,
    "stale_after_hours": 36,
    "max_cve_failures_ratio": 0.05,
    "max_cve_failures_absolute": 25,
}

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
CWE_ID_PATTERN = r"^CWE-[0-9]+$"

MITRE_CVE_ATTRIBUTION = (
    "CVE is a registered trademark and the CVE List is copyright "
    "The MITRE Corporation. Use of CVE and the CVE List is subject to the "
    "CVE Program Terms of Use at https://www.cve.org/Legal/TermsOfUse. "
    "Any copy of CVE data must reproduce MITRE's copyright designation and "
    "that license."
)

CISA_KEV_ATTRIBUTION = (
    "The CISA Known Exploited Vulnerabilities catalog is dedicated to the "
    "public domain under CC0 1.0. Use does not authorize use of the CISA "
    "logo or DHS seal and is not an endorsement by CISA or DHS. "
    "See https://www.cisa.gov/sites/default/files/licenses/kev/license.txt"
)

EPSS_ATTRIBUTION = (
    "EPSS scores, when enabled, are used under the FIRST EPSS Usage "
    "Agreement with requested attribution to https://www.first.org/epss "
    "and Jacobs et al., Exploit Prediction Scoring System, DTRAP 2(3), 2021."
)
