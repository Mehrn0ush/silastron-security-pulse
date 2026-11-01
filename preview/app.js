(function () {
  "use strict";

  var CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/;
  var CVE_PATH = "/CVERecord";
  var KEV_PATH = "/known-exploited-vulnerabilities-catalog";
  var CVELIST_BLOB =
    /^\/CVEProject\/cvelistV5\/blob\/main\/cves\/[0-9]{4}\/[0-9]+xxx\/CVE-[0-9]{4}-[0-9]{4,}\.json$/;
  var PAGE_SIZE = 25;
  var RECENT_LIMIT = 10;
  var PRODUCT_DETAIL_LIMIT = 8;
  var VERSION_DETAIL_LIMIT = 3;
  var FIELD_LABELS = {
    vendor_project: "Vendor",
    product: "Product",
    vulnerability_name: "Vulnerability name",
    kev_date_added: "KEV added",
    required_action: "Required action",
    due_date: "Due date",
    cve_state: "CVE state",
    cve_title: "CVE title",
    cve_description: "CVE description",
    cve_date_updated: "CVE date updated",
    cve_assigner: "CVE assigner",
    cve_status: "CVE extraction status",
    affected_products: "Affected products",
    cvss_base_score: "CVSS base score",
    cvss_base_severity: "CVSS severity",
    completeness: "Extraction completeness",
    remediation_item_count: "Extracted remediation items",
  };
  var CATEGORY_LABELS = {
    added_kev: "Newly added KEV entries",
    removed_kev: "Removed KEV entries",
    kev_update: "KEV record updates",
    cve_update: "CVE information updates",
    cvss_change: "CVSS changes",
    completeness_change: "Extraction completeness changes",
    enrichment_update: "Extracted remediation evidence",
  };
  var CATEGORY_ORDER = [
    "added_kev",
    "removed_kev",
    "cvss_change",
    "cve_update",
    "completeness_change",
    "kev_update",
  ];
  var CORE_CHANGE_CATEGORIES = {
    kev_update: true,
    cvss_change: true,
    completeness_change: true,
  };
  var ENRICHMENT_CHANGE_CATEGORIES = {
    enrichment_update: true,
    remediation_update: true,
  };

  var statusBanner = document.getElementById("status-banner");
  var statusDetails = document.getElementById("status-details");
  var technicalDetails = document.getElementById("technical-details-list");
  var overviewCards = document.getElementById("overview-cards");
  var changesNote = document.getElementById("changes-note");
  var changesBody = document.getElementById("changes-body");
  var recentHeading = document.getElementById("recent-heading");
  var recentNote = document.getElementById("recent-note");
  var recentCaption = document.getElementById("recent-caption");
  var recentBody = document.getElementById("recent-body");
  var recentChangeCol = document.getElementById("recent-change-col");
  var catalogNote = document.getElementById("catalog-note");
  var catalogStatus = document.getElementById("catalog-status");
  var catalogBody = document.getElementById("catalog-body");
  var catalogLoad = document.getElementById("catalog-load");
  var catalogQuery = document.getElementById("catalog-query");
  var catalogVendor = document.getElementById("catalog-vendor");
  var catalogProduct = document.getElementById("catalog-product");
  var catalogDateFrom = document.getElementById("catalog-date-from");
  var catalogDateTo = document.getElementById("catalog-date-to");
  var catalogCompleteness = document.getElementById("catalog-completeness");
  var catalogCvss = document.getElementById("catalog-cvss");
  var catalogCvssMin = document.getElementById("catalog-cvss-min");
  var catalogCvssMax = document.getElementById("catalog-cvss-max");
  var catalogCwe = document.getElementById("catalog-cwe");
  var catalogTruncated = document.getElementById("catalog-truncated");
  var catalogRemediation = document.getElementById("catalog-remediation");
  var catalogCvssVersion = document.getElementById("catalog-cvss-version");
  var catalogAttackVector = document.getElementById("catalog-attack-vector");
  var catalogPrivileges = document.getElementById("catalog-privileges");
  var catalogUserInteraction = document.getElementById("catalog-user-interaction");
  var catalogFixedVersion = document.getElementById("catalog-fixed-version");
  var catalogVendorAdvisory = document.getElementById("catalog-vendor-advisory");
  var catalogNvd = document.getElementById("catalog-nvd");
  var catalogSort = document.getElementById("catalog-sort");
  var catalogClear = document.getElementById("catalog-clear");
  var catalogExport = document.getElementById("catalog-export");
  var catalogPrev = document.getElementById("catalog-prev");
  var catalogNext = document.getElementById("catalog-next");
  var catalogPage = document.getElementById("catalog-page");
  var cveDetail = document.getElementById("cve-detail");
  var cveDetailHeading = document.getElementById("cve-detail-heading");
  var cveDetailStatus = document.getElementById("cve-detail-status");
  var cveDetailBody = document.getElementById("cve-detail-body");
  var NVD_DETAIL = /^\/vuln\/detail\/CVE-[0-9]{4}-[0-9]{4,}$/;

  var epssDisabled = false;
  var catalogRows = [];
  var catalogLoaded = false;
  var catalogPageIndex = 0;
  var filteredCatalog = [];
  var catalogSnapshotMeta = null;
  var historyIndexIds = {};

  function asText(value) {
    if (value === null || value === undefined || value === "") {
      return "Unavailable";
    }
    return String(value);
  }

  function appendNamedMeta(list, term, value) {
    if (!list) {
      return;
    }
    var dt = document.createElement("dt");
    dt.textContent = term;
    var dd = document.createElement("dd");
    dd.textContent = asText(value);
    list.appendChild(dt);
    list.appendChild(dd);
  }

  function appendMeta(term, value) {
    appendNamedMeta(statusDetails, term, value);
  }

  function evaluateFreshness(generatedAt, staleAfterHours, nowMs) {
    var generated = Date.parse(generatedAt);
    if (!isFinite(generated)) {
      return { stale: true, fresh: false, ageHours: null, invalid: true };
    }
    var ageHours = (nowMs - generated) / 3600000;
    if (ageHours < 0) {
      return { stale: true, fresh: false, ageHours: ageHours, invalid: true };
    }
    var stale = ageHours > Number(staleAfterHours || 36);
    return { stale: stale, fresh: !stale, ageHours: ageHours, invalid: false };
  }

  function formatInstant(value) {
    var parsed = Date.parse(value);
    if (!isFinite(parsed)) {
      return asText(value);
    }
    return new Date(parsed).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC").replace("Z", " UTC");
  }

  function formatAge(hours) {
    if (hours === null || hours === undefined || !isFinite(hours)) {
      return "Unavailable";
    }
    if (Math.abs(hours) < 1) {
      return String(Math.round(hours * 60)) + " minutes";
    }
    if (hours < 48) {
      return String(Math.round(hours * 10) / 10) + " hours";
    }
    return String(Math.round((hours / 24) * 10) / 10) + " days";
  }

  function safeHttpsUrl(value) {
    if (typeof value !== "string") {
      return null;
    }
    try {
      var parsed = new URL(value);
      if (parsed.protocol !== "https:") {
        return null;
      }
      if (parsed.username || parsed.password) {
        return null;
      }
      if (parsed.port && parsed.port !== "443") {
        return null;
      }
      var host = parsed.hostname;
      var path = parsed.pathname || "";
      if (host === "www.cisa.gov" || host === "cisa.gov") {
        return path.replace(/\/$/, "") === KEV_PATH ? parsed.href : null;
      }
      if (host === "www.cve.org" || host === "cve.org") {
        if (path !== CVE_PATH) {
          return null;
        }
        var cveId = parsed.searchParams.get("id");
        if (!cveId || !CVE_ID.test(cveId)) {
          return null;
        }
        return parsed.href;
      }
      if (host === "github.com") {
        return CVELIST_BLOB.test(path) ? parsed.href : null;
      }
      if (host === "nvd.nist.gov") {
        return NVD_DETAIL.test(path) ? parsed.href : null;
      }
      return null;
    } catch (err) {
      return null;
    }
  }

  function safePublicHttpsUrl(value) {
    if (typeof value !== "string") {
      return null;
    }
    try {
      var parsed = new URL(value);
      if (parsed.protocol !== "https:") {
        return null;
      }
      if (parsed.username || parsed.password) {
        return null;
      }
      if (parsed.port && parsed.port !== "443") {
        return null;
      }
      if (parsed.hash) {
        return null;
      }
      var host = parsed.hostname || "";
      if (!host || host === "localhost" || host.slice(-6) === ".local") {
        return null;
      }
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.indexOf(":") !== -1) {
        return null;
      }
      if (!/[a-z]/i.test(host) || host.indexOf(".") === -1) {
        return null;
      }
      return parsed.href;
    } catch (err) {
      return null;
    }
  }

  function bannerLabel(kind) {
    if (kind === "ok") {
      return "Fresh collection";
    }
    if (kind === "stale") {
      return "Stale snapshot";
    }
    if (kind === "warn") {
      return "Degraded collection";
    }
    if (kind === "failed") {
      return "Failed";
    }
    return "Unavailable";
  }

  function setBanner(kind, message) {
    statusBanner.className = "banner " + kind;
    statusBanner.textContent = "";
    var label = document.createElement("strong");
    label.className = "banner-label";
    label.textContent = bannerLabel(kind);
    statusBanner.appendChild(label);
    statusBanner.appendChild(document.createTextNode(" " + message));
  }

  function appendCvePulseLink(container, cveId) {
    if (CVE_ID.test(cveId)) {
      var pulseLink = document.createElement("a");
      pulseLink.setAttribute("href", "#cve/" + cveId);
      pulseLink.textContent = asText(cveId);
      container.appendChild(pulseLink);
      return;
    }
    container.textContent = asText(cveId);
  }

  function addLink(container, href, label) {
    var safe = safeHttpsUrl(href);
    if (!safe) {
      var unavailable = document.createElement("span");
      unavailable.textContent = label + " unavailable";
      container.appendChild(unavailable);
      return;
    }
    if (container.childNodes.length) {
      container.appendChild(document.createTextNode(" · "));
    }
    var anchor = document.createElement("a");
    anchor.setAttribute("href", safe);
    anchor.setAttribute("rel", "noopener noreferrer");
    anchor.setAttribute("target", "_blank");
    container.appendChild(anchor);
    anchor.textContent = label;
  }

  function epssLabel(row) {
    if (epssDisabled) {
      return "Disabled";
    }
    if (row.epss_status === "ok" && row.epss_score !== null && row.epss_score !== undefined) {
      return "Estimated " + asText(row.epss_score);
    }
    if (row.epss_status === "disabled") {
      return "Disabled";
    }
    return "Unavailable";
  }

  function completenessLabel(row) {
    if (row.completeness === "unavailable") {
      return "Unavailable enrichment";
    }
    if (row.completeness === "partial" || row.partial) {
      var omitted = [];
      if (row.omitted_product_count) {
        omitted.push(asText(row.omitted_product_count) + " products omitted");
      }
      if (row.omitted_version_count) {
        omitted.push(asText(row.omitted_version_count) + " versions omitted");
      }
      return omitted.length
        ? "Partial extracted inventory (" + omitted.join(", ") + ")"
        : "Partial extracted inventory";
    }
    return "Complete extracted inventory";
  }

  function cvssLabel(row) {
    if (row.severity_status === "available" && row.cvss_base_score !== null && row.cvss_base_score !== undefined) {
      return asText(row.cvss_base_score);
    }
    return "Unavailable";
  }

  function cvssBand(row) {
    if (row.severity_status !== "available" || row.cvss_base_score === null || row.cvss_base_score === undefined) {
      return null;
    }
    var numeric = Number(row.cvss_base_score);
    if (!isFinite(numeric)) {
      return null;
    }
    if (numeric >= 9) {
      return "critical";
    }
    if (numeric >= 7) {
      return "high";
    }
    if (numeric >= 4) {
      return "medium";
    }
    if (numeric > 0) {
      return "low";
    }
    return null;
  }

  function labeledCell(label) {
    var cell = document.createElement("td");
    cell.setAttribute("data-label", label);
    return cell;
  }

  function comparisonCount(value) {
    if (value === null || value === undefined || value === "") {
      return "No comparison available";
    }
    return String(value);
  }

  function presentEpssNote(value) {
    if (typeof value !== "string" || !value) {
      return value;
    }
    if (value.indexOf("#Usage-Agreement") === -1 && value.indexOf("FIRST EPSS Usage Agreement") === -1) {
      return value;
    }
    return (
      "EPSS is disabled in this snapshot. FIRST currently publishes scores for public use " +
      "with requested attribution (https://www.first.org/epss/faq). That is not a " +
      "redistribution license for this public JSON feed. The published snapshot still " +
      "contains a historic Usage Agreement URL that FIRST removed."
    );
  }

  function appendCard(term, value, hint, tone) {
    var article = document.createElement("article");
    article.className = tone ? "card card-" + tone : "card";
    var heading = document.createElement("h3");
    heading.textContent = term;
    var valueEl = document.createElement("p");
    valueEl.className = "value";
    valueEl.textContent = asText(value);
    article.appendChild(heading);
    article.appendChild(valueEl);
    if (hint) {
      var hintEl = document.createElement("p");
      hintEl.className = "hint";
      hintEl.textContent = hint;
      article.appendChild(hintEl);
    }
    overviewCards.appendChild(article);
  }

  function appendTextRow(parent, label, value) {
    var dt = document.createElement("dt");
    dt.textContent = label;
    var dd = document.createElement("dd");
    dd.textContent = asText(value);
    parent.appendChild(dt);
    parent.appendChild(dd);
  }

  function appendList(parent, items) {
    if (!items || !items.length) {
      return;
    }
    var list = document.createElement("ul");
    items.forEach(function (item) {
      if (item === null || item === undefined || item === "") {
        return;
      }
      var li = document.createElement("li");
      li.textContent = String(item);
      list.appendChild(li);
    });
    if (list.childNodes.length) {
      parent.appendChild(list);
    }
  }

  function buildRecordDetails(row) {
    var details = document.createElement("details");
    var summary = document.createElement("summary");
    summary.textContent = "Record details";
    details.appendChild(summary);
    var list = document.createElement("dl");
    list.className = "meta-list record-details";
    appendTextRow(list, "KEV description", row.short_description);
    appendTextRow(list, "Required action", row.required_action);
    appendTextRow(list, "Due date", row.due_date);
    appendTextRow(list, "CVE state", row.cve_state);
    appendTextRow(list, "CVE description", row.cve_description);
    appendTextRow(list, "CVSS vector", row.cvss_vector);
    appendTextRow(list, "Known ransomware campaign use", row.known_ransomware_campaign_use);
    details.appendChild(list);
    if (row.cwes && row.cwes.length) {
      var cweHeading = document.createElement("p");
      cweHeading.className = "detail-label";
      cweHeading.textContent = "CWEs";
      details.appendChild(cweHeading);
      appendList(details, row.cwes);
    }
    if (row.products && row.products.length) {
      var productHeading = document.createElement("p");
      productHeading.className = "detail-label";
      productHeading.textContent = "Extracted CNA products";
      details.appendChild(productHeading);
      appendList(details, row.products);
    }
    details.appendChild(buildRemediation(row.remediation));
    details.appendChild(buildCveHistory(row));
    return details;
  }

  function buildCveHistory(row) {
    var section = document.createElement("div");
    var heading = document.createElement("p");
    heading.className = "detail-label";
    heading.textContent = "Published CVE history";
    section.appendChild(heading);
    var status = document.createElement("p");
    if (!historyIndexIds[row.cve_id]) {
      status.textContent =
        "No published history index entry. Historical coverage is incomplete for this CVE.";
      section.appendChild(status);
      return section;
    }
    if (!CVE_ID.test(row.cve_id)) {
      status.textContent = "CVE identifier is not valid for history lookup.";
      section.appendChild(status);
      return section;
    }
    status.textContent = "Loading published-to-published history for this CVE.";
    section.appendChild(status);
    loadJson("data/history/cves/" + row.cve_id + ".json")
      .then(function (documentPayload) {
        status.textContent = "";
        if (!documentPayload) {
          status.textContent =
            "History file unavailable. Values absent from earlier snapshots are not invented.";
          return;
        }
        renderHistoryDocument(section, documentPayload);
      })
      .catch(function () {
        status.textContent = "History could not be loaded from this site.";
      });
    return section;
  }

  function renderHistoryDocument(section, documentPayload) {
    var list = document.createElement("dl");
    list.className = "meta-list record-details";
    appendNamedMeta(list, "First observed publication", documentPayload.first_observed_generated_at);
    appendNamedMeta(list, "First observed snapshot", documentPayload.first_observed_snapshot_id);
    appendNamedMeta(list, "CISA KEV dateAdded", documentPayload.kev_date_added);
    appendNamedMeta(
      list,
      "Coverage",
      documentPayload.first_observed_may_be_incomplete
        ? "Incomplete: first observed may predate the retained snapshot window"
        : documentPayload.coverage || "unavailable"
    );
    section.appendChild(list);
    var note = document.createElement("p");
    note.textContent =
      "First observed publication is not CISA KEV dateAdded. Remediation and completeness events are extraction enrichment, not confirmed upstream vulnerability changes.";
    section.appendChild(note);
    var events = Array.isArray(documentPayload.events) ? documentPayload.events : [];
    if (!events.length) {
      var empty = document.createElement("p");
      empty.textContent = "No later published-to-published field changes are stored.";
      section.appendChild(empty);
      return;
    }
    events.forEach(function (event) {
      var block = document.createElement("div");
      var title = document.createElement("p");
      title.className = "detail-label";
      title.textContent =
        asText(event.kind) +
        " · " +
        asText(event.classification) +
        " · " +
        asText(event.generated_at);
      block.appendChild(title);
      if (event.note) {
        var eventNote = document.createElement("p");
        eventNote.textContent = asText(event.note);
        block.appendChild(eventNote);
      }
      (event.changes || []).forEach(function (change) {
        var beforeAfter = document.createElement("p");
        beforeAfter.textContent =
          asText(change.field) +
          ": " +
          formatHistoryValue(change.before) +
          " → " +
          formatHistoryValue(change.after);
        block.appendChild(beforeAfter);
      });
      section.appendChild(block);
    });
  }

  function formatHistoryValue(value) {
    if (value === null || value === undefined || value === "") {
      return "unavailable";
    }
    if (typeof value === "object") {
      try {
        return JSON.stringify(value);
      } catch (err) {
        return "unavailable";
      }
    }
    return String(value);
  }

  var CSV_FORMULA_PREFIXES = ["=", "+", "-", "@", "\t", "\r"];
  var CSV_COLUMNS = [
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "kev_date_added",
    "kev_due_date",
    "known_ransomware_campaign_use",
    "short_description",
    "required_action",
    "cwes",
    "completeness",
    "cvss_base_score",
    "cvss_severity_status",
    "cvss_vector",
    "cve_state",
    "cve_description",
    "remediation_status",
    "remediation_kinds",
    "omitted_product_count",
    "omitted_version_count",
    "snapshot_id",
    "snapshot_generated_at",
    "kev_catalog_url",
    "cve_record_url",
    "cvelist_v5_url",
    "nvd_url",
    "nvd_status",
    "cvss_versions",
    "cvss_sources",
    "attack_vector",
    "privileges_required",
    "user_interaction",
    "cwe_ids",
    "has_fixed_version",
    "has_vendor_advisory",
    "has_affected_versions",
    "source_conflicts",
  ];

  function sanitizeCsvCell(value) {
    var text;
    if (value === null || value === undefined || value === "") {
      text = "unavailable";
    } else if (Array.isArray(value)) {
      text = value.length ? value.map(sanitizeCsvCell).join("; ") : "unavailable";
      return neutralizeCsv(text);
    } else {
      text = String(value);
    }
    return neutralizeCsv(text);
  }

  function neutralizeCsv(text) {
    if (CSV_FORMULA_PREFIXES.indexOf(text.charAt(0)) !== -1) {
      return "'" + text;
    }
    return text;
  }

  function quoteCsv(value) {
    return '"' + value.replace(/"/g, '""') + '"';
  }

  function csvField(row, column) {
    if (column === "kev_due_date") {
      return row.due_date;
    }
    if (column === "cvss_severity_status") {
      return row.severity_status || "unavailable";
    }
    if (column === "cwes") {
      return row.cwes && row.cwes.length ? row.cwes : "unavailable";
    }
    if (column === "remediation_status") {
      return (row.remediation && row.remediation.status) || "unavailable";
    }
    if (column === "remediation_kinds") {
      return row.remediation_kinds && row.remediation_kinds.length
        ? row.remediation_kinds
        : "unavailable";
    }
    if (column === "snapshot_id") {
      return catalogSnapshotMeta && catalogSnapshotMeta.snapshot_id;
    }
    if (column === "snapshot_generated_at") {
      return catalogSnapshotMeta && catalogSnapshotMeta.generated_at;
    }
    if (column === "kev_catalog_url") {
      return row.links && row.links.kev_catalog;
    }
    if (column === "cve_record_url") {
      return row.links && row.links.cve_record;
    }
    if (column === "cvelist_v5_url") {
      return row.links && row.links.cvelist_v5;
    }
    if (column === "nvd_url") {
      return row.links && row.links.nvd;
    }
    if (column === "nvd_status") {
      return row.nvd_status || "unavailable";
    }
    if (column === "cvss_versions") {
      return row.cvss_versions && row.cvss_versions.length ? row.cvss_versions : "unavailable";
    }
    if (column === "cvss_sources") {
      return row.cvss_sources && row.cvss_sources.length ? row.cvss_sources : "unavailable";
    }
    if (column === "attack_vector") {
      return row.attack_vector && row.attack_vector.length ? row.attack_vector : "unavailable";
    }
    if (column === "privileges_required") {
      return row.privileges_required && row.privileges_required.length
        ? row.privileges_required
        : "unavailable";
    }
    if (column === "user_interaction") {
      return row.user_interaction && row.user_interaction.length
        ? row.user_interaction
        : "unavailable";
    }
    if (column === "cwe_ids") {
      return row.cwe_ids && row.cwe_ids.length ? row.cwe_ids : "unavailable";
    }
    if (column === "has_fixed_version") {
      return row.has_fixed_version === true ? true : row.has_fixed_version === false ? false : "unavailable";
    }
    if (column === "has_vendor_advisory") {
      return row.has_vendor_advisory === true
        ? true
        : row.has_vendor_advisory === false
          ? false
          : "unavailable";
    }
    if (column === "has_affected_versions") {
      return row.has_affected_versions === true
        ? true
        : row.has_affected_versions === false
          ? false
          : "unavailable";
    }
    if (column === "source_conflicts") {
      return row.source_conflicts && row.source_conflicts.length
        ? row.source_conflicts
        : "unavailable";
    }
    return row[column];
  }

  function exportFilteredCsv() {
    if (!catalogLoaded) {
      return;
    }
    var lines = [CSV_COLUMNS.map(quoteCsv).join(",")];
    filteredCatalog.forEach(function (row) {
      lines.push(
        CSV_COLUMNS.map(function (column) {
          return quoteCsv(sanitizeCsvCell(csvField(row, column)));
        }).join(",")
      );
    });
    var blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "silastron-pulse-filtered.csv");
    link.textContent = "Download filtered CSV";
    link.click();
    URL.revokeObjectURL(url);
  }

  var REMEDIATION_LABELS = {
    required_action: "Required Action",
    verified_fix: "CNA-Reported Solution",
    mitigation: "Mitigation",
    reference: "Reference",
  };

  function buildRemediation(remediation) {
    var section = document.createElement("div");
    var heading = document.createElement("p");
    heading.className = "detail-label";
    heading.textContent = "Remediation";
    section.appendChild(heading);
    var items = remediation && Array.isArray(remediation.items) ? remediation.items : [];
    if (!remediation || remediation.status !== "available" || !items.length) {
      var empty = document.createElement("p");
      empty.textContent = "No verified remediation data";
      section.appendChild(empty);
      return section;
    }
    var list = document.createElement("ul");
    items.forEach(function (item) {
      var li = document.createElement("li");
      var kind = document.createElement("strong");
      kind.textContent = REMEDIATION_LABELS[item.kind] || "Reference";
      li.appendChild(kind);
      li.appendChild(document.createTextNode(" · " + asText(item.attribution)));
      if (item.text) {
        var text = document.createElement("div");
        text.textContent = asText(item.text);
        li.appendChild(text);
      }
      var url = safePublicHttpsUrl(item.url);
      if (url) {
        var linkWrap = document.createElement("div");
        var anchor = document.createElement("a");
        anchor.setAttribute("href", url);
        anchor.setAttribute("rel", "noopener noreferrer");
        anchor.setAttribute("target", "_blank");
        anchor.textContent = url;
        linkWrap.appendChild(anchor);
        li.appendChild(linkWrap);
      } else if (item.url) {
        var unavailable = document.createElement("div");
        unavailable.textContent = "Reference URL unavailable";
        li.appendChild(unavailable);
      }
      list.appendChild(li);
    });
    section.appendChild(list);
    return section;
  }

  function renderRows(tbody, rows, options) {
    tbody.textContent = "";
    var showChange = options && options.showChange;
    var showDetails = options && options.showDetails;
    var colSpan = 7 + (showChange ? 1 : 0) + (showDetails ? 1 : 0);
    if (!rows.length) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = colSpan;
      cell.textContent = options && options.emptyText ? options.emptyText : "No rows to display.";
      empty.appendChild(cell);
      tbody.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var cve = labeledCell("CVE");
      appendCvePulseLink(cve, row.cve_id);
      tr.appendChild(cve);
      if (showChange) {
        var change = labeledCell("Change");
        change.textContent = asText(row.change);
        tr.appendChild(change);
      }
      var product = labeledCell("Vendor / product");
      product.textContent = asText(row.vendor_project) + " / " + asText(row.product);
      if (row.vulnerability_name) {
        var name = document.createElement("div");
        name.className = "product-name";
        name.textContent = asText(row.vulnerability_name);
        product.appendChild(name);
      }
      tr.appendChild(product);
      var added = labeledCell("KEV added");
      added.textContent = asText(row.kev_date_added);
      tr.appendChild(added);
      var completeness = labeledCell("Completeness");
      var pill = document.createElement("span");
      pill.className = "pill ok";
      if (row.completeness === "partial" || row.partial) {
        pill.className = "pill warn";
      } else if (row.completeness === "unavailable") {
        pill.className = "pill danger";
      }
      pill.textContent = completenessLabel(row);
      completeness.appendChild(pill);
      tr.appendChild(completeness);
      var cvss = labeledCell("CVSS");
      var band = cvssBand(row);
      cvss.textContent = cvssLabel(row);
      if (band) {
        cvss.className = "severity-" + band;
        var mark = document.createElement("span");
        mark.className = "severity-text";
        mark.textContent = " " + band;
        cvss.appendChild(mark);
      }
      tr.appendChild(cvss);
      var epss = labeledCell("EPSS");
      epss.textContent = epssLabel(row);
      tr.appendChild(epss);
      var links = labeledCell("Sources");
      addLink(links, row.links && row.links.cve_record, "CVE record");
      addLink(links, row.links && row.links.kev_catalog, "KEV catalog");
      addLink(links, row.links && row.links.cvelist_v5, "CVE List V5");
      addLink(links, row.links && row.links.nvd, "NVD");
      tr.appendChild(links);
      if (showDetails) {
        var detailsCell = labeledCell("Details");
        detailsCell.appendChild(buildRecordDetails(row));
        tr.appendChild(detailsCell);
      }
      tbody.appendChild(tr);
    });
  }

  function sideObject(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  }

  function objectHasKey(value, key) {
    return !!(sideObject(value) && Object.prototype.hasOwnProperty.call(value, key));
  }

  function fieldPair(before, after, key) {
    var hasBefore = objectHasKey(before, key);
    var hasAfter = objectHasKey(after, key);
    if (!hasBefore && !hasAfter) {
      return null;
    }
    var previousValue = hasBefore ? before[key] : undefined;
    var currentValue = hasAfter ? after[key] : undefined;
    if (hasBefore && hasAfter && previousValue === currentValue) {
      return null;
    }
    return {
      field: FIELD_LABELS[key] || key,
      previous: hasBefore ? previousValue : "Not in previous published snapshot",
      current: hasAfter ? currentValue : "Removed from current published snapshot",
    };
  }

  function displayableChangedFields(row) {
    var before = sideObject(row && row.before);
    var after = sideObject(row && row.after);
    var declared = row && Array.isArray(row.changed_fields) ? row.changed_fields.slice() : [];
    var keys = declared;
    if (!keys.length) {
      keys = [];
      [before, after].forEach(function (side) {
        if (!side) {
          return;
        }
        Object.keys(side).forEach(function (key) {
          if (keys.indexOf(key) === -1) {
            keys.push(key);
          }
        });
      });
    }
    return keys.filter(function (key) {
      return fieldPair(before, after, key) != null;
    });
  }

  function classifyPublishedComparison(comparison) {
    var empty = {
      available: false,
      added_count: null,
      removed_count: null,
      updated_count: null,
      enrichment_count: null,
      unresolved_count: null,
      field_evidence: null,
      added_rows: [],
      removed_rows: [],
      core_rows: [],
      enrichment_rows: [],
      unresolved_rows: [],
      enrichment_sample: [],
    };
    if (!comparison || comparison.available !== true) {
      return empty;
    }
    var addedRows = [];
    var removedRows = [];
    var coreRows = [];
    var enrichmentRows = [];
    var unresolvedRows = [];
    (comparison.rows || []).forEach(function (row) {
      var cats = row.categories || [];
      if (cats.indexOf("added_kev") !== -1) {
        addedRows.push(row);
        return;
      }
      if (cats.indexOf("removed_kev") !== -1) {
        removedRows.push(row);
        return;
      }
      var fields = displayableChangedFields(row);
      var hasCoreCat = cats.some(function (item) {
        return CORE_CHANGE_CATEGORIES[item];
      });
      var enrichmentOnly = cats.some(function (item) {
        return ENRICHMENT_CHANGE_CATEGORIES[item];
      }) && !hasCoreCat && cats.indexOf("cve_update") === -1;
      if (enrichmentOnly) {
        enrichmentRows.push(row);
      } else if (hasCoreCat || fields.length) {
        coreRows.push(row);
      } else {
        unresolvedRows.push(row);
      }
    });
    var publishedUpdated = comparison.updated_count;
    var publishedEnrichment = comparison.enrichment_count;
    var updated;
    var enrichment;
    var unresolvedCount;
    var fieldEvidence;
    if (typeof publishedEnrichment === "number") {
      updated = typeof publishedUpdated === "number" ? publishedUpdated : coreRows.length;
      enrichment = publishedEnrichment;
      unresolvedCount = 0;
      fieldEvidence = "stored";
    } else if (typeof publishedUpdated === "number" && publishedUpdated === 0 && !unresolvedRows.length) {
      updated = 0;
      enrichment = 0;
      unresolvedCount = 0;
      fieldEvidence = "stored";
    } else {
      updated = null;
      enrichment = null;
      unresolvedCount = typeof publishedUpdated === "number" ? publishedUpdated : unresolvedRows.length;
      fieldEvidence = "unavailable";
    }
    var sample = Array.isArray(comparison.enrichment_sample)
      ? comparison.enrichment_sample.filter(function (item) {
          return typeof item === "string";
        })
      : enrichmentRows.map(function (row) {
          return row.cve_id;
        });
    return {
      available: true,
      added_count: comparison.added_count,
      removed_count: comparison.removed_count,
      updated_count: updated,
      enrichment_count: enrichment,
      unresolved_count: unresolvedCount,
      field_evidence: fieldEvidence,
      added_rows: addedRows,
      removed_rows: removedRows,
      core_rows: coreRows,
      enrichment_rows: enrichmentRows,
      unresolved_rows: unresolvedRows,
      enrichment_sample: sample.slice(0, 8),
    };
  }

  function changedFieldsLabel(row) {
    var cats = row.categories || [];
    if (cats.indexOf("added_kev") !== -1) {
      return "New in current published snapshot";
    }
    if (cats.indexOf("removed_kev") !== -1) {
      return "Removed from current published snapshot";
    }
    var fields = displayableChangedFields(row);
    if (!fields.length) {
      return "Stored values are unchanged";
    }
    return fields
      .map(function (item) {
        return FIELD_LABELS[item] || item;
      })
      .join(", ");
  }

  function buildBeforeAfter(row) {
    var pairs = [];
    var keys = row.changed_fields && row.changed_fields.length
      ? row.changed_fields
      : displayableChangedFields(row);
    keys.forEach(function (key) {
      var pair = fieldPair(row.before, row.after, key);
      if (pair) {
        pairs.push(pair);
      }
    });
    if (!pairs.length) {
      return null;
    }
    var details = document.createElement("details");
    var summary = document.createElement("summary");
    summary.textContent = "Before and after";
    details.appendChild(summary);
    var table = document.createElement("table");
    table.className = "diff-table";
    var caption = document.createElement("caption");
    caption.className = "visually-hidden";
    caption.textContent = "Published values before and after for " + asText(row.cve_id);
    table.appendChild(caption);
    var thead = document.createElement("thead");
    var headRow = document.createElement("tr");
    ["Field", "Previous published", "Current published"].forEach(function (label) {
      var th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");
    pairs.forEach(function (pair) {
      var tr = document.createElement("tr");
      var field = document.createElement("th");
      field.scope = "row";
      field.textContent = pair.field;
      var previous = document.createElement("td");
      previous.textContent = asText(pair.previous);
      var current = document.createElement("td");
      current.textContent = asText(pair.current);
      tr.appendChild(field);
      tr.appendChild(previous);
      tr.appendChild(current);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    details.appendChild(table);
    return details;
  }

  function appendCount(list, label, value) {
    var item = document.createElement("li");
    var strong = document.createElement("strong");
    strong.textContent = value === null || value === undefined ? "Unavailable" : String(value);
    item.appendChild(strong);
    item.appendChild(document.createTextNode(" " + label));
    list.appendChild(item);
  }

  function renderChangeGroup(title, rows) {
    if (!rows.length) {
      return;
    }
    var details = document.createElement("details");
    var summary = document.createElement("summary");
    summary.textContent = title + " (" + String(rows.length) + ")";
    details.appendChild(summary);
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    var table = document.createElement("table");
    var caption = document.createElement("caption");
    caption.className = "visually-hidden";
    caption.textContent = title;
    table.appendChild(caption);
    var thead = document.createElement("thead");
    var headRow = document.createElement("tr");
    ["CVE", "Categories", "Changed fields", "Sources", "Details"].forEach(function (label) {
      var th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var cve = labeledCell("CVE");
      appendCvePulseLink(cve, row.cve_id);
      tr.appendChild(cve);
      var cats = labeledCell("Categories");
      cats.textContent = (row.categories || [])
        .map(function (item) {
          return CATEGORY_LABELS[item] || item;
        })
        .join("; ");
      tr.appendChild(cats);
      var fields = labeledCell("Changed fields");
      fields.textContent = changedFieldsLabel(row);
      tr.appendChild(fields);
      var links = labeledCell("Sources");
      addLink(links, row.links && row.links.cve_record, "CVE record");
      addLink(links, row.links && row.links.kev_catalog, "KEV catalog");
      addLink(links, row.links && row.links.cvelist_v5, "CVE List V5");
      addLink(links, row.links && row.links.nvd, "NVD");
      tr.appendChild(links);
      var detailsCell = labeledCell("Details");
      var beforeAfter = buildBeforeAfter(row);
      if (beforeAfter) {
        detailsCell.appendChild(beforeAfter);
      } else {
        detailsCell.textContent = changedFieldsLabel(row);
      }
      tr.appendChild(detailsCell);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    details.appendChild(wrap);
    changesBody.appendChild(details);
  }

  function renderPublicationComparison(comparison) {
    changesBody.textContent = "";
    var classified = classifyPublishedComparison(comparison);
    if (!classified.available) {
      changesNote.textContent =
        "No comparison available. Baseline unavailable because no immediately preceding published snapshot was retained or the previous published snapshot is incompatible.";
      var unavailable = document.createElement("p");
      unavailable.className = "empty-state";
      unavailable.textContent = "No comparison available";
      changesBody.appendChild(unavailable);
      return;
    }
    var note =
      "Published-to-published comparison against snapshot " +
      asText(comparison.compared_to_snapshot_id) +
      " generated " +
      formatInstant(comparison.compared_to_generated_at) +
      ". Retrieval timestamps are not treated as vulnerability updates. Collect-time candidate diffs are not shown here. Newly extracted remediation is not counted as a KEV, CVE, CVSS, or completeness update.";
    if (comparison.truncated) {
      note += " Record-level rows are a bounded subset. Truncation is not proof that omitted updates are enrichment or that core field changes are absent.";
    }
    changesNote.textContent = note;
    var summary = document.createElement("ul");
    summary.className = "change-summary";
    appendCount(summary, "newly added to KEV", classified.added_count);
    appendCount(summary, "removed from KEV", classified.removed_count);
    if (classified.field_evidence === "unavailable") {
      appendCount(
        summary,
        "confirmed KEV, CVE, CVSS, or completeness field changes. This published comparison listed updates without stored field-level before/after values, so that count is unavailable rather than zero.",
        classified.updated_count
      );
      appendCount(
        summary,
        "confirmed newly extracted remediation changes. Missing field-level diffs are not treated as enrichment.",
        classified.enrichment_count
      );
    } else {
      appendCount(
        summary,
        "records with KEV, CVE, CVSS, or completeness field changes",
        classified.updated_count
      );
      appendCount(
        summary,
        "existing records that now include extracted remediation evidence. That is not a change to those CVEs' upstream vulnerability facts.",
        classified.enrichment_count
      );
    }
    changesBody.appendChild(summary);
    renderChangeGroup("Newly added KEV entries", classified.added_rows);
    renderChangeGroup("Removed KEV entries", classified.removed_rows);
    renderChangeGroup("Records with field-level updates", classified.core_rows);
    if (classified.unresolved_count) {
      var unresolved = document.createElement("p");
      unresolved.className = "empty-state";
      unresolved.textContent =
        String(classified.unresolved_count) +
        " listed updates have no stored field-level before/after values. They are not shown as individual rows, and missing values are not treated as remediation enrichment or as confirmed core vulnerability changes.";
      changesBody.appendChild(unresolved);
    }
    if (classified.enrichment_count) {
      var enrichment = document.createElement("details");
      var enrichmentSummary = document.createElement("summary");
      enrichmentSummary.textContent =
        "Extracted remediation evidence newly present (" +
        String(classified.enrichment_count) +
        ")";
      enrichment.appendChild(enrichmentSummary);
      var explain = document.createElement("p");
      explain.textContent =
        "These IDs were already in the previous published snapshot. The collector now extracts CNA solutions, workarounds, vendor advisories, or KEV required actions. That enrichment is not a newly changed upstream KEV/CVE/CVSS fact.";
      enrichment.appendChild(explain);
      if (classified.enrichment_sample.length) {
        var sample = document.createElement("p");
        sample.textContent = "Examples: " + classified.enrichment_sample.join(", ");
        enrichment.appendChild(sample);
      }
      changesBody.appendChild(enrichment);
    }
    if (
      !classified.added_rows.length &&
      !classified.removed_rows.length &&
      !classified.core_rows.length &&
      !classified.unresolved_count &&
      !classified.enrichment_count
    ) {
      var empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No published-to-published record changes.";
      changesBody.appendChild(empty);
    }
  }

  function fallbackRemediation(kev) {
    var items = [];
    if (kev.required_action) {
      items.push({
        kind: "required_action",
        source: "cisa_kev",
        attribution: "CISA KEV requiredAction",
        text: kev.required_action,
      });
    }
    if (kev.notes) {
      items.push({
        kind: "reference",
        source: "cisa_kev",
        attribution: "CISA KEV notes",
        text: kev.notes,
      });
    }
    return {
      status: items.length ? "available" : "unavailable",
      items: items,
    };
  }

  function compactRecord(record) {
    var cve = record.cve || {};
    var kev = record.kev || {};
    var epss = record.epss || {};
    var links = record.links || {};
    var severity = cve.severity && typeof cve.severity === "object" ? cve.severity : {};
    var products = Array.isArray(cve.products) ? cve.products.slice(0, PRODUCT_DETAIL_LIMIT) : [];
    return {
      cve_id: record.cve_id,
      vendor_project: kev.vendor_project,
      product: kev.product,
      vulnerability_name: kev.vulnerability_name,
      kev_date_added: kev.date_added,
      kev_listed: kev.listed !== false,
      completeness: record.completeness,
      omitted_product_count: cve.omitted_product_count || 0,
      omitted_version_count: cve.omitted_version_count || 0,
      truncated_fields: (cve.truncated_fields || []).concat(kev.truncated_fields || []),
      partial: Boolean((cve.truncated_fields || []).length) || cve.status !== "ok",
      cvss_base_score: severity.base_score,
      severity_status: severity.base_score === null || severity.base_score === undefined ? "unavailable" : "available",
      cvss_vector: severity.vector,
      epss_status: epss.status,
      epss_score: epss.score,
      short_description: kev.short_description,
      required_action: kev.required_action,
      due_date: kev.due_date,
      known_ransomware_campaign_use: kev.known_ransomware_campaign_use,
      cwes: Array.isArray(kev.cwes) ? kev.cwes.slice() : [],
      cve_state: cve.state,
      cve_description: cve.description,
      products: products.map(function (item) {
        var versions = Array.isArray(item.versions) ? item.versions.slice(0, VERSION_DETAIL_LIMIT) : [];
        return [item.vendor, item.product, item.status].filter(Boolean).join(" / ") +
          (versions.length ? " (" + versions.join(", ") + ")" : "");
      }),
      remediation: record.remediation || fallbackRemediation(kev),
      remediation_kinds: remediationKinds(record.remediation || fallbackRemediation(kev)),
      links: {
        cve_record: links.cve_record,
        kev_catalog: links.kev_catalog,
        cvelist_v5: links.cvelist_v5,
        nvd: links.nvd,
      },
      intelligence: record.intelligence && typeof record.intelligence === "object" ? record.intelligence : null,
      cwe_ids: intelligenceCweIds(record),
      cvss_versions: intelligenceValues(record, "cvss_version"),
      cvss_sources: intelligenceValues(record, "source"),
      attack_vector: intelligenceMetrics(record, "attackVector"),
      privileges_required: intelligenceMetrics(record, "privilegesRequired"),
      user_interaction: intelligenceMetrics(record, "userInteraction"),
      has_fixed_version: coverageFlag(record, "has_fixed_version"),
      has_vendor_advisory: coverageFlag(record, "has_vendor_advisory"),
      has_affected_versions: coverageFlag(record, "has_affected_versions"),
      nvd_status: nvdStatus(record),
      source_conflicts: conflictKinds(record),
    };
  }

  function coverageFlag(record, key) {
    var intel = record.intelligence;
    if (!intel || !intel.coverage) {
      return null;
    }
    return intel.coverage[key] === true;
  }

  function nvdStatus(record) {
    var intel = record.intelligence;
    if (!intel || !intel.sources || !intel.sources.nvd) {
      return "unavailable";
    }
    return intel.sources.nvd.status || "unavailable";
  }

  function conflictKinds(record) {
    var intel = record.intelligence;
    if (!intel || !Array.isArray(intel.conflicts)) {
      return [];
    }
    return intel.conflicts
      .map(function (item) {
        return item && item.kind ? String(item.kind) : "";
      })
      .filter(Boolean);
  }

  function intelligenceCweIds(record) {
    var ids = {};
    (record.kev && Array.isArray(record.kev.cwes) ? record.kev.cwes : []).forEach(function (item) {
      if (item) {
        ids[String(item)] = true;
      }
    });
    var assertions =
      record.intelligence && record.intelligence.cwes && Array.isArray(record.intelligence.cwes.assertions)
        ? record.intelligence.cwes.assertions
        : [];
    assertions.forEach(function (item) {
      if (item && item.cwe_id) {
        ids[String(item.cwe_id)] = true;
      }
    });
    return Object.keys(ids).sort();
  }

  function intelligenceAssessments(record) {
    var intel = record.intelligence;
    if (!intel || !intel.cvss || !Array.isArray(intel.cvss.assessments)) {
      return [];
    }
    return intel.cvss.assessments;
  }

  function intelligenceValues(record, key) {
    var seen = {};
    intelligenceAssessments(record).forEach(function (item) {
      if (item && item[key]) {
        seen[String(item[key])] = true;
      }
    });
    return Object.keys(seen).sort();
  }

  function intelligenceMetrics(record, key) {
    var seen = {};
    intelligenceAssessments(record).forEach(function (item) {
      var metrics = item && item.metrics && typeof item.metrics === "object" ? item.metrics : {};
      var value = metrics[key] || (key === "attackVector" ? metrics.accessVector : "");
      if (value) {
        seen[String(value)] = true;
      }
    });
    return Object.keys(seen).sort();
  }

  function remediationKinds(remediation) {
    if (!remediation || !Array.isArray(remediation.items)) {
      return [];
    }
    return remediation.items
      .map(function (item) {
        return item && item.kind ? String(item.kind) : "";
      })
      .filter(Boolean);
  }

  function cvssMatches(row, band) {
    if (band === "all") {
      return true;
    }
    var score = row.cvss_base_score;
    if (score === null || score === undefined || row.severity_status !== "available") {
      return band === "unavailable";
    }
    var numeric = Number(score);
    if (!isFinite(numeric)) {
      return band === "unavailable";
    }
    if (band === "unavailable") {
      return false;
    }
    if (band === "critical") {
      return numeric >= 9;
    }
    if (band === "high") {
      return numeric >= 7 && numeric < 9;
    }
    if (band === "medium") {
      return numeric >= 4 && numeric < 7;
    }
    if (band === "low") {
      return numeric > 0 && numeric < 4;
    }
    return true;
  }

  function rowMatches(row, filters) {
    var completeness = filters.completeness || "all";
    if (completeness !== "all" && row.completeness !== completeness) {
      return false;
    }
    if (!cvssMatches(row, filters.cvss || "all")) {
      return false;
    }
    if (!cvssRangeMatches(row, filters.cvssMin, filters.cvssMax)) {
      return false;
    }
    var isTruncated = (row.truncated_fields || []).indexOf("versions") !== -1 || Number(row.omitted_version_count) > 0;
    if (filters.truncated === "truncated" && !isTruncated) {
      return false;
    }
    if (filters.vendor && filters.vendor !== "all" && (row.vendor_project || "") !== filters.vendor) {
      return false;
    }
    if (filters.product && filters.product !== "all" && (row.product || "") !== filters.product) {
      return false;
    }
    if (!dateInRange(row.kev_date_added, filters.dateFrom, filters.dateTo)) {
      return false;
    }
    if (!cweMatches(row, filters.cwe)) {
      return false;
    }
    if (!listFilterMatches(row.cvss_versions, filters.cvssVersion)) {
      return false;
    }
    if (!listFilterMatches(row.attack_vector, filters.attackVector)) {
      return false;
    }
    if (!listFilterMatches(row.privileges_required, filters.privilegesRequired)) {
      return false;
    }
    if (!listFilterMatches(row.user_interaction, filters.userInteraction)) {
      return false;
    }
    if (!flagFilterMatches(row.has_fixed_version, filters.fixedVersion)) {
      return false;
    }
    if (!flagFilterMatches(row.has_vendor_advisory, filters.vendorAdvisory)) {
      return false;
    }
    if (!nvdFilterMatches(row.nvd_status, filters.nvd)) {
      return false;
    }
    if (!remediationMatches(row, filters.remediation)) {
      return false;
    }
    var query = filters.query || "";
    if (!query) {
      return true;
    }
    var haystack = [
      row.cve_id,
      row.vendor_project,
      row.product,
      row.vulnerability_name,
      row.cve_description,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.indexOf(query) !== -1;
  }

  function cvssRangeMatches(row, minValue, maxValue) {
    if ((minValue === "" || minValue == null) && (maxValue === "" || maxValue == null)) {
      return true;
    }
    if (row.severity_status !== "available" || row.cvss_base_score == null) {
      return false;
    }
    var numeric = Number(row.cvss_base_score);
    if (!isFinite(numeric)) {
      return false;
    }
    if (minValue !== "" && minValue != null && numeric < Number(minValue)) {
      return false;
    }
    if (maxValue !== "" && maxValue != null && numeric > Number(maxValue)) {
      return false;
    }
    return true;
  }

  function dateInRange(value, start, end) {
    if (!start && !end) {
      return true;
    }
    if (!value) {
      return false;
    }
    if (start && String(value) < String(start)) {
      return false;
    }
    if (end && String(value) > String(end)) {
      return false;
    }
    return true;
  }

  function cweMatches(row, wanted) {
    if (!wanted || wanted === "all") {
      return true;
    }
    var cwes = Array.isArray(row.cwe_ids) && row.cwe_ids.length ? row.cwe_ids : row.cwes || [];
    if (wanted === "unavailable") {
      return cwes.length === 0;
    }
    return cwes.indexOf(wanted) !== -1;
  }

  function listFilterMatches(values, wanted) {
    if (!wanted || wanted === "all") {
      return true;
    }
    var items = Array.isArray(values) ? values : [];
    if (wanted === "unavailable") {
      return items.length === 0;
    }
    return items.indexOf(wanted) !== -1;
  }

  function flagFilterMatches(value, wanted) {
    if (!wanted || wanted === "all") {
      return true;
    }
    if (wanted === "available") {
      return value === true;
    }
    return value !== true;
  }

  function nvdFilterMatches(status, wanted) {
    if (!wanted || wanted === "all") {
      return true;
    }
    if (wanted === "ok") {
      return status === "ok";
    }
    return status !== "ok";
  }

  function remediationMatches(row, wanted) {
    if (!wanted || wanted === "all") {
      return true;
    }
    var status = row.remediation && row.remediation.status ? row.remediation.status : "unavailable";
    var kinds = row.remediation_kinds || [];
    if (wanted === "unavailable") {
      return status !== "available";
    }
    if (wanted === "available") {
      return status === "available";
    }
    return kinds.indexOf(wanted) !== -1;
  }

  function sortRows(rows, key) {
    var copy = rows.slice();
    copy.sort(function (left, right) {
      if (key === "cvss_base_score") {
        var lv = left.cvss_base_score;
        var rv = right.cvss_base_score;
        if (lv == null && rv == null) {
          return String(left.cve_id).localeCompare(String(right.cve_id));
        }
        if (lv == null) {
          return 1;
        }
        if (rv == null) {
          return -1;
        }
        return Number(rv) - Number(lv);
      }
      if (key === "cve_id" || key === "vendor_project") {
        return String(left[key] || "").localeCompare(String(right[key] || ""));
      }
      var lDate = String(left.kev_date_added || "");
      var rDate = String(right.kev_date_added || "");
      if (lDate === rDate) {
        return String(right.cve_id || "").localeCompare(String(left.cve_id || ""));
      }
      return rDate.localeCompare(lDate);
    });
    return copy;
  }

  function currentCatalogFilters() {
    return {
      query: catalogQuery ? (catalogQuery.value || "").trim().toLowerCase() : "",
      vendor: catalogVendor ? catalogVendor.value : "all",
      product: catalogProduct ? catalogProduct.value : "all",
      dateFrom: catalogDateFrom ? catalogDateFrom.value : "",
      dateTo: catalogDateTo ? catalogDateTo.value : "",
      completeness: catalogCompleteness ? catalogCompleteness.value : "all",
      truncated: catalogTruncated ? catalogTruncated.value : "all",
      cvss: catalogCvss ? catalogCvss.value : "all",
      cvssMin: catalogCvssMin ? catalogCvssMin.value : "",
      cvssMax: catalogCvssMax ? catalogCvssMax.value : "",
      cwe: catalogCwe ? catalogCwe.value : "all",
      cvssVersion: catalogCvssVersion ? catalogCvssVersion.value : "all",
      attackVector: catalogAttackVector ? catalogAttackVector.value : "all",
      privilegesRequired: catalogPrivileges ? catalogPrivileges.value : "all",
      userInteraction: catalogUserInteraction ? catalogUserInteraction.value : "all",
      fixedVersion: catalogFixedVersion ? catalogFixedVersion.value : "all",
      vendorAdvisory: catalogVendorAdvisory ? catalogVendorAdvisory.value : "all",
      nvd: catalogNvd ? catalogNvd.value : "all",
      remediation: catalogRemediation ? catalogRemediation.value : "all",
      sort: catalogSort ? catalogSort.value : "kev_date_added",
    };
  }

  function applyCatalogFilters() {
    var filters = currentCatalogFilters();
    var sorted = sortRows(catalogRows, filters.sort);
    filteredCatalog = sorted.filter(function (row) {
      return rowMatches(row, filters);
    });
    var maxPage = Math.max(0, Math.ceil(filteredCatalog.length / PAGE_SIZE) - 1);
    if (catalogPageIndex > maxPage) {
      catalogPageIndex = maxPage;
    }
    var start = catalogPageIndex * PAGE_SIZE;
    var pageRows = filteredCatalog.slice(start, start + PAGE_SIZE);
    renderRows(catalogBody, pageRows, {
      showChange: false,
      showDetails: true,
      emptyText: catalogLoaded ? "No published records match this search." : "Catalog not loaded.",
    });
    var pageLabel = catalogLoaded
      ? filteredCatalog.length
        ? "Showing " +
          String(start + 1) +
          "–" +
          String(start + pageRows.length) +
          " of " +
          String(filteredCatalog.length)
        : "0 matching records"
      : "Catalog not loaded.";
    catalogPage.textContent = pageLabel;
    catalogPrev.disabled = !catalogLoaded || catalogPageIndex <= 0;
    catalogNext.disabled = !catalogLoaded || start + PAGE_SIZE >= filteredCatalog.length;
  }

  function setCatalogEnabled(enabled) {
    var controls = [
      catalogQuery,
      catalogVendor,
      catalogProduct,
      catalogDateFrom,
      catalogDateTo,
      catalogCompleteness,
      catalogTruncated,
      catalogSort,
      catalogCvss,
      catalogCvssMin,
      catalogCvssMax,
      catalogCwe,
      catalogCvssVersion,
      catalogAttackVector,
      catalogPrivileges,
      catalogUserInteraction,
      catalogFixedVersion,
      catalogVendorAdvisory,
      catalogNvd,
      catalogRemediation,
      catalogClear,
      catalogExport,
    ];
    controls.forEach(function (control) {
      if (control) {
        control.disabled = !enabled;
      }
    });
  }

  function fillSelect(select, values, allLabel, unavailableLabel) {
    if (!select) {
      return;
    }
    var current = select.value || "all";
    select.textContent = "";
    var all = document.createElement("option");
    all.value = "all";
    all.textContent = allLabel;
    select.appendChild(all);
    if (unavailableLabel) {
      var missing = document.createElement("option");
      missing.value = "unavailable";
      missing.textContent = unavailableLabel;
      select.appendChild(missing);
    }
    values.forEach(function (value) {
      var option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      select.appendChild(option);
    });
    select.value = current;
    if (select.value !== current) {
      select.value = "all";
    }
  }

  function uniqueSorted(values) {
    var seen = {};
    var out = [];
    values.forEach(function (value) {
      if (!value || seen[value]) {
        return;
      }
      seen[value] = true;
      out.push(value);
    });
    out.sort(function (left, right) {
      return left.localeCompare(right);
    });
    return out;
  }

  function populateCatalogFacets() {
    fillSelect(
      catalogVendor,
      uniqueSorted(
        catalogRows.map(function (row) {
          return row.vendor_project;
        })
      ),
      "All vendors"
    );
    var vendor = catalogVendor && catalogVendor.value !== "all" ? catalogVendor.value : "";
    fillSelect(
      catalogProduct,
      uniqueSorted(
        catalogRows
          .filter(function (row) {
            return !vendor || row.vendor_project === vendor;
          })
          .map(function (row) {
            return row.product;
          })
      ),
      "All products"
    );
    var cwes = [];
    catalogRows.forEach(function (row) {
      (row.cwe_ids && row.cwe_ids.length ? row.cwe_ids : row.cwes || []).forEach(function (cwe) {
        cwes.push(cwe);
      });
    });
    fillSelect(catalogCwe, uniqueSorted(cwes), "All", "CWE unavailable");
  }

  function loadJson(path) {
    return fetch(path, { credentials: "same-origin" }).then(function (response) {
      if (response.status === 404) {
        return null;
      }
      if (!response.ok) {
        throw new Error("Failed to load " + path);
      }
      return response.json();
    });
  }

  function parseCveHash() {
    var match = String(window.location.hash || "").match(/^#cve\/(CVE-[0-9]{4}-[0-9]{4,})$/);
    return match ? match[1] : null;
  }

  function applyCveHash() {
    var cveId = parseCveHash();
    if (!cveDetail) {
      return;
    }
    if (!cveId) {
      cveDetail.hidden = true;
      if (cveDetailBody) {
        cveDetailBody.textContent = "";
      }
      return;
    }
    cveDetail.hidden = false;
    if (!catalogLoaded) {
      if (cveDetailStatus) {
        cveDetailStatus.textContent = "Loading published catalog for " + cveId + ".";
      }
      loadCatalog();
      return;
    }
    renderCveDetail(cveId);
  }

  function renderCveDetail(cveId) {
    if (!cveDetailBody || !cveDetailHeading) {
      return;
    }
    cveDetailBody.textContent = "";
    cveDetailHeading.textContent = cveId;
    var row = null;
    catalogRows.forEach(function (item) {
      if (item.cve_id === cveId) {
        row = item;
      }
    });
    if (!row) {
      if (cveDetailStatus) {
        cveDetailStatus.textContent = "This CVE is not in the published snapshot.";
      }
      return;
    }
    if (cveDetailStatus) {
      cveDetailStatus.textContent = "Source-attributed intelligence for " + cveId + ". No composite risk score.";
    }
    var intel = row.intelligence || {};
    appendDetailSection(cveDetailBody, "Identity", function (section) {
      var list = document.createElement("dl");
      list.className = "meta-list";
      var identity = intel.identity || {};
      appendNamedMeta(list, "CVE ID", row.cve_id);
      appendNamedMeta(list, "CVE publication status", identity.cve_status || row.cve_state || "unavailable");
      appendNamedMeta(list, "CNA organization", identity.cna_organization || "unavailable");
      appendNamedMeta(list, "CVE published", identity.cve_published_at || "unavailable");
      appendNamedMeta(list, "CVE updated", identity.cve_updated_at || "unavailable");
      section.appendChild(list);
    });
    appendDetailSection(cveDetailBody, "KEV exploitation confirmation", function (section) {
      var kev = intel.kev || {};
      var list = document.createElement("dl");
      list.className = "meta-list";
      appendNamedMeta(list, "KEV added", kev.date_added || row.kev_date_added);
      appendNamedMeta(list, "Due date", kev.due_date || row.due_date);
      appendNamedMeta(list, "Required action", kev.required_action || row.required_action);
      appendNamedMeta(list, "Known ransomware campaign use", kev.known_ransomware_campaign_use || row.known_ransomware_campaign_use);
      appendNamedMeta(list, "CISA notes", kev.notes || "unavailable");
      appendNamedMeta(list, "Source", kev.source || "cisa_kev");
      section.appendChild(list);
    });
    appendDetailSection(cveDetailBody, "Technical description", function (section) {
      var descriptions = Array.isArray(intel.descriptions) ? intel.descriptions : [];
      if (!descriptions.length) {
        var fallback = document.createElement("p");
        fallback.textContent = asText(row.cve_description || row.short_description || "unavailable");
        section.appendChild(fallback);
        return;
      }
      descriptions.forEach(function (item) {
        var block = document.createElement("p");
        block.textContent =
          asText(item.source) +
          ": " +
          asText(item.text) +
          (item.source_updated_at ? " (updated " + asText(item.source_updated_at) + ")" : "");
        section.appendChild(block);
      });
    });
    appendDetailSection(cveDetailBody, "CVSS assessments", function (section) {
      var assessments = intel.cvss && Array.isArray(intel.cvss.assessments) ? intel.cvss.assessments : [];
      if (intel.cvss && intel.cvss.display_preference_note) {
        var note = document.createElement("p");
        note.textContent = asText(intel.cvss.display_preference_note);
        section.appendChild(note);
      }
      if (!assessments.length) {
        var empty = document.createElement("p");
        empty.textContent = "No structured CVSS assessment is available.";
        section.appendChild(empty);
        return;
      }
      section.appendChild(
        buildTable(
          ["Source", "Version", "Score", "Severity", "Vector", "AV", "PR", "UI"],
          assessments.map(function (item) {
            var metrics = item.metrics || {};
            return [
              item.source,
              item.cvss_version,
              item.base_score,
              item.severity,
              item.vector,
              metrics.attackVector || metrics.accessVector || "unavailable",
              metrics.privilegesRequired || "unavailable",
              metrics.userInteraction || "unavailable",
            ];
          })
        )
      );
    });
    appendDetailSection(cveDetailBody, "CWE classifications", function (section) {
      var assertions = intel.cwes && Array.isArray(intel.cwes.assertions) ? intel.cwes.assertions : [];
      if (!assertions.length) {
        var empty = document.createElement("p");
        empty.textContent = row.cwes && row.cwes.length ? row.cwes.join(", ") : "No CWE classification is available.";
        section.appendChild(empty);
        return;
      }
      section.appendChild(
        buildTable(
          ["CWE", "Name", "Source"],
          assertions.map(function (item) {
            return [item.cwe_id, item.name || "unavailable", item.source];
          })
        )
      );
    });
    appendDetailSection(cveDetailBody, "Affected products and versions", function (section) {
      var note = document.createElement("p");
      note.textContent =
        (intel.affected && intel.affected.note) ||
        "Affected ranges are source-specific. An upper bound is not a fixed version.";
      section.appendChild(note);
      var products = intel.affected && Array.isArray(intel.affected.products) ? intel.affected.products : [];
      if (!products.length) {
        var empty = document.createElement("p");
        empty.textContent = "No structured affected-version evidence is available.";
        section.appendChild(empty);
        return;
      }
      products.forEach(function (product) {
        var heading = document.createElement("p");
        heading.className = "detail-label";
        heading.textContent =
          asText(product.source) +
          " · " +
          asText(product.vendor || "unavailable") +
          " / " +
          asText(product.product || "unavailable");
        section.appendChild(heading);
        var ranges = Array.isArray(product.ranges) ? product.ranges : [];
        if (!ranges.length) {
          var missing = document.createElement("p");
          missing.textContent = "No version range evidence from this source.";
          section.appendChild(missing);
          return;
        }
        section.appendChild(
          buildTable(
            ["Status", "Version", "Greater than", "Greater or equal", "Less than", "Less or equal", "Type"],
            ranges.map(function (item) {
              return [
                item.status,
                item.version,
                item.greater_than,
                item.greater_than_or_equal,
                item.less_than,
                item.less_than_or_equal,
                item.version_type,
              ];
            })
          )
        );
      });
    });
    appendDetailSection(cveDetailBody, "Remediation and advisories", function (section) {
      var rem = intel.remediation || {};
      if (rem.note) {
        var note = document.createElement("p");
        note.textContent = asText(rem.note);
        section.appendChild(note);
      }
      var fixed = Array.isArray(rem.fixed_versions) ? rem.fixed_versions : [];
      if (!fixed.length) {
        var missing = document.createElement("p");
        missing.textContent = "No explicit fixed-version evidence. Affected-range upper bounds are not treated as patches.";
        section.appendChild(missing);
      } else {
        section.appendChild(
          buildTable(
            ["Vendor", "Product", "Fixed version", "Source", "Evidence"],
            fixed.map(function (item) {
              return [item.vendor, item.product, item.version, item.source, item.evidence];
            })
          )
        );
      }
      var advisories = Array.isArray(rem.vendor_advisories) ? rem.vendor_advisories : [];
      if (advisories.length) {
        var heading = document.createElement("p");
        heading.className = "detail-label";
        heading.textContent = "Vendor advisories";
        section.appendChild(heading);
        appendReferenceList(section, advisories);
      } else {
        var noAdv = document.createElement("p");
        noAdv.textContent = "No vendor advisory URL is available.";
        section.appendChild(noAdv);
      }
      section.appendChild(buildRemediation(row.remediation));
    });
    appendDetailSection(cveDetailBody, "References", function (section) {
      var refs = Array.isArray(intel.references) ? intel.references : [];
      if (!refs.length) {
        var empty = document.createElement("p");
        empty.textContent = "No validated HTTPS references are available.";
        section.appendChild(empty);
        return;
      }
      appendReferenceList(section, refs);
    });
    appendDetailSection(cveDetailBody, "Source availability and freshness", function (section) {
      var sources = intel.sources || {};
      section.appendChild(
        buildTable(
          ["Source", "Status", "Retrieved", "Upstream modified", "Completeness", "Error"],
          ["cisa_kev", "cve_list_v5", "nvd"].map(function (name) {
            var meta = sources[name] || {};
            return [
              name,
              meta.status || "unavailable",
              meta.retrieved_at || "unavailable",
              meta.upstream_modified_at || "unavailable",
              meta.completeness || "unavailable",
              meta.error || "none",
            ];
          })
        )
      );
      var conflicts = Array.isArray(intel.conflicts) ? intel.conflicts : [];
      if (conflicts.length) {
        var heading = document.createElement("p");
        heading.className = "detail-label";
        heading.textContent = "Conflicting source assertions";
        section.appendChild(heading);
        conflicts.forEach(function (item) {
          var block = document.createElement("p");
          block.textContent = asText(item.kind) + ": " + asText(item.note);
          section.appendChild(block);
        });
      } else {
        var none = document.createElement("p");
        none.textContent = "No contradictory source assertions were recorded.";
        section.appendChild(none);
      }
    });
    appendDetailSection(cveDetailBody, "Published CVE history", function (section) {
      section.appendChild(buildCveHistory(row));
    });
  }

  function appendDetailSection(parent, title, builder) {
    var details = document.createElement("details");
    details.open = true;
    var summary = document.createElement("summary");
    summary.textContent = title;
    details.appendChild(summary);
    var body = document.createElement("div");
    builder(body);
    details.appendChild(body);
    parent.appendChild(details);
  }

  function buildTable(headers, rows) {
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    var table = document.createElement("table");
    var caption = document.createElement("caption");
    caption.className = "visually-hidden";
    caption.textContent = headers.join(", ");
    table.appendChild(caption);
    var thead = document.createElement("thead");
    var headRow = document.createElement("tr");
    headers.forEach(function (label) {
      var th = document.createElement("th");
      th.scope = "col";
      th.textContent = asText(label);
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      row.forEach(function (value) {
        var td = document.createElement("td");
        td.textContent = asText(value);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function appendReferenceList(parent, refs) {
    var list = document.createElement("ul");
    refs.forEach(function (item) {
      var li = document.createElement("li");
      li.appendChild(document.createTextNode(asText(item.source) + " · " + asText(item.classification) + " · "));
      var url = safePublicHttpsUrl(item.url);
      if (url) {
        var anchor = document.createElement("a");
        anchor.setAttribute("href", url);
        anchor.setAttribute("rel", "noopener noreferrer");
        anchor.textContent = asText(item.title || url);
        li.appendChild(anchor);
      } else {
        li.appendChild(document.createTextNode(asText(item.title || "unavailable URL rejected")));
      }
      list.appendChild(li);
    });
    parent.appendChild(list);
  }

  function loadCatalog() {
    if (catalogLoaded) {
      applyCatalogFilters();
      return;
    }
    catalogLoad.disabled = true;
    catalogStatus.textContent = "Loading published snapshot from this site. No external API is called.";
    loadJson("data/latest.json")
      .then(function (snapshot) {
        if (!snapshot || !Array.isArray(snapshot.records)) {
          throw new Error("Published snapshot unavailable");
        }
        catalogRows = snapshot.records.map(compactRecord);
        catalogSnapshotMeta = {
          snapshot_id: snapshot.snapshot_id,
          generated_at: snapshot.generated_at,
        };
        catalogLoaded = true;
        catalogPageIndex = 0;
        populateCatalogFacets();
        setCatalogEnabled(true);
        catalogStatus.textContent =
          "Loaded " + String(catalogRows.length) + " published records. Search is local to this snapshot.";
        applyCatalogFilters();
        applyCveHash();
        loadJson("data/history/index.json").then(function (index) {
          historyIndexIds = {};
          if (index && Array.isArray(index.cves)) {
            index.cves.forEach(function (item) {
              if (item && item.cve_id) {
                historyIndexIds[item.cve_id] = item;
              }
            });
          }
        });
      })
      .catch(function () {
        catalogLoad.disabled = false;
        catalogStatus.textContent =
          "The published catalog could not be loaded. Overview data is unchanged.";
        renderRows(catalogBody, [], { emptyText: "Catalog failed to load." });
      });
  }

  function resetCatalogPage() {
    catalogPageIndex = 0;
    applyCatalogFilters();
  }

  catalogLoad.addEventListener("click", loadCatalog);
  catalogQuery.addEventListener("input", resetCatalogPage);
  catalogCompleteness.addEventListener("change", resetCatalogPage);
  if (catalogCvss) {
    catalogCvss.addEventListener("change", resetCatalogPage);
  }
  catalogTruncated.addEventListener("change", resetCatalogPage);
  catalogSort.addEventListener("change", resetCatalogPage);
  [
    catalogVendor,
    catalogProduct,
    catalogDateFrom,
    catalogDateTo,
    catalogCvssMin,
    catalogCvssMax,
    catalogCwe,
    catalogCvssVersion,
    catalogAttackVector,
    catalogPrivileges,
    catalogUserInteraction,
    catalogFixedVersion,
    catalogVendorAdvisory,
    catalogNvd,
    catalogRemediation,
  ].forEach(function (control) {
    if (!control) {
      return;
    }
    control.addEventListener("change", function () {
      if (control === catalogVendor) {
        populateCatalogFacets();
      }
      resetCatalogPage();
    });
  });
  if (catalogClear) {
    catalogClear.addEventListener("click", function () {
      if (catalogQuery) {
        catalogQuery.value = "";
      }
      [
        catalogVendor,
        catalogProduct,
        catalogCompleteness,
        catalogCvss,
        catalogCwe,
        catalogCvssVersion,
        catalogAttackVector,
        catalogPrivileges,
        catalogUserInteraction,
        catalogFixedVersion,
        catalogVendorAdvisory,
        catalogNvd,
        catalogTruncated,
        catalogRemediation,
        catalogSort,
      ].forEach(function (control) {
        if (control) {
          control.value = control === catalogSort ? "kev_date_added" : "all";
        }
      });
      if (catalogDateFrom) {
        catalogDateFrom.value = "";
      }
      if (catalogDateTo) {
        catalogDateTo.value = "";
      }
      if (catalogCvssMin) {
        catalogCvssMin.value = "";
      }
      if (catalogCvssMax) {
        catalogCvssMax.value = "";
      }
      populateCatalogFacets();
      resetCatalogPage();
    });
  }
  if (catalogExport) {
    catalogExport.addEventListener("click", exportFilteredCsv);
  }
  catalogPrev.addEventListener("click", function () {
    catalogPageIndex -= 1;
    applyCatalogFilters();
  });
  catalogNext.addEventListener("click", function () {
    catalogPageIndex += 1;
    applyCatalogFilters();
  });
  catalogPrev.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      catalogPrev.click();
    }
  });
  catalogNext.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      catalogNext.click();
    }
  });

  Promise.all([
    loadJson("data/manifest.json"),
    loadJson("data/preview.json"),
    loadJson("data/publication-status.json"),
  ])
    .then(function (results) {
      var manifest = results[0];
      var preview = results[1];
      var publicationStatus = results[2];
      if (!manifest) {
        setBanner(
          "unavailable",
          "No published snapshot is available. This preview is not a live intelligence feed."
        );
        recentNote.textContent = "Snapshot unavailable.";
        renderRows(recentBody, [], { showChange: false });
        renderPublicationComparison(null);
        return;
      }
      var publication = manifest.publication_state || manifest.status;
      if (publication === "not_published" || manifest.status === "unpublished") {
        setBanner(
          "unavailable",
          asText(manifest.message) ||
            "Publication is disabled until source contracts and security review are approved."
        );
        appendMeta("Status", "Not published");
        appendMeta("Generated at", manifest.generated_at);
        appendMeta("Information state", "unavailable");
        recentNote.textContent = "No approved snapshot has been published.";
        renderRows(recentBody, [], { showChange: false });
        renderPublicationComparison(null);
        catalogLoad.disabled = true;
        return;
      }
      var freshness = evaluateFreshness(
        manifest.snapshot_generated_at || manifest.generated_at,
        manifest.stale_after_hours || 36,
        Date.now()
      );
      var collectionOutcome = manifest.status;
      if (freshness.invalid) {
        setBanner(
          "unavailable",
          "Snapshot timestamps are invalid. Do not treat this page as intelligence."
        );
      } else if (freshness.stale) {
        setBanner(
          "stale",
          "The published snapshot is stale at viewing time. Do not treat it as a fresh collection."
        );
      } else if (collectionOutcome === "degraded") {
        setBanner(
          "warn",
          "Collection succeeded with incomplete extracted inventories or unavailable enrichments. This is not a failed collection. Freshness is evaluated at viewing time and is independent of record completeness."
        );
      } else if (collectionOutcome === "ok") {
        setBanner(
          "ok",
          "Collection succeeded. Freshness is evaluated at viewing time and is independent of record completeness."
        );
      } else if (collectionOutcome === "failed") {
        setBanner("unavailable", "Collection failed. No successful snapshot is shown.");
      } else {
        setBanner("unavailable", "Published snapshot is unavailable.");
      }
      if (
        publicationStatus &&
        publicationStatus.state &&
        publicationStatus.state !== "consistent"
      ) {
        setBanner(
          "unavailable",
          "Published Pages data and persisted pulse-state may have diverged. " +
            "Do not treat this page as an authoritative publication until an operator reconciles. " +
            asText(publicationStatus.classification)
        );
        appendMeta("Publication state", publicationStatus.state);
        appendMeta("Collect run ID", publicationStatus.collect_run_id);
        appendMeta("Snapshot ID", publicationStatus.snapshot_id);
        appendMeta("Manifest digest", publicationStatus.manifest_digest);
        appendMeta("Deployment run", publicationStatus.deployment_run_id);
      }
      var summary = (preview && preview.summary) || {};
      epssDisabled = Boolean(
        summary.epss_enabled === false ||
          ((preview && preview.sources && preview.sources.epss && preview.sources.epss.status) === "disabled")
      );
      var comparison = preview && preview.publication_comparison;
      var classified = classifyPublishedComparison(comparison);
      var comparisonAvailable = classified.available;
      appendCard(
        "Known Exploited CVEs",
        manifest.record_count,
        "CISA KEV entries in this published snapshot. Not a count of exposed systems."
      );
      appendCard(
        "New in KEV",
        comparisonAvailable ? comparisonCount(classified.added_count) : "No comparison available",
        comparisonAvailable
          ? "Added since the previous published snapshot. Not CISA dateAdded recency."
          : "Baseline unavailable. This is not zero new entries."
      );
      appendCard(
        "Vulnerability Updates",
        comparisonAvailable
          ? classified.field_evidence === "unavailable"
            ? "Field-level evidence not stored"
            : comparisonCount(classified.updated_count)
          : "No comparison available",
        comparisonAvailable
          ? classified.field_evidence === "unavailable"
            ? "This published comparison lists updates but did not store displayable before/after field diffs. That is not zero updates and is not confirmed enrichment."
            : "KEV, CVE, CVSS, or completeness field changes versus the previous published snapshot. Newly extracted remediation is counted separately."
          : "Baseline unavailable. This is not zero updates."
      );
      appendCard(
        "Published Data Freshness",
        freshness.invalid ? "Invalid" : freshness.fresh ? "Fresh" : "Stale",
        "Collection " +
          formatInstant(manifest.snapshot_generated_at) +
          ". Publication " +
          formatInstant(manifest.generated_at) +
          ". Age " +
          formatAge(freshness.ageHours) +
          " at viewing time. Stale after " +
          asText(manifest.stale_after_hours || 36) +
          " hours.",
        freshness.invalid ? "invalid" : freshness.stale ? "stale" : "fresh"
      );

      appendMeta("Collection outcome", collectionOutcome);
      appendMeta("Fresh at viewing time", freshness.fresh ? "yes" : "no");
      appendMeta("Stale at viewing time", freshness.stale ? "yes" : "no");
      appendMeta(
        "Age hours at viewing time",
        freshness.ageHours === null ? "Unavailable" : String(Math.round(freshness.ageHours * 1000) / 1000)
      );
      appendMeta("Snapshot generated at", manifest.snapshot_generated_at);
      appendMeta("Manifest generated at", manifest.generated_at);
      appendMeta("Collection started at", preview && preview.collection_started_at);
      appendMeta("Collection completed at", preview && preview.collection_completed_at);
      appendMeta("Publication timestamp", manifest.generated_at);
      appendMeta("Record count", manifest.record_count);
      appendMeta("Complete extracted inventories", summary.complete_records);
      appendMeta("Partial extracted inventories", summary.partial_records);
      appendMeta("Unavailable enrichments", summary.unavailable_records);
      var sources = (preview && preview.sources) || manifest.sources || {};
      var kev = sources.kev || {};
      var cve = sources.cve || {};
      var epss = sources.epss || {};
      appendMeta("KEV source published at", kev.source_published_at);
      appendMeta("KEV retrieved at", kev.retrieved_at);
      appendMeta("CVE source updated at", cve.source_updated_at);
      appendMeta("CVE retrieved at", cve.retrieved_at);
      appendMeta("EPSS source status", epss.status);
      appendMeta("EPSS source note", presentEpssNote(epss.error || epss.notes));
      appendMeta("EPSS redistribution", epssDisabled ? "Disabled is not a zero probability." : asText(epss.status));
      if (preview && preview.note) {
        appendMeta("Consumer note", preview.note);
      }
      appendNamedMeta(technicalDetails, "Snapshot ID", manifest.snapshot_id);
      appendNamedMeta(technicalDetails, "Schema version", preview && preview.schema_version);
      appendNamedMeta(technicalDetails, "Preview schema version", preview && preview.schema_version);
      appendNamedMeta(technicalDetails, "KEV content digest", kev.content_sha256);
      appendNamedMeta(technicalDetails, "KEV source revision", kev.source_revision);
      appendNamedMeta(technicalDetails, "CVE content digest", cve.content_sha256);
      appendNamedMeta(technicalDetails, "CVE source revision", cve.source_revision);
      appendNamedMeta(technicalDetails, "CVE strategy", summary.cve_strategy);
      appendNamedMeta(technicalDetails, "Compared to published snapshot", comparison && comparison.compared_to_snapshot_id);
      appendNamedMeta(
        technicalDetails,
        "Collect-time changes_available",
        preview && preview.changes_available ? "yes" : "no"
      );
      if (!preview) {
        recentNote.textContent = "Preview document unavailable.";
        renderRows(recentBody, [], { showChange: false });
        renderPublicationComparison(null);
        return;
      }
      renderPublicationComparison(comparison);
      recentHeading.textContent = "Recently Added to CISA KEV";
      recentCaption.textContent = "Recently Added to CISA KEV";
      recentChangeCol.hidden = true;
      recentNote.textContent =
        "CISA dateAdded recency for this published snapshot, not a published-to-published diff. KEV added is the CISA date_added, not collection or publication time. EPSS: " +
        (epssDisabled ? "disabled" : asText(epss.status));
      renderRows(recentBody, (preview.recent_kev_additions || []).slice(0, RECENT_LIMIT), {
        showChange: false,
        emptyText: "No recently added KEV entries are available in this snapshot.",
      });
    })
    .catch(function () {
      setBanner(
        "failed",
        "The preview failed to load local JSON. No intelligence is shown."
      );
      recentNote.textContent = "Preview failed.";
      renderRows(recentBody, [], { showChange: false });
      renderPublicationComparison(null);
    });
  window.addEventListener("hashchange", applyCveHash);
  applyCveHash();
})();
