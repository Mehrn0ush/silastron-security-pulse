(function () {
  "use strict";

  var CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/;
  var CVE_PATH = "/CVERecord";
  var KEV_PATH = "/known-exploited-vulnerabilities-catalog";
  var CVELIST_BLOB =
    /^\/CVEProject\/cvelistV5\/blob\/main\/cves\/[0-9]{4}\/[0-9]+xxx\/CVE-[0-9]{4}-[0-9]{4,}\.json$/;
  var PAGE_SIZE = 25;
  var PRODUCT_DETAIL_LIMIT = 8;
  var VERSION_DETAIL_LIMIT = 3;

  var statusBanner = document.getElementById("status-banner");
  var statusDetails = document.getElementById("status-details");
  var dataStatusSummary = document.getElementById("data-status-summary");
  var dataStatusDetails = document.getElementById("data-status-details");
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
  var catalogSsvcExploitation = document.getElementById("catalog-ssvc-exploitation");
  var catalogSsvcAutomatable = document.getElementById("catalog-ssvc-automatable");
  var catalogSsvcTechnicalImpact = document.getElementById("catalog-ssvc-technical-impact");
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
      return "Data status";
    }
    if (kind === "neutral") {
      return "Data status";
    }
    if (kind === "stale") {
      return "Data status";
    }
    if (kind === "warn") {
      return "Degraded collection";
    }
    if (kind === "failed") {
      return "Failed";
    }
    return "Unavailable";
  }

  function appendDataStatus(term, value) {
    appendNamedMeta(dataStatusDetails, term, value);
  }

  var FAILED_ATTEMPT_CONCLUSIONS = ["failure", "timed_out", "cancelled", "startup_failure"];

  function attemptIsValid(attempt) {
    if (attempt === null || attempt === undefined) {
      return true;
    }
    return Boolean(
      typeof attempt === "object" &&
        FAILED_ATTEMPT_CONCLUSIONS.indexOf(attempt.conclusion) !== -1 &&
        /^[0-9]+$/.test(String(attempt.collect_run_id || "")) &&
        isFinite(Date.parse(attempt.attempted_at))
    );
  }

  function attemptOutcome(attempt) {
    return attempt.conclusion === "failure" ? "failed" : String(attempt.conclusion).replace(/_/g, " ");
  }

  function hoursSince(value, nowMs) {
    var parsed = Date.parse(value);
    return isFinite(parsed) ? (nowMs - parsed) / 3600000 : null;
  }

  function formatInstantWithAge(value, nowMs) {
    var hours = hoursSince(value, nowMs);
    if (hours === null || hours < 0) {
      return formatInstant(value);
    }
    return formatInstant(value) + " (" + formatAge(hours) + " ago)";
  }

  function formatCount(value) {
    var number = value === null || value === undefined || value === "" ? NaN : Number(value);
    return isFinite(number) ? number.toLocaleString("en-US") : asText(value);
  }

  function sourceValidationSummary(verification) {
    var names = [
      ["kev", "KEV"],
      ["cve", "CVE List V5"],
      ["nvd", "NVD"],
    ];
    var validated = [];
    var notValidated = [];
    names.forEach(function (pair) {
      var view = verification[pair[0]] || {};
      if (view.validated === true) {
        validated.push(pair[1]);
      } else {
        notValidated.push(pair[1] + " (" + asText(view.status) + ")");
      }
    });
    var text = "Independently validated: " + (validated.length ? validated.join(", ") : "none") + ".";
    if (notValidated.length) {
      text += " Not independently validated: " + notValidated.join(", ") + ".";
    }
    return text;
  }

  function knownGaps(preview, manifest, verification) {
    var sources = (preview && preview.sources) || (manifest && manifest.sources) || {};
    var gaps = [];
    ["kev", "cve"].forEach(function (key) {
      var source = sources[key] || {};
      if (source.status === "degraded" && source.error) {
        gaps.push(String(source.error));
      }
    });
    var metrics = verification && verification.nvd_metrics;
    var total = manifest && manifest.record_count;
    if (
      metrics &&
      formatCount(metrics.ok) !== "Unavailable" &&
      formatCount(total) !== "Unavailable" &&
      Number(metrics.ok) < Number(total)
    ) {
      var gap = "NVD enrichment covers " + formatCount(metrics.ok) + " of " + formatCount(total) + " records";
      if (Number(metrics.pending_backfill) > 0) {
        gap += " (" + formatCount(metrics.pending_backfill) + " pending backfill)";
      }
      gaps.push(gap);
    }
    return gaps;
  }

  function verificationIsValid(doc) {
    return Boolean(
      doc &&
        attemptIsValid(doc.last_attempt) &&
        doc.kind === "verification_status" &&
        doc.schema_version === "1.0.0" &&
        (doc.verified === true
          ? doc.verification_state === "verified" &&
            doc.verified_at &&
            doc.kev &&
            doc.kev.status === "ok" &&
            doc.kev.content_sha256 &&
            doc.kev.retrieved_at
          : doc.verification_state === "failed" ||
            doc.verification_state === "rejected" ||
            doc.verification_state === "insufficient")
    );
  }

  function evaluateDataStatus(manifest, preview, publicationStatus, verification, nowMs) {
    var expectedHours = Number((manifest && manifest.stale_after_hours) || 36);
    var pubState = publicationStatus && publicationStatus.state;
    var integrity = Boolean(pubState && pubState !== "consistent");
    var validVerification = verificationIsValid(verification) ? verification : null;
    var verified = Boolean(validVerification && validVerification.verified === true);
    var collectionOutcome = (preview && preview.status) || (manifest && manifest.status);
    var headline = "Verification evidence unavailable";
    var message =
      "Timestamps below come from the last published snapshot only. A later successful Collect that skipped publication is not visible here.";
    var tone = "neutral";
    var label = null;
    var verifiedAgeHours =
      verified && validVerification ? hoursSince(validVerification.verified_at, nowMs) : null;
    var attempt = validVerification && validVerification.last_attempt;
    var failedAttempt =
      attempt && Date.parse(attempt.attempted_at) > Date.parse(validVerification.verified_at || 0)
        ? attempt
        : null;
    if (integrity) {
      headline = "Publication consistency problem";
      message =
        "Published Pages data and persisted pulse-state may have diverged. Do not treat this page as an authoritative publication until an operator reconciles. " +
        asText(publicationStatus && publicationStatus.classification);
      tone = "unavailable";
    } else if (verification && !validVerification) {
      headline = "Verification evidence is invalid";
      message =
        "A verification-status document was present but failed validation. Do not treat snapshot age as proof of a recent successful collection.";
      tone = "unavailable";
    } else if (validVerification && validVerification.verification_state === "failed") {
      headline = "Collection verification failed";
      message = asText(validVerification.note) || "The latest recorded collection did not independently validate KEV.";
      tone = "unavailable";
    } else if (validVerification && validVerification.verification_state === "rejected") {
      headline = "Publication rejected";
      message = asText(validVerification.note) || "The latest Collect artifact was not published.";
      tone = "unavailable";
    } else if (verified && failedAttempt) {
      headline = "Latest scheduled collection failed";
      label = "Collection failed";
      message =
        "Collect run " +
        asText(failedAttempt.collect_run_id) +
        " " +
        attemptOutcome(failedAttempt) +
        " at " +
        formatInstant(failedAttempt.attempted_at) +
        ". The data below was last independently verified " +
        formatInstantWithAge(validVerification.verified_at, nowMs) +
        " and has not been re-checked since.";
      tone = "stale";
    } else if (verified && verifiedAgeHours !== null && verifiedAgeHours > expectedHours) {
      headline = "Verification overdue";
      label = "Verification overdue";
      message =
        "No successful verification for " +
        formatAge(verifiedAgeHours) +
        " (last " +
        formatInstant(validVerification.verified_at) +
        "). Collection is scheduled daily, so upstream changes since then may be missing.";
      tone = "stale";
    } else if (verified) {
      headline = validVerification.status_only
        ? "Unchanged catalog, independently verified"
        : "Published snapshot, independently verified";
      message =
        (validVerification.status_only
          ? "Published snapshot content is unchanged. This is not a new vulnerability snapshot. "
          : validVerification.publication_decision === "publish"
            ? "A new snapshot was published. "
            : "") + sourceValidationSummary(validVerification);
      tone = collectionOutcome === "degraded" ? "warn" : "ok";
      if (tone === "warn") {
        var gaps = knownGaps(preview, manifest, validVerification);
        if (gaps.length) {
          message += " Known gaps: " + gaps.join("; ") + ".";
        }
      }
    } else if (!validVerification && collectionOutcome === "degraded") {
      headline = "Published snapshot";
      message =
        "Collection of this snapshot succeeded with incomplete extracted inventories or unavailable enrichments. " +
        message;
      tone = "warn";
    }
    var lastSuccessfulCollection = null;
    if (
      validVerification &&
      (verified || validVerification.collection_outcome === "ok" || validVerification.collection_outcome === "degraded")
    ) {
      lastSuccessfulCollection = validVerification.collection_completed_at || null;
    } else if (preview && (preview.status === "ok" || preview.status === "degraded")) {
      lastSuccessfulCollection = preview.collection_completed_at || null;
    }
    return {
      headline: headline,
      message: message,
      tone: tone,
      label: label,
      failedAttempt: failedAttempt,
      verified: verified,
      verification: validVerification,
      lastSuccessfulVerificationAt: verified && validVerification ? validVerification.verified_at : null,
      lastSuccessfulCollectionAt: lastSuccessfulCollection,
    };
  }

  function setBanner(kind, message, labelText) {
    statusBanner.className = "banner " + kind;
    statusBanner.textContent = "";
    var label = document.createElement("strong");
    label.className = "banner-label";
    label.textContent = labelText || bannerLabel(kind);
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
    "ssvc_exploitation",
    "ssvc_automatable",
    "ssvc_technical_impact",
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
    if (!ssvcFilterMatches(row.ssvc_exploitation, filters.ssvcExploitation)) {
      return false;
    }
    if (!ssvcFilterMatches(row.ssvc_automatable, filters.ssvcAutomatable)) {
      return false;
    }
    if (!ssvcFilterMatches(row.ssvc_technical_impact, filters.ssvcTechnicalImpact)) {
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

  function ssvcFilterMatches(value, wanted) {
    if (!wanted || wanted === "all") {
      return true;
    }
    return (value || "unavailable") === wanted;
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
      ssvcExploitation: catalogSsvcExploitation ? catalogSsvcExploitation.value : "all",
      ssvcAutomatable: catalogSsvcAutomatable ? catalogSsvcAutomatable.value : "all",
      ssvcTechnicalImpact: catalogSsvcTechnicalImpact ? catalogSsvcTechnicalImpact.value : "all",
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
      catalogSsvcExploitation,
      catalogSsvcAutomatable,
      catalogSsvcTechnicalImpact,
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

  // Full source-attributed intelligence for one CVE is fetched on demand
  // from its own small file, not from the (much larger) catalog index. A
  // deep link to one CVE never requires loading the whole catalog.
  var cveDetailCache = {};

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
    cveDetailHeading.textContent = cveId;
    cveDetailBody.textContent = "";
    if (cveDetailStatus) {
      cveDetailStatus.textContent = "Loading intelligence for " + cveId + ".";
    }
    if (Object.prototype.hasOwnProperty.call(cveDetailCache, cveId)) {
      renderCveDetail(cveId, cveDetailCache[cveId]);
      return;
    }
    loadJson("data/cve/" + cveId + ".json")
      .then(function (detail) {
        cveDetailCache[cveId] = detail;
        if (parseCveHash() === cveId) {
          renderCveDetail(cveId, detail);
        }
      })
      .catch(function () {
        if (parseCveHash() === cveId && cveDetailStatus) {
          cveDetailStatus.textContent = "This CVE's intelligence could not be loaded.";
        }
      });
  }

  function renderCveDetail(cveId, row) {
    if (!cveDetailBody || !cveDetailHeading) {
      return;
    }
    cveDetailBody.textContent = "";
    cveDetailHeading.textContent = cveId;
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
    appendDetailSection(cveDetailBody, "CISA SSVC decision points", function (section) {
      var adp = intel.cisa_adp || {};
      var ssvc = adp.ssvc;
      var note = document.createElement("p");
      note.textContent = asText(
        adp.note || "CISA ADP (Vulnrichment) assertions copied from the CVE List V5 record. Not a risk score."
      );
      section.appendChild(note);
      if (!ssvc) {
        var empty = document.createElement("p");
        empty.textContent =
          adp.status === "available" || adp.status === "unavailable"
            ? "CISA has not published SSVC decision points for this CVE. That is not evidence of low impact."
            : "CISA ADP data is unavailable because the CVE List V5 record was not collected.";
        section.appendChild(empty);
        return;
      }
      var list = document.createElement("dl");
      list.className = "meta-list";
      appendNamedMeta(list, "Exploitation", ssvc.exploitation);
      appendNamedMeta(list, "Automatable", ssvc.automatable);
      appendNamedMeta(list, "Technical impact", ssvc.technical_impact);
      appendNamedMeta(list, "Assessed at", ssvc.assessed_at);
      appendNamedMeta(list, "Role", ssvc.role);
      appendNamedMeta(list, "SSVC version", ssvc.ssvc_version);
      appendNamedMeta(list, "ADP updated", adp.source_updated_at);
      appendNamedMeta(list, "Source", "cisa_adp");
      section.appendChild(list);
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
    catalogStatus.textContent = "Loading published catalog index from this site. No external API is called.";
    loadJson("data/catalog-index.json")
      .then(function (catalogIndex) {
        if (!catalogIndex || !Array.isArray(catalogIndex.records)) {
          throw new Error("Published catalog index unavailable");
        }
        // Each row is already the compact, server-built index entry. Full
        // source-attributed intelligence for one CVE is fetched separately,
        // on demand, by applyCveHash / renderCveDetail.
        catalogRows = catalogIndex.records;
        catalogSnapshotMeta = {
          snapshot_id: catalogIndex.snapshot_id,
          generated_at: catalogIndex.generated_at,
        };
        catalogLoaded = true;
        catalogPageIndex = 0;
        populateCatalogFacets();
        setCatalogEnabled(true);
        catalogStatus.textContent =
          "Loaded " + String(catalogRows.length) + " published records. Search is local to this snapshot.";
        applyCatalogFilters();
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
    catalogSsvcExploitation,
    catalogSsvcAutomatable,
    catalogSsvcTechnicalImpact,
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
        catalogSsvcExploitation,
        catalogSsvcAutomatable,
        catalogSsvcTechnicalImpact,
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

  // The status, overview, changes and recent sections are pre-rendered at build
  // time. This only refreshes what depends on the current time: the banner, the
  // data-status summary and the age-bearing detail lists.
  Promise.all([
    loadJson("data/manifest.json"),
    loadJson("data/preview.json"),
    loadJson("data/publication-status.json"),
    loadJson("data/verification-status.json"),
  ])
    .then(function (results) {
      var manifest = results[0];
      var preview = results[1];
      var publicationStatus = results[2];
      var verificationStatus = results[3];
      if (!manifest) {
        return;
      }
      var publication = manifest.publication_state || manifest.status;
      if (publication === "not_published" || manifest.status === "unpublished") {
        catalogLoad.disabled = true;
        return;
      }
      var freshness = evaluateFreshness(
        manifest.snapshot_generated_at || manifest.generated_at,
        manifest.stale_after_hours || 36,
        Date.now()
      );
      var collectionOutcome = manifest.status;
      var nowMs = Date.now();
      var dataStatus = evaluateDataStatus(manifest, preview, publicationStatus, verificationStatus, nowMs);
      if (statusDetails) {
        statusDetails.textContent = "";
      }
      if (dataStatusDetails) {
        dataStatusDetails.textContent = "";
      }
      if (freshness.invalid) {
        setBanner(
          "unavailable",
          "Snapshot timestamps are invalid. Do not treat this page as intelligence."
        );
      } else if (collectionOutcome === "failed") {
        setBanner("unavailable", "Collection failed. No successful snapshot is shown.");
      } else {
        setBanner(dataStatus.tone, dataStatus.message, dataStatus.label);
      }
      if (dataStatusSummary) {
        dataStatusSummary.textContent = dataStatus.headline + ". " + dataStatus.message;
      }
      var builtNote = document.getElementById("data-status-built");
      if (builtNote) {
        builtNote.hidden = true;
      }
      if (
        publicationStatus &&
        publicationStatus.state &&
        publicationStatus.state !== "consistent"
      ) {
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
      appendDataStatus(
        "Last successful verification",
        dataStatus.verified ? formatInstantWithAge(dataStatus.lastSuccessfulVerificationAt, nowMs) : "Unavailable"
      );
      if (dataStatus.failedAttempt) {
        appendDataStatus(
          "Latest collection attempt",
          "Collection " +
            attemptOutcome(dataStatus.failedAttempt) +
            " " +
            formatInstantWithAge(dataStatus.failedAttempt.attempted_at, nowMs) +
            ", run " +
            asText(dataStatus.failedAttempt.collect_run_id)
        );
      }
      appendDataStatus(
        "Last successful collection",
        dataStatus.lastSuccessfulCollectionAt
          ? formatInstantWithAge(dataStatus.lastSuccessfulCollectionAt, nowMs)
          : "Unavailable"
      );
      appendDataStatus("Last published snapshot", formatInstantWithAge(manifest.snapshot_generated_at, nowMs));
      appendDataStatus("Publication consistency", (publicationStatus && publicationStatus.state) || "Unavailable");
      appendDataStatus("Publication decision", dataStatus.verification ? asText(dataStatus.verification.publication_decision) : "Unavailable");
      appendMeta("Collection outcome", collectionOutcome);
      appendMeta("Published snapshot age", formatAge(freshness.ageHours));
      appendMeta(
        "Snapshot age is not verification",
        "Age shows when snapshot content last changed, not when sources were last checked."
      );
      appendMeta("Snapshot generated at", formatInstant(manifest.snapshot_generated_at));
      appendMeta("Published at", formatInstant(manifest.generated_at));
      appendMeta("Collection started at", formatInstant(preview && preview.collection_started_at));
      appendMeta("Collection completed at", formatInstant(preview && preview.collection_completed_at));
      appendMeta("Record count", formatCount(manifest.record_count));
      appendMeta("Complete extracted inventories", formatCount(summary.complete_records));
      appendMeta("Partial extracted inventories", formatCount(summary.partial_records));
      appendMeta("Unavailable enrichments", formatCount(summary.unavailable_records));
      var sources = (preview && preview.sources) || manifest.sources || {};
      var kev = sources.kev || {};
      var cve = sources.cve || {};
      var epss = sources.epss || {};
      appendMeta("KEV source published at", formatInstant(kev.source_published_at));
      appendMeta("CVE source updated at", formatInstant(cve.source_updated_at));
      var kevStatus = (dataStatus.verification && dataStatus.verification.kev) || kev;
      var cveStatus = (dataStatus.verification && dataStatus.verification.cve) || cve;
      var nvdStatus = (dataStatus.verification && dataStatus.verification.nvd) || sources.nvd || {};
      appendDataStatus("KEV source status", kevStatus.status);
      appendDataStatus("KEV retrieved at", formatInstant(kevStatus.retrieved_at));
      appendDataStatus("KEV upstream update", formatInstant(kevStatus.source_updated_at || kev.source_published_at));
      appendDataStatus("CVE List V5 status", cveStatus.status);
      appendDataStatus("CVE retrieved at", formatInstant(cveStatus.retrieved_at));
      appendDataStatus("NVD status", nvdStatus.status || "unavailable");
      appendDataStatus("NVD retrieved at", formatInstant(nvdStatus.retrieved_at));
      appendMeta("EPSS source status", epss.status);
      appendMeta("EPSS source note", presentEpssNote(epss.error || epss.notes));
      appendMeta("EPSS redistribution", epssDisabled ? "Disabled is not a zero probability." : asText(epss.status));
      if (preview && preview.note) {
        appendMeta("Consumer note", preview.note);
      }
    })
    .catch(function () {
      // Leave the pre-rendered sections as built; only say the refresh failed.
      setBanner(
        "unavailable",
        "Status could not be refreshed in the browser. The page below shows the status as built."
      );
    });
  window.addEventListener("hashchange", applyCveHash);
  applyCveHash();
})();
