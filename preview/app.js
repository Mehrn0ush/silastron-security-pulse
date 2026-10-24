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
  var catalogCompleteness = document.getElementById("catalog-completeness");
  var catalogCvss = document.getElementById("catalog-cvss");
  var catalogTruncated = document.getElementById("catalog-truncated");
  var catalogSort = document.getElementById("catalog-sort");
  var catalogPrev = document.getElementById("catalog-prev");
  var catalogNext = document.getElementById("catalog-next");
  var catalogPage = document.getElementById("catalog-page");

  var epssDisabled = false;
  var catalogRows = [];
  var catalogLoaded = false;
  var catalogPageIndex = 0;
  var filteredCatalog = [];

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

  function setBanner(kind, message) {
    statusBanner.className = "banner " + kind;
    statusBanner.textContent = message;
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

  function appendCard(term, value, hint) {
    var article = document.createElement("article");
    article.className = "card";
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
    return details;
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
      var cve = document.createElement("td");
      var cveLink = row.links && row.links.cve_record;
      if (safeHttpsUrl(cveLink)) {
        addLink(cve, cveLink, asText(row.cve_id));
      } else {
        cve.textContent = asText(row.cve_id);
      }
      tr.appendChild(cve);
      if (showChange) {
        var change = document.createElement("td");
        change.textContent = asText(row.change);
        tr.appendChild(change);
      }
      var product = document.createElement("td");
      product.textContent = asText(row.vendor_project) + " / " + asText(row.product);
      if (row.vulnerability_name) {
        var name = document.createElement("div");
        name.className = "product-name";
        name.textContent = asText(row.vulnerability_name);
        product.appendChild(name);
      }
      tr.appendChild(product);
      var added = document.createElement("td");
      added.textContent = asText(row.kev_date_added);
      tr.appendChild(added);
      var completeness = document.createElement("td");
      var pill = document.createElement("span");
      pill.className = "pill";
      if (row.completeness === "partial" || row.partial) {
        pill.className = "pill warn";
      } else if (row.completeness === "unavailable") {
        pill.className = "pill danger";
      }
      pill.textContent = completenessLabel(row);
      completeness.appendChild(pill);
      tr.appendChild(completeness);
      var cvss = document.createElement("td");
      cvss.textContent = cvssLabel(row);
      tr.appendChild(cvss);
      var epss = document.createElement("td");
      epss.textContent = epssLabel(row);
      tr.appendChild(epss);
      var links = document.createElement("td");
      addLink(links, row.links && row.links.cve_record, "CVE record");
      addLink(links, row.links && row.links.kev_catalog, "KEV catalog");
      addLink(links, row.links && row.links.cvelist_v5, "CVE List V5");
      tr.appendChild(links);
      if (showDetails) {
        var detailsCell = document.createElement("td");
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
      return "No stored field-level diff";
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
      var cve = document.createElement("td");
      var cveLink = row.links && row.links.cve_record;
      if (safeHttpsUrl(cveLink)) {
        addLink(cve, cveLink, asText(row.cve_id));
      } else {
        cve.textContent = asText(row.cve_id);
      }
      tr.appendChild(cve);
      var cats = document.createElement("td");
      cats.textContent = (row.categories || [])
        .map(function (item) {
          return CATEGORY_LABELS[item] || item;
        })
        .join("; ");
      tr.appendChild(cats);
      var fields = document.createElement("td");
      fields.textContent = changedFieldsLabel(row);
      tr.appendChild(fields);
      var links = document.createElement("td");
      addLink(links, row.links && row.links.cve_record, "CVE record");
      addLink(links, row.links && row.links.kev_catalog, "KEV catalog");
      addLink(links, row.links && row.links.cvelist_v5, "CVE List V5");
      tr.appendChild(links);
      var detailsCell = document.createElement("td");
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
      appendCount(
        summary,
        "listed updates without stored field-level diffs. Those rows are not classified as enrichment or as confirmed core fact changes.",
        classified.unresolved_count
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
    renderChangeGroup(
      "Published updates without stored field-level diffs",
      classified.unresolved_rows || []
    );
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
      !(classified.unresolved_rows && classified.unresolved_rows.length) &&
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
      links: {
        cve_record: links.cve_record,
        kev_catalog: links.kev_catalog,
        cvelist_v5: links.cvelist_v5,
      },
    };
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

  function rowMatches(row, query, completeness, truncated, cvss) {
    if (completeness !== "all" && row.completeness !== completeness) {
      return false;
    }
    if (!cvssMatches(row, cvss || "all")) {
      return false;
    }
    var isTruncated = (row.truncated_fields || []).indexOf("versions") !== -1 || Number(row.omitted_version_count) > 0;
    if (truncated === "truncated" && !isTruncated) {
      return false;
    }
    if (!query) {
      return true;
    }
    var haystack = [
      row.cve_id,
      row.vendor_project,
      row.product,
      row.vulnerability_name,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.indexOf(query) !== -1;
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

  function applyCatalogFilters() {
    var query = (catalogQuery.value || "").trim().toLowerCase();
    var completeness = catalogCompleteness.value;
    var truncated = catalogTruncated.value;
    var cvss = catalogCvss ? catalogCvss.value : "all";
    var sorted = sortRows(catalogRows, catalogSort.value);
    filteredCatalog = sorted.filter(function (row) {
      return rowMatches(row, query, completeness, truncated, cvss);
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
    catalogQuery.disabled = !enabled;
    catalogCompleteness.disabled = !enabled;
    catalogTruncated.disabled = !enabled;
    catalogSort.disabled = !enabled;
    if (catalogCvss) {
      catalogCvss.disabled = !enabled;
    }
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
        catalogLoaded = true;
        catalogPageIndex = 0;
        setCatalogEnabled(true);
        catalogStatus.textContent =
          "Loaded " + String(catalogRows.length) + " published records. Search is local to this snapshot.";
        applyCatalogFilters();
      })
      .catch(function () {
        catalogLoad.disabled = false;
        catalogStatus.textContent =
          "The published catalog could not be loaded. Overview data is unchanged.";
        renderRows(catalogBody, [], { emptyText: "Catalog failed to load." });
      });
  }

  catalogLoad.addEventListener("click", loadCatalog);
  catalogQuery.addEventListener("input", function () {
    catalogPageIndex = 0;
    applyCatalogFilters();
  });
  catalogCompleteness.addEventListener("change", function () {
    catalogPageIndex = 0;
    applyCatalogFilters();
  });
  if (catalogCvss) {
    catalogCvss.addEventListener("change", function () {
      catalogPageIndex = 0;
      applyCatalogFilters();
    });
  }
  catalogTruncated.addEventListener("change", function () {
    catalogPageIndex = 0;
    applyCatalogFilters();
  });
  catalogSort.addEventListener("change", function () {
    catalogPageIndex = 0;
    applyCatalogFilters();
  });
  catalogPrev.addEventListener("click", function () {
    catalogPageIndex -= 1;
    applyCatalogFilters();
  });
  catalogNext.addEventListener("click", function () {
    catalogPageIndex += 1;
    applyCatalogFilters();
  });

  Promise.all([loadJson("data/manifest.json"), loadJson("data/preview.json")])
    .then(function (results) {
      var manifest = results[0];
      var preview = results[1];
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
        "Updated Records",
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
          " hours."
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
})();
