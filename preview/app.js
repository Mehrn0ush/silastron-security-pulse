(function () {
  "use strict";

  var CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/;
  var CVE_PATH = "/CVERecord";
  var KEV_PATH = "/known-exploited-vulnerabilities-catalog";
  var CVELIST_BLOB =
    /^\/CVEProject\/cvelistV5\/blob\/main\/cves\/[0-9]{4}\/[0-9]+xxx\/CVE-[0-9]{4}-[0-9]{4,}\.json$/;
  var PAGE_SIZE = 25;

  var statusBanner = document.getElementById("status-banner");
  var statusDetails = document.getElementById("status-details");
  var overviewCards = document.getElementById("overview-cards");
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

  function appendMeta(term, value) {
    var dt = document.createElement("dt");
    dt.textContent = term;
    var dd = document.createElement("dd");
    dd.textContent = asText(value);
    statusDetails.appendChild(dt);
    statusDetails.appendChild(dd);
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

  function renderRows(tbody, rows, options) {
    tbody.textContent = "";
    var showChange = options && options.showChange;
    var colSpan = showChange ? 8 : 7;
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
      tbody.appendChild(tr);
    });
  }

  function compactRecord(record) {
    var cve = record.cve || {};
    var kev = record.kev || {};
    var epss = record.epss || {};
    var links = record.links || {};
    var severity = cve.severity && typeof cve.severity === "object" ? cve.severity : {};
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
      epss_status: epss.status,
      epss_score: epss.score,
      links: {
        cve_record: links.cve_record,
        kev_catalog: links.kev_catalog,
        cvelist_v5: links.cvelist_v5,
      },
    };
  }

  function rowMatches(row, query, completeness, truncated) {
    if (completeness !== "all" && row.completeness !== completeness) {
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
    var sorted = sortRows(catalogRows, catalogSort.value);
    filteredCatalog = sorted.filter(function (row) {
      return rowMatches(row, query, completeness, truncated);
    });
    var maxPage = Math.max(0, Math.ceil(filteredCatalog.length / PAGE_SIZE) - 1);
    if (catalogPageIndex > maxPage) {
      catalogPageIndex = maxPage;
    }
    var start = catalogPageIndex * PAGE_SIZE;
    var pageRows = filteredCatalog.slice(start, start + PAGE_SIZE);
    renderRows(catalogBody, pageRows, {
      showChange: false,
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
      appendCard(
        "Latest update",
        formatInstant(manifest.snapshot_generated_at || manifest.generated_at),
        "Snapshot generated at. Freshness is computed at viewing time."
      );
      appendCard(
        "Known exploited vulnerabilities",
        manifest.record_count,
        "CISA KEV entries in this snapshot. Not a count of exposed systems."
      );
      appendCard(
        "Collection outcome",
        collectionOutcome,
        collectionOutcome === "degraded"
          ? "Succeeded with limitations. Not a failed collection."
          : "Collector finish state, not freshness."
      );
      appendCard(
        "Fresh at viewing time",
        freshness.invalid ? "Invalid" : freshness.fresh ? "Yes" : "No",
        "Age " + formatAge(freshness.ageHours) + ". Stale after " + asText(manifest.stale_after_hours || 36) + " hours."
      );
      appendCard(
        "Extracted inventories",
        asText(summary.complete_records) +
          " complete / " +
          asText(summary.partial_records) +
          " partial / " +
          asText(summary.unavailable_records) +
          " unavailable",
        "Completeness of extracted product/version text, not real-world coverage."
      );
      appendCard(
        "EPSS",
        epssDisabled ? "Disabled" : asText(preview && preview.sources && preview.sources.epss && preview.sources.epss.status),
        "Disabled is not a zero probability."
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
      appendMeta("EPSS source note", epss.error || epss.notes);
      appendMeta("Snapshot ID", manifest.snapshot_id);
      if (preview && preview.note) {
        appendMeta("Consumer note", preview.note);
      }
      if (!preview) {
        recentNote.textContent = "Preview document unavailable.";
        renderRows(recentBody, [], { showChange: false });
        return;
      }
      if (preview.changes_available) {
        recentHeading.textContent = "Meaningful changes since the previous snapshot";
        recentCaption.textContent = "Meaningful changes since the previous snapshot";
        recentChangeCol.hidden = false;
        recentNote.textContent =
          "These rows are snapshot-to-snapshot changes. KEV added is the CISA date_added, not the catalog publication timestamp. EPSS: " +
          (epssDisabled ? "disabled" : asText(epss.status));
        renderRows(recentBody, preview.changes || [], { showChange: true });
      } else {
        recentHeading.textContent = "Recently Added to CISA KEV";
        recentCaption.textContent = "Recently Added to CISA KEV";
        recentChangeCol.hidden = true;
        recentNote.textContent =
          "No previous snapshot was available, so this table is not a diff. It lists the most recently added KEV entries in this snapshot. KEV added is CISA date_added, not catalog publication time. EPSS: " +
          (epssDisabled ? "disabled" : asText(epss.status));
        renderRows(recentBody, preview.recent_kev_additions || [], { showChange: false });
      }
    })
    .catch(function () {
      setBanner(
        "failed",
        "The preview failed to load local JSON. No intelligence is shown."
      );
      recentNote.textContent = "Preview failed.";
      renderRows(recentBody, [], { showChange: false });
    });
})();
