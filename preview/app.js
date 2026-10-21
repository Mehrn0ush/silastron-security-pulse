(function () {
  "use strict";

  var CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/;
  var CVE_PATH = "/CVERecord";
  var KEV_PATH = "/known-exploited-vulnerabilities-catalog";
  var CVELIST_BLOB =
    /^\/CVEProject\/cvelistV5\/blob\/main\/cves\/[0-9]{4}\/[0-9]+xxx\/CVE-[0-9]{4}-[0-9]{4,}\.json$/;

  var statusBanner = document.getElementById("status-banner");
  var statusDetails = document.getElementById("status-details");
  var changesNote = document.getElementById("changes-note");
  var changesBody = document.getElementById("changes-body");

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
    anchor.textContent = label;
    container.appendChild(anchor);
  }

  function renderRows(rows) {
    changesBody.textContent = "";
    if (!rows.length) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 6;
      cell.textContent = "No rows to display.";
      empty.appendChild(cell);
      changesBody.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var cve = document.createElement("td");
      cve.textContent = asText(row.cve_id);
      var change = document.createElement("td");
      change.textContent = asText(row.change);
      var kev = document.createElement("td");
      if (row.kev_listed) {
        kev.textContent = "Listed (" + asText(row.kev_date_added) + ")";
      } else {
        kev.textContent = "Not listed";
      }
      if (row.completeness && row.completeness !== "complete") {
        kev.appendChild(document.createTextNode(" · " + asText(row.completeness)));
        if (row.omitted_product_count || row.omitted_version_count) {
          kev.appendChild(
            document.createTextNode(
              " (" +
                asText(row.omitted_product_count || 0) +
                " products omitted, " +
                asText(row.omitted_version_count || 0) +
                " versions omitted)"
            )
          );
        }
      } else if (row.partial) {
        kev.appendChild(document.createTextNode(" · partial"));
      }
      var product = document.createElement("div");
      product.textContent =
        asText(row.vendor_project) + " / " + asText(row.product);
      kev.appendChild(product);
      var epss = document.createElement("td");
      if (row.epss_status === "ok" && row.epss_score !== null && row.epss_score !== undefined) {
        epss.textContent = "Estimated " + asText(row.epss_score);
      } else {
        epss.textContent = "EPSS " + asText(row.epss_status || "unavailable");
      }
      var links = document.createElement("td");
      addLink(links, row.links && row.links.cve_record, "CVE record");
      addLink(links, row.links && row.links.kev_catalog, "KEV catalog");
      addLink(links, row.links && row.links.cvelist_v5, "CVE List V5");
      var time = document.createElement("td");
      time.textContent =
        "KEV published " +
        asText(row.kev_source_published_at || row.source_published_at) +
        "; KEV retrieved " +
        asText(row.kev_retrieved_at) +
        "; CVE updated " +
        asText(row.cve_date_updated || row.cve_source_updated_at) +
        "; CVE retrieved " +
        asText(row.cve_retrieved_at || row.retrieved_at);
      tr.appendChild(cve);
      tr.appendChild(change);
      tr.appendChild(kev);
      tr.appendChild(epss);
      tr.appendChild(links);
      tr.appendChild(time);
      changesBody.appendChild(tr);
    });
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

  Promise.all([loadJson("data/manifest.json"), loadJson("data/preview.json")])
    .then(function (results) {
      var manifest = results[0];
      var preview = results[1];
      if (!manifest) {
        setBanner(
          "unavailable",
          "No published snapshot is available. This preview is not a live intelligence feed."
        );
        changesNote.textContent = "Snapshot unavailable.";
        renderRows([]);
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
        changesNote.textContent = "No approved snapshot has been published.";
        renderRows([]);
        return;
      }
      var freshness = evaluateFreshness(
        manifest.snapshot_generated_at || manifest.generated_at,
        manifest.stale_after_hours || 36,
        Date.now()
      );
      var infoState = "verified";
      if (freshness.invalid) {
        infoState = "unavailable";
        setBanner(
          "unavailable",
          "Snapshot timestamps are invalid. Do not treat this page as intelligence."
        );
      } else if (freshness.stale) {
        infoState = "stale";
        setBanner(
          "stale",
          "The published snapshot is stale at viewing time. Do not treat it as a fresh collection."
        );
      } else if (manifest.status === "degraded") {
        infoState = "partial";
        setBanner(
          "warn",
          "The published snapshot is partial. Some CVE enrichments were unavailable or truncated."
        );
      } else if (manifest.status === "ok") {
        infoState = "verified";
        setBanner("ok", "Published snapshot is available and fresh at viewing time.");
      } else {
        infoState = "unavailable";
        setBanner("unavailable", "Published snapshot is unavailable.");
      }
      appendMeta("Status", manifest.status);
      appendMeta("Information state", infoState);
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
      var summary = (preview && preview.summary) || {};
      appendMeta("Complete records", summary.complete_records);
      appendMeta("Partial records", summary.partial_records);
      appendMeta("Unavailable records", summary.unavailable_records);
      var sources = (preview && preview.sources) || manifest.sources || {};
      var kev = sources.kev || {};
      var cve = sources.cve || {};
      appendMeta("KEV source published at", kev.source_published_at);
      appendMeta("KEV retrieved at", kev.retrieved_at);
      appendMeta("CVE source updated at", cve.source_updated_at);
      appendMeta("CVE retrieved at", cve.retrieved_at);
      if (!preview) {
        changesNote.textContent = "Preview document unavailable.";
        renderRows([]);
        return;
      }
      var epss = preview.sources && preview.sources.epss;
      if (preview.changes_available) {
        changesNote.textContent =
          "Changes since the previous snapshot. EPSS: " +
          asText(epss && epss.status);
        renderRows(preview.changes || []);
      } else {
        changesNote.textContent =
          "No previous snapshot was available, so this table shows the most recently added KEV entries in this snapshot rather than a diff. EPSS: " +
          asText(epss && epss.status);
        renderRows(preview.recent_kev_additions || []);
      }
    })
    .catch(function () {
      setBanner(
        "failed",
        "The preview failed to load local JSON. No intelligence is shown."
      );
      changesNote.textContent = "Preview failed.";
      renderRows([]);
    });
})();
