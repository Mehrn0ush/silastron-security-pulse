(function () {
  "use strict";

  var ALLOWED_HOSTS = {
    "www.cisa.gov": true,
    "cisa.gov": true,
    "www.cve.org": true,
    "cve.org": true,
    "github.com": true,
    "www.first.org": true,
  };

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
      if (!ALLOWED_HOSTS[parsed.hostname]) {
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
      kev.textContent = row.kev_listed
        ? "Listed (" + asText(row.kev_date_added) + ")"
        : "Not listed";
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
        "KEV added " +
        asText(row.kev_date_added) +
        "; CVE updated " +
        asText(row.cve_date_updated);
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
        changesNote.textContent = "No approved snapshot has been published.";
        renderRows([]);
        return;
      }
      if (manifest.stale) {
        setBanner(
          "stale",
          "The published snapshot is stale. Do not treat it as a fresh collection."
        );
      } else if (manifest.status === "degraded") {
        setBanner(
          "warn",
          "The published snapshot is degraded. Some CVE enrichments were unavailable."
        );
      } else if (manifest.status === "ok") {
        setBanner("ok", "Published snapshot is available.");
      } else {
        setBanner("unavailable", "Published snapshot is unavailable.");
      }
      appendMeta("Status", manifest.status);
      appendMeta("Fresh", manifest.fresh ? "yes" : "no");
      appendMeta("Stale", manifest.stale ? "yes" : "no");
      appendMeta("Snapshot generated at", manifest.snapshot_generated_at);
      appendMeta("Manifest generated at", manifest.generated_at);
      appendMeta("Record count", manifest.record_count);
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
