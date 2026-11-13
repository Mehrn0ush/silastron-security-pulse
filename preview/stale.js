(function () {
  "use strict";
  // Warns a visitor when the page outlives its data (no rebuild, collection failing). Pages are rebuilt
  // only when Publish runs, so age is computed here from the footer's data-collected stamp.
  var LIMIT_HOURS = 72;
  var footer = document.querySelector("footer[data-collected]");
  var main = document.querySelector("main") || document.body;
  if (!footer || !main) {
    return;
  }
  var collected = Date.parse(footer.getAttribute("data-collected"));
  if (!isFinite(collected) || (Date.now() - collected) / 3600000 <= LIMIT_HOURS) {
    return;
  }
  var note = document.createElement("p");
  note.className = "banner stale";
  note.setAttribute("role", "status");
  var label = document.createElement("strong");
  label.className = "banner-label";
  label.textContent = "Possibly out of date";
  note.appendChild(label);
  note.appendChild(
    document.createTextNode(
      " Data on this page was collected on " +
        new Date(collected).toISOString().slice(0, 10) +
        ", more than 3 days ago. Newer data may exist; this page may not have been rebuilt."
    )
  );
  main.insertBefore(note, main.firstChild);
})();
