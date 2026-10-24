(function () {
  "use strict";

  var STORAGE_KEY = "silastron-pulse-theme";
  var root = document.documentElement;

  function readStored() {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch (err) {
      return null;
    }
  }

  function writeStored(mode) {
    try {
      window.localStorage.setItem(STORAGE_KEY, mode);
    } catch (err) {
      /* Persistence is optional when storage is blocked. */
    }
  }

  function normalize(mode) {
    return mode === "light" || mode === "dark" || mode === "system" ? mode : "system";
  }

  function apply(mode) {
    var next = normalize(mode);
    root.setAttribute("data-theme", next);
    root.style.colorScheme = next === "system" ? "light dark" : next;
    return next;
  }

  apply(readStored() || "system");

  function syncButtons() {
    var current = normalize(readStored() || "system");
    var buttons = document.querySelectorAll("[data-theme-choice]");
    buttons.forEach(function (button) {
      var pressed = button.getAttribute("data-theme-choice") === current;
      button.setAttribute("aria-pressed", pressed ? "true" : "false");
    });
  }

  function bind() {
    document.querySelectorAll("[data-theme-choice]").forEach(function (button) {
      button.addEventListener("click", function () {
        var mode = apply(button.getAttribute("data-theme-choice"));
        writeStored(mode);
        syncButtons();
      });
    });
    syncButtons();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
