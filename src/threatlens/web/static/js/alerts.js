// Alert queue: select-all, selection count and keyboard shortcuts.
// j/k move, x select, o/Enter open, / search, ? help. No HTML is built from data here.
(function () {
  "use strict";

  function init() {
    var table = document.getElementById("alert-table");
    var all = document.getElementById("select-all");
    var counter = document.getElementById("selected-count");
    var help = document.getElementById("kbd-help");
    var search = document.getElementById("alert-search");
    var rows = table ? Array.prototype.slice.call(table.querySelectorAll("tbody tr")) : [];
    var current = -1;

    function boxes() {
      return rows.map(function (r) { return r.querySelector('input[name="ids"]'); });
    }
    function updateCount() {
      var n = boxes().filter(function (b) { return b && b.checked; }).length;
      if (counter) counter.textContent = n + " selected";
    }
    function focusRow(i) {
      if (!rows.length) return;
      current = Math.max(0, Math.min(rows.length - 1, i));
      rows.forEach(function (r, idx) { r.classList.toggle("row-focus", idx === current); });
      rows[current].scrollIntoView({ block: "nearest" });
    }

    if (all) {
      all.addEventListener("change", function () {
        boxes().forEach(function (b) { if (b) b.checked = all.checked; });
        updateCount();
      });
    }
    rows.forEach(function (r) {
      var b = r.querySelector('input[name="ids"]');
      if (b) b.addEventListener("change", updateCount);
    });

    document.addEventListener("keydown", function (e) {
      var tag = (e.target && e.target.tagName) || "";
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA" || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "j") { focusRow(current + 1); e.preventDefault(); }
      else if (e.key === "k") { focusRow(current - 1); e.preventDefault(); }
      else if (e.key === "x" && current >= 0) {
        var b = rows[current].querySelector('input[name="ids"]');
        if (b) { b.checked = !b.checked; updateCount(); }
        e.preventDefault();
      } else if ((e.key === "o" || e.key === "Enter") && current >= 0) {
        var href = rows[current].getAttribute("data-href");
        if (href && href.indexOf("/alerts/") === 0) window.location.assign(href);
        e.preventDefault();
      } else if (e.key === "/" && search) { search.focus(); e.preventDefault(); }
      else if (e.key === "?" && help && help.showModal) { help.showModal(); e.preventDefault(); }
    });
    updateCount();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
