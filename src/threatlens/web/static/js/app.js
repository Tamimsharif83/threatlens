// ThreatLens UI glue. Loaded as an external file: the CSP forbids inline scripts.
// Never assign log data to innerHTML here — server-rendered, escaped HTML only.
(function () {
  "use strict";

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  // Every HTMX request carries the session's CSRF token.
  document.addEventListener("htmx:configRequest", function (event) {
    event.detail.headers["X-CSRF-Token"] = csrfToken();
  });
})();
