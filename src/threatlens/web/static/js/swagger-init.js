// Initialises the vendored Swagger UI (kept out of the HTML because of the CSP).
(function () {
  "use strict";
  var root = document.getElementById("swagger-ui");
  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute("content") : "";
  window.SwaggerUIBundle({
    url: root.getAttribute("data-spec-url"),
    dom_id: "#swagger-ui",
    deepLinking: true,
    // Swagger's "Try it out" uses the session cookie; add the CSRF header too.
    requestInterceptor: function (req) {
      req.headers["X-CSRF-Token"] = csrf;
      return req;
    },
  });
})();
