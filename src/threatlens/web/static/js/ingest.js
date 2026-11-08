// Ingest page: drag & drop onto the file input, upload progress bar.
// Only textContent is used for anything derived from file names.
(function () {
  "use strict";

  function init() {
    var zone = document.getElementById("dropzone");
    var input = document.getElementById("files");
    var list = document.getElementById("dropzone-files");
    var form = document.getElementById("upload-form");
    var bar = document.getElementById("upload-progress");
    if (!zone || !input || !form) return;

    function showFiles() {
      var names = [];
      for (var i = 0; i < input.files.length; i++) names.push(input.files[i].name);
      list.textContent = names.length ? names.join(", ") : "";
    }

    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (e) {
        e.preventDefault();
        zone.classList.add("dragging");
      });
    });
    ["dragleave", "drop"].forEach(function (type) {
      zone.addEventListener(type, function (e) {
        e.preventDefault();
        zone.classList.remove("dragging");
      });
    });
    zone.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showFiles();
      }
    });
    input.addEventListener("change", showFiles);

    form.addEventListener("htmx:xhr:progress", function (e) {
      if (!bar || !e.detail.lengthComputable) return;
      bar.hidden = false;
      bar.value = Math.round((e.detail.loaded / e.detail.total) * 100);
    });
    form.addEventListener("htmx:afterRequest", function () {
      if (bar) {
        bar.hidden = true;
        bar.value = 0;
      }
      form.reset();
      showFiles();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
