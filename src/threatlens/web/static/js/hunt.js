// Hunt console: Ctrl/Cmd+Enter runs the query; "Save" stores what is in the editor.
(function () {
  "use strict";

  function init() {
    var sql = document.getElementById("hunt-sql");
    var form = document.getElementById("hunt-form");
    var saveSql = document.getElementById("save-sql");
    if (!sql || !form) return;
    sql.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        form.requestSubmit ? form.requestSubmit() : form.submit();
      }
    });
    if (saveSql) {
      var saveForm = saveSql.form;
      saveForm.addEventListener("submit", function () { saveSql.value = sql.value; });
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
