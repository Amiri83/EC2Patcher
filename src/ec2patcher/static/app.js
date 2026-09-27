// Minimal progressive enhancement. Every action still works (and is validated
// server-side) without JavaScript.
(function () {
  "use strict";

  // Confirmation prompt for single destructive actions (e.g. delete server).
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // "Clear All Servers": enable the button only when the exact text is typed.
  document.querySelectorAll("input[data-required-text]").forEach(function (input) {
    var button = input.form.querySelector("[data-enable-when-confirmed]");
    var required = input.getAttribute("data-required-text");
    function update() { button.disabled = input.value.trim() !== required; }
    input.addEventListener("input", update);
    update();
  });

  // Report upload: show chosen file name and support drag & drop.
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("report_file");
  var label = document.getElementById("dropzone-text");
  if (dropzone && fileInput && label) {
    fileInput.addEventListener("change", function () {
      if (fileInput.files.length) { label.textContent = fileInput.files[0].name; }
    });
    ["dragenter", "dragover"].forEach(function (name) {
      dropzone.addEventListener(name, function (event) {
        event.preventDefault();
        dropzone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      dropzone.addEventListener(name, function () { dropzone.classList.remove("dragover"); });
    });
    dropzone.addEventListener("drop", function (event) {
      event.preventDefault();
      if (event.dataTransfer && event.dataTransfer.files.length) {
        fileInput.files = event.dataTransfer.files;
        label.textContent = event.dataTransfer.files[0].name;
      }
    });
  }
})();
