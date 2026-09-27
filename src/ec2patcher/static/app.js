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

  // Buttons that must only submit once (e.g. Approve & Start Patching). The server also
  // refuses duplicate approvals; this only avoids an accidental double click.
  document.querySelectorAll("button[data-once]").forEach(function (button) {
    button.form.addEventListener("submit", function () {
      window.setTimeout(function () { button.disabled = true; }, 0);
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

  // Server form: add/remove tag rows. Blank rows are ignored server-side.
  var tagRows = document.getElementById("tag-rows");
  var addTag = document.getElementById("add-tag");
  var tagTemplate = document.getElementById("tag-row-template");
  if (tagRows && addTag && tagTemplate) {
    addTag.addEventListener("click", function () {
      tagRows.appendChild(tagTemplate.content.cloneNode(true));
      tagRows.lastElementChild.querySelector("input").focus();
    });
    tagRows.addEventListener("click", function (event) {
      var button = event.target.closest("[data-remove-tag]");
      if (button) { button.closest(".tag-row").remove(); }
    });
  }

  // Report upload: submit as soon as a file is picked or dropped (the <noscript>
  // button covers the no-JS case). The dropzone is locked while uploading so the
  // report cannot be submitted twice.
  var uploadForm = document.getElementById("upload-form");
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("report_file");
  var label = document.getElementById("dropzone-text");
  if (uploadForm && dropzone && fileInput && label) {
    var uploading = false;
    function submitUpload() {
      if (uploading || !fileInput.files.length) { return; }
      uploading = true;
      label.textContent = "Uploading… " + fileInput.files[0].name;
      dropzone.classList.add("uploading");
      dropzone.setAttribute("aria-disabled", "true");
      dropzone.setAttribute("aria-busy", "true");
      // The input stays enabled: a disabled file input is left out of the form data.
      uploadForm.submit();
    }
    // Returning via the back button restores the page from cache; unlock it.
    window.addEventListener("pageshow", function (event) {
      if (event.persisted) {
        uploading = false;
        uploadForm.reset();
        label.textContent = "Choose a JSON file or drag it here";
        dropzone.classList.remove("uploading");
        dropzone.removeAttribute("aria-disabled");
        dropzone.removeAttribute("aria-busy");
      }
    });
    fileInput.addEventListener("click", function (event) {
      if (uploading) { event.preventDefault(); }
    });
    fileInput.addEventListener("change", submitUpload);
    ["dragenter", "dragover"].forEach(function (name) {
      dropzone.addEventListener(name, function (event) {
        event.preventDefault();
        if (!uploading) { dropzone.classList.add("dragover"); }
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      dropzone.addEventListener(name, function () { dropzone.classList.remove("dragover"); });
    });
    dropzone.addEventListener("drop", function (event) {
      event.preventDefault();
      if (uploading) { return; }
      if (event.dataTransfer && event.dataTransfer.files.length) {
        fileInput.files = event.dataTransfer.files;
        submitUpload();
      }
    });
  }
})();
