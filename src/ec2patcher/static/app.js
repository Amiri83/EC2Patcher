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

  // Server form: show only the fields of the chosen login type (PEM key or password).
  // Without JavaScript both stay visible (see the <noscript> block of the form).
  var authSelect = document.querySelector("select[data-auth-method]");
  if (authSelect) {
    var showAuthFields = function () {
      var method = authSelect.value || "pem";
      document.querySelectorAll("[data-auth-only]").forEach(function (el) {
        el.hidden = el.getAttribute("data-auth-only") !== method;
      });
    };
    authSelect.addEventListener("change", showAuthFields);
    showAuthFields();
  }

  // Server form: the SSM fields only matter for SSH over SSM. Without JavaScript they stay
  // visible and are ignored for direct SSH.
  var connectionSelect = document.querySelector("select[data-connection-type]");
  if (connectionSelect) {
    var showConnectionFields = function () {
      var kind = connectionSelect.value || connectionSelect.getAttribute("data-default");
      document.querySelectorAll("[data-connection-only]").forEach(function (el) {
        el.hidden = el.getAttribute("data-connection-only") !== kind;
      });
    };
    connectionSelect.addEventListener("change", showConnectionFields);
    showConnectionFields();
  }

  // AWS profile and region: Other… reveals its text input. Without JavaScript the input stays
  // visible and only counts when Other… is selected.
  var otherField = function (select) {
    return document.querySelector('[data-other-input="' + select.id + '"]');
  };
  var otherInput = function (select) {
    return otherField(select).querySelector("input");
  };
  var showOtherInput = function (select) {
    otherField(select).hidden = select.value !== select.getAttribute("data-other");
  };
  document.querySelectorAll("select[data-other]").forEach(function (select) {
    showOtherInput(select);
    select.addEventListener("change", function () {
      showOtherInput(select);
      if (!otherField(select).hidden) { otherInput(select).focus(); }
    });
  });

  // Choosing a profile selects its own region, until a region has been chosen by hand.
  var profileSelect = document.querySelector('select[data-aws-choice="profile"]');
  var regionSelect = document.querySelector('select[data-aws-choice="region"]');
  if (profileSelect && regionSelect) {
    var regionChosen = regionSelect.value !== "" && !regionSelect.hasAttribute("data-from-profile");
    var profileRegions = {};
    var markRegionChosen = function () { regionChosen = true; };
    regionSelect.addEventListener("change", markRegionChosen);
    otherInput(regionSelect).addEventListener("input", markRegionChosen);
    fetch(profileSelect.getAttribute("data-aws-options-url"))
      .then(function (response) { return response.ok ? response.json() : Promise.reject(); })
      .then(function (data) { profileRegions = data.profile_regions || {}; })
      .catch(function () { profileRegions = {}; });
    var applyProfileRegion = function () {
      if (regionChosen) { return; }
      var isOther = profileSelect.value === profileSelect.getAttribute("data-other");
      var profile = isOther ? otherInput(profileSelect).value.trim() : profileSelect.value;
      var known = Object.prototype.hasOwnProperty.call(profileRegions, profile);
      var region = known ? profileRegions[profile] : "";
      var listed = Array.prototype.some.call(regionSelect.options, function (option) {
        return option.value === region;
      });
      regionSelect.value = listed ? region : regionSelect.getAttribute("data-other");
      otherInput(regionSelect).value = listed ? "" : region;
      showOtherInput(regionSelect);
    };
    profileSelect.addEventListener("change", applyProfileRegion);
    otherInput(profileSelect).addEventListener("change", applyProfileRegion);
  }

  // Settings: the SSM status runs the aws CLI, so it loads after the page. The Check now link
  // does the same without JavaScript.
  var ssmStatus = document.querySelector("[data-ssm-status-url]");
  if (ssmStatus) {
    fetch(ssmStatus.getAttribute("data-ssm-status-url"))
      .then(function (response) { return response.ok ? response.text() : Promise.reject(); })
      .then(function (html) { ssmStatus.innerHTML = html; })
      .catch(function () { ssmStatus.textContent = "The status could not be loaded. Use Check now."; });
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
