// Minimal progressive enhancement. Every action still works (and is validated
// server-side) without JavaScript.
(function () {
  "use strict";

  document.documentElement.classList.add("js");

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

  // Live progress of a run (templates/_run_progress.html). Everything from the server is written
  // with textContent: messages can hold text from remote servers.
  var drawer = document.querySelector("[data-run-progress]");
  if (drawer) { runProgress(drawer); }

  function runProgress(panel) {
    var part = function (name) { return panel.querySelector("[data-rp-" + name + "]"); };
    var badge = document.querySelector("[data-rp-badge]");
    var stateKey = "ec2patcher.progress." + panel.getAttribute("data-run-progress");
    var active = panel.getAttribute("data-active") === "true";
    var servers = {};
    var phases = [];
    var terminal = [];
    var serverOrder = [];
    var last = 0;
    var clockSkew = 0;
    var startedAt = null;
    var finishedAt = null;
    var delay = 1000;
    var timer = null;
    var polling = false;
    var pollFailed = false;
    var finished = false;
    var loaded = false;
    var lastRefresh = Date.now();
    var pageRefreshMs = 3000;
    var maxDelay = 8000;
    var maxLogLines = 1000;
    var cancelRequested = false;

    var saved = {};
    try { saved = JSON.parse(window.sessionStorage.getItem(stateKey)) || {}; } catch (e) { saved = {}; }
    var open = saved.open === undefined ? active : saved.open;
    var paused = Boolean(saved.paused);

    function remember() {
      try {
        window.sessionStorage.setItem(stateKey, JSON.stringify({ open: open, paused: paused }));
      } catch (e) { /* private mode: the state just does not survive a refresh */ }
    }

    function formatTime(ms) {
      if (ms < 1000) { return ms + " ms"; }
      var seconds = Math.round(ms / 1000);
      if (seconds < 60) { return seconds + " s"; }
      return Math.floor(seconds / 60) + " min " + (seconds % 60) + " s";
    }

    function elapsedSince(iso) {
      return Math.max(0, Date.now() - clockSkew - Date.parse(iso));
    }

    function element(tag, className, text) {
      var node = document.createElement(tag);
      if (className) { node.className = className; }
      if (text !== undefined && text !== null) { node.textContent = text; }
      return node;
    }

    function serverState(name) {
      if (!servers[name]) { servers[name] = { steps: {}, end: null, status: "" }; }
      return servers[name];
    }

    function applyEvent(event) {
      appendLog(event);
      if (!event.server) { return; }
      var server = serverState(event.server);
      if (terminal.indexOf(event.phase) !== -1) {
        server.end = event;
        Object.keys(server.steps).forEach(function (id) {
          if (server.steps[id].state === "running") {
            server.steps[id].state = event.phase === "done" ? "done" : "stopped";
          }
        });
        return;
      }
      // A follow-up (re-analysis, retry) of a finished server starts over.
      if (server.end && phases.length && event.phase === phases[0].id) {
        server.steps = {};
        server.end = null;
      }
      var step = server.steps[event.phase];
      if (!step) {
        step = server.steps[event.phase] = { state: "running", startedAt: event.ts };
      }
      step.message = event.message;
      if (event.level === "error") {
        step.state = "failed";
        step.error = event.message;
        step.hint = event.hint;
        if (event.duration_ms !== null) { step.duration = event.duration_ms; }
      } else if (event.duration_ms !== null) {
        step.state = "done";
        step.duration = event.duration_ms;
      }
    }

    function appendLog(event) {
      var log = part("log");
      var time = event.ts.length >= 19 ? event.ts.slice(11, 19) : event.ts;
      var who = event.server ? " [" + event.server + "]" : "";
      var line = element("div", "rp-log-" + event.level);
      line.textContent = time + who + " " + event.phase_label + ": " + event.message;
      log.appendChild(line);
      while (log.childElementCount > maxLogLines) { log.removeChild(log.firstElementChild); }
    }

    function scrollLog() {
      var log = part("log");
      if (!paused) { log.scrollTop = log.scrollHeight; }
    }

    function stepMark(state) {
      if (state === "running") {
        return element("span", "rp-spinner");
      }
      return document.createTextNode(
        { done: "✓", failed: "✕", stopped: "⊘" }[state] || "○"
      );
    }

    function stateWord(state) {
      return { running: "running", done: "done", failed: "failed", stopped: "stopped" }[state] || "pending";
    }

    function renderStep(server, phase) {
      var step = server.steps[phase.id] || { state: "pending" };
      var item = element("li", "rp-step rp-step-" + step.state);
      if (step.state === "running") { item.setAttribute("aria-current", "step"); }
      var mark = element("span", "rp-step-mark");
      mark.setAttribute("aria-hidden", "true");
      mark.appendChild(stepMark(step.state));
      item.appendChild(mark);
      var body = element("div", "rp-step-body");
      body.appendChild(element("span", "rp-step-label", phase.label));
      body.appendChild(element("span", "sr-only", " (" + stateWord(step.state) + ")"));
      if (step.error) {
        body.appendChild(element("div", "rp-error", step.error));
        if (step.hint) { body.appendChild(element("div", "rp-hint", step.hint)); }
      } else if (step.message) {
        body.appendChild(element("div", "rp-step-detail", step.message));
      }
      item.appendChild(body);
      var time = element("span", "rp-step-time");
      if (step.duration !== undefined) {
        time.textContent = formatTime(step.duration);
      } else if (step.state === "running") {
        time.setAttribute("data-started", step.startedAt);
        time.textContent = formatTime(elapsedSince(step.startedAt));
      }
      item.appendChild(time);
      return item;
    }

    function renderServer(name) {
      var server = serverState(name);
      var section = element("section", "rp-server");
      var title = element("div", "rp-server-title");
      title.appendChild(element("strong", null, name));
      title.appendChild(element("span", "rp-server-state", server.end ? server.end.phase_label : server.status));
      section.appendChild(title);
      var doneSteps = phases.filter(function (phase) {
        var step = server.steps[phase.id];
        return step && step.state === "done";
      }).length;
      var bar = element("progress");
      bar.max = Math.max(1, phases.length);
      bar.value = server.end && server.end.phase === "done" ? bar.max : doneSteps;
      bar.setAttribute("aria-label", name + " steps");
      section.appendChild(bar);
      var list = element("ol", "rp-steps");
      phases.forEach(function (phase) {
        // A server not reached yet lists nothing; one that ended early, no step it never reached.
        var started = Object.keys(server.steps).length > 0;
        if (server.steps[phase.id] || (started && !server.end)) {
          list.appendChild(renderStep(server, phase));
        }
      });
      section.appendChild(list);
      var failedStep = Object.keys(server.steps).some(function (id) { return server.steps[id].error; });
      if (server.end && server.end.level !== "info" && !failedStep) {
        var cls = server.end.level === "error" ? "rp-error" : "rp-step-detail";
        section.appendChild(element("div", cls, server.end.message));
        if (server.end.hint) { section.appendChild(element("div", "rp-hint", server.end.hint)); }
      }
      return section;
    }

    function renderServers() {
      var box = part("servers");
      var scroll = box.scrollTop;
      box.textContent = "";
      serverOrder.forEach(function (name) { box.appendChild(renderServer(name)); });
      box.scrollTop = scroll;
    }

    function renderTotals(data) {
      part("status").textContent = data.status;
      part("status").className = "badge " + (
        data.cancelled ? "badge-neutral" : data.done ? "badge-info" : "badge-warning"
      );
      part("servers-count").textContent = data.servers_done + "/" + data.servers_total;
      part("cves-count").textContent = data.cves_done + "/" + data.cves_total;
      var serverBar = part("servers-bar");
      serverBar.max = Math.max(1, data.servers_total);
      serverBar.value = data.servers_done;
      var cveBar = part("cves-bar");
      cveBar.max = Math.max(1, data.cves_total);
      cveBar.value = data.cves_done;
      if (badge) {
        badge.querySelector("[data-rp-badge-count]").textContent =
          data.servers_done + "/" + data.servers_total;
      }
      var cancel = part("cancel");
      cancelRequested = data.cancel_requested;
      cancel.hidden = data.done;
      cancel.disabled = data.cancel_requested;
      cancel.textContent = data.cancel_requested ? "Cancelling…" : "Cancel";
      if (data.done && data.cancelled) {
        part("note").textContent = "The run was cancelled.";
      }
    }

    function renderElapsed() {
      if (startedAt) {
        var total = finishedAt ? Date.parse(finishedAt) - Date.parse(startedAt) : elapsedSince(startedAt);
        part("elapsed").textContent = formatTime(Math.max(0, total));
      }
      panel.querySelectorAll("[data-started]").forEach(function (node) {
        node.textContent = formatTime(elapsedSince(node.getAttribute("data-started")));
      });
    }

    function showOpenState() {
      panel.hidden = !open;
      if (badge) { badge.hidden = open || !active || finished; }
      if (open) { scrollLog(); }
    }

    function setOpen(value, moveFocus) {
      open = value;
      remember();
      showOpenState();
      if (open && !loaded) { poll(); }
      if (!moveFocus) { return; }
      if (open) {
        part("hide").focus();
      } else {
        var opener = badge && !badge.hidden ? badge : document.querySelector(".rp-needs-js[data-rp-show]");
        if (opener) { opener.focus(); }
      }
    }

    // The page behind the drawer (status line, server list), as its old automatic refresh did.
    function refreshPage() {
      fetch(window.location.href)
        .then(function (response) { return response.ok ? response.text() : Promise.reject(); })
        .then(function (html) {
          var fresh = new DOMParser().parseFromString(html, "text/html").querySelector("main.content");
          var current = document.querySelector("main.content");
          if (fresh && current) { current.innerHTML = fresh.innerHTML; }
        })
        .catch(function () { /* the next change tries again */ });
    }

    function schedule(wait) {
      window.clearTimeout(timer);
      timer = window.setTimeout(poll, wait);
    }

    function onData(data) {
      if (pollFailed) {
        pollFailed = false;
        part("note").textContent = "";
      }
      phases = data.phases;
      terminal = data.terminal_phases;
      serverOrder = data.servers.map(function (server) {
        serverState(server.name).status = server.status;
        return server.name;
      });
      startedAt = data.started_at;
      finishedAt = data.done ? data.finished_at : null;
      clockSkew = Date.now() - Date.parse(data.now);
      data.events.forEach(applyEvent);
      data.events.forEach(function (event) {
        if (event.server && serverOrder.indexOf(event.server) === -1) { serverOrder.push(event.server); }
      });
      last = data.next;
      loaded = true;
      renderServers();
      renderTotals(data);
      renderElapsed();
      scrollLog();
      if (!serverOrder.length && !last) {
        part("note").textContent = "No progress was recorded for this run.";
      }
      if (data.more) {
        schedule(0);
        return;
      }
      if (data.done) {
        finished = true;
        showOpenState();
        // A run that ended while this page was open: show its final state (and buttons).
        if (active) { window.location.reload(); }
        return;
      }
      if (data.events.length && Date.now() - lastRefresh >= pageRefreshMs) {
        lastRefresh = Date.now();
        refreshPage();
      }
      delay = data.events.length ? 1000 : Math.min(maxDelay, delay * 1.5);
      schedule(delay);
    }

    function poll() {
      if (polling || finished) { return; }
      polling = true;
      fetch(panel.getAttribute("data-events-url") + "?after=" + last, {
        headers: { Accept: "application/json" }
      })
        .then(function (response) {
          if (response.status === 404) {
            finished = true;
            part("note").textContent = "This run no longer exists.";
            return null;
          }
          return response.ok ? response.json() : Promise.reject();
        })
        .then(function (data) {
          polling = false;
          if (data) { onData(data); }
        })
        .catch(function () {
          polling = false;
          pollFailed = true;
          part("note").textContent = "Could not read the progress; trying again.";
          delay = Math.min(maxDelay, delay * 1.5);
          schedule(delay);
        });
    }

    function cancelRun() {
      if (cancelRequested) { return; }
      var question = "Cancel this run? It stops after the current step; finished servers keep their results.";
      if (!window.confirm(question)) { return; }
      var cancel = part("cancel");
      cancel.disabled = true;
      fetch(panel.getAttribute("data-cancel-url"), { method: "POST" })
        .then(function (response) { return response.json(); })
        .then(function (answer) {
          part("note").textContent = answer.message || answer.error || "";
          delay = 1000;
          schedule(0);
        })
        .catch(function () {
          cancel.disabled = false;
          part("note").textContent = "The cancel request could not be sent. Try again.";
        });
    }

    // Delegated: the page behind the drawer is replaced as servers finish.
    document.addEventListener("click", function (event) {
      if (event.target.closest("[data-rp-show]")) { setOpen(true, true); }
    });
    part("hide").addEventListener("click", function () { setOpen(false, true); });
    part("cancel").addEventListener("click", cancelRun);
    var pause = part("pause");
    var showPause = function () {
      pause.textContent = paused ? "Resume" : "Pause";
      pause.setAttribute("aria-pressed", paused ? "true" : "false");
    };
    pause.addEventListener("click", function () {
      paused = !paused;
      remember();
      showPause();
      scrollLog();
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && open) { setOpen(false, true); }
    });

    showPause();
    showOpenState();
    window.setInterval(renderElapsed, 1000);
    if (active || open) { poll(); }
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
