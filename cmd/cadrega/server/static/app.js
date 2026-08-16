(function() {
  var skillContent = null;
  var skillFilename = null;

  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("file-input");
  var filenameEl = document.getElementById("filename");
  var providerSelect = document.getElementById("provider");
  var modelInput = document.getElementById("model_name");
  var ollamaFields = document.getElementById("ollama-fields");
  var submitBtn = document.getElementById("submit-btn");
  var statusEl = document.getElementById("status");
  var resultsEl = document.getElementById("results");
  var form = document.getElementById("analyze-form");

  function severityLabel(sev) {
    switch (sev) {
      case 0: return "LOW";
      case 1: return "MEDIUM";
      case 2: return "HIGH";
      default: return "UNKNOWN";
    }
  }

  function updateSubmitState() {
    submitBtn.disabled = !(skillContent !== null && modelInput.value.trim() !== "");
  }

  // UX-only: fails fast client-side before reading/uploading a huge file.
  // The server enforces its own independent cap (maxRequestBodySize in
  // cmd/cadrega/server/server.go) via http.MaxBytesReader — that's the real
  // security boundary, since this check is trivially bypassable.
  var MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MiB

  function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_SIZE) {
      statusEl.textContent = "File too large (" + Math.round(file.size / 1024) + " KiB). Max is " + Math.round(MAX_FILE_SIZE / 1024) + " KiB.";
      return;
    }
    var reader = new FileReader();
    reader.onload = function() {
      skillContent = reader.result;
      skillFilename = file.name;
      filenameEl.textContent = "Loaded: " + skillFilename;
      updateSubmitState();
    };
    reader.onerror = function() {
      statusEl.textContent = "Failed to read file: " + reader.error;
    };
    reader.readAsText(file);
  }

  dropzone.addEventListener("click", function() {
    fileInput.click();
  });
  fileInput.addEventListener("change", function() {
    loadFile(fileInput.files[0]);
  });
  ["dragenter", "dragover"].forEach(function(evtName) {
    dropzone.addEventListener(evtName, function(e) {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach(function(evtName) {
    dropzone.addEventListener(evtName, function(e) {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });
  dropzone.addEventListener("drop", function(e) {
    var file = e.dataTransfer.files && e.dataTransfer.files[0];
    loadFile(file);
  });

  providerSelect.addEventListener("change", function() {
    ollamaFields.hidden = providerSelect.value !== "ollama";
  });
  modelInput.addEventListener("input", updateSubmitState);

  // severityLabel returns one of a fixed set of strings, so it is safe to
  // use as a CSS class as well as text content.
  function renderFinding(f) {
    var sevLabel = severityLabel(f.Severity);

    var div = document.createElement("div");
    div.className = "finding";

    var head = document.createElement("div");
    head.className = "finding-head";

    var badge = document.createElement("span");
    badge.className = "badge " + sevLabel;
    badge.textContent = sevLabel;
    head.appendChild(badge);

    var name = document.createElement("strong");
    name.textContent = f.Name || "";
    head.appendChild(name);

    var id = document.createElement("span");
    id.className = "finding-id";
    id.textContent = f.ID || "";
    head.appendChild(id);

    div.appendChild(head);

    var message = document.createElement("p");
    message.textContent = f.Message || "";
    div.appendChild(message);

    var evidence = document.createElement("pre");
    evidence.textContent = f.Evidence || "";
    div.appendChild(evidence);

    return div;
  }

  function renderFindingsSection(title, findings) {
    var section = document.createElement("div");
    var h2 = document.createElement("h2");
    h2.textContent = title;
    section.appendChild(h2);

    if (!findings || findings.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No findings.";
      section.appendChild(empty);
      return section;
    }

    findings.forEach(function(f) {
      section.appendChild(renderFinding(f));
    });
    return section;
  }

  // The verdict class is looked up in this fixed whitelist rather than
  // taken directly from the response, since staticVerdict/llmVerdict
  // (llmVerdict especially, sourced from the LLM's own output) is
  // attacker-influenceable and must never end up unescaped in a class
  // attribute.
  var VERDICT_CLASSES = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"];

  function verdictClass(v) {
    return VERDICT_CLASSES.indexOf(v) !== -1 ? v : "unmapped";
  }

  function renderVerdict(label, verdict) {
    var wrap = document.createElement("div");
    wrap.appendChild(document.createTextNode(label));
    wrap.appendChild(document.createElement("br"));

    var badge = document.createElement("span");
    badge.className = "badge " + verdictClass(verdict);
    badge.textContent = verdict || "?";
    wrap.appendChild(badge);

    return wrap;
  }

  function renderResults(data) {
    resultsEl.innerHTML = "";

    var panel = document.createElement("div");
    panel.className = "panel";

    var verdicts = document.createElement("div");
    verdicts.className = "verdicts";
    verdicts.appendChild(renderVerdict("Static verdict", data.staticVerdict));
    verdicts.appendChild(renderVerdict("LLM verdict", data.llmVerdict));
    panel.appendChild(verdicts);

    panel.appendChild(renderFindingsSection("Static Findings", data.staticFindings));
    panel.appendChild(renderFindingsSection("LLM Findings", data.llmFindings));

    resultsEl.appendChild(panel);
  }

  function renderError(message) {
    resultsEl.innerHTML = "";
    var box = document.createElement("div");
    box.className = "error-box";
    box.textContent = message;
    resultsEl.appendChild(box);
  }

  // Armed while an /analyze request is in flight, so a refresh/close/back
  // navigation prompts for confirmation instead of silently discarding an
  // in-progress (potentially slow, LLM-backed) analysis.
  //
  // beforeunload is not Baseline and Safari (particularly iOS) largely
  // ignores the confirmation dialog — that's a browser limitation with no
  // cross-browser workaround, not a bug here. It still degrades gracefully:
  // on browsers that ignore it, a refresh just behaves as it does today.
  var requestInFlight = false;

  window.addEventListener("beforeunload", function(e) {
    if (!requestInFlight) return;
    e.preventDefault();
  });

  form.addEventListener("submit", async function(e) {
    e.preventDefault();
    if (skillContent === null) return;

    var payload = {
      provider: providerSelect.value,
      model_name: modelInput.value.trim(),
      skill_content: skillContent
    };

    if (providerSelect.value === "ollama") {
      payload.ollama_address = document.getElementById("ollama_address").value;
      payload.ollama_port = parseInt(document.getElementById("ollama_port").value, 10) || 0;
      payload.ollama_num_ctx = parseInt(document.getElementById("ollama_num_ctx").value, 10) || 0;
      payload.ollama_think = document.getElementById("ollama_think").checked;
      payload.ollama_unload_model = document.getElementById("ollama_unload_model").checked;
    }

    submitBtn.disabled = true;
    statusEl.textContent = "Analyzing " + skillFilename + ": this can take a while for LLM analysis...";
    resultsEl.innerHTML = "";
    requestInFlight = true;

    try {
      var resp = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        var text = await resp.text();
        throw new Error("HTTP " + resp.status + ": " + text);
      }

      var data = await resp.json();
      statusEl.textContent = "Done.";
      renderResults(data);
    } catch (err) {
      statusEl.textContent = "Request failed.";
      renderError(err.message);
    } finally {
      requestInFlight = false;
      updateSubmitState();
    }
  });
})();
