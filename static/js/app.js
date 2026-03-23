// static/js/app.js — GhostVenumAI v2.0 Agent Edition

// ── State ──────────────────────────────────────────────────────────────────────
const state = {
  scanOutput:  "",
  agentOutput: "",
  running:     false,
  config:      {},
};

// ── Utils ──────────────────────────────────────────────────────────────────────
function toast(msg, type = "info") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className   = `toast show ${type}`;
  setTimeout(() => { el.className = "toast"; }, 3500);
}

function setStatus(id, text, cls = "") {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = "log-status " + cls;
}

function appendLog(logId, text, cssClass = "log-plain") {
  const log = document.getElementById(logId);
  if (!log) return;
  const span = document.createElement("span");
  span.className = cssClass;
  span.textContent = text + "\n";
  log.appendChild(span);
  log.scrollTop = log.scrollHeight;
}

function clearLog(logId) {
  const el = document.getElementById(logId);
  if (el) el.innerHTML = "";
}

function agentClass(agentName) {
  const map = {
    "OrchestratorAgent": "log-orch",
    "ReconAgent":        "log-recon",
    "VulnAgent":         "log-vuln",
    "RemediationAgent":  "log-remed",
  };
  return map[agentName] || "log-plain";
}

function setStep(stepId, state) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = "step " + state;
  // Update verbinding lijn
  const line = el.nextElementSibling;
  if (line && line.classList.contains("step-line") && state === "done") {
    line.classList.add("done");
  }
}

function disableBtn(id, label) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.disabled = true;
  btn.dataset.origLabel = btn.textContent;
  btn.innerHTML = `<span class="spinner"></span>${label || "..."}`;
}

function enableBtn(id) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.disabled = false;
  btn.textContent = btn.dataset.origLabel || btn.textContent;
}

// ── Tabs ───────────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ── Config laden ───────────────────────────────────────────────────────────────
async function loadConfig() {
  try {
    const r   = await fetch("/api/config");
    const cfg = await r.json();
    state.config = cfg;

    if (cfg.target)    { document.getElementById("c-target").value = cfg.target;
                         document.getElementById("a-target").value = cfg.target;
                         document.getElementById("s-target").value = cfg.target; }
    if (cfg.nmap_args) { document.getElementById("c-args").value   = cfg.nmap_args;
                         document.getElementById("s-nmap-args").value = cfg.nmap_args; }
    if (cfg.openai_model) document.getElementById("c-model").value = cfg.openai_model;
    if (cfg.claude_model) document.getElementById("a-model").value = cfg.claude_model;
    if (cfg.language)     document.getElementById("s-lang").value  = cfg.language;

    // Badge-Status
    document.getElementById("badge-openai").className =
      "badge badge-key " + (cfg.has_openai_key ? "badge-on" : "badge-off");
    document.getElementById("badge-openai").textContent =
      cfg.has_openai_key ? "OpenAI ✓" : "OpenAI ✗";

    document.getElementById("badge-claude").className =
      "badge badge-key " + (cfg.has_anthropic_key ? "badge-on" : "badge-off");
    document.getElementById("badge-claude").textContent =
      cfg.has_anthropic_key ? "Claude ✓" : "Claude ✗";

  } catch (e) {
    console.error("Config-Fehler:", e);
  }
}

// ── Classic Scan ───────────────────────────────────────────────────────────────
document.getElementById("btn-scan").addEventListener("click", async () => {
  const target   = document.getElementById("c-target").value.trim();
  const nmap_args = document.getElementById("c-args").value.trim();
  if (!target) { toast("Bitte Ziel-IP eingeben.", "err"); return; }

  disableBtn("btn-scan", "Scan läuft...");
  setStatus("classic-status", "Scan läuft...", "running");
  clearLog("log-classic");
  appendLog("log-classic", `[INFO] Starte Nmap-Scan → Ziel: ${target}`, "log-info");

  try {
    const r = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, nmap_args })
    });
    const data = await r.json();
    if (data.error) {
      appendLog("log-classic", `[ERR] ${data.error}`, "log-err");
      setStatus("classic-status", "Fehler", "");
    } else {
      state.scanOutput = data.output;
      appendLog("log-classic", data.output, "log-dim");
      appendLog("log-classic", "[OK] Scan abgeschlossen.", "log-ok");
      setStatus("classic-status", "Scan fertig", "done");
      toast("Scan abgeschlossen.", "ok");
    }
  } catch (e) {
    appendLog("log-classic", `[ERR] ${e.message}`, "log-err");
    setStatus("classic-status", "Fehler", "");
  } finally {
    enableBtn("btn-scan");
  }
});

document.getElementById("btn-gpt").addEventListener("click", async () => {
  if (!state.scanOutput) { toast("Zuerst einen Scan durchführen.", "err"); return; }
  const model = document.getElementById("c-model").value;

  disableBtn("btn-gpt", "GPT läuft...");
  setStatus("classic-status", "GPT-Analyse...", "running");
  appendLog("log-classic", `[INFO] Starte GPT-Analyse (Modell: ${model})...`, "log-info");

  try {
    const r = await fetch("/api/gpt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_output: state.scanOutput, model })
    });
    const data = await r.json();
    if (data.error) {
      appendLog("log-classic", `[ERR] ${data.error}`, "log-err");
    } else {
      appendLog("log-classic", "\n[GPT-Analyse]\n" + data.output, "log-ok");
      appendLog("log-classic", `[OK] Gespeichert: ${data.path}`, "log-info");
      setStatus("classic-status", "GPT fertig", "done");
      toast("GPT-Analyse gespeichert.", "ok");
    }
  } catch (e) {
    appendLog("log-classic", `[ERR] ${e.message}`, "log-err");
  } finally {
    enableBtn("btn-gpt");
  }
});

document.getElementById("btn-sysinfo").addEventListener("click", async () => {
  try {
    const r    = await fetch("/api/sysinfo");
    const info = await r.json();
    const lines = Object.entries(info).map(([k, v]) => `  ${k}: ${v}`).join("\n");
    appendLog("log-classic", "[INFO] System-Informationen:\n" + lines, "log-info");
  } catch (e) {
    appendLog("log-classic", `[ERR] ${e.message}`, "log-err");
  }
});

document.getElementById("btn-save-classic").addEventListener("click", async () => {
  if (!state.scanOutput) { toast("Kein Scan-Output zum Speichern.", "err"); return; }
  try {
    const r    = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_output: state.scanOutput })
    });
    const data = await r.json();
    if (data.error) { toast(data.error, "err"); return; }
    appendLog("log-classic", `[OK] Report gespeichert: ${data.path}`, "log-ok");
    toast(`Report: ${data.path}`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

document.getElementById("btn-clear-classic").addEventListener("click", () => {
  clearLog("log-classic");
  state.scanOutput = "";
  setStatus("classic-status", "Bereit", "");
});

// ── Agent Mode ─────────────────────────────────────────────────────────────────
document.getElementById("btn-run-agents").addEventListener("click", () => {
  const target = document.getElementById("a-target").value.trim();
  if (!target) { toast("Bitte Ziel-IP eingeben.", "err"); return; }
  if (state.running)  { toast("Analyse läuft bereits.", "info"); return; }

  state.running     = true;
  state.agentOutput = "";
  disableBtn("btn-run-agents", "Analyse läuft...");
  clearLog("log-agents");
  setStatus("agents-status", "Läuft...", "running");

  // Fortschritts-Steps zurücksetzen
  const progressBox = document.getElementById("progress-container");
  progressBox.style.display = "block";
  ["step-recon", "step-vuln", "step-remed", "step-done"].forEach(id => setStep(id, ""));
  document.querySelectorAll(".step-line").forEach(l => l.classList.remove("done"));

  appendLog("log-agents",
    `[OrchestratorAgent] Starte Vollanalyse für: ${target}`, "log-orch");

  const evtSource = new EventSource(
    `/api/agents/stream?target=${encodeURIComponent(target)}`
  );

  evtSource.onmessage = (e) => {
    const data = JSON.parse(e.data);

    if (data.status === "start") return;
    if (data.status === "done") {
      evtSource.close();
      state.running = false;
      enableBtn("btn-run-agents");
      setStatus("agents-status", "Fertig", "done");
      setStep("step-done", "done");
      toast("Analyse abgeschlossen.", "ok");
      return;
    }

    const agent   = data.agent   || "";
    const content = data.content || "";
    const cls     = agentClass(agent);
    const prefix  = agent ? `[${agent}] ` : "";
    appendLog("log-agents", prefix + content, cls);

    // Fortschritts-Steps
    if (agent === "ReconAgent") {
      setStep("step-recon", "active");
      if (content.includes("abgeschlossen") || content.includes("fertig") || content.includes("Zeichen")) {
        setStep("step-recon", "done");
      }
    }
    if (agent === "VulnAgent") {
      setStep("step-vuln", "active");
      if (content.includes("abgeschlossen") || content.includes("Zeichen")) {
        setStep("step-vuln", "done");
      }
    }
    if (agent === "RemediationAgent") {
      setStep("step-remed", "active");
      if (content.includes("gespeichert") || content.includes("Empfehlungen generiert")) {
        setStep("step-remed", "done");
      }
    }

    state.agentOutput += prefix + content + "\n";
  };

  evtSource.onerror = () => {
    evtSource.close();
    state.running = false;
    enableBtn("btn-run-agents");
    setStatus("agents-status", "Fehler", "");
    appendLog("log-agents", "[ERR] Verbindung unterbrochen.", "log-err");
    toast("Fehler bei der Analyse.", "err");
  };
});

document.getElementById("btn-save-agents").addEventListener("click", () => {
  if (!state.agentOutput) { toast("Kein Agent-Output vorhanden.", "err"); return; }
  const blob = new Blob([state.agentOutput], { type: "text/plain;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `ghostvenumai_agents_${new Date().toISOString().slice(0,19).replace(/:/g,"-")}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  toast("Agent-Output heruntergeladen.", "ok");
});

document.getElementById("btn-clear-agents").addEventListener("click", () => {
  clearLog("log-agents");
  state.agentOutput = "";
  setStatus("agents-status", "Bereit", "");
  document.getElementById("progress-container").style.display = "none";
});

// ── Einstellungen ──────────────────────────────────────────────────────────────
function saveKey(type) {
  const inputId = type === "openai" ? "s-openai-key" : "s-anthropic-key";
  const key     = document.getElementById(inputId).value.trim();
  if (!key) { toast("Kein Key eingegeben.", "err"); return; }

  const payload = type === "openai"
    ? { openai_key: key }
    : { anthropic_key: key };

  fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).then(() => {
    toast(`${type === "openai" ? "OpenAI" : "Anthropic"} Key gespeichert.`, "ok");
    document.getElementById(inputId).value = "";
    loadConfig();
  }).catch(e => toast(e.message, "err"));
}

function saveSettings() {
  const payload = {
    language:     document.getElementById("s-lang").value,
    target:       document.getElementById("s-target").value.trim(),
    nmap_args:    document.getElementById("s-nmap-args").value.trim(),
  };
  fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).then(() => {
    toast("Einstellungen gespeichert.", "ok");
    loadConfig();
  }).catch(e => toast(e.message, "err"));
}

async function loadSysinfo() {
  const el = document.getElementById("sysinfo-output");
  el.innerHTML = "Laden...";
  try {
    const r    = await fetch("/api/sysinfo");
    const info = await r.json();
    el.innerHTML = Object.entries(info).map(([k, v]) => `
      <div class="sysinfo-item">
        <div class="sysinfo-label">${k.replace(/_/g, " ")}</div>
        <div class="sysinfo-value">${v}</div>
      </div>
    `).join("");
  } catch (e) {
    el.textContent = "Fehler: " + e.message;
  }
}

// ── Init ───────────────────────────────────────────────────────────────────────
loadConfig();
loadSysinfo();

// ── Historie ───────────────────────────────────────────────────────────────────

/**
 * Lädt alle bekannten Targets vom Backend und befüllt das Dropdown.
 */
async function loadTargets() {
  const select = document.getElementById("h-target-select");
  if (!select) return;
  try {
    const r       = await fetch("/api/targets");
    const targets = await r.json();
    // Placeholder beibehalten, dann Targets einfügen
    select.innerHTML = '<option value="">— Bitte Target wählen —</option>';
    if (Array.isArray(targets) && targets.length > 0) {
      targets.forEach(t => {
        const opt   = document.createElement("option");
        opt.value   = t;
        opt.textContent = t;
        select.appendChild(opt);
      });
    } else {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "Keine History-Daten vorhanden";
      opt.disabled = true;
      select.appendChild(opt);
    }
  } catch (e) {
    toast("Targets konnten nicht geladen werden: " + e.message, "err");
  }
}

/**
 * Lädt und rendert die Scan-Timeline für ein Target.
 */
async function loadHistory(target) {
  const timeline  = document.getElementById("history-timeline");
  const statusEl  = document.getElementById("history-status");
  if (!timeline || !target) return;

  timeline.innerHTML = '<div class="timeline-empty">Lade...</div>';
  if (statusEl) { statusEl.textContent = "Lade..."; statusEl.className = "log-status running"; }

  try {
    const r     = await fetch(`/api/history/${encodeURIComponent(target)}`);
    const scans = await r.json();

    if (!Array.isArray(scans) || scans.length === 0) {
      timeline.innerHTML = '<div class="timeline-empty">Keine Scan-Daten für dieses Target.</div>';
      if (statusEl) { statusEl.textContent = "Keine Daten"; statusEl.className = "log-status"; }
      return;
    }

    timeline.innerHTML = "";
    scans.forEach((scan, idx) => {
      const item = document.createElement("div");
      item.className = "timeline-item" + (idx === 0 ? " timeline-item-latest" : "");

      const dateStr = scan.timestamp
        ? new Date(scan.timestamp).toLocaleString("de-DE")
        : scan.scan_id;

      item.innerHTML = `
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <div class="timeline-date">${dateStr}</div>
          <div class="timeline-meta">
            <span class="diff-badge" style="background:rgba(88,166,255,.15);color:var(--blue);border-color:rgba(88,166,255,.3)">
              ${scan.port_count} Port${scan.port_count !== 1 ? "s" : ""}
            </span>
            <span class="diff-badge" style="background:rgba(248,81,73,.12);color:var(--red);border-color:rgba(248,81,73,.3)">
              ${scan.cve_count} CVE${scan.cve_count !== 1 ? "s" : ""}
            </span>
            ${idx === 0 ? '<span class="diff-badge" style="background:rgba(63,185,80,.15);color:var(--green);border-color:rgba(63,185,80,.3)">Aktuellster</span>' : ""}
          </div>
          <div class="timeline-id">ID: ${scan.scan_id}</div>
        </div>
      `;
      timeline.appendChild(item);
    });

    if (statusEl) {
      statusEl.textContent = `${scans.length} Scan${scans.length !== 1 ? "s" : ""}`;
      statusEl.className = "log-status done";
    }
  } catch (e) {
    timeline.innerHTML = `<div class="timeline-empty">Fehler: ${e.message}</div>`;
    if (statusEl) { statusEl.textContent = "Fehler"; statusEl.className = "log-status"; }
    toast("History konnte nicht geladen werden: " + e.message, "err");
  }
}

/**
 * Lädt und rendert den Diff (Vergleich der letzten 2 Scans) für ein Target.
 */
async function loadDiff(target) {
  const container = document.getElementById("diff-container");
  if (!container || !target) return;

  container.innerHTML = '<div class="timeline-empty">Lade Vergleich...</div>';

  try {
    const r    = await fetch(`/api/diff/${encodeURIComponent(target)}`);
    const data = await r.json();

    if (data.error) {
      container.innerHTML = `<div class="timeline-empty">Fehler: ${data.error}</div>`;
      return;
    }

    if (!data.available) {
      container.innerHTML = '<div class="timeline-empty">Mindestens 2 Scans erforderlich für einen Vergleich.</div>';
      return;
    }

    const diff       = data.diff;
    const oldDate    = data.old_timestamp ? new Date(data.old_timestamp).toLocaleString("de-DE") : "—";
    const newDate    = data.new_timestamp ? new Date(data.new_timestamp).toLocaleString("de-DE") : "—";

    function renderItems(items, cls, badge) {
      if (!items || items.length === 0) return "";
      return items.map(item => {
        const label = item.port !== undefined
          ? `${item.port}/${item.proto} — ${item.service}${item.version ? " " + item.version : ""}`
          : `${item.cve_id} — CVSS ${item.cvss} — ${item.severity}`;
        return `<div class="diff-item ${cls}"><span class="diff-badge-inline">${badge}</span>${escapeHtml(label)}</div>`;
      }).join("");
    }

    container.innerHTML = `
      <div class="diff-meta">
        <span class="diff-meta-label">Alt:</span> ${escapeHtml(oldDate)}
        &nbsp;&nbsp;→&nbsp;&nbsp;
        <span class="diff-meta-label">Neu:</span> ${escapeHtml(newDate)}
      </div>
      <div class="diff-summary-bar">${escapeHtml(diff.summary)}</div>

      <div class="diff-section">
        <div class="diff-section-title">Ports</div>
        ${renderItems(diff.ports.new,       "new",       "NEU")}
        ${renderItems(diff.ports.closed,    "closed",    "GESCHLOSSEN")}
        ${renderItems(diff.ports.unchanged, "unchanged", "UNVERÄNDERT")}
        ${(!diff.ports.new.length && !diff.ports.closed.length && !diff.ports.unchanged.length)
          ? '<div class="timeline-empty" style="padding:8px 0">Keine Port-Daten.</div>' : ""}
      </div>

      <div class="diff-section">
        <div class="diff-section-title">CVEs</div>
        ${renderItems(diff.cves.new,       "new",      "NEU")}
        ${renderItems(diff.cves.resolved,  "resolved", "BEHOBEN ✓")}
        ${renderItems(diff.cves.unchanged, "unchanged","UNVERÄNDERT")}
        ${(!diff.cves.new.length && !diff.cves.resolved.length && !diff.cves.unchanged.length)
          ? '<div class="timeline-empty" style="padding:8px 0">Keine CVE-Daten.</div>' : ""}
      </div>
    `;
  } catch (e) {
    container.innerHTML = `<div class="timeline-empty">Fehler: ${e.message}</div>`;
    toast("Diff konnte nicht geladen werden: " + e.message, "err");
  }
}

/**
 * Einfaches HTML-Escaping.
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Event-Listener für History-Tab ─────────────────────────────────────────────

// History-Tab: Targets automatisch laden wenn Tab geöffnet wird
document.querySelectorAll(".tab-btn").forEach(btn => {
  if (btn.dataset.tab === "history") {
    btn.addEventListener("click", () => {
      loadTargets();
    });
  }
});

// Target-Dropdown: History laden wenn Target gewählt wird
const hTargetSelect = document.getElementById("h-target-select");
if (hTargetSelect) {
  hTargetSelect.addEventListener("change", () => {
    const target = hTargetSelect.value;
    if (target) {
      loadHistory(target);
      // Diff-Container zurücksetzen
      const diffContainer = document.getElementById("diff-container");
      if (diffContainer) {
        diffContainer.innerHTML = '<div class="timeline-empty">Klicke "Vergleich laden" um den Scan-Vergleich anzuzeigen.</div>';
      }
    } else {
      const timeline = document.getElementById("history-timeline");
      if (timeline) timeline.innerHTML = '<div class="timeline-empty">Kein Target gewählt oder keine History vorhanden.</div>';
    }
  });
}

// Targets-Refresh-Button
const btnRefreshTargets = document.getElementById("btn-refresh-targets");
if (btnRefreshTargets) {
  btnRefreshTargets.addEventListener("click", () => {
    loadTargets().then(() => toast("Targets aktualisiert.", "ok"));
  });
}

// ── Monitoring ──────────────────────────────────────────────────────────────────

let monitorEvtSource = null;

function updateMonitorStatus(status) {
  if (!status) return;
  const dot  = document.getElementById("monitor-dot");
  const text = document.getElementById("monitor-status-text");
  const bar  = document.getElementById("monitor-status-bar");

  if (bar) bar.style.display = "flex";

  if (status.running) {
    if (dot)  { dot.className = "monitor-dot running"; }
    if (text) text.textContent = `Läuft — Ziel: ${status.target}`;
    setStatus("monitor-log-status", "Läuft...", "running");
  } else {
    if (dot)  { dot.className = "monitor-dot stopped"; }
    if (text) text.textContent = "Gestoppt";
    setStatus("monitor-log-status", "Gestoppt", "");
  }

  const sc = document.getElementById("m-scan-count");
  const cc = document.getElementById("m-change-count");
  const ls = document.getElementById("m-last-scan");
  const ns = document.getElementById("m-next-scan");
  if (sc) sc.textContent = status.scan_count   || 0;
  if (cc) cc.textContent = status.change_count || 0;
  if (ls) ls.textContent = status.last_scan    || "—";
  if (ns) ns.textContent = status.next_scan    || "—";
}

document.getElementById("btn-monitor-start").addEventListener("click", () => {
  const target   = document.getElementById("m-target").value.trim();
  const interval = document.getElementById("m-interval").value;
  const nmapArgs = document.getElementById("m-nmap-args").value.trim();

  if (!target) { toast("Bitte Ziel-IP eingeben.", "err"); return; }

  document.getElementById("btn-monitor-start").disabled = true;
  document.getElementById("btn-monitor-stop").disabled  = false;
  clearLog("log-monitor");
  appendLog("log-monitor", `[Monitor] Starte Monitoring — Ziel: ${target} | Intervall: ${interval} min`, "log-info");

  if (monitorEvtSource) { monitorEvtSource.close(); }

  fetch("/api/monitor/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, interval_min: parseInt(interval), nmap_args: nmapArgs })
  }).then(r => {
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    function read() {
      reader.read().then(({ done, value }) => {
        if (done) return;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n\n");
        buf = lines.pop();
        lines.forEach(line => {
          const dataLine = line.replace(/^data: /, "").trim();
          if (!dataLine) return;
          try {
            const msg = JSON.parse(dataLine);
            if (msg.status) updateMonitorStatus(msg.status);

            if (msg.type === "log") {
              const content = msg.content || "";
              const cls = content.includes("ÄNDERUNG") || content.includes("⚠️")
                ? "log-change"
                : content.includes("✅") ? "log-ok"
                : content.includes("FEHLER") || content.includes("ERR") ? "log-err"
                : "log-plain";
              appendLog("log-monitor", content, cls);
            } else if (msg.type === "change") {
              const d = msg.diff;
              appendLog("log-monitor", `⚠️  ÄNDERUNG: ${d.summary}`, "log-change");
              (d.new_ports    || []).forEach(p => appendLog("log-monitor", `  🔴 Neuer Port: ${p}`, "log-err"));
              (d.closed_ports || []).forEach(p => appendLog("log-monitor", `  🟡 Port geschlossen: ${p}`, "log-warn"));
              (d.versions     || []).forEach(v => appendLog("log-monitor",
                `  🔵 Version: ${v.port} ${v.service} ${v.old_version} → ${v.new_version}`, "log-info"));
              toast("⚠️ Netzwerkänderung erkannt!", "err");
            } else if (msg.type === "stopped") {
              document.getElementById("btn-monitor-start").disabled = false;
              document.getElementById("btn-monitor-stop").disabled  = true;
              appendLog("log-monitor", "[Monitor] Gestoppt.", "log-warn");
              setStatus("monitor-log-status", "Gestoppt", "");
            }
          } catch (e) { /* ignorieren */ }
        });
        read();
      });
    }
    read();
  }).catch(e => {
    toast("Monitoring-Fehler: " + e.message, "err");
    document.getElementById("btn-monitor-start").disabled = false;
    document.getElementById("btn-monitor-stop").disabled  = true;
  });
});

document.getElementById("btn-monitor-stop").addEventListener("click", () => {
  fetch("/api/monitor/stop", { method: "POST" })
    .then(() => {
      document.getElementById("btn-monitor-start").disabled = false;
      document.getElementById("btn-monitor-stop").disabled  = true;
      appendLog("log-monitor", "[Monitor] Stopp-Signal gesendet.", "log-warn");
      setStatus("monitor-log-status", "Gestoppt", "");
      const dot = document.getElementById("monitor-dot");
      if (dot) dot.className = "monitor-dot stopped";
    });
});

document.getElementById("btn-monitor-clear").addEventListener("click", () => {
  clearLog("log-monitor");
});

// Diff-Button
const btnLoadDiff = document.getElementById("btn-load-diff");
if (btnLoadDiff) {
  btnLoadDiff.addEventListener("click", () => {
    const target = document.getElementById("h-target-select")
      ? document.getElementById("h-target-select").value
      : "";
    if (!target) { toast("Bitte zuerst ein Target wählen.", "err"); return; }
    loadDiff(target);
  });
}
