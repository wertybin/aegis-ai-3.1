const startBtn = document.getElementById("startAuditBtn");
const dastBtn = document.getElementById("dastBtn");
const targetInput = document.getElementById("targetInput");
const consoleOutput = document.getElementById("consoleOutput");
const chatFeed = document.getElementById("chatFeed");
const scoreBadge = document.getElementById("scoreBadge");
const downloadPdfBtn = document.getElementById("downloadPdfBtn");
const stages = document.querySelectorAll(".pipeline .stage");
const siteChips = document.querySelectorAll(".site-chip");

const engineStatus = document.getElementById("engineStatus");
const scanIdLabel = document.getElementById("scanIdLabel");
const scanElapsed = document.getElementById("scanElapsed");
const cancelScanBtn = document.getElementById("cancelScanBtn");
const retryStageBtn = document.getElementById("retryStageBtn");
const historyBtn = document.getElementById("historyBtn");
const historyPanel = document.getElementById("historyPanel");
const historyList = document.getElementById("historyList");
const closeHistoryBtn = document.getElementById("closeHistoryBtn");
const surfaceBtn = document.getElementById("surfaceBtn");
const graphBtn = document.getElementById("graphBtn");
const intelPanel = document.getElementById("intelPanel");
const intelTitle = document.getElementById("intelTitle");
const intelStats = document.getElementById("intelStats");
const intelBody = document.getElementById("intelBody");
const closeIntelBtn = document.getElementById("closeIntelBtn");
const remediationBtn = document.getElementById("remediationBtn");
const remediationPanel = document.getElementById("remediationPanel");
const remediationStats = document.getElementById("remediationStats");
const remediationBody = document.getElementById("remediationBody");
const closeRemediationBtn = document.getElementById("closeRemediationBtn");
const verifyBtn = document.getElementById("verifyBtn");
const verificationPanel = document.getElementById("verificationPanel");
const verificationStats = document.getElementById("verificationStats");
const verificationBody = document.getElementById("verificationBody");
const closeVerificationBtn = document.getElementById("closeVerificationBtn");
const compareBtn = document.getElementById("compareBtn");
const comparisonPanel = document.getElementById("comparisonPanel");
const comparisonStats = document.getElementById("comparisonStats");
const comparisonBody = document.getElementById("comparisonBody");
const closeComparisonBtn = document.getElementById("closeComparisonBtn");
const apiSecBtn = document.getElementById("apiSecBtn");
const apiSecPanel = document.getElementById("apiSecPanel");
const apiSecStats = document.getElementById("apiSecStats");
const apiSecBody = document.getElementById("apiSecBody");
const closeApiSecBtn = document.getElementById("closeApiSecBtn");
const monitorBtn = document.getElementById("monitorBtn");
const monitorPanel = document.getElementById("monitorPanel");
const monitorStats = document.getElementById("monitorStats");
const monitorBody = document.getElementById("monitorBody");
const closeMonitorBtn = document.getElementById("closeMonitorBtn");
const overviewBtn = document.getElementById("overviewBtn");
const overviewPanel = document.getElementById("overviewPanel");
const overviewStats = document.getElementById("overviewStats");
const overviewBody = document.getElementById("overviewBody");
const closeOverviewBtn = document.getElementById("closeOverviewBtn");
const vulnCenterBtn = document.getElementById("vulnCenterBtn");
const vulnCenterPanel = document.getElementById("vulnCenterPanel");
const vulnCenterStats = document.getElementById("vulnCenterStats");
const vulnCenterBody = document.getElementById("vulnCenterBody");
const closeVulnCenterBtn = document.getElementById("closeVulnCenterBtn");
const aiIntelBtn = document.getElementById("aiIntelBtn");
const aiIntelPanel = document.getElementById("aiIntelPanel");
const aiIntelStats = document.getElementById("aiIntelStats");
const aiIntelBody = document.getElementById("aiIntelBody");
const closeAiIntelBtn = document.getElementById("closeAiIntelBtn");
const reportsBtn = document.getElementById("reportsBtn");
const reportsPanel = document.getElementById("reportsPanel");
const reportsStats = document.getElementById("reportsStats");
const reportsBody = document.getElementById("reportsBody");
const closeReportsBtn = document.getElementById("closeReportsBtn");
const copilotBtn = document.getElementById("copilotBtn");
const copilotPanel = document.getElementById("copilotPanel");
const copilotStats = document.getElementById("copilotStats");
const copilotBody = document.getElementById("copilotBody");
const closeCopilotBtn = document.getElementById("closeCopilotBtn");
const settingsBtn = document.getElementById("settingsBtn");
const settingsPanel = document.getElementById("settingsPanel");
const settingsStats = document.getElementById("settingsStats");
const settingsBody = document.getElementById("settingsBody");
const closeSettingsBtn = document.getElementById("closeSettingsBtn");
let activeRemediationApproval = null;
let monitorPollTimer = null;

siteChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    targetInput.value = chip.dataset.target;
    siteChips.forEach((c) => c.classList.toggle("active", c === chip));
  });
});

let currentSource = null;
let dastSource = null;
let activeScanId = null;
let activeScanMode = null;
let failedStage = 0;
let scanStartedAt = null;
let elapsedTimer = null;

function appendLog(text, type = "normal") {
  const div = document.createElement("div");
  div.className = `log-line ${type}`;
  div.textContent = `> ${text}`;
  consoleOutput.appendChild(div);
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setPipelineStep(data) {
  const stepNumber = typeof data === "number" ? data : Number(data.step);
  const state = typeof data === "object" && data.state ? data.state : "running";
  const durationMs = typeof data === "object" ? data.durationMs : null;

  stages.forEach((el) => {
    const step = Number(el.dataset.step);
    el.classList.remove("active", "done", "running", "failed", "skipped", "pending");
    const oldTime = el.querySelector(".stage-time");
    if (oldTime) oldTime.remove();

    if (step === stepNumber && durationMs !== null && durationMs !== undefined) {
      const time = document.createElement("span");
      time.className = "stage-time";
      time.textContent = `${(durationMs / 1000).toFixed(2)}s`;
      el.appendChild(time);
    }

    if (state === "completed" && step <= stepNumber) {
      el.classList.add("done");
    } else if (state === "running" && step === stepNumber) {
      el.classList.add("running");
    } else if (state === "failed" && step === stepNumber) {
      el.classList.add("failed");
      failedStage = Math.max(failedStage, step);
    } else if (state === "skipped" && step === stepNumber) {
      el.classList.add("skipped");
      failedStage = Math.max(failedStage, step);
    } else if (step < stepNumber) {
      el.classList.add("done");
    } else {
      el.classList.add("pending");
    }
  });
}

function completeAllStages() {
  stages.forEach((el) => {
    if (el.classList.contains("failed") || el.classList.contains("skipped")) return;
    el.classList.remove("active", "running", "pending");
    el.classList.add("done");
  });
}

function resetPipeline() {
  failedStage = 0;
  stages.forEach((el) => {
    el.classList.remove("active", "done", "running", "failed", "skipped", "pending");
    const time = el.querySelector(".stage-time");
    if (time) time.remove();
  });
}

function startElapsedTimer() {
  scanStartedAt = Date.now();
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = setInterval(() => {
    if (scanStartedAt) {
      scanElapsed.textContent = `${((Date.now() - scanStartedAt) / 1000).toFixed(1)}s`;
    }
  }, 200);
}

function stopElapsedTimer() {
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = null;
}

function setEngineStatus(status) {
  engineStatus.textContent = String(status || "IDLE").toUpperCase();
  const running = ["queued", "running", "cancelling", "scanning"].includes(String(status).toLowerCase());
  cancelScanBtn.disabled = !running || !activeScanId;
  retryStageBtn.disabled = running || !activeScanId || failedStage === 0;
}

function registerScan(scanId, status = "running", mode = null) {
  if (scanId && scanId !== activeScanId) {
    activeScanId = scanId;
    scanIdLabel.textContent = scanId;
    startElapsedTimer();
  }
  if (mode) activeScanMode = mode;
  setEngineStatus(status);
}

function finishEngine(status) {
  setEngineStatus(status);
  if (activeScanId && failedStage > 0) retryStageBtn.disabled = false;
  stopElapsedTimer();
}

function renderAuditResult(audit, statusBanner = null) {
  scoreBadge.textContent = `SCORE: ${audit.score}/100`;
  scoreBadge.style.color = audit.score >= 80 ? "#10B981" : "#F43F5E";
  downloadPdfBtn.classList.remove("hidden");

  const card = document.createElement("div");
  card.className = "chat-msg";

  let html = "";
  if (statusBanner) {
    html += `<div style="color:#10B981;font-weight:bold;margin-bottom:8px;">✔ ${escapeHtml(statusBanner)}</div>`;
  }

  const endpoints = audit.endpoints || [];
  const findings = audit.findings || [];
  html += `<div><strong>Target Audited:</strong> <code>${escapeHtml(audit.file_name)}</code> | <strong>Routes Discovered:</strong> ${endpoints.length}</div>`;

  if (findings.length === 0) {
    html += `<div style="margin-top:10px;color:#10B981;">All static OWASP security checks passed. No vulnerabilities remain in the target file.</div>`;
  } else {
    html += `<div style="margin-top:8px;">Detected <strong>${findings.length}</strong> security weakness(es):</div>`;
    findings.forEach((f) => {
      html += `
        <div class="finding-card">
          <div class="finding-title">[${escapeHtml(f.severity)}] ${escapeHtml(f.title)} — (${escapeHtml(f.endpoint)})</div>
          <div>${escapeHtml(f.explanation)}</div>
          <div class="diff-grid">
            <div>
              <small style="color:#FDA4AF;">VULNERABLE CODE</small>
              <pre class="code-box vuln">${escapeHtml(f.vulnerable_snippet)}</pre>
            </div>
            <div>
              <small style="color:#6EE7B7;">RECOMMENDED PATCH</small>
              <pre class="code-box patch">${escapeHtml(f.patched_snippet)}</pre>
            </div>
          </div>
        </div>
      `;
    });
  }

  card.innerHTML = html;

  if (findings.length > 0 && audit.file_path) {
    const patchBtn = document.createElement("button");
    patchBtn.className = "btn-patch";
    patchBtn.textContent = "[ APPLY FIX & RE-VERIFY ]";
    patchBtn.addEventListener("click", () => applyFix(audit.file_path));
    card.appendChild(patchBtn);
  }

  chatFeed.appendChild(card);
  chatFeed.scrollTop = chatFeed.scrollHeight;
}

function setDastBusy(busy) {
  startBtn.disabled = busy;
  dastBtn.disabled = busy;
  dastBtn.textContent = busy ? "[ DAST RUNNING... ]" : "[ RUN DAST ]";
}

function handleComplete(data) {
  completeAllStages();
  downloadPdfBtn.classList.remove("hidden");

  if (data.audit) {
    renderAuditResult(data.audit);
    if (typeof data.audit.score === "number") {
      scoreBadge.textContent = `SCORE: ${data.audit.score}/100`;
      scoreBadge.style.color = data.audit.score >= 80 ? "#10B981" : "#F43F5E";
    }
  } else if (data.dast) {
    if (typeof data.score === "number") {
      scoreBadge.textContent = `SCORE: ${data.score}/100`;
      scoreBadge.style.color = data.score >= 80 ? "#10B981" : "#F43F5E";
    }
    renderDastResult(data.dast, data.score, data.file_name);
  }

  const correlation = data.audit ? data.audit.correlations : data.correlations;
  if (correlation) renderCorrelations(correlation);

  const vuln = data.audit ? data.audit.vulnerability_analysis : data.vulnerability_analysis;
  if (vuln) renderVulnerabilityAnalysis(vuln);

  if (!data.pdf_filename) downloadPdfBtn.classList.add("hidden");
  finishEngine("completed");
  setDastBusy(false);
  loadHistory();
}

function handleEngineError(data) {
  appendLog(data.msg, "error");
  const errCard = document.createElement("div");
  errCard.className = "chat-msg";
  errCard.style.borderColor = "#F43F5E";
  const label = document.createElement("strong");
  label.style.color = "#F43F5E";
  label.textContent = data.cancelled ? "SCAN CANCELLED:" : "ENGINE ERROR:";
  errCard.appendChild(label);
  errCard.appendChild(document.createTextNode(` ${data.msg}`));
  chatFeed.appendChild(errCard);
  finishEngine(data.cancelled ? "cancelled" : "failed");
  setDastBusy(false);
}

function clearWorkspace() {
  consoleOutput.innerHTML = "";
  chatFeed.innerHTML = "";
  downloadPdfBtn.classList.add("hidden");
  resetPipeline();
  activeScanId = null;
  activeScanMode = null;
  failedStage = 0;
  scanIdLabel.textContent = "--";
  scanElapsed.textContent = "0.0s";
  stopElapsedTimer();
}

function attachStream(source, isDast = false) {
  source.addEventListener("scan", (e) => {
    const data = JSON.parse(e.data);
    const scan = data.scan || {};
    registerScan(scan.id, scan.status, scan.mode);
    (scan.stages || []).forEach((stage) => {
      if (stage.state && stage.state !== "pending") setPipelineStep(stage);
    });
    if (data.finished) {
      finishEngine(scan.status || "completed");
      source.close();
      setDastBusy(false);
    }
  });

  source.addEventListener("stage", (e) => {
    const data = JSON.parse(e.data);
    registerScan(data.scanId, "running");
    setPipelineStep(data);
  });

  source.addEventListener("log", (e) => {
    const data = JSON.parse(e.data);
    registerScan(data.scanId, "running");
    appendLog(data.msg, data.level === "error" ? "error" : "normal");
  });

  source.addEventListener("error", (e) => {
    if (!e.data) return;
    const data = JSON.parse(e.data);
    handleEngineError(data);
    source.close();
    if (isDast) setDastBusy(false);
  });

  source.addEventListener("complete", (e) => {
    handleComplete(JSON.parse(e.data));
    source.close();
  });
}

startBtn.addEventListener("click", () => {
  if (currentSource) currentSource.close();
  if (dastSource) {
    dastSource.close();
    dastSource = null;
  }
  clearWorkspace();
  setEngineStatus("queued");

  const target = encodeURIComponent(targetInput.value.trim());
  currentSource = new EventSource(`/api/audit-stream?target=${target}`);
  attachStream(currentSource, false);
});

dastBtn.addEventListener("click", () => {
  if (currentSource) currentSource.close();
  if (dastSource) dastSource.close();
  clearWorkspace();
  setDastBusy(true);
  setEngineStatus("queued");

  const target = encodeURIComponent(targetInput.value.trim());
  dastSource = new EventSource(`/api/dast-stream?target=${target}`);
  attachStream(dastSource, true);
});

async function applyFix(filePath) {
  appendLog("Applying automated defensive code patch & creating .bak backup...");
  const res = await fetch("/api/apply-patch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file_path: filePath }),
  });
  const data = await res.json();
  if (!res.ok) {
    appendLog(`Patch error: ${data.detail}`, "error");
    return;
  }
  appendLog(data.message);
  appendLog(data.hw_status);
  renderAuditResult(data.audit, `${data.message} Security Score updated!`);
  loadHistory();
}

cancelScanBtn.addEventListener("click", async () => {
  if (!activeScanId) return;
  const res = await fetch(`/api/engine/scans/${activeScanId}/cancel`, { method: "POST" });
  const data = await res.json();
  if (!res.ok) {
    appendLog(data.detail || "Cancel failed.", "error");
    return;
  }
  setEngineStatus("cancelling");
  appendLog(`[ENGINE] Cancel requested for ${data.scanId}.`);
});

retryStageBtn.addEventListener("click", async () => {
  if (!activeScanId || !failedStage) return;
  const res = await fetch(`/api/engine/scans/${activeScanId}/retry`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ step: failedStage }),
  });
  const data = await res.json();
  if (!res.ok) {
    appendLog(data.detail || "Retry failed.", "error");
    return;
  }
  clearWorkspace();
  setEngineStatus("queued");
  setDastBusy(data.mode === "dast");
  const source = new EventSource(data.stream_url);
  attachStream(source, data.mode === "dast");
});

historyBtn.addEventListener("click", () => {
  historyPanel.classList.remove("hidden");
  loadHistory();
});

closeHistoryBtn.addEventListener("click", () => historyPanel.classList.add("hidden"));

async function loadHistory() {
  try {
    const res = await fetch("/api/history?limit=30");
    const data = await res.json();
    const scans = data.scans || [];
    if (!scans.length) {
      historyList.innerHTML = `<div class="log-line muted">No scans recorded yet.</div>`;
      return;
    }
    historyList.innerHTML = scans
      .map((scan) => {
        const score = typeof scan.score === "number" ? `${scan.score}/100` : "--";
        const stateClasses = (scan.stages || [])
          .filter((s) => s.state === "failed" || s.state === "skipped")
          .map((s) => `${s.step}:${s.state}`)
          .join(", ");
        return `
          <div class="history-item">
            <div class="history-item-head">
              <strong>${escapeHtml(scan.mode)} · ${escapeHtml(scan.status)}</strong>
              <span>${escapeHtml(score)}</span>
            </div>
            <div class="history-item-meta">
              <code>${escapeHtml(scan.id)}</code><br />
              ${escapeHtml(scan.created_at)} · ${escapeHtml(scan.target)}<br />
              ${stateClasses ? `stages: ${escapeHtml(stateClasses)}` : "all stages completed"}
            </div>
          </div>
        `;
      })
      .join("");
  } catch (exc) {
    historyList.innerHTML = `<div class="log-line error">History unavailable: ${escapeHtml(exc)}</div>`;
  }
}

async function openIntel(kind) {
  intelPanel.classList.remove("hidden");
  intelTitle.textContent = kind === "surface" ? "ATTACK SURFACE INTELLIGENCE" : "ATTACK PATH GRAPH";
  intelStats.textContent = "Loading real scan evidence...";
  intelBody.innerHTML = `<div class="log-line muted">Fetching data from the latest completed scan...</div>`;
  try {
    const res = await fetch(kind === "surface" ? "/api/attack-surface" : "/api/attack-graph");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    if (kind === "surface") renderAttackSurface(data);
    else renderAttackGraph(data);
  } catch (exc) {
    intelStats.textContent = "UNAVAILABLE";
    intelBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderAttackSurface(surface) {
  const stats = surface.stats || {};
  intelStats.innerHTML = `
    <span>HOST: ${escapeHtml((surface.scope || {}).host || "-")}</span>
    <span>SERVICES: ${stats.services || 0}</span>
    <span>ENDPOINTS: ${stats.endpoints || 0}</span>
    <span>RESOURCES: ${stats.resources || 0}</span>
    <span>TECH: ${stats.technologies || 0}</span>
    <span>EVIDENCE EDGES: ${stats.evidence_edges || 0}</span>
  `;
  if (surface.snapshot_error) {
    intelBody.innerHTML = `<div class="log-line error">HTTP snapshot: ${escapeHtml(surface.snapshot_error)}</div>`;
  } else {
    intelBody.innerHTML = "";
  }

  (surface.nodes || []).slice(0, 60).forEach((node) => {
    const card = document.createElement("div");
    card.className = "intel-card";
    card.innerHTML = `
      <div><strong>[${escapeHtml(node.kind)}]</strong> ${escapeHtml(node.label)}</div>
      <div style="color:#9CA3AF;margin-top:4px;">${escapeHtml(node.detail)}</div>
      <div style="color:#D8B4FE;margin-top:4px;">${(node.evidence || [])
        .slice(0, 4)
        .map((e) => escapeHtml(e))
        .join(" · ")}</div>
    `;
    intelBody.appendChild(card);
  });
}

const GRAPH_W = 1000;
const GRAPH_H = 460;
const GRAPH_SEV_COLORS = {
  CRITICAL: "#F43F5E",
  HIGH: "#FB923C",
  MEDIUM: "#F59E0B",
  LOW: "#38BDF8",
  INFO: "#94A3B8",
};
const graphView = {
  nodes: [],
  edges: [],
  nodeById: new Map(),
  positions: new Map(),
  filter: "all",
  q: "",
  selected: null,
  zoom: 1,
  panX: 0,
  panY: 0,
  dragMoved: false,
};

function graphNodeColor(node) {
  if (node.kind === "finding") return node.color || "#C084FC";
  return { endpoint: "#38BDF8", service: "#34D399", resource: "#F59E0B" }[node.kind] || "#64748B";
}

function graphTransform() {
  const tx = graphView.panX + (1 - graphView.zoom) * (GRAPH_W / 2);
  const ty = graphView.panY + (1 - graphView.zoom) * (GRAPH_H / 2);
  return `translate(${tx.toFixed(2)} ${ty.toFixed(2)}) scale(${graphView.zoom})`;
}

function graphApplyTransform() {
  const canvas = document.getElementById("graphCanvas");
  const layer = canvas && canvas.querySelector(".graph-zoom-layer");
  if (layer) layer.setAttribute("transform", graphTransform());
  const label = document.getElementById("graphZoomLabel");
  if (label) label.textContent = `${Math.round(graphView.zoom * 100)}%`;
}

function computeGraphLayout(nodes) {
  const positions = new Map();
  const findings = nodes
    .filter((node) => node.kind === "finding")
    .sort((a, b) => (a.risk_rank || 999) - (b.risk_rank || 999));
  const assets = nodes
    .filter((node) => node.kind !== "finding")
    .sort((a, b) => String(a.kind).localeCompare(String(b.kind)));

  const placeRings = (list, baseRx, baseRy, perRing, offset) => {
    const rings = Math.max(1, Math.ceil(list.length / perRing));
    const per = Math.max(1, Math.ceil(list.length / rings));
    list.forEach((node, index) => {
      const ring = Math.floor(index / per);
      const indexInRing = index % per;
      const countInRing = Math.min(per, list.length - ring * per);
      const angle = offset + (2 * Math.PI * indexInRing) / Math.max(countInRing, 1);
      positions.set(node.id, {
        x: GRAPH_W / 2 + (baseRx + ring * 82) * Math.cos(angle),
        y: GRAPH_H / 2 + (baseRy + ring * 48) * Math.sin(angle),
      });
    });
  };

  placeRings(findings, 205, 105, 10, -Math.PI / 2);
  placeRings(assets, 420, 185, 12, -Math.PI / 2 + Math.PI / 12);

  positions.forEach((pos) => {
    pos.x = Math.max(66, Math.min(GRAPH_W - 66, pos.x));
    pos.y = Math.max(44, Math.min(GRAPH_H - 44, pos.y));
  });
  return positions;
}

function graphNodeRadius(node) {
  if (!node) return 5;
  if (node.kind !== "finding") return 5;
  return 6 + Math.min(7, Number(node.evidence_count || 0) / 2);
}

function graphNodeVisible(node) {
  if (graphView.filter !== "all" && node.kind !== graphView.filter) return false;
  const query = graphView.q.trim().toLowerCase();
  if (!query) return true;
  return `${node.label || ""} ${node.id || ""} ${node.classification || ""} ${node.severity || ""}`
    .toLowerCase()
    .includes(query);
}

function paintGraphSvg() {
  const canvas = document.getElementById("graphCanvas");
  if (!canvas) return;

  const visible = graphView.nodes.filter(graphNodeVisible);
  const visibleIds = new Set(visible.map((node) => node.id));
  const edges = graphView.edges.filter(
    (edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target),
  );
  const selected = graphView.selected;
  const neighbours = new Set();
  if (selected) {
    neighbours.add(selected);
    graphView.edges.forEach((edge) => {
      if (edge.source === selected) neighbours.add(edge.target);
      if (edge.target === selected) neighbours.add(edge.source);
    });
  }

  let svg = `<svg class="intel-graph" viewBox="0 0 ${GRAPH_W} ${GRAPH_H}" role="img" aria-label="Attack path graph">`;
  svg += `<defs>
    <marker id="gArrowEvidence" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#A855F7"></path>
    </marker>
    <marker id="gArrowTheory" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748B"></path>
    </marker>
  </defs>`;
  svg += `<g class="graph-zoom-layer" transform="${graphTransform()}">`;

  edges.forEach((edge) => {
    const a = graphView.positions.get(edge.source);
    const b = graphView.positions.get(edge.target);
    if (!a || !b) return;
    const kind = edge.kind === "evidence" ? "evidence" : "theoretical";
    const marker = kind === "evidence" ? "gArrowEvidence" : "gArrowTheory";
    const hot = selected && (edge.source === selected || edge.target === selected) ? " hot" : "";
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    const startOffset = graphNodeRadius(graphView.nodeById.get(edge.source)) + 1;
    const endOffset = graphNodeRadius(graphView.nodeById.get(edge.target)) + 4;
    const x1 = a.x + (dx / len) * startOffset;
    const y1 = a.y + (dy / len) * startOffset;
    const x2 = b.x - (dx / len) * endOffset;
    const y2 = b.y - (dy / len) * endOffset;
    svg += `<line class="edge-${kind}${hot}" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" marker-end="url(#${marker})">
      <title>${escapeHtml(`${edge.label || edge.kind} (${edge.confidence || kind})`)}</title>
    </line>`;
  });

  visible.forEach((node) => {
    const pos = graphView.positions.get(node.id);
    if (!pos) return;
    const color = graphNodeColor(node);
    const isSelected = node.id === selected;
    const dim = selected && !neighbours.has(node.id) ? " dimmed" : "";
    const cls = `node-group${isSelected ? " selected" : ""}${dim}`;
    const evidence = Number(node.evidence_count || 0);
    svg += `<g class="${cls}" data-node-id="${escapeHtml(node.id)}" style="color:${color}">`;
    if (node.kind === "finding") {
      const radius = 6 + Math.min(7, evidence / 2);
      if (node.classification === "Confirmed" || isSelected) {
        svg += `<circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${(radius + 4.5).toFixed(1)}" fill="none" stroke="${color}" stroke-opacity="0.38" stroke-width="1"></circle>`;
      }
      svg += `<circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${radius.toFixed(1)}" fill="${color}" fill-opacity="0.86" stroke="${color}" stroke-width="1.3"></circle>`;
      svg += `<text class="node-label" x="${(pos.x + radius + 6).toFixed(1)}" y="${(pos.y + 3).toFixed(1)}">${escapeHtml(String(node.label || node.id).slice(0, 22))}</text>`;
    } else if (node.kind === "endpoint") {
      svg += `<rect x="${(pos.x - 4.2).toFixed(1)}" y="${(pos.y - 4.2).toFixed(1)}" width="8.4" height="8.4" fill="${color}" fill-opacity="0.8" stroke="${color}" stroke-width="1" transform="rotate(45 ${pos.x.toFixed(1)} ${pos.y.toFixed(1)})"></rect>`;
      svg += `<text class="node-label" x="${(pos.x + 9).toFixed(1)}" y="${(pos.y + 3).toFixed(1)}">${escapeHtml(String(node.label || node.id).slice(0, 22))}</text>`;
    } else if (node.kind === "resource") {
      svg += `<rect x="${(pos.x - 4.6).toFixed(1)}" y="${(pos.y - 4.6).toFixed(1)}" width="9.2" height="9.2" rx="1.6" fill="${color}" fill-opacity="0.8" stroke="${color}" stroke-width="1"></rect>`;
      svg += `<text class="node-label" x="${(pos.x + 9).toFixed(1)}" y="${(pos.y + 3).toFixed(1)}">${escapeHtml(String(node.label || node.id).slice(0, 22))}</text>`;
    } else {
      svg += `<circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="4.4" fill="${color}" fill-opacity="0.75" stroke="${color}" stroke-width="1"></circle>`;
      svg += `<text class="node-label" x="${(pos.x + 9).toFixed(1)}" y="${(pos.y + 3).toFixed(1)}">${escapeHtml(String(node.label || node.id).slice(0, 22))}</text>`;
    }
    svg += `<title>${escapeHtml(`${node.label} · ${node.classification || "Informational"} · ${node.severity || "INFO"}`)}</title>`;
    svg += `</g>`;
  });

  svg += `</g></svg>`;
  canvas.innerHTML = `${svg}<div class="graph-hint">Click a node to inspect · drag to pan · wheel to zoom</div>`;
  graphApplyTransform();
}

function graphConnections(node) {
  const rows = [];
  graphView.edges.forEach((edge) => {
    if (edge.source !== node.id && edge.target !== node.id) return;
    const outgoing = edge.source === node.id;
    const other = graphView.nodeById.get(outgoing ? edge.target : edge.source);
    if (!other) return;
    rows.push({ edge, outgoing, other });
  });
  return rows;
}

function renderGraphInspector() {
  const inspector = document.getElementById("graphInspector");
  if (!inspector) return;
  const node = graphView.nodeById.get(graphView.selected);
  if (!node) {
    const findings = graphView.nodes.filter((n) => n.kind === "finding");
    const assets = graphView.nodes.length - findings.length;
    const confirmed = findings.filter((n) => n.classification === "Confirmed").length;
    const potential = findings.filter((n) => n.classification === "Potential").length;
    const evidenceEdges = graphView.edges.filter((e) => e.kind === "evidence").length;
    const theoreticalEdges = graphView.edges.length - evidenceEdges;
    const isolated = graphView.nodes.filter((n) => graphConnections(n).length === 0).length;
    inspector.innerHTML = `
      <div class="graph-inspector-title">GRAPH SUMMARY</div>
      <div class="graph-kv">
        <span>Findings</span><strong>${findings.length}</strong>
        <span>Surface assets</span><strong>${assets}</strong>
        <span>Confirmed findings</span><strong>${confirmed}</strong>
        <span>Potential findings</span><strong>${potential}</strong>
        <span>Evidence edges</span><strong>${evidenceEdges}</strong>
        <span>Theoretical edges</span><strong>${theoreticalEdges}</strong>
        <span>Isolated nodes</span><strong>${isolated}</strong>
      </div>
      <div class="graph-inspector-title" style="margin-top:14px;">HIGHEST RISK</div>
      <div class="graph-connections">
        ${findings
          .slice()
          .sort((a, b) => (a.risk_rank || 999) - (b.risk_rank || 999))
          .slice(0, 5)
          .map(
            (finding) => `<button class="graph-conn" data-inspect="${escapeHtml(finding.id)}">
              <span class="dir">#${escapeHtml(String(finding.risk_rank || "-"))}</span>
              <span class="kind">${escapeHtml(finding.classification || "")}</span>
              <div style="margin-top:3px;">${escapeHtml(finding.label)}</div>
            </button>`,
          )
          .join("") || `<div class="graph-empty">No findings in this graph.</div>`}
      </div>
      <div class="graph-empty" style="padding:10px 0 0;">Select a node on the canvas to see its evidence, severity and connections.</div>
    `;
    bindGraphInspector(inspector);
    return;
  }

  const color = graphNodeColor(node);
  const severityColor = GRAPH_SEV_COLORS[String(node.severity || "").toUpperCase()] || "#94A3B8";
  const connections = graphConnections(node);
  const endpoints = Array.isArray(node.endpoints) ? node.endpoints.filter(Boolean).slice(0, 8) : [];
  const tools = Array.isArray(node.tools) ? node.tools.filter(Boolean).slice(0, 8) : [];
  inspector.innerHTML = `
    <div class="graph-detail">
      <div>
        <span class="graph-badge" style="color:${color}">${escapeHtml(node.classification || "Informational")}</span>
        <span class="graph-badge" style="color:${severityColor}">${escapeHtml(node.severity || "INFO")}</span>
        <span class="graph-badge" style="color:#38BDF8">${escapeHtml(node.kind || "node")}</span>
      </div>
      <h3>${escapeHtml(node.label || node.id)}</h3>
      <div class="graph-kv">
        <span>Evidence items</span><strong>${Number(node.evidence_count || 0)}</strong>
        <span>Risk rank</span><strong>${node.risk_rank ? `#${escapeHtml(String(node.risk_rank))}` : "-"}</strong>
        <span>Connections</span><strong>${connections.length}</strong>
        <span>Node id</span><strong style="word-break:break-all;max-width:170px;">${escapeHtml(String(node.id).slice(0, 42))}</strong>
      </div>
      ${endpoints.length ? `<div class="graph-inspector-title" style="margin-top:12px;">OBSERVED ENDPOINTS</div>
        <div class="graph-connections">
          ${endpoints.map((endpoint) => `<div class="graph-conn" style="cursor:default;">${escapeHtml(endpoint)}</div>`).join("")}
        </div>` : ""}
      ${tools.length ? `<div class="graph-inspector-title" style="margin-top:12px;">EVIDENCE SOURCES</div>
        <div class="graph-connections">
          ${tools.map((tool) => `<div class="graph-conn" style="cursor:default;">${escapeHtml(tool)}</div>`).join("")}
        </div>` : ""}
      <div class="graph-inspector-title" style="margin-top:12px;">CONNECTIONS (${connections.length})</div>
      <div class="graph-connections">
        ${connections.slice(0, 10).map(({ edge, outgoing, other }) => `
          <button class="graph-conn" data-inspect="${escapeHtml(other.id)}">
            <span class="dir">${outgoing ? "→" : "←"}</span>
            <span class="kind ${edge.kind}">${escapeHtml(edge.kind)}</span>
            <span>${escapeHtml(other.label)}</span>
            <div style="margin-top:3px;color:#64748B;font-size:0.62rem;">${escapeHtml(edge.label || "")}${edge.note ? ` · ${escapeHtml(edge.note)}` : ""}</div>
          </button>`).join("") || `<div class="graph-empty">No edges for this node (isolated).</div>`}
      </div>
      <button class="page-home" id="graphClearSelection" style="margin-top:12px;">← Back to summary</button>
    </div>
  `;
  bindGraphInspector(inspector);
}

function bindGraphInspector(inspector) {
  inspector.querySelectorAll("[data-inspect]").forEach((button) => {
    button.addEventListener("click", () => selectGraphNode(button.getAttribute("data-inspect")));
  });
  const clear = inspector.querySelector("#graphClearSelection");
  if (clear) {
    clear.addEventListener("click", () => {
      graphView.selected = null;
      paintGraphSvg();
      renderGraphInspector();
    });
  }
}

function selectGraphNode(nodeId) {
  if (!graphView.nodeById.has(nodeId)) return;
  graphView.selected = nodeId;
  paintGraphSvg();
  renderGraphInspector();
  const inspector = document.getElementById("graphInspector");
  if (inspector) inspector.scrollTop = 0;
}

function applyGraphFilter() {
  document.querySelectorAll("[data-graph-filter]").forEach((button) => {
    button.classList.toggle("active", button.getAttribute("data-graph-filter") === graphView.filter);
  });
  paintGraphSvg();
  renderGraphInspector();
}

function renderAttackGraph(graph) {
  const nodes = Array.isArray(graph.nodes) ? graph.nodes.slice(0, 100) : [];
  const edges = Array.isArray(graph.edges) ? graph.edges.slice(0, 240) : [];
  graphView.nodes = nodes;
  graphView.edges = edges;
  graphView.nodeById = new Map(nodes.map((node) => [node.id, node]));
  graphView.selected = null;
  graphView.zoom = 1;
  graphView.panX = 0;
  graphView.panY = 0;
  graphView.filter = "all";
  graphView.q = "";
  graphView.positions = computeGraphLayout(nodes, edges);

  const findings = nodes.filter((node) => node.kind === "finding");
  const evidenceEdges = edges.filter((edge) => edge.kind === "evidence").length;
  const theoreticalEdges = edges.length - evidenceEdges;
  const confirmed = findings.filter((node) => node.classification === "Confirmed").length;
  const potential = findings.filter((node) => node.classification === "Potential").length;
  const isolated = nodes.filter((node) => graphConnections(node).length === 0).length;

  intelStats.innerHTML = `
    <span>NODES <strong>${nodes.length}</strong></span>
    <span>EDGES <strong>${edges.length}</strong></span>
    <span>EVIDENCE <strong>${evidenceEdges}</strong></span>
    <span>THEORETICAL <strong>${theoreticalEdges}</strong></span>
    <span>CONFIRMED <strong>${confirmed}</strong></span>
    <span>POTENTIAL <strong>${potential}</strong></span>
    <span>ISOLATED <strong>${isolated}</strong></span>
  `;

  if (!nodes.length) {
    intelBody.innerHTML = `<div class="graph-empty">No attack graph data yet. Run a real audit or DAST scan to build the graph.</div>`;
    return;
  }

  const evidencePct = edges.length ? Math.round((evidenceEdges / edges.length) * 100) : 0;
  const kindCounts = nodes.reduce((acc, node) => {
    acc[node.kind] = (acc[node.kind] || 0) + 1;
    return acc;
  }, {});
  const riskRows = findings
    .slice()
    .sort((a, b) => (a.risk_rank || 999) - (b.risk_rank || 999))
    .slice(0, 12);

  intelBody.innerHTML = `
    <div class="graph-toolbar">
      <div class="graph-filter-group">
        ${[
          ["all", "All"],
          ["finding", "Findings"],
          ["endpoint", "Endpoints"],
          ["service", "Services"],
          ["resource", "Resources"],
        ]
          .map(
            ([key, label]) =>
              `<button type="button" class="graph-filter${key === "all" ? " active" : ""}" data-graph-filter="${key}">${label} <span style="opacity:.6">${key === "all" ? nodes.length : kindCounts[key] || 0}</span></button>`,
          )
          .join("")}
      </div>
      <input id="graphSearch" class="graph-search" type="search" placeholder="Filter nodes by label, severity, id..." maxlength="80" />
      <div class="graph-zoom">
        <button type="button" data-graph-zoom="out" title="Zoom out">−</button>
        <button type="button" id="graphZoomLabel" data-graph-zoom="reset" title="Reset zoom">100%</button>
        <button type="button" data-graph-zoom="in" title="Zoom in">+</button>
      </div>
    </div>

    <div class="graph-legend">
      <span><i></i> evidence edge</span>
      <span><i class="dashed"></i> theoretical edge</span>
      <span><i class="dot"></i> finding (size = evidence)</span>
      <span style="color:#38BDF8;">◆ endpoint</span>
      <span style="color:#34D399;">● service</span>
      <span style="color:#F59E0B;">■ resource</span>
      <span>${evidenceEdges}/${edges.length} edges are evidence-backed (${evidencePct}%)</span>
    </div>

    <div class="graph-layout">
      <div class="graph-canvas" id="graphCanvas"></div>
      <aside class="graph-inspector" id="graphInspector"></aside>
    </div>

    <div class="graph-grid-2">
      <section class="graph-section">
        <div class="graph-section-head"><span>RISK LADDER</span><span>top ${riskRows.length} findings</span></div>
        <div class="graph-rows" id="graphRiskList">
          ${riskRows.map((finding) => `
            <button class="graph-risk-item" data-inspect="${escapeHtml(finding.id)}">
              <span class="rank">#${escapeHtml(String(finding.risk_rank || "-"))}</span>
              <span class="name">${escapeHtml(finding.label)}</span>
              <span class="sev" style="color:${GRAPH_SEV_COLORS[String(finding.severity || "").toUpperCase()] || "#94A3B8"}">${escapeHtml(finding.severity || "INFO")}</span>
            </button>`).join("") || `<div class="graph-empty">No findings in this graph.</div>`}
        </div>
      </section>
      <section class="graph-section">
        <div class="graph-section-head"><span>CONNECTION LEDGER</span><span>${edges.length} real edges</span></div>
        <div class="graph-rows" id="graphEdgeList">
          ${edges.slice(0, 60).map((edge, index) => {
            const source = graphView.nodeById.get(edge.source);
            const target = graphView.nodeById.get(edge.target);
            return `<button class="graph-row" data-edge-index="${index}">
              <span class="kind ${edge.kind}">${escapeHtml(edge.kind)}</span>
              <span class="label">${escapeHtml(source ? source.label : edge.source)}</span>
              <span class="label" style="text-align:right;">${escapeHtml(target ? target.label : edge.target)}</span>
            </button>`;
          }).join("") || `<div class="graph-empty">No edges were derived from the latest scan.</div>`}
        </div>
      </section>
    </div>
    <div class="graph-empty" style="margin-top:12px;">Policy: ${escapeHtml(graph.policy || "Evidence edges are solid; theoretical chains are dashed and never presented as confirmed attacks.")}</div>
  `;

  const canvas = document.getElementById("graphCanvas");
  paintGraphSvg();
  renderGraphInspector();

  const bindInspectorButtons = () => {
    document.querySelectorAll("[data-inspect]").forEach((button) => {
      if (button.dataset.bound === "1") return;
      button.dataset.bound = "1";
      button.addEventListener("click", () => selectGraphNode(button.getAttribute("data-inspect")));
    });
  };
  bindInspectorButtons();

  document.querySelectorAll("[data-graph-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      graphView.filter = button.getAttribute("data-graph-filter") || "all";
      applyGraphFilter();
    });
  });

  const search = document.getElementById("graphSearch");
  if (search) {
    search.addEventListener("input", () => {
      graphView.q = search.value;
      paintGraphSvg();
      renderGraphInspector();
    });
  }

  document.querySelectorAll("[data-graph-zoom]").forEach((button) => {
    button.addEventListener("click", () => {
      const mode = button.getAttribute("data-graph-zoom");
      if (mode === "reset") {
        graphView.zoom = 1;
        graphView.panX = 0;
        graphView.panY = 0;
      } else {
        const delta = mode === "in" ? 0.18 : -0.18;
        graphView.zoom = Math.max(0.55, Math.min(2.4, Number((graphView.zoom + delta).toFixed(2))));
      }
      graphApplyTransform();
    });
  });

  document.querySelectorAll("[data-edge-index]").forEach((row) => {
    row.addEventListener("click", () => {
      const edge = edges[Number(row.getAttribute("data-edge-index"))];
      if (!edge) return;
      selectGraphNode(edge.source);
    });
  });

  document.getElementById("graphClearSelection")?.addEventListener("click", () => {
    graphView.selected = null;
    paintGraphSvg();
    renderGraphInspector();
  });

  canvas.addEventListener("click", (event) => {
    if (graphView.dragMoved) return;
    const group = event.target.closest("[data-node-id]");
    if (group) selectGraphNode(group.getAttribute("data-node-id"));
  });

  let dragStart = null;
  canvas.addEventListener("pointerdown", (event) => {
    if (event.target.closest("[data-node-id]") || event.target.closest("button")) return;
    dragStart = { x: event.clientX, y: event.clientY, panX: graphView.panX, panY: graphView.panY };
    graphView.dragMoved = false;
    canvas.classList.add("dragging");
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener("pointermove", (event) => {
    if (!dragStart) return;
    const dx = event.clientX - dragStart.x;
    const dy = event.clientY - dragStart.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) graphView.dragMoved = true;
    graphView.panX = dragStart.panX + dx;
    graphView.panY = dragStart.panY + dy;
    graphApplyTransform();
  });
  const endDrag = (event) => {
    if (!dragStart) return;
    dragStart = null;
    canvas.classList.remove("dragging");
    try { canvas.releasePointerCapture(event.pointerId); } catch (exc) { /* already released */ }
    setTimeout(() => { graphView.dragMoved = false; }, 40);
  };
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", endDrag);

  canvas.addEventListener(
    "wheel",
    (event) => {
      if (!event.target.closest("svg")) return;
      event.preventDefault();
      const delta = event.deltaY > 0 ? -0.12 : 0.12;
      graphView.zoom = Math.max(0.55, Math.min(2.4, Number((graphView.zoom + delta).toFixed(2))));
      graphApplyTransform();
    },
    { passive: false },
  );
}

surfaceBtn.addEventListener("click", () => openIntel("surface"));
graphBtn.addEventListener("click", () => openIntel("graph"));
closeIntelBtn.addEventListener("click", () => intelPanel.classList.add("hidden"));
remediationBtn.addEventListener("click", openRemediation);
closeRemediationBtn.addEventListener("click", () => remediationPanel.classList.add("hidden"));
verifyBtn.addEventListener("click", openVerification);
closeVerificationBtn.addEventListener("click", () => verificationPanel.classList.add("hidden"));
compareBtn.addEventListener("click", () => {
  openComparison();
  loadVisualSnapshots();
});
closeComparisonBtn.addEventListener("click", () => comparisonPanel.classList.add("hidden"));
document.getElementById("visualCaptureBtn")?.addEventListener("click", captureVisualSnapshot);
document.getElementById("visualLoadBtn")?.addEventListener("click", loadVisualSnapshots);
document.getElementById("visualRange")?.addEventListener("input", (event) => {
  const slider = document.getElementById("visualSlider");
  if (slider) slider.style.setProperty("--split", `${event.target.value}%`);
});
apiSecBtn.addEventListener("click", openApiSecurity);
closeApiSecBtn.addEventListener("click", () => apiSecPanel.classList.add("hidden"));
monitorBtn.addEventListener("click", openMonitor);
closeMonitorBtn.addEventListener("click", () => {
  monitorPanel.classList.add("hidden");
  stopMonitorPolling();
});
overviewBtn.addEventListener("click", openOverview);
closeOverviewBtn.addEventListener("click", () => overviewPanel.classList.add("hidden"));
vulnCenterBtn.addEventListener("click", openVulnerabilityCenter);
closeVulnCenterBtn.addEventListener("click", () => vulnCenterPanel.classList.add("hidden"));
aiIntelBtn.addEventListener("click", openAiIntelligence);
closeAiIntelBtn.addEventListener("click", () => aiIntelPanel.classList.add("hidden"));
reportsBtn.addEventListener("click", openReports);
closeReportsBtn.addEventListener("click", () => reportsPanel.classList.add("hidden"));
copilotBtn.addEventListener("click", openCopilot);
closeCopilotBtn.addEventListener("click", () => copilotPanel.classList.add("hidden"));
settingsBtn.addEventListener("click", openSettings);
closeSettingsBtn.addEventListener("click", () => settingsPanel.classList.add("hidden"));
document.getElementById("copilotAskBtn").addEventListener("click", askCopilotQuestion);
document.getElementById("copilotQuestion").addEventListener("keydown", (e) => {
  if (e.key === "Enter") askCopilotQuestion();
});
document.getElementById("quickScanBtn").addEventListener("click", () => {
  appendLog("[QUICK SCAN] Starting real 5-stage static audit (same engine as START AUDIT).");
  startBtn.click();
});
document.getElementById("fullAuditBtn").addEventListener("click", () => {
  appendLog("[FULL AUDIT] Starting real 9-stage dynamic audit (same engine as RUN DAST).");
  dastBtn.click();
});

loadHistory();

function renderVulnerabilityAnalysis(vuln) {
  if (!vuln || !Array.isArray(vuln.findings)) return;
  const summary = vuln.summary || {};
  const card = document.createElement("div");
  card.className = "chat-msg";

  let html = `<div class="finding-title">VULNERABILITY ANALYST · CVSS v3.1 / CVE</div>`;
  html += `<div style="margin:6px 0;color:#9CA3AF;">
    ${summary.scored_groups || 0} scored · max CVSS <strong style="color:#F43F5E;">${summary.max_cvss ?? "-"}</strong> ·
    avg ${summary.average_cvss ?? "-"} · critical ${summary.critical_cvss || 0} · high ${summary.high_cvss || 0} ·
    NVD lookups ${summary.cve_sources_queried || 0} · CVEs ${summary.total_cves || 0}
  </div>`;

  const ratingColor = { CRITICAL: "#F43F5E", HIGH: "#FB923C", MEDIUM: "#F59E0B", LOW: "#34D399" };
  (vuln.findings || []).slice(0, 10).forEach((f) => {
    const cvss = f.cvss || {};
    const color = ratingColor[cvss.severity] || "#C084FC";
    html += `<div class="intel-card" style="border-left-color:${color};">
      <div style="display:flex;justify-content:space-between;gap:8px;">
        <strong>${escapeHtml(f.title)}</strong>
        <span style="color:${color};font-weight:bold;">${cvss.base_score ?? "-"} · ${escapeHtml(cvss.severity || "-")}</span>
      </div>
      <div style="color:#9CA3AF;margin-top:4px;">
        <code>${escapeHtml(cvss.vector || "")}</code> · classification=${escapeHtml(f.classification || "-")}
        · evidence confidence=${cvss.confidence ?? "-"}
      </div>
    </div>`;
  });

  (vuln.cve_lookups || []).forEach((lookup) => {
    const cves = lookup.cves || [];
    html += `<div class="intel-card" style="margin-top:8px;">
      <div><strong>CVE CHECK:</strong> ${escapeHtml(lookup.product || "-")} ${escapeHtml(lookup.version || "")}</div>
      <div style="color:#9CA3AF;margin-top:4px;">${escapeHtml(lookup.status || "-")} · ${escapeHtml(lookup.note || "")}</div>
      ${cves.length
        ? cves
            .slice(0, 5)
            .map(
              (c) =>
                `<div style="margin-top:4px;"><code style="color:#C084FC;">${escapeHtml(c.id)}</code> ` +
                `NVD score=${c.nvd_score ?? "-"} · ${escapeHtml((c.description || "").slice(0, 160))}</div>`,
            )
            .join("")
        : `<div style="margin-top:4px;color:#10B981;">No NVD-confirmed CVE for this exact version — none reported.</div>`}
    </div>`;
  });

  card.innerHTML = html;
  chatFeed.appendChild(card);
  chatFeed.scrollTop = chatFeed.scrollHeight;
}

function renderCorrelations(correlation) {
  if (!correlation || !Array.isArray(correlation.groups)) return;
  const summary = correlation.summary || {};
  const card = document.createElement("div");
  card.className = "chat-msg";
  const classColors = {
    Confirmed: "#F43F5E",
    Potential: "#F59E0B",
    Unverified: "#38BDF8",
    Informational: "#34D399",
    "False Positive": "#9CA3AF",
  };

  let html = `<div class="finding-title">AI CORRELATION ENGINE · ${escapeHtml(correlation.engine || "aegis-correlation")}</div>`;
  html += `<div style="margin:6px 0;color:#9CA3AF;">
    ${summary.total || 0} groups · ${summary.confirmed || 0} confirmed · ${summary.potential || 0} potential ·
    ${summary.unverified || 0} unverified · ${summary.informational || 0} informational ·
    mode=${escapeHtml(summary.ai_mode || "deterministic")}
  </div>`;

  correlation.groups.slice(0, 10).forEach((group) => {
    const color = classColors[group.classification] || "#C084FC";
    const evidence = (group.evidence || [])
      .slice(0, 3)
      .map((e) => `<li><code>${escapeHtml(e.tool)}</code> · ${escapeHtml(e.title)} ${e.endpoint ? `— ${escapeHtml(e.endpoint)}` : ""}</li>`)
      .join("");
    html += `
      <div class="finding-card" style="border-left-color:${color};background:rgba(255,255,255,0.02);">
        <div class="finding-title" style="color:${color};">
          #${group.risk_rank} [${escapeHtml(group.classification)}] ${escapeHtml(group.title)}
        </div>
        <div>${escapeHtml(group.ai_analysis || group.reason || "")}</div>
        ${evidence ? `<ul style="margin:8px 0 0 18px;font-size:0.82rem;">${evidence}</ul>` : ""}
        <div style="margin-top:8px;color:#6EE7B7;">→ ${escapeHtml(group.ai_recommendation || group.recommendation || "")}</div>
      </div>
    `;
  });

  card.innerHTML = html;
  chatFeed.appendChild(card);
  chatFeed.scrollTop = chatFeed.scrollHeight;
}

function renderDastResult(dast, score = null, file_name = null) {
  const card = document.createElement("div");
  card.className = "chat-msg";

  let html = `<div><strong>DAST Target:</strong> <code>${escapeHtml(dast.target)}</code></div>`;
  if (score !== null && score !== undefined) {
    const scoreColor = score >= 80 ? "#10B981" : "#F43F5E";
    html += `<div style="margin-top:6px;"><strong>Security Score:</strong> ` +
      `<code style="color:${scoreColor};font-weight:bold;">${score}/100</code>` +
      (file_name ? ` <span style="color:#9CA3AF;">· ${escapeHtml(file_name)}</span>` : "") + `</div>`;
  }

  const tools = dast.tools || {};
  html += `<div style="margin-top:6px;color:#9CA3AF;">Tools: ${Object.keys(tools)
    .map((name) => `${escapeHtml(name)}=${escapeHtml(tools[name].status)}`)
    .join(" · ")}</div>`;

  const dns = dast.dnsrecon;
  if (dns && !dns.offline) {
    html += `<div class="finding-card" style="border-left-color:#38BDF8;background:rgba(56,189,248,0.05);">
      <div class="finding-title" style="color:#7DD3FC;">dnsrecon — offline DNS recon @ ${escapeHtml(dns.domain || "-")}</div>
      <div style="margin-top:6px;">Resolver <code>${escapeHtml(dns.resolver || "-")}</code> ·
        ${(dns.subdomains || []).length} subdomain(s) · ${(dns.ptr || []).length} PTR record(s)</div>
      <ul style="margin:8px 0 0 18px;">${(dns.subdomains || [])
        .slice(0, 10)
        .map((s) => `<li><code>${escapeHtml(s.host)}</code> → ${escapeHtml(s.ip)}</li>`)
        .join("")}</ul></div>`;
  } else if (dns) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">dnsrecon: ${escapeHtml(dns.error || "unavailable")}</div>`;
  }

  const nmap = dast.nmap;
  if (nmap && nmap.ports && nmap.ports.length) {
    html += `<div class="finding-card" style="border-left-color:#34D399;background:rgba(52,211,153,0.05);">
      <div class="finding-title" style="color:#6EE7B7;">Nmap — ${nmap.ports.length} open port(s) on ${escapeHtml(nmap.host || "-")}</div>
      <ul style="margin:8px 0 0 18px;">${nmap.ports
        .map(
          (p) =>
            `<li><code>${escapeHtml(p.port)}</code> ${escapeHtml(p.state)} · ${escapeHtml(p.service)} ${
              p.version ? `— ${escapeHtml(p.version)}` : ""
            }</li>`,
        )
        .join("")}</ul></div>`;
  } else if (nmap) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">Nmap: ${escapeHtml(nmap.error || "no open ports")}</div>`;
  }

  const ffuf = dast.ffuf;
  if (ffuf && ffuf.ok) {
    const results = ffuf.results || [];
    html += `<div class="finding-card" style="border-left-color:#A855F7;background:rgba(168,85,247,0.05);">
      <div class="finding-title" style="color:#C084FC;">ffuf — ${results.length} route(s) discovered</div>`;
    if (results.length) {
      html += `<ul style="margin:8px 0 0 18px;">${results
        .map((r) => `<li><code>${escapeHtml(r.path)}</code> — HTTP ${r.status}</li>`)
        .join("")}</ul>`;
    } else {
      html += `<div>No additional routes.</div>`;
    }
    html += `</div>`;
  } else if (ffuf) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">ffuf: ${escapeHtml(ffuf.error || "unavailable")}</div>`;
  }

  const gofile = dast.gofile;
  if (gofile && gofile.ok) {
    const files = gofile.findings || [];
    html += `<div class="finding-card" style="border-left-color:#FB7185;background:rgba(251,113,133,0.05);">
      <div class="finding-title" style="color:#FDA4AF;">GoFile — ${files.length} file/dir(s), ${gofile.hidden_count || 0} hidden</div>`;
    if (files.length) {
      html += `<ul style="margin:8px 0 0 18px;">${files
        .map(
          (f) =>
            `<li>${f.hidden ? "<strong>[HIDDEN]</strong> " : ""}<code>${escapeHtml(f.path)}</code> — HTTP ${f.status}</li>`,
        )
        .join("")}</ul>`;
    } else {
      html += `<div>No hidden files or directories.</div>`;
    }
    html += `</div>`;
  } else if (gofile) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">GoFile: ${escapeHtml(gofile.error || "unavailable")}</div>`;
  }

  const sm = dast.sqlmap;
  if (sm && sm.injectable) {
    html += `<div class="finding-card">
      <div class="finding-title">[CRITICAL] SQL Injection confirmed by sqlmap</div>
      <div><strong>Parameter(s):</strong> <code>${escapeHtml((sm.parameters || []).join(", "))}</code></div>
      <div><strong>Technique:</strong> ${escapeHtml((sm.types || []).join(", "))}</div>
      <div><strong>DBMS:</strong> ${escapeHtml(sm.dbms || "unknown")}</div>`;
    (sm.payloads || []).slice(0, 2).forEach((p) => {
      html += `<pre class="code-box vuln" style="margin-top:8px;">${escapeHtml(p)}</pre>`;
    });
    html += `</div>`;
  } else if (sm) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">sqlmap: ${escapeHtml(sm.error || "no injection detected")}</div>`;
  }

  const zap = dast.zap;
  if (zap && zap.ok) {
    const alerts = zap.alerts || [];
    html += `<div class="finding-card" style="border-left-color:#F59E0B;background:rgba(245,158,11,0.05);">
      <div class="finding-title" style="color:#FCD34D;">OWASP ZAP — ${alerts.length} high/medium alert(s)</div>`;
    if (alerts.length) {
      html += `<ul style="margin:8px 0 0 18px;">${alerts
        .map(
          (a) =>
            `<li><strong>${escapeHtml(a.risk)}</strong> — ${escapeHtml(a.title)}<br><small>${escapeHtml(
              a.endpoint || "",
            )}</small></li>`,
        )
        .join("")}</ul>`;
    } else {
      html += `<div>No high/medium alerts.</div>`;
    }
    html += `</div>`;
  } else if (zap) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">ZAP: ${escapeHtml(zap.error || "unavailable")}</div>`;
  }

  const nuclei = dast.nuclei;
  if (nuclei && nuclei.findings && nuclei.findings.length) {
    html += `<div class="finding-card" style="border-left-color:#F472B6;background:rgba(244,114,182,0.05);">
      <div class="finding-title" style="color:#F9A8D4;">Nuclei — ${nuclei.findings.length} template finding(s)</div>
      <ul style="margin:8px 0 0 18px;">${nuclei.findings
        .map(
          (f) =>
            `<li><strong>[${escapeHtml(f.severity)}]</strong> ${escapeHtml(f.id)}<br><small>${escapeHtml(
              f.endpoint || "",
            )}</small></li>`,
        )
        .join("")}</ul></div>`;
  } else if (nuclei) {
    html += `<div style="margin-top:8px;color:#9CA3AF;">Nuclei: ${escapeHtml(nuclei.error || "no findings")}</div>`;
  }

  const guard = dast.guardrail;
  if (guard) {
    html += `<div style="margin-top:10px;font-size:0.78rem;color:${
      guard.ok ? "#34D399" : "#F43F5E"
    };">[ OUTPUT GUARDRAIL · ${escapeHtml(guard.mode || "-")} ] ${escapeHtml(guard.message || "")}</div>`;
  }

  card.innerHTML = html;
  chatFeed.appendChild(card);
  chatFeed.scrollTop = chatFeed.scrollHeight;
}

/* ---------------------------------------------------------------------------
 * V2 Phase 6 — Remediation Center
 * No patch is applied until the user explicitly approves it. Backups and
 * rollback are always available; every action is recorded in the ledger.
 * ------------------------------------------------------------------------- */

async function openRemediation() {
  remediationPanel.classList.remove("hidden");
  remediationStats.textContent = "Loading real remediation data...";
  remediationBody.innerHTML = `<div class="log-line muted">Fetching proposals, backups and ledger from the backend...</div>`;
  await refreshRemediation();
}

async function refreshRemediation() {
  try {
    const [proposalsRes, backupsRes, ledgerRes] = await Promise.all([
      fetch("/api/remediation/proposals"),
      fetch("/api/remediation/backups"),
      fetch("/api/remediation/ledger"),
    ]);
    const [proposalsData, backupsData, ledgerData] = await Promise.all([
      proposalsRes.json(),
      backupsRes.json(),
      ledgerRes.json(),
    ]);
    if (!proposalsRes.ok) throw new Error(proposalsData.detail || "Proposals request failed");
    renderRemediationCenter(proposalsData, backupsData, ledgerData);
  } catch (exc) {
    remediationStats.textContent = "UNAVAILABLE";
    remediationBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderRemediationCenter(proposalsData, backupsData, ledgerData) {
  const proposals = proposalsData.proposals || [];
  const backups = backupsData.backups || [];
  const ledger = ledgerData.entries || [];
  window.__remediationProposals = proposals;

  remediationStats.innerHTML = `
    <span>PROPOSALS: ${proposals.length}</span>
    <span>BACKUPS: ${backups.length}</span>
    <span>LEDGER: ${ledger.length}</span>
    <span>APPROVAL: ${activeRemediationApproval ? escapeHtml(activeRemediationApproval.id) : "REQUIRED"}</span>
  `;

  let html = `<div class="remediation-section">1 / PROPOSED PATCHES (derived from real scan findings)</div>`;
  if (!proposals.length) {
    html += `<div class="log-line muted">No proposals yet. Run a scan that finds real vulnerabilities first.</div>`;
  } else {
    const sevColor = { CRITICAL: "#F43F5E", HIGH: "#FB923C", MEDIUM: "#F59E0B", LOW: "#34D399" };
    proposals.forEach((p) => {
      const color = sevColor[p.severity] || "#C084FC";
      const approved = activeRemediationApproval && activeRemediationApproval.proposal_ids.includes(p.id);
      html += `
        <div class="intel-card remediation-proposal">
          <label>
            <input type="checkbox" class="remediation-check" value="${escapeHtml(p.id)}" ${approved ? "checked" : ""}>
            <span class="proposal-title">
              <span style="color:${color};font-weight:bold;">[${escapeHtml(p.severity)}]</span>
              ${escapeHtml(p.id)} · ${escapeHtml(p.title)}<br>
              <small style="color:#9CA3AF;">${escapeHtml(p.file_name)} · ${escapeHtml(p.endpoint || "-")}</small>
            </span>
          </label>
          ${approved ? `<div class="remediation-actions"><button class="btn-engine btn-apply remediation-apply" data-proposal-id="${escapeHtml(p.id)}">[ APPLY PATCH ]</button></div>` : ""}
        </div>`;
    });
    html += `
      <div class="intel-card">
        <input id="remediationNote" class="remediation-note" placeholder="Approval note (optional, stored in audit ledger)" maxlength="500">
        <div class="remediation-actions">
          <button id="approveRemediationBtn" class="btn-engine btn-approve">[ APPROVE SELECTED ]</button>
        </div>
      </div>`;
  }

  html += `<div class="remediation-section">2 / IMMUTABLE BACKUPS &amp; ROLLBACK</div>`;
  if (!backups.length) {
    html += `<div class="log-line muted">No backups recorded yet.</div>`;
  } else {
    backups.forEach((b) => {
      html += `
        <div class="intel-card">
          <div><strong>${escapeHtml(b.id)}</strong></div>
          <div style="color:#9CA3AF;margin-top:4px;">${b.size_bytes} bytes · ${escapeHtml(b.created_at)}</div>
          <div class="remediation-actions">
            <button class="btn-engine btn-rollback remediation-rollback" data-backup-id="${escapeHtml(b.id)}">[ ROLLBACK ]</button>
          </div>
        </div>`;
    });
  }

  html += `<div class="remediation-section">3 / REMEDIATION LEDGER</div>`;
  if (!ledger.length) {
    html += `<div class="log-line muted">No remediation actions yet.</div>`;
  } else {
    ledger.slice(0, 12).forEach((e) => {
      const detail = e.changed === true || e.changed === false
        ? `changed=${e.changed}`
        : `sha=${String(e.restored_sha256 || "-").slice(0, 10)}`;
      html += `<div class="remediation-ledger-row">
        ${escapeHtml(e.created_at)} · <strong>${escapeHtml(e.action)}</strong> · ${escapeHtml(e.id)} ·
        ${escapeHtml(e.file_path || e.backup_id || "-")} · ${detail}
      </div>`;
    });
  }

  remediationBody.innerHTML = html;

  const approveBtn = document.getElementById("approveRemediationBtn");
  if (approveBtn) approveBtn.addEventListener("click", approveSelectedRemediation);
  remediationBody.querySelectorAll(".remediation-apply").forEach((btn) => {
    btn.addEventListener("click", () => applyApprovedProposal(btn.dataset.proposalId));
  });
  remediationBody.querySelectorAll(".remediation-rollback").forEach((btn) => {
    btn.addEventListener("click", () => rollbackRemediationBackup(btn.dataset.backupId));
  });
}

async function approveSelectedRemediation() {
  const ids = [...remediationBody.querySelectorAll(".remediation-check:checked")].map((el) => el.value);
  if (!ids.length) {
    appendLog("[REMEDIATION] Select at least one proposal before approving.", "error");
    return;
  }
  const noteEl = document.getElementById("remediationNote");
  const res = await fetch("/api/remediation/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ proposal_ids: ids, note: noteEl ? noteEl.value : "" }),
  });
  const data = await res.json();
  if (!res.ok) {
    appendLog(`[REMEDIATION] Approval rejected: ${data.detail}`, "error");
    return;
  }
  activeRemediationApproval = data;
  appendLog(`[REMEDIATION] Approval ${data.id} recorded for ${ids.length} proposal(s). No file changed yet.`);
  await refreshRemediation();
}

async function applyApprovedProposal(proposalId) {
  if (!activeRemediationApproval) return;
  const proposal = (window.__remediationProposals || []).find((p) => p.id === proposalId);
  if (!proposal) return;
  const res = await fetch("/api/remediation/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      approval_id: activeRemediationApproval.id,
      file_path: proposal.file_path,
      proposal_id: proposalId,
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    appendLog(`[REMEDIATION] Apply failed: ${data.detail}`, "error");
    return;
  }
  appendLog(`[REMEDIATION] ${data.ok ? "Applied" : "No change detected"} · ${data.message}`);
  appendLog(`[REMEDIATION] Backup ${data.backup_id} · new score ${(data.audit || {}).score} · PDF ${data.pdf_filename}`);
  if (typeof (data.audit || {}).score === "number") {
    scoreBadge.textContent = `SCORE: ${data.audit.score}/100`;
    scoreBadge.style.color = data.audit.score >= 80 ? "#10B981" : "#F43F5E";
  }
  activeRemediationApproval = null;
  await refreshRemediation();
  loadHistory();
}

async function rollbackRemediationBackup(backupId) {
  const res = await fetch("/api/remediation/rollback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ backup_id: backupId }),
  });
  const data = await res.json();
  if (!res.ok) {
    appendLog(`[REMEDIATION] Rollback failed: ${data.detail}`, "error");
    return;
  }
  appendLog(`[REMEDIATION] Rolled back ${backupId} -> ${data.file_path}`);
  await refreshRemediation();
  loadHistory();
}

/* ---------------------------------------------------------------------------
 * V2 Phase 7 — Fix Verification (real before/after evidence).
 * ------------------------------------------------------------------------- */

async function openVerification() {
  verificationPanel.classList.remove("hidden");
  verificationStats.textContent = "Loading verification evidence...";
  verificationBody.innerHTML = `<div class="log-line muted">Fetching real before/after verification records...</div>`;
  await refreshVerification();
}

async function refreshVerification() {
  try {
    const res = await fetch("/api/verification?limit=5");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderVerification(data);
  } catch (exc) {
    verificationStats.textContent = "UNAVAILABLE";
    verificationBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderVerification(data) {
  const latest = data.latest;
  const history = data.history || [];
  verificationStats.innerHTML = `
    <span>RECORDS: ${history.length}</span>
    <span>LATEST: ${latest ? escapeHtml(latest.id) : "NONE"}</span>
    <span>TARGET: ${latest ? escapeHtml(latest.file_name) : "-"}</span>
  `;
  let html = `<div class="remediation-actions"><button id="runVerificationBtn" class="btn-engine btn-apply">[ RUN VERIFICATION ]</button></div>`;

  if (!latest) {
    html += `<div class="log-line muted" style="margin-top:10px;">No verification record yet. Apply an approved patch first, then run verification.</div>`;
    verificationBody.innerHTML = html;
    document.getElementById("runVerificationBtn").addEventListener("click", runFixVerification);
    return;
  }

  const statusColors = {
    VERIFIED_FIXED: "#34D399",
    PARTIALLY_VERIFIED: "#F59E0B",
    REGRESSION_DETECTED: "#F43F5E",
    NO_CHANGE: "#9CA3AF",
    UNKNOWN: "#C084FC",
  };
  const color = statusColors[latest.status] || "#C084FC";
  html += `
    <div class="intel-card" style="border-left-color:${color};">
      <div class="verify-status" style="color:${color}">${escapeHtml(latest.status)}</div>
      <div style="margin-top:8px;color:#9CA3AF;">${escapeHtml(latest.id)} · ${escapeHtml(latest.created_at)} · apply=${escapeHtml(latest.apply_id || "-")} · approval=${escapeHtml(latest.approval_id || "-")}</div>
      <div style="margin-top:8px;">
        <div class="verify-metric"><span>SECURITY SCORE</span><strong><span style="color:#F43F5E;">${latest.before.score}</span> → <span style="color:#34D399;">${latest.after.score}</span> (Δ ${latest.score_delta >= 0 ? "+" : ""}${latest.score_delta})</strong></div>
        <div class="verify-metric"><span>FINDINGS</span><strong>${latest.before.finding_count} → ${latest.after.finding_count}</strong></div>
        <div class="verify-metric"><span>ENDPOINTS</span><strong>${latest.before.endpoint_count} → ${latest.after.endpoint_count}</strong></div>
      </div>
    </div>`;

  const integrity = latest.integrity || {};
  html += `<div class="remediation-section">EVIDENCE INTEGRITY</div>`;
  html += `<div class="intel-card">
    <div class="verify-metric"><span>BACKUP SHA-256</span><code>${escapeHtml(integrity.backup_sha256 || "-")}</code></div>
    <div class="verify-metric"><span>SOURCE SHA-256</span><code>${escapeHtml(integrity.source_sha256 || "-")}</code></div>
    <div class="verify-metric"><span>BACKUP MATCHES LEDGER</span><strong>${integrity.backup_matches_ledger}</strong></div>
    <div class="verify-metric"><span>SOURCE MATCHES LEDGER</span><strong>${integrity.source_matches_ledger}</strong></div>
    <div style="color:${integrity.drift && integrity.drift !== "none" ? "#F59E0B" : "#34D399"};margin-top:6px;">drift: ${escapeHtml(integrity.drift || "-")}</div>
  </div>`;

  const findingSection = (title, items, itemColor) => {
    let section = `<div class="remediation-section">${title} (${items.length})</div>`;
    if (!items.length) section += `<div class="log-line muted">none</div>`;
    items.forEach((f) => {
      section += `<div class="verify-finding" style="border-left:2px solid ${itemColor};padding-left:8px;">[${escapeHtml(f.severity)}] ${escapeHtml(f.title)} <small style="color:#9CA3AF;">· ${escapeHtml(f.id)} @ ${escapeHtml(f.endpoint)}</small></div>`;
    });
    return section;
  };
  html += findingSection("FIXED BY PATCH", latest.fixed || [], "#34D399");
  html += findingSection("STILL OPEN", latest.still_open || [], "#F59E0B");
  html += findingSection("NEWLY INTRODUCED", latest.introduced || [], "#F43F5E");
  html += `<div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(latest.evidence_note || "")}</div>`;

  if (history.length > 1) {
    html += `<div class="remediation-section">PREVIOUS VERIFICATIONS</div>`;
    history.slice(1).forEach((v) => {
      html += `<div class="remediation-ledger-row">${escapeHtml(v.created_at)} · ${escapeHtml(v.status)} · ${escapeHtml(v.id)} · score ${v.before.score}→${v.after.score}</div>`;
    });
  }

  verificationBody.innerHTML = html;
  document.getElementById("runVerificationBtn").addEventListener("click", runFixVerification);
}

async function runFixVerification() {
  const btn = document.getElementById("runVerificationBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "[ VERIFYING... ]";
  }
  try {
    const res = await fetch("/api/verification/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Verification failed");
    appendLog(`[VERIFY] ${data.id} · ${data.status} · score ${data.before.score}->${data.after.score} · fixed ${data.fixed.length}`);
    await refreshVerification();
  } catch (exc) {
    appendLog(`[VERIFY] ${exc.message || exc}`, "error");
    if (btn) {
      btn.disabled = false;
      btn.textContent = "[ RUN VERIFICATION ]";
    }
  }
}

/* ---------------------------------------------------------------------------
 * V2 Phase 8 — Before & After comparison of two real persisted scans.
 * ------------------------------------------------------------------------- */

async function openComparison() {
  comparisonPanel.classList.remove("hidden");
  comparisonStats.textContent = "Loading real scan comparison...";
  comparisonBody.innerHTML = `<div class="log-line muted">Fetching persisted scans from history...</div>`;
  try {
    const [scansRes, compareRes] = await Promise.all([
      fetch("/api/comparison/scans?limit=40"),
      fetch("/api/comparison"),
    ]);
    const [scansData, compareData] = await Promise.all([scansRes.json(), compareRes.json()]);
    if (!scansRes.ok) throw new Error(scansData.detail || "Scans request failed");
    if (!compareRes.ok) throw new Error(compareData.detail || "Comparison request failed");
    renderComparison(scansData.scans || [], compareData);
  } catch (exc) {
    comparisonStats.textContent = "UNAVAILABLE";
    comparisonBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function comparisonOptions(scans, selectedId) {
  return scans
    .map((s) => {
      const label = `${s.created_at || "-"} · ${s.mode} · score=${s.score} · findings=${s.finding_count}`;
      return `<option value="${escapeHtml(s.id)}" ${s.id === selectedId ? "selected" : ""}>${escapeHtml(label)}</option>`;
    })
    .join("");
}

function renderComparison(scans, data) {
  window.__comparisonScans = scans;
  const before = data.before || {};
  const after = data.after || {};
  const deltas = data.deltas || {};
  const verdictColors = {
    IMPROVED: "#34D399",
    REGRESSED: "#F43F5E",
    UNCHANGED: "#9CA3AF",
  };
  const color = verdictColors[data.verdict] || "#C084FC";

  comparisonStats.innerHTML = `
    <span>SCANS: ${scans.length}</span>
    <span>SELECTION: ${escapeHtml(data.selection || "-")}</span>
    <span>VERDICT: <strong style="color:${color};">${escapeHtml(data.verdict || "-")}</strong></span>
  `;

  let html = `<div class="remediation-section">SELECT TWO REAL SCANS FROM HISTORY</div>`;
  html += `
    <div class="intel-card">
      <div style="color:#F43F5E;">BEFORE (older scan)</div>
      <select id="compareBefore" class="compare-select">${comparisonOptions(scans, before.id)}</select>
      <div style="color:#34D399;margin-top:8px;">AFTER (newer scan)</div>
      <select id="compareAfter" class="compare-select">${comparisonOptions(scans, after.id)}</select>
      <div class="remediation-actions">
        <button id="runComparisonBtn" class="btn-engine btn-approve">[ COMPARE SCANS ]</button>
      </div>
    </div>`;

  html += `
    <div class="intel-card" style="border-left-color:${color};">
      <div class="verify-status" style="color:${color}">${escapeHtml(data.verdict || "-")}</div>
      <div style="margin-top:8px;color:#9CA3AF;">${escapeHtml(before.id)} → ${escapeHtml(after.id)}</div>
      <div class="compare-score" style="margin-top:10px;">
        <span style="color:#F43F5E;">${before.score ?? "-"}</span>
        <span style="color:#9CA3AF;">→</span>
        <span style="color:#34D399;">${after.score ?? "-"}</span>
        <small style="font-size:0.8rem;color:${deltas.score >= 0 ? "#34D399" : "#F43F5E"};">(Δ ${deltas.score >= 0 ? "+" : ""}${deltas.score})</small>
      </div>
      <div style="margin-top:10px;">
        <div class="verify-metric"><span>FINDINGS</span><strong>${before.finding_count} → ${after.finding_count}</strong></div>
        <div class="verify-metric"><span>ENDPOINTS</span><strong>${before.endpoint_count} → ${after.endpoint_count}</strong></div>
        <div class="verify-metric"><span>CORRELATION GROUPS</span><strong>${before.correlation_groups} → ${after.correlation_groups}</strong></div>
        <div class="verify-metric"><span>MAX CVSS</span><strong>${before.cvss?.max ?? "-"} → ${after.cvss?.max ?? "-"}</strong></div>
        <div class="verify-metric"><span>ATTACK SURFACE ENDPOINTS</span><strong>${before.surface?.endpoints ?? 0} → ${after.surface?.endpoints ?? 0}</strong></div>
        <div class="verify-metric"><span>GRAPH NODES</span><strong>${before.graph?.nodes ?? 0} → ${after.graph?.nodes ?? 0}</strong></div>
      </div>
    </div>`;

  const severity = deltas.severity || {};
  html += `<div class="remediation-section">SEVERITY DELTA</div><div class="intel-card">`;
  Object.entries(severity).forEach(([name, value]) => {
    const c = value < 0 ? "#34D399" : value > 0 ? "#F43F5E" : "#9CA3AF";
    html += `<div class="verify-metric"><span>${escapeHtml(name)}</span><strong style="color:${c};">${value > 0 ? "+" : ""}${value}</strong></div>`;
  });
  html += `</div>`;

  const findingSection = (title, items, itemColor) => {
    let section = `<div class="remediation-section">${title} (${items.length})</div>`;
    if (!items.length) section += `<div class="log-line muted">none</div>`;
    items.forEach((f) => {
      section += `<div class="verify-finding" style="border-left:2px solid ${itemColor};padding-left:8px;">[${escapeHtml(f.severity)}] ${escapeHtml(f.title)} <small style="color:#9CA3AF;">· ${escapeHtml(f.id)} @ ${escapeHtml(f.endpoint)}</small></div>`;
    });
    return section;
  };
  html += findingSection("FIXED IN AFTER", data.fixed || [], "#34D399");
  html += findingSection("NEWLY INTRODUCED", data.introduced || [], "#F43F5E");
  html += findingSection("STILL PRESENT", data.persisting || [], "#9CA3AF");
  html += `<div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(data.policy || "")}</div>`;

  comparisonBody.innerHTML = html;
  document.getElementById("runComparisonBtn").addEventListener("click", runScanComparison);
}

async function runScanComparison() {
  const before = document.getElementById("compareBefore").value;
  const after = document.getElementById("compareAfter").value;
  try {
    const res = await fetch(
      `/api/comparison?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`
    );
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Comparison failed");
    appendLog(`[COMPARE] ${data.verdict} · ${data.before.score} -> ${data.after.score} · fixed ${data.fixed.length}`);
    renderComparison(window.__comparisonScans || [], data);
  } catch (exc) {
    appendLog(`[COMPARE] ${exc.message || exc}`, "error");
  }
}

/* ---------------------------------------------------------------------------
 * V3.1 — visual BEFORE/AFTER proof. Capture is optional; differences are never
 * treated as automatic vulnerability resolution.
 * ------------------------------------------------------------------------- */

async function loadVisualSnapshots() {
  const note = document.getElementById("visualCompareNote");
  if (!note) return;
  try {
    const res = await fetch("/api/comparison/snapshots");
    const data = await res.json();
    const snaps = data.snapshots || [];
    window.__visualSnapshots = snaps;
    note.textContent = data.available
      ? `${snaps.length} real snapshot(s). ${data.policy}`
      : `Capture unavailable: ${data.install || data.error || "Playwright not installed"}`;
    if (snaps.length >= 2) await renderVisualPair(snaps[snaps.length - 2], snaps[snaps.length - 1]);
  } catch (exc) {
    note.textContent = `Snapshot API unavailable: ${exc.message || exc}`;
  }
}

async function captureVisualSnapshot() {
  const note = document.getElementById("visualCompareNote");
  if (!note) return;
  const target = document.getElementById("visualTargetInput")?.value.trim() || "";
  const label = document.getElementById("visualLabelInput")?.value.trim() || "";
  if (!target) {
    note.textContent = "Enter your localhost URL first.";
    return;
  }
  note.textContent = "Capturing real localhost screenshot…";
  try {
    const res = await fetch("/api/comparison/capture", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, label }),
    });
    const data = await res.json();
    if (!data.ok) {
      note.textContent = data.available
        ? `Capture failed: ${data.error || "unknown"} ${data.hint || ""}`
        : `Playwright not installed: ${data.install || data.error}`;
      return;
    }
    note.textContent = `Captured ${data.snapshot.snapshot_id}. ${data.snapshot.target}`;
    await loadVisualSnapshots();
  } catch (exc) {
    note.textContent = `Capture request failed: ${exc.message || exc}`;
  }
}

async function renderVisualPair(before, after) {
  const slider = document.getElementById("visualSlider");
  const beforeImg = document.getElementById("visualBefore");
  const afterImg = document.getElementById("visualAfter");
  if (!slider || !beforeImg || !afterImg) return;
  const imageUrl = (meta) => `/api/comparison/image/${encodeURIComponent(String(meta.path || "").split("/").pop())}`;
  beforeImg.src = imageUrl(before);
  afterImg.src = imageUrl(after);
  slider.style.setProperty("--split", "50%");
  slider.classList.remove("hidden");
  const note = document.getElementById("visualCompareNote");
  try {
    const res = await fetch(
      `/api/comparison/image-diff?before=${encodeURIComponent(before.snapshot_id)}&after=${encodeURIComponent(after.snapshot_id)}`
    );
    const data = await res.json();
    if (note && data.ok) {
      note.textContent += ` Changed pixels: ${(Number(data.changed_ratio) * 100).toFixed(2)}% — visual only, no automatic RESOLVED status.`;
    }
  } catch (_) { /* the images are still usable without a diff */ }
}

/* ---------------------------------------------------------------------------
 * V2 Phase 9 — API Security (real evidence, honest control reporting).
 * Controls are reported as "observed in source" or "not observed in source";
 * absence of evidence is never presented as proof that a control is safe.
 * ------------------------------------------------------------------------- */

async function openApiSecurity() {
  apiSecPanel.classList.remove("hidden");
  apiSecStats.textContent = "Loading API security evidence...";
  apiSecBody.innerHTML = `<div class="log-line muted">Fetching endpoint risk from the latest real audit...</div>`;
  await refreshApiSecurity();
}

async function refreshApiSecurity() {
  try {
    const res = await fetch("/api/api-security");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderApiSecurity(data);
  } catch (exc) {
    apiSecStats.textContent = "UNAVAILABLE";
    apiSecBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderApiSecurity(data) {
  if (!data.available) {
    apiSecStats.textContent = "NO DATA";
    apiSecBody.innerHTML = `<div class="log-line muted">${escapeHtml(data.reason || "No audit available.")} Run an audit first.</div>`;
    return;
  }

  const s = data.summary || {};
  apiSecStats.innerHTML = `
    <span>ENDPOINTS: ${s.api_endpoints}</span>
    <span>CRITICAL/HIGH: <strong style="color:#F43F5E;">${s.critical_or_high}</strong></span>
    <span>AUTH OBSERVED: ${s.with_auth_observed} / ${s.api_endpoints}</span>
    <span>RATE LIMIT OBSERVED: ${s.with_rate_limit_observed}</span>
    <span>SNAPSHOT HTTP: ${s.local_snapshot_status ?? "-"}</span>
  `;

  let html = `<div class="remediation-section">ENDPOINT RISK (from real scan evidence)</div>`;
  const riskColors = { CRITICAL: "#F43F5E", HIGH: "#FB923C", MEDIUM: "#F59E0B", LOW: "#34D399", NONE: "#9CA3AF" };

  (data.endpoints || []).forEach((ep) => {
    const color = riskColors[ep.risk] || "#C084FC";
    const controls = ep.controls || {};

    const control = (label, observed) => `
      <span style="color:${observed ? "#34D399" : "#F59E0B"};">
        ${observed ? "[+] " : "[!] "}${label}: ${observed ? "observed in source" : "not observed in source"}
      </span>`;

    const evidence = (ep.evidence || [])
      .slice(0, 4)
      .map((e) => `<li><code>${escapeHtml(e.source)}</code> · ${escapeHtml(e.title || "-")} ${e.detail ? `— ${escapeHtml(e.detail)}` : ""}</li>`)
      .join("");

    html += `
      <div class="intel-card" style="border-left-color:${color};">
        <div class="finding-title" style="color:${color};">
          [${escapeHtml(ep.risk)}] ${escapeHtml(ep.path)}
        </div>
        <div style="margin:6px 0;color:#9CA3AF;">
          line ${ep.line ?? "-"} · findings ${ep.finding_count} · correlations ${ep.correlation_count}
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:12px;margin:6px 0;font-size:0.74rem;">
          ${control("authorization", controls.authorization_in_source)}
          ${control("input validation", controls.input_validation_in_source)}
          ${control("rate limiting", controls.rate_limit_in_source)}
        </div>
        ${evidence ? `<ul style="margin:6px 0 0 18px;font-size:0.74rem;color:#D1D5DB;">${evidence}</ul>` : ""}
      </div>`;
  });

  html += `
    <div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;border-top:1px solid var(--border-violet);padding-top:8px;">
      ${escapeHtml(data.policy || "")}
      "not observed in source" does not prove a control is absent at runtime — it means no matching evidence was found in the reviewed source.
    </div>`;

  apiSecBody.innerHTML = html;
}

/* ---------------------------------------------------------------------------
 * V2 Phase 9 — Continuous Monitoring (localhost-only, bounded, real events).
 * The drawer polls status/history while open; closing the drawer stops polling
 * but does NOT stop the background watcher (it keeps recording real drift).
 * ------------------------------------------------------------------------- */

async function openMonitor() {
  monitorPanel.classList.remove("hidden");
  monitorStats.textContent = "Loading monitor status...";
  monitorBody.innerHTML = `<div class="log-line muted">Fetching real monitoring state and recorded events...</div>`;
  await refreshMonitor();
  startMonitorPolling();
}

async function refreshMonitor() {
  try {
    const [statusRes, historyRes] = await Promise.all([
      fetch("/api/monitor/status"),
      fetch("/api/monitor/history?limit=20"),
    ]);
    const [statusData, historyData] = await Promise.all([statusRes.json(), historyRes.json()]);
    if (!statusRes.ok) throw new Error(statusData.detail || "Status request failed");
    if (!historyRes.ok) throw new Error(historyData.detail || "History request failed");
    renderMonitor(statusData, historyData.events || []);
  } catch (exc) {
    monitorStats.textContent = "UNAVAILABLE";
    monitorBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderMonitor(status, events) {
  monitorStats.innerHTML = `
    <span>STATE: <strong style="color:${status.running ? "#34D399" : "#9CA3AF"};">${status.running ? "RUNNING" : "STOPPED"}</strong></span>
    <span>INTERVAL: ${status.interval_seconds}s</span>
    <span>TICKS: ${status.ticks}</span>
    <span>EVENTS: ${status.recorded_events}</span>
    <span>TARGET: ${status.target ? escapeHtml(status.target) : "none"}</span>
  `;

  let html = `
    <div class="remediation-section">WATCHER CONTROL (localhost only)</div>
    <div class="intel-card">
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
        <label style="color:#9CA3AF;">Target:
          <input id="monitorTarget" class="remediation-note" style="width:220px;margin:0 4px;" value="" placeholder="Your localhost URL" spellcheck="false">
        </label>
        <label style="color:#9CA3AF;">Interval (s):
          <input id="monitorInterval" class="remediation-note" style="width:70px;margin:0 4px;" type="number" min="10" max="3600" value="30">
        </label>
      </div>
      <div class="remediation-actions">
        <button id="startMonitorBtn" class="btn-engine btn-apply" ${status.running ? "disabled" : ""}>[ START MONITOR ]</button>
        <button id="stopMonitorBtn" class="btn-engine btn-rollback" ${status.running ? "" : "disabled"}>[ STOP MONITOR ]</button>
        <button id="refreshMonitorBtn" class="btn-engine">[ REFRESH ]</button>
      </div>
      <div style="margin-top:8px;color:#9CA3AF;font-size:0.72rem;">${escapeHtml(status.policy || "")}</div>
    </div>`;

  html += `<div class="remediation-section">RECORDED EVENTS (${events.length})</div>`;
  if (!events.length) {
    html += `<div class="log-line muted">No monitoring events yet. Start the watcher to capture real source/HTTP snapshots.</div>`;
  } else {
    events.slice(0, 12).forEach((e) => {
      const http = e.http || {};
      const sources = e.sources || [];
      const drift = e.drift || [];
      const sourceText = sources
        .map((s) => `${escapeHtml(s.file)} score=${s.score} findings=${s.finding_count} ${String(s.sha256 || "").slice(0, 10)}`)
        .join(" | ");
      const driftText = drift.length
        ? drift
            .map((d) => `<div style="color:#F59E0B;">• ${escapeHtml(d.file)}: ${escapeHtml((d.change || []).join(", "))}${d.score_delta ? ` (Δ ${d.score_delta})` : ""}</div>`)
            .join("")
        : `<div style="color:#34D399;">no drift vs previous tick</div>`;
      const httpText = http.enabled
        ? http.error
          ? `<span style="color:#F43F5E;">${escapeHtml(http.error)}</span>`
          : `HTTP ${http.status_code ?? "-"} · html ${String(http.html_sha256 || "-").slice(0, 12)} · missing headers ${(http.security_headers_missing || []).length}`
        : `HTTP disabled`;

      html += `
        <div class="intel-card" style="margin-bottom:8px;">
          <div class="finding-title">${escapeHtml(e.id)} · ${escapeHtml(e.captured_at)}</div>
          <div style="margin:4px 0;color:#D1D5DB;font-size:0.74rem;">${sourceText}</div>
          <div style="margin:4px 0;color:#9CA3AF;font-size:0.72rem;">${httpText}</div>
          <div style="margin-top:4px;font-size:0.74rem;">DRIFT: ${driftText}</div>
        </div>`;
    });
  }

  monitorBody.innerHTML = html;

  const startBtn = document.getElementById("startMonitorBtn");
  const stopBtn = document.getElementById("stopMonitorBtn");
  const refreshBtn = document.getElementById("refreshMonitorBtn");
  if (startBtn) startBtn.addEventListener("click", startMonitoring);
  if (stopBtn) stopBtn.addEventListener("click", stopMonitoring);
  if (refreshBtn) refreshBtn.addEventListener("click", refreshMonitor);
}

async function startMonitoring() {
  const targetEl = document.getElementById("monitorTarget");
  const intervalEl = document.getElementById("monitorInterval");
  const target = (targetEl ? targetEl.value : "").trim();
  const interval = intervalEl ? Number(intervalEl.value) : 30;

  // Local guardrail mirrors the backend localhost-only policy.
  let parsed;
  try {
    parsed = new URL(target);
  } catch (_) {
    appendLog("[MONITOR] Invalid target URL.", "error");
    return;
  }
  if (!["127.0.0.1", "localhost"].includes(parsed.hostname)) {
    appendLog("[MONITOR] Target must be localhost or 127.0.0.1.", "error");
    return;
  }

  try {
    const res = await fetch("/api/monitor/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interval_seconds: interval, target }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Start failed");
    appendLog(`[MONITOR] Started · target ${target} · interval ${data.interval_seconds}s`);
    await refreshMonitor();
    startMonitorPolling();
  } catch (exc) {
    appendLog(`[MONITOR] ${exc.message || exc}`, "error");
  }
}

async function stopMonitoring() {
  try {
    const res = await fetch("/api/monitor/stop", { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Stop failed");
    appendLog(`[MONITOR] Stopped · ${data.ticks} tick(s) recorded.`);
    stopMonitorPolling();
    await refreshMonitor();
  } catch (exc) {
    appendLog(`[MONITOR] ${exc.message || exc}`, "error");
  }
}

function startMonitorPolling() {
  stopMonitorPolling();
  monitorPollTimer = setInterval(() => {
    if (monitorPanel.classList.contains("hidden")) {
      stopMonitorPolling();
      return;
    }
    refreshMonitor();
  }, 5000);
}

function stopMonitorPolling() {
  if (monitorPollTimer) {
    clearInterval(monitorPollTimer);
    monitorPollTimer = null;
  }
}

/* ---------------------------------------------------------------------------
 * V2 Phase 10 — Overview / Dashboard.
 * ------------------------------------------------------------------------- */

function metricTile(label, value, color = "#E9D5FF") {
  return `<div class="metric-tile">
    <div class="metric-label">${escapeHtml(label)}</div>
    <div class="metric-value" style="color:${color};">${value}</div>
  </div>`;
}

async function openOverview() {
  overviewPanel.classList.remove("hidden");
  overviewStats.textContent = "Loading real dashboard data...";
  overviewBody.innerHTML = `<div class="log-line muted">Aggregating persisted scan history...</div>`;
  try {
    const res = await fetch("/api/overview");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderOverview(data);
  } catch (exc) {
    overviewStats.textContent = "UNAVAILABLE";
    overviewBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderOverview(data) {
  const latest = data.latest || {};
  const sec = data.security || {};
  const surf = data.surface || {};
  const health = data.engine_health || {};
  const hist = data.history || {};

  overviewStats.innerHTML = `
    <span>SCANS: ${hist.total_scans}</span>
    <span>COMPLETED: ${hist.completed_scans}</span>
    <span>FAILED: ${hist.failed_scans}</span>
    <span>LATEST: ${escapeHtml(latest.id || "-")}</span>
    <span>MODE: ${escapeHtml(latest.mode || "-")}</span>
  `;

  let html = `<div class="remediation-section">LATEST REAL SCAN SECURITY POSTURE</div>`;
  html += `<div class="metric-grid">
    ${metricTile("SECURITY SCORE", (latest.score ?? "-") + "/100", (latest.score ?? 0) >= 80 ? "#34D399" : "#F43F5E")}
    ${metricTile("FINDINGS", sec.finding_count ?? "-", "#FB923C")}
    ${metricTile("ENDPOINTS", sec.endpoint_count ?? "-", "#7DD3FC")}
    ${metricTile("CORRELATION GROUPS", sec.correlation_groups ?? "-", "#C084FC")}
    ${metricTile("MAX CVSS", sec.max_cvss ?? "-", "#F59E0B")}
    ${metricTile("VALIDATED CVES", sec.total_cves ?? "-", "#34D399")}
  </div>`;

  const sev = sec.severity_counts || {};
  html += `<div class="remediation-section">SEVERITY BREAKDOWN</div><div class="intel-card">`;
  Object.entries(sev).forEach(([name, count]) => {
    const color = { CRITICAL: "#F43F5E", HIGH: "#FB923C", MEDIUM: "#F59E0B", LOW: "#34D399" }[name] || "#9CA3AF";
    html += `<div class="verify-metric"><span style="color:${color};">${name}</span><strong>${count}</strong></div>`;
  });
  html += `</div>`;

  html += `<div class="remediation-section">ATTACK SURFACE / GRAPH</div><div class="intel-card">`;
  [
    ["Surface endpoints", surf.endpoints],
    ["Graph nodes", surf.graph_nodes],
    ["Evidence edges", surf.evidence_edges],
    ["Theoretical edges", surf.theoretical_edges],
  ].forEach(([label, value]) => {
    html += `<div class="verify-metric"><span>${label}</span><strong>${value ?? 0}</strong></div>`;
  });
  html += `</div>`;

  const toolEntries = Object.entries(health.tool_status || {});
  html += `<div class="remediation-section">ENGINE HEALTH ${health.source_scan ? `· ${escapeHtml(health.source_scan)}` : ""}</div><div class="intel-card">`;
  html += `<div class="verify-metric"><span>GUARDRAIL</span><strong style="color:${health.guardrail_ok ? "#34D399" : "#F43F5E"};">${health.guardrail_ok ? "OK" : "N/A"} · ${escapeHtml(health.guardrail_mode || "-")}</strong></div>`;
  html += `<div class="verify-metric"><span>TOOLS OK</span><strong>${health.tools_ok} / ${health.tools_total}</strong></div>`;
  toolEntries.forEach(([name, status]) => {
    html += `<div class="verify-metric"><span>${escapeHtml(name)}</span><strong style="color:${status === "OK" ? "#34D399" : "#F59E0B"};">${escapeHtml(status)}</strong></div>`;
  });
  html += `</div>`;

  html += `<div class="remediation-section">RECENT SCANS</div>`;
  (data.recent_scans || []).forEach((s) => {
    html += `<div class="remediation-ledger-row">${escapeHtml(s.created_at || "-")} · ${escapeHtml(s.mode)} · ${escapeHtml(s.id)} · score ${s.score} · ${s.finding_count} findings · ${escapeHtml(s.pdf_filename || "no PDF")}</div>`;
  });

  html += `<div class="remediation-section">PIPELINE (9 STAGES)</div>`;
  html += `<div class="log-line muted">${(data.pipeline || []).map((s, i) => `${i + 1}. ${escapeHtml(s)}`).join(" → ")}</div>`;
  html += `<div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(data.policy || "")}</div>`;

  overviewBody.innerHTML = html;
}

/* ---------------------------------------------------------------------------
 * V2 Phase 10 — Vulnerability Center.
 * ------------------------------------------------------------------------- */

async function openVulnerabilityCenter() {
  vulnCenterPanel.classList.remove("hidden");
  vulnCenterStats.textContent = "Loading real findings...";
  vulnCenterBody.innerHTML = `<div class="log-line muted">Fetching CVSS, classification and evidence from the latest scan...</div>`;
  try {
    const res = await fetch("/api/vulnerability-center");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderVulnerabilityCenter(data);
  } catch (exc) {
    vulnCenterStats.textContent = "UNAVAILABLE";
    vulnCenterBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderVulnerabilityCenter(data) {
  if (!data.available) {
    vulnCenterStats.textContent = "NO DATA";
    vulnCenterBody.innerHTML = `<div class="log-line muted">${escapeHtml(data.reason || "Run an audit first.")}</div>`;
    return;
  }

  const s = data.summary || {};
  vulnCenterStats.innerHTML = `
    <span>SCAN: ${escapeHtml((data.scan || {}).id || "-")}</span>
    <span>FINDINGS: ${s.total}</span>
    <span>MAX CVSS: ${s.max_cvss ?? "-"}</span>
    <span>CVES: ${s.total_cves}</span>
    <span>GROUPS: ${s.correlation_groups}</span>
  `;

  let html = `<div class="intel-card">
    <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;">
      <label style="color:#9CA3AF;">Severity:
        <select id="vulnSeverityFilter" class="compare-select" style="width:auto;margin:0 4px;">
          <option value="ALL">ALL</option>
          ${(data.filters.severities || []).map((x) => `<option value="${x}">${x}</option>`).join("")}
        </select>
      </label>
      <label style="color:#9CA3AF;">Classification:
        <select id="vulnClassFilter" class="compare-select" style="width:auto;margin:0 4px;">
          <option value="ALL">ALL</option>
          ${(data.filters.classifications || []).map((x) => `<option value="${x}">${x}</option>`).join("")}
        </select>
      </label>
      <span style="color:#9CA3AF;">showing <strong id="vulnVisibleCount">${s.total}</strong> / ${s.total}</span>
    </div>
  </div>`;

  const sevColors = { CRITICAL: "#F43F5E", HIGH: "#FB923C", MEDIUM: "#F59E0B", LOW: "#34D399" };
  (data.findings || []).forEach((f) => {
    const cvss = f.cvss || {};
    html += `<div class="intel-card vuln-card" data-severity="${escapeHtml(f.severity)}" data-classification="${escapeHtml(f.classification)}">
      <div class="finding-title" style="color:${sevColors[f.severity] || "#C084FC"};">
        [${escapeHtml(f.severity)}] ${escapeHtml(f.title)}
      </div>
      <div style="margin:6px 0;color:#9CA3AF;">
        ${escapeHtml(f.id)} · ${escapeHtml(f.endpoint || "-")} ·
        class=<span style="color:#C084FC;">${escapeHtml(f.classification)}</span> ·
        CVSS <strong style="color:#F59E0B;">${cvss.base_score ?? cvss.score ?? "-"}</strong> ${cvss.vector ? `<code>${escapeHtml(cvss.vector)}</code>` : ""}
      </div>
      ${f.explanation ? `<div style="margin:4px 0;">${escapeHtml(f.explanation)}</div>` : ""}
      ${f.recommendation ? `<div style="margin:4px 0;color:#6EE7B7;">[FIX] ${escapeHtml(f.recommendation)}</div>` : ""}
      ${(f.evidence || []).length ? `<ul style="margin:6px 0 0 18px;font-size:0.74rem;color:#D1D5DB;">${f.evidence.map((e) => `<li><code>${escapeHtml(e.tool)}</code> · ${escapeHtml(e.title)} ${e.endpoint ? `— ${escapeHtml(e.endpoint)}` : ""}</li>`).join("")}</ul>` : ""}
    </div>`;
  });

  html += `<div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(data.policy || "")}</div>`;
  vulnCenterBody.innerHTML = html;

  const sevFilter = document.getElementById("vulnSeverityFilter");
  const classFilter = document.getElementById("vulnClassFilter");
  const applyFilter = () => {
    let visible = 0;
    vulnCenterBody.querySelectorAll(".vuln-card").forEach((card) => {
      const sevOk = sevFilter.value === "ALL" || card.dataset.severity === sevFilter.value;
      const classOk = classFilter.value === "ALL" || card.dataset.classification === classFilter.value;
      card.style.display = sevOk && classOk ? "" : "none";
      if (sevOk && classOk) visible += 1;
    });
    document.getElementById("vulnVisibleCount").textContent = visible;
  };
  sevFilter.addEventListener("change", applyFilter);
  classFilter.addEventListener("change", applyFilter);
}

/* ---------------------------------------------------------------------------
 * V2 Phase 10 — AI Intelligence.
 * ------------------------------------------------------------------------- */

async function openAiIntelligence() {
  aiIntelPanel.classList.remove("hidden");
  aiIntelStats.textContent = "Loading AI-layer evidence...";
  aiIntelBody.innerHTML = `<div class="log-line muted">Fetching correlation explanations, guardrail and CVSS/CVE analysis...</div>`;
  try {
    const res = await fetch("/api/ai-intelligence");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderAiIntelligence(data);
  } catch (exc) {
    aiIntelStats.textContent = "UNAVAILABLE";
    aiIntelBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderAiIntelligence(data) {
  if (!data.available) {
    aiIntelStats.textContent = "NO DATA";
    aiIntelBody.innerHTML = `<div class="log-line muted">${escapeHtml(data.reason || "Run an audit first.")}</div>`;
    return;
  }

  const mode = data.mode || {};
  const corr = data.correlation || {};
  const summary = corr.summary || {};
  aiIntelStats.innerHTML = `
    <span>CORRELATION AI: ${escapeHtml(mode.correlation_ai_mode || "-")}</span>
    <span>GUARDRAIL: ${escapeHtml(mode.guardrail_mode || "-")} (${mode.guardrail_ok ? "OK" : "N/A"})</span>
    <span>GROUPS: ${summary.total ?? 0}</span>
    <span>MODEL: ${escapeHtml(mode.model || "-")}</span>
  `;

  let html = `<div class="remediation-section">AI ENGINE STATUS</div><div class="intel-card">
    <div class="verify-metric"><span>Correlation engine</span><strong>${escapeHtml(mode.correlation_engine || "-")}</strong></div>
    <div class="verify-metric"><span>Correlation AI mode</span><strong>${escapeHtml(mode.correlation_ai_mode || "-")}</strong></div>
    <div class="verify-metric"><span>Guardrail mode</span><strong>${escapeHtml(mode.guardrail_mode || "-")}</strong></div>
    <div class="verify-metric"><span>Guardrail verdict</span><strong style="color:${mode.guardrail_ok ? "#34D399" : "#F59E0B"};">${escapeHtml(mode.guardrail_message || "-")}</strong></div>
    ${mode.guardrail_source_scan ? `<div class="verify-metric"><span>Guardrail source scan</span><strong>${escapeHtml(mode.guardrail_source_scan)}</strong></div>` : ""}
    <div style="margin-top:8px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(data.policy || "")}</div>
  </div>`;

  html += `<div class="remediation-section">CORRELATION GROUPS (${(corr.groups || []).length})</div>`;
  (corr.groups || []).forEach((g) => {
    const classColors = { Confirmed: "#F43F5E", Potential: "#F59E0B", Unverified: "#7DD3FC", Informational: "#34D399" };
    html += `<div class="intel-card" style="border-left-color:${classColors[g.classification] || "#C084FC"};">
      <div class="finding-title" style="color:${classColors[g.classification] || "#C084FC"};">
        ${escapeHtml(g.id)} · ${escapeHtml(g.classification)} · ${escapeHtml(g.title)}
      </div>
      <div style="margin:6px 0;color:#9CA3AF;">
        severity=${escapeHtml(g.severity || "-")} · confidence=${escapeHtml(g.confidence || "-")} ·
        cvss=${(g.cvss && (g.cvss.base_score ?? g.cvss.score ?? g.cvss)) ?? "-"} · evidence=${g.evidence_count} · tools=${(g.tools || []).map(escapeHtml).join(",")}
      </div>
      ${g.reason ? `<div style="margin:4px 0;">${escapeHtml(g.reason)}</div>` : ""}
      ${g.ai_analysis || g.analysis ? `<div style="margin:4px 0;color:#C084FC;">[AI ANALYSIS] ${escapeHtml(g.ai_analysis || g.analysis)}</div>` : ""}
      ${g.ai_recommendation || g.recommendation ? `<div style="margin:4px 0;color:#6EE7B7;">[AI FIX] ${escapeHtml(g.ai_recommendation || g.recommendation)}</div>` : ""}
      ${(g.endpoints || []).length ? `<div style="margin:4px 0;color:#9CA3AF;font-size:0.74rem;">endpoints: ${g.endpoints.map(escapeHtml).join(", ")}</div>` : ""}
    </div>`;
  });

  const cvss = data.cvss_cve || {};
  html += `<div class="remediation-section">CVSS / CVE ANALYSIS</div><div class="intel-card">
    <div class="verify-metric"><span>CVSS engine</span><strong>${escapeHtml(cvss.engine || "-")}</strong></div>
    <div class="verify-metric"><span>Max / Average CVSS</span><strong>${(cvss.summary || {}).max_cvss ?? "-"} / ${(cvss.summary || {}).average_cvss ?? "-"}</strong></div>
    <div class="verify-metric"><span>Validated CVEs</span><strong>${(cvss.summary || {}).total_cves ?? 0}</strong></div>
    ${(cvss.cve_lookups || []).map((l) => `<div class="verify-metric"><span>${escapeHtml(l.component || "-")}</span><strong>${escapeHtml(l.status || "-")}</strong></div>`).join("")}
    <div style="margin-top:8px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(cvss.policy || "")}</div>
  </div>`;

  aiIntelBody.innerHTML = html;
}

/* ---------------------------------------------------------------------------
 * V2 Phase 10 — Reports (real PDF files linked to real scans).
 * ------------------------------------------------------------------------- */

async function openReports() {
  reportsPanel.classList.remove("hidden");
  reportsStats.textContent = "Loading real reports...";
  reportsBody.innerHTML = `<div class="log-line muted">Listing generated PDFs from the reports directory...</div>`;
  try {
    const res = await fetch("/api/reports");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderReports(data);
  } catch (exc) {
    reportsStats.textContent = "UNAVAILABLE";
    reportsBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderReports(data) {
  const s = data.summary || {};
  reportsStats.innerHTML = `
    <span>REPORTS: ${s.total_reports}</span>
    <span>LINKED TO SCAN: ${s.linked_to_scan}</span>
    <span>LATEST: ${escapeHtml(s.latest_filename || "-")}</span>
  `;
  let html = `<div class="remediation-actions"><a href="/api/download-report" target="_blank" class="btn-engine btn-approve">[ DOWNLOAD LATEST PDF ]</a></div>`;
  (data.reports || []).forEach((r) => {
    const scan = r.scan || {};
    html += `<div class="intel-card" style="margin-top:8px;">
      <div class="finding-title">${escapeHtml(r.filename)}</div>
      <div style="margin:4px 0;color:#9CA3AF;">
        ${escapeHtml(r.created_at)} · ${r.size_bytes} bytes ·
        ${scan.id ? `scan=${escapeHtml(scan.id)} · mode=${escapeHtml(scan.mode)} · score=${scan.score}` : "no linked scan record"}
      </div>
      <div class="remediation-actions">
        <a href="${escapeHtml(r.download_url)}" target="_blank" class="btn-engine">[ OPEN PDF ]</a>
      </div>
    </div>`;
  });
  html += `<div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(data.policy || "")}</div>`;
  reportsBody.innerHTML = html;
}

/* ---------------------------------------------------------------------------
 * V2 Phase 10 — AI Copilot (Gemini grounded in real scan context).
 * ------------------------------------------------------------------------- */

function openCopilot() {
  copilotPanel.classList.remove("hidden");
  copilotStats.textContent = "Ready · answers are grounded in the latest real scan";
  const feed = document.getElementById("copilotFeed");
  if (!feed.children.length) {
    appendCopilotMessage(
      "assistant",
      "Ask me about the latest real scan: scores, findings, CVSS/CVE, affected endpoints, guardrail status, or fix recommendations. I only use data from persisted scan evidence."
    );
  }
  const input = document.getElementById("copilotQuestion");
  if (input) input.focus();
}

function appendCopilotMessage(kind, text) {
  const feed = document.getElementById("copilotFeed");
  if (!feed) return;
  const el = document.createElement("div");
  el.className = `copilot-msg ${kind}`;
  el.textContent = text;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

async function askCopilotQuestion() {
  const input = document.getElementById("copilotQuestion");
  const btn = document.getElementById("copilotAskBtn");
  const question = (input.value || "").trim();
  if (!question) return;
  appendCopilotMessage("user", question);
  input.value = "";
  btn.disabled = true;
  btn.textContent = "[ THINKING... ]";
  copilotStats.textContent = "Querying real scan context...";
  try {
    const res = await fetch("/api/copilot/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    appendCopilotMessage("assistant", data.answer || "(empty answer)");
    copilotStats.textContent = `mode=${data.mode} · scan=${(data.sources || {}).scan_id || "-"} · findings=${(data.sources || {}).findings || 0}`;
    appendLog(`[COPILOT] answered via ${data.mode} from scan ${(data.sources || {}).scan_id || "-"}`);
  } catch (exc) {
    appendCopilotMessage("error", exc.message || exc);
    copilotStats.textContent = "ERROR";
  } finally {
    btn.disabled = false;
    btn.textContent = "[ ASK ]";
  }
}

/* ---------------------------------------------------------------------------
 * V2 Phase 10 — Settings / diagnostics (real runtime values only).
 * ------------------------------------------------------------------------- */

async function openSettings() {
  settingsPanel.classList.remove("hidden");
  settingsStats.textContent = "Loading real runtime configuration...";
  settingsBody.innerHTML = `<div class="log-line muted">Reading active settings from the backend...</div>`;
  try {
    const res = await fetch("/api/settings");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    renderSettings(data);
  } catch (exc) {
    settingsStats.textContent = "UNAVAILABLE";
    settingsBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderSettings(data) {
  const ai = data.ai || {};
  const scope = data.scope || {};
  const storage = data.storage || {};
  settingsStats.innerHTML = `
    <span>GEMINI KEY: ${ai.gemini_key_present ? "CONFIGURED" : "NOT SET"}</span>
    <span>MODEL: ${escapeHtml(ai.active_model || ai.gemini_model || "-")}</span>
    <span>SCOPE: ${scope.localhost_only ? "LOCALHOST ONLY" : "UNKNOWN"}</span>
    <span>HISTORY: ${storage.history_records}</span>
  `;

  let html = `<div class="remediation-section">AI / GUARDRAIL</div><div class="intel-card">
    <div class="verify-metric"><span>Gemini API key</span><strong>${ai.gemini_key_present ? "present (value hidden)" : "not configured"}</strong></div>
    <div class="verify-metric"><span>Model</span><strong>${escapeHtml(ai.active_model || ai.gemini_model || "-")}</strong></div>
    <div class="verify-metric"><span>Guardrail mode</span><strong>${escapeHtml(ai.guardrail_mode || "-")}</strong></div>
    <div class="verify-metric"><span>Correlation AI mode</span><strong>${escapeHtml(ai.correlation_ai_mode || "-")}</strong></div>
  </div>`;

  html += `<div class="remediation-section">LOCALHOST-ONLY SCOPE</div><div class="intel-card">
    <div class="verify-metric"><span>Allowed hosts</span><strong>${(scope.allowed_snapshot_hosts || []).map(escapeHtml).join(", ")}</strong></div>
    <div class="verify-metric"><span>Snapshot timeout</span><strong>${scope.snapshot_timeout_seconds}s</strong></div>
    <div class="verify-metric"><span>Snapshot size cap</span><strong>${scope.snapshot_max_bytes} bytes</strong></div>
    <div class="verify-metric"><span>Monitor interval range</span><strong>${(scope.monitor_interval_range || []).join(" - ")}s</strong></div>
    <div class="verify-metric"><span>Monitor max events</span><strong>${scope.monitor_max_events}</strong></div>
    <div style="margin-top:6px;color:#9CA3AF;font-size:0.72rem;">${escapeHtml(scope.dast_target || "")} · ${escapeHtml(scope.monitor_target || "")}</div>
  </div>`;

  html += `<div class="remediation-section">STORAGE</div><div class="intel-card">
    <div class="verify-metric"><span>History file</span><code>${escapeHtml(storage.history_file || "-")}</code></div>
    <div class="verify-metric"><span>History records</span><strong>${storage.history_records} (${storage.completed_scans} completed)</strong></div>
    <div class="verify-metric"><span>Backup files</span><strong>${storage.backup_files}</strong></div>
    <div class="verify-metric"><span>Verifications present</span><strong>${storage.verifications_present}</strong></div>
    <div class="verify-metric"><span>Monitor events present</span><strong>${storage.monitor_events_present}</strong></div>
  </div>`;

  html += `<div class="remediation-section">DAST TOOLS (${escapeHtml(data.tools_source || "-")})</div><div class="intel-card">
    ${Object.entries(data.tools || {}).map(([name, status]) => `<div class="verify-metric"><span>${escapeHtml(name)}</span><strong style="color:${status === "OK" ? "#34D399" : "#F59E0B"};">${escapeHtml(status)}</strong></div>`).join("") || `<div class="log-line muted">No DAST tool data yet.</div>`}
    <div class="remediation-actions"><button id="recheckToolsBtn" class="btn-engine">[ RECHECK TOOLS LIVE ]</button></div>
  </div>`;

  html += `<div class="remediation-section">PIPELINE</div><div class="log-line muted">${(data.pipeline || []).map((s, i) => `${i + 1}. ${escapeHtml(s)}`).join(" → ")}</div>`;
  html += `<div class="remediation-section">PRESERVED V1 CONTRACT</div><div class="log-line muted">${(data.preserved_v1_contract || []).map(escapeHtml).join(" · ")}</div>`;
  html += `<div style="margin-top:10px;color:#9CA3AF;font-size:0.74rem;">${escapeHtml(data.policy || "")}</div>`;

  settingsBody.innerHTML = html;
  const recheck = document.getElementById("recheckToolsBtn");
  if (recheck) recheck.addEventListener("click", recheckDastTools);
}

async function recheckDastTools() {
  const btn = document.getElementById("recheckToolsBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "[ CHECKING WSL2... ]";
  }
  appendLog("[SETTINGS] Running live WSL2 tool check...");
  try {
    const res = await fetch("/api/settings/tools", { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Recheck failed");
    appendLog(`[SETTINGS] Live tool check: ${data.ok_count}/${data.total} OK (${data.source}).`);
    await refreshSettingsInline();
  } catch (exc) {
    appendLog(`[SETTINGS] ${exc.message || exc}`, "error");
    if (btn) {
      btn.disabled = false;
      btn.textContent = "[ RECHECK TOOLS LIVE ]";
    }
  }
}

async function refreshSettingsInline() {
  try {
    const res = await fetch("/api/settings");
    const data = await res.json();
    if (res.ok) renderSettings(data);
  } catch (_) {
    /* best effort */
  }
}

/* ---------------------------------------------------------------------------
 * V2 Phase 11 — sleek dropdown navigation.
 * Keeps every existing button ID/listener intact; only groups the triggers.
 * ------------------------------------------------------------------------- */
function closeNavMenus() {
  document.querySelectorAll(".nav-group.open").forEach((group) => group.classList.remove("open"));
}

function setupNavMenus() {
  document.querySelectorAll(".nav-group").forEach((group) => {
    const trigger = group.querySelector(".nav-btn");
    const menu = group.querySelector(".nav-menu");
    if (!trigger || !menu) return;
    trigger.addEventListener("click", (event) => {
      event.stopPropagation();
      const wasOpen = group.classList.contains("open");
      closeNavMenus();
      if (!wasOpen) group.classList.add("open");
    });
    menu.addEventListener("click", (event) => {
      event.stopPropagation();
      if (event.target.closest(".nav-item")) closeNavMenus();
    });
  });

  document.addEventListener("click", closeNavMenus);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeNavMenus();
  });
}

setupNavMenus();

/* ---------------------------------------------------------------------------
 * V2 Phase 12 — full-page module router
 * Every module keeps its existing markup, listeners and data loaders, but now
 * opens as its own page with a real back control and animated transitions.
 * ------------------------------------------------------------------------- */
const PAGE_BUTTON_MAP = {
  overviewBtn: "overviewPanel",
  vulnCenterBtn: "vulnCenterPanel",
  surfaceBtn: "intelPanel",
  graphBtn: "intelPanel",
  aiIntelBtn: "aiIntelPanel",
  apiSecBtn: "apiSecPanel",
  monitorBtn: "monitorPanel",
  remediationBtn: "remediationPanel",
  verifyBtn: "verificationPanel",
  compareBtn: "comparisonPanel",
  reportsBtn: "reportsPanel",
  copilotBtn: "copilotPanel",
  agentModeBtn: "agentPanel",
  toolCenterBtn: "toolCenterPanel",
  deepLabBtn: "deepLabPanel",
  settingsBtn: "settingsPanel",
  historyBtn: "historyPanel",
  devBtn: "devPanel",
};

const PAGE_BUTTON_SLUGS = {
  overviewBtn: "overview",
  vulnCenterBtn: "vulnerabilities",
  surfaceBtn: "surface",
  graphBtn: "graph",
  aiIntelBtn: "ai",
  apiSecBtn: "api",
  monitorBtn: "monitor",
  remediationBtn: "remediation",
  verifyBtn: "verification",
  compareBtn: "comparison",
  reportsBtn: "reports",
  copilotBtn: "copilot",
  agentModeBtn: "agent",
  toolCenterBtn: "tools",
  deepLabBtn: "deep-lab",
  settingsBtn: "settings",
  historyBtn: "history",
  devBtn: "dev",
};

const SLUG_TO_BUTTON = Object.fromEntries(
  Object.entries(PAGE_BUTTON_SLUGS).map(([buttonId, slug]) => [slug, buttonId]),
);

let activePagePanel = null;

function panelPageSlug(panel) {
  if (panel.dataset.pageSlug) return panel.dataset.pageSlug;
  switch (panel.id) {
    case "vulnCenterPanel": return "vulnerabilities";
    case "aiIntelPanel": return "ai";
    case "apiSecPanel": return "api";
    case "intelPanel": return "surface";
    default: return panel.id.replace(/Panel$/, "").toLowerCase();
  }
}

function activatePagePanel(panel) {
  document.querySelectorAll(".history-panel").forEach((other) => {
    if (other !== panel && !other.classList.contains("hidden")) other.classList.add("hidden");
  });
  activePagePanel = panel;
  document.body.classList.add("page-open");
  document.body.classList.remove("dashboard-return");
  closeNavMenus();
  const slug = panelPageSlug(panel);
  try {
    history.replaceState({ aegisPage: slug }, "", `${location.pathname}${location.search}#/${slug}`);
  } catch (exc) { /* file:// or restricted contexts */ }
  panel.scrollTop = 0;
  const scroller = panel.querySelector(".intel-body, .history-list");
  if (scroller) scroller.scrollTop = 0;
  panel.classList.remove("page-enter");
  void panel.offsetWidth;
  panel.classList.add("page-enter");
  setTimeout(() => panel.classList.remove("page-enter"), 760);
}

function deactivatePagePanel() {
  activePagePanel = null;
  document.body.classList.remove("page-open");
  document.body.classList.add("dashboard-return");
  setTimeout(() => document.body.classList.remove("dashboard-return"), 520);
  try {
    history.replaceState({ aegisPage: null }, "", `${location.pathname}${location.search}#/`);
  } catch (exc) { /* restricted contexts */ }
}

function setupPageRouter() {
  document.querySelectorAll(".history-panel").forEach((panel) => {
    const header = panel.querySelector(".history-header");
    if (header && !header.querySelector(".page-home")) {
      const heading = header.querySelector("h2");
      const closeButton = header.querySelector("button");
      const left = document.createElement("div");
      left.className = "page-head-left";
      const home = document.createElement("button");
      home.type = "button";
      home.className = "page-home";
      home.innerHTML = "← COMMAND CENTER";
      home.addEventListener("click", () => {
        if (closeButton) closeButton.click();
        else panel.classList.add("hidden");
      });
      left.appendChild(home);
      if (heading) left.appendChild(heading);
      header.insertBefore(left, header.firstChild);
    }

    const observer = new MutationObserver(() => {
      if (!panel.classList.contains("hidden")) {
        if (activePagePanel !== panel) activatePagePanel(panel);
      } else if (activePagePanel === panel) {
        deactivatePagePanel();
      }
    });
    observer.observe(panel, { attributes: true, attributeFilter: ["class"] });
  });

  Object.entries(PAGE_BUTTON_SLUGS).forEach(([buttonId, slug]) => {
    const button = document.getElementById(buttonId);
    const panelId = PAGE_BUTTON_MAP[buttonId];
    if (!button || !panelId) return;
    button.addEventListener(
      "click",
      () => {
        const panel = document.getElementById(panelId);
        if (panel) panel.dataset.pageSlug = slug;
      },
      true,
    );
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !activePagePanel) return;
    const closeButton = activePagePanel.querySelector(".history-header button:last-of-type");
    if (closeButton) closeButton.click();
  });

  const restore = () => {
    const slug = (location.hash || "").replace(/^#\/?/, "").trim();
    if (!slug) return;
    const buttonId = SLUG_TO_BUTTON[slug];
    const button = buttonId ? document.getElementById(buttonId) : null;
    if (button) button.click();
  };
  setTimeout(restore, 0);
}

/* --- AEGIS wordmark: erase itself, then retype -------------------------- */
function startBrandTypewriter() {
  const target = document.getElementById("brandType");
  const caret = document.querySelector(".brand-caret");
  if (!target) return;
  const full = "AEGIS-AI";
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    target.textContent = full;
    return;
  }

  let text = full;
  let mode = "hold";

  const tick = () => {
    if (mode === "hold") {
      mode = "erase";
      if (caret) caret.classList.remove("typing");
      setTimeout(tick, 2200);
      return;
    }
    if (mode === "erase") {
      text = text.slice(0, -1);
      target.textContent = text;
      if (caret) caret.classList.add("typing");
      if (!text) {
        mode = "type";
        setTimeout(tick, 480);
      } else {
        setTimeout(tick, 72);
      }
      return;
    }
    text = full.slice(0, text.length + 1);
    target.textContent = text;
    if (caret) caret.classList.add("typing");
    if (text.length === full.length) {
      mode = "hold";
      if (caret) caret.classList.remove("typing");
      setTimeout(tick, 3400);
    } else {
      setTimeout(tick, 96);
    }
  };

  setTimeout(tick, 1800);
}

/* --- DEV console: real commands only ------------------------------------ */
let devConsoleReady = false;
const devCommandHistory = [];
let devHistoryIndex = -1;

function devFeedEl() {
  return document.getElementById("devFeed");
}

function devAppendLine(text, cls = "", pre = false) {
  const feed = devFeedEl();
  if (!feed) return;
  const line = document.createElement("div");
  line.className = `dev-line ${cls}`.trim();
  if (pre) {
    const block = document.createElement("pre");
    block.textContent = text;
    line.appendChild(block);
  } else {
    line.textContent = text;
  }
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
}

async function devJson(url) {
  const started = performance.now();
  const response = await fetch(url, { cache: "no-store" });
  const ms = Math.round(performance.now() - started);
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`);
  return { data: await response.json(), ms, status: response.status };
}

function devTile(label, value) {
  return `<div class="dev-tile"><span class="dev-tile-label">${escapeHtml(label)}</span><span class="dev-tile-value">${escapeHtml(String(value))}</span></div>`;
}

async function loadDevDiagnostics() {
  const tiles = document.getElementById("devTiles");
  const stats = document.getElementById("devStats");
  if (!tiles || !stats) return;
  tiles.innerHTML = `<div class="dev-tile"><span class="dev-tile-label">DIAGNOSTICS</span><span class="dev-tile-value">loading real data...</span></div>`;
  stats.innerHTML = "";
  try {
    const [settings, historyResult] = await Promise.all([
      devJson("/api/settings"),
      devJson("/api/history?limit=1"),
    ]);
    const info = settings.data || {};
    const ai = info.ai || {};
    const storage = info.storage || {};
    const tools = info.tools || {};
    const toolValues = Object.values(tools);
    const toolsOk = toolValues.filter((status) => String(status).toUpperCase() === "OK").length;
    const latest = (historyResult.data.scans || [])[0] || null;
    const engineState = (document.getElementById("engineStatus") || {}).textContent || "unknown";

    tiles.innerHTML = [
      devTile("ENGINE", engineState),
      devTile("API LATENCY", `${settings.ms} ms · HTTP ${settings.status}`),
      devTile("SCANS STORED", `${storage.history_records ?? "-"} total / ${storage.completed_scans ?? "-"} completed`),
      devTile("DAST TOOLS", `${toolsOk}/${toolValues.length || "-"} OK`),
      devTile("GUARDRAIL", ai.guardrail_mode ? `${ai.guardrail_mode}${ai.guardrail_ok ? " · OK" : ""}` : "no DAST scan"),
      devTile("REMEDIATION BACKUPS", storage.backup_files ?? "-"),
    ].join("");

    stats.innerHTML = `
      <span>MODEL <strong>${escapeHtml(ai.active_model || ai.gemini_model || "-")}</strong></span>
      <span>SCOPE <strong>${info.scope && info.scope.localhost_only ? "LOCALHOST ONLY" : "-"}</strong></span>
      <span>LATEST <strong>${escapeHtml(latest ? `${latest.id} · ${latest.status}` : "none")}</strong></span>
      <span>GENERATED <strong>${escapeHtml(info.generated_at || "-")}</strong></span>
    `;
  } catch (exc) {
    tiles.innerHTML = `<div class="dev-tile"><span class="dev-tile-label">DIAGNOSTICS</span><span class="dev-tile-value">unavailable</span></div>`;
    devAppendLine(`diagnostics error: ${exc.message || exc}`, "err");
  }
}

async function runDevCommand(raw) {
  const input = raw.trim();
  if (!input) return;
  devCommandHistory.push(input);
  devHistoryIndex = devCommandHistory.length;
  devAppendLine(`aegis@localhost:~$ ${input}`, "dim");
  const [command, ...args] = input.split(/\s+/);
  const cmd = command.toLowerCase();

  try {
    if (cmd === "help") {
      devAppendLine(
        [
          "commands:",
          "  help                  show this list",
          "  status                live engine + page state",
          "  ping                  measure real API latency",
          "  settings              real runtime configuration",
          "  tools                 DAST tool status from latest scan",
          "  scans [n]             recent persisted scans",
          "  latest                latest persisted scan",
          "  reports               real report files",
          "  overview              live overview payload",
          "  scope                 localhost-only scope guards",
          "  open <page>           open a module page",
          "  whoami                browser/runtime facts",
          "  version               engine versions",
          "  clear                 clear this terminal",
        ].join("\n"),
        "",
        true,
      );
      return;
    }
    if (cmd === "clear") {
      const feed = devFeedEl();
      if (feed) feed.innerHTML = "";
      return;
    }
    if (cmd === "status") {
      devAppendLine(
        [
          `engine: ${(document.getElementById("engineStatus") || {}).textContent || "-"}`,
          `scan: ${(document.getElementById("scanIdLabel") || {}).textContent || "-"}`,
          `elapsed: ${(document.getElementById("scanElapsed") || {}).textContent || "-"}`,
          `active page: ${activePagePanel ? panelPageSlug(activePagePanel) : "command center"}`,
          `viewport: ${window.innerWidth}x${window.innerHeight}`,
        ].join("\n"),
        "ok",
        true,
      );
      return;
    }
    if (cmd === "ping" || cmd === "overview") {
      const result = await devJson("/api/overview");
      if (cmd === "ping") {
        devAppendLine(`API OK · HTTP ${result.status} · ${result.ms} ms`, "ok");
      } else {
        devAppendLine(JSON.stringify(result.data, null, 2).slice(0, 4000), "", true);
      }
      return;
    }
    if (cmd === "settings") {
      const result = await devJson("/api/settings");
      const info = result.data || {};
      devAppendLine(
        JSON.stringify({ ai: info.ai, scope: info.scope, storage: info.storage, tools: info.tools }, null, 2),
        "",
        true,
      );
      return;
    }
    if (cmd === "tools") {
      const result = await devJson("/api/settings");
      const tools = (result.data || {}).tools || {};
      const names = Object.keys(tools);
      if (!names.length) {
        devAppendLine("No DAST tool status recorded yet. Run a Full Audit first.", "dim");
        return;
      }
      devAppendLine(names.map((name) => `${name.padEnd(12, " ")} ${tools[name] || "UNKNOWN"}`).join("\n"), "", true);
      return;
    }
    if (cmd === "scans" || cmd === "history") {
      const limit = Math.max(1, Math.min(30, Number(args[0]) || 10));
      const result = await devJson(`/api/history?limit=${limit}`);
      const scans = (result.data || {}).scans || [];
      if (!scans.length) {
        devAppendLine("No scans recorded yet.", "dim");
        return;
      }
      devAppendLine(
        scans
          .map(
            (scan) =>
              `${scan.id}\n  ${scan.mode} · ${scan.status} · score ${scan.score ?? "-"}/100 · ${scan.created_at}\n  ${scan.target}`,
          )
          .join("\n"),
        "",
        true,
      );
      return;
    }
    if (cmd === "latest") {
      const historyResult = await devJson("/api/history?limit=1");
      const latest = ((historyResult.data || {}).scans || [])[0];
      if (!latest) {
        devAppendLine("No scans recorded yet.", "dim");
        return;
      }
      const detail = await devJson(`/api/history/${encodeURIComponent(latest.id)}`);
      const record = detail.data || {};
      const audit = record.audit || {};
      const dast = record.dast || {};
      devAppendLine(
        JSON.stringify(
          {
            id: record.id || latest.id,
            mode: record.mode || latest.mode,
            status: record.status || latest.status,
            score: record.score ?? latest.score,
            target: record.target || latest.target,
            created_at: record.created_at || latest.created_at,
            audit_findings: Array.isArray(audit.findings) ? audit.findings.length : undefined,
            dast_alerts: Array.isArray(dast.alerts) ? dast.alerts.length : undefined,
            stages: Array.isArray(record.stages) ? record.stages.length : undefined,
          },
          null,
          2,
        ),
        "ok",
        true,
      );
      return;
    }
    if (cmd === "reports") {
      const result = await devJson("/api/reports");
      const files = (result.data || {}).reports || [];
      if (!files.length) {
        devAppendLine("No report files found.", "dim");
        return;
      }
      devAppendLine(
        files
          .slice(0, 20)
          .map((file) => {
            const size = file.size_bytes;
            return `${file.filename || file.name || file}${size !== undefined ? ` · ${Math.round(size / 102.4) / 10} KB` : ""}`;
          })
          .join("\n"),
        "",
        true,
      );
      return;
    }
    if (cmd === "scope") {
      const result = await devJson("/api/settings");
      devAppendLine(JSON.stringify((result.data || {}).scope || {}, null, 2), "", true);
      return;
    }
    if (cmd === "whoami") {
      devAppendLine(
        [
          `url: ${location.href}`,
          `agent: ${navigator.userAgent}`,
          `language: ${navigator.language}`,
          `timezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}`,
          `local time: ${new Date().toString()}`,
          `viewport: ${window.innerWidth}x${window.innerHeight}`,
        ].join("\n"),
        "",
        true,
      );
      return;
    }
    if (cmd === "version") {
      const result = await devJson("/api/settings");
      const info = result.data || {};
      devAppendLine(
        [
          "AEGIS-AI // v2.0",
          `settings engine: ${info.engine || "-"}`,
          `gemini model: ${(info.ai || {}).gemini_model || "-"}`,
          `pipeline stages: ${(info.pipeline || []).length}`,
        ].join("\n"),
        "ok",
        true,
      );
      return;
    }
    if (cmd === "open") {
      const slug = (args[0] || "").toLowerCase();
      const buttonId = SLUG_TO_BUTTON[slug];
      const button = buttonId ? document.getElementById(buttonId) : null;
      if (!button) {
        devAppendLine(`unknown page '${slug}'. pages: ${Object.keys(SLUG_TO_BUTTON).join(", ")}`, "err");
        return;
      }
      devAppendLine(`opening ${slug}...`, "ok");
      if (activePagePanel) {
        const closeButton = activePagePanel.querySelector(".history-header button:last-of-type");
        if (closeButton) closeButton.click();
      }
      setTimeout(() => button.click(), 40);
      return;
    }
    devAppendLine(`unknown command '${cmd}'. Type help.`, "err");
  } catch (exc) {
    devAppendLine(`command failed: ${exc.message || exc}`, "err");
  }
}

function setupDevConsole() {
  const devButton = document.getElementById("devBtn");
  const devPanel = document.getElementById("devPanel");
  const closeButton = document.getElementById("closeDevBtn");
  const form = document.getElementById("devForm");
  const input = document.getElementById("devInput");
  if (!devButton || !devPanel) return;

  devButton.addEventListener("click", () => {
    devPanel.classList.remove("hidden");
    if (!devConsoleReady) {
      devConsoleReady = true;
      devAppendLine("AEGIS-AI // developer console", "ok");
      devAppendLine("Real diagnostics only. Type help for commands.", "dim");
    }
    loadDevDiagnostics();
    setTimeout(() => { if (input) input.focus(); }, 260);
  });

  if (closeButton) closeButton.addEventListener("click", () => devPanel.classList.add("hidden"));

  if (form && input) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const raw = input.value;
      input.value = "";
      runDevCommand(raw);
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "ArrowUp") {
        event.preventDefault();
        if (!devCommandHistory.length) return;
        devHistoryIndex = Math.max(0, devHistoryIndex - 1);
        input.value = devCommandHistory[devHistoryIndex] || "";
      } else if (event.key === "ArrowDown") {
        event.preventDefault();
        devHistoryIndex = Math.min(devCommandHistory.length, devHistoryIndex + 1);
        input.value = devCommandHistory[devHistoryIndex] || "";
      }
    });
  }
}

/* ---------------------------------------------------------------------------
 * AEGIS AI V3 — Tool Management Center + Deep Security Lab.
 * Additive pages only. The preserved 9-stage pipeline is never touched here.
 * ------------------------------------------------------------------------- */

const toolCenterPanel = document.getElementById("toolCenterPanel");
const toolCenterStats = document.getElementById("toolCenterStats");
const toolCenterBody = document.getElementById("toolCenterBody");
const deepLabPanel = document.getElementById("deepLabPanel");
const deepLabStats = document.getElementById("deepLabStats");
const deepLabBody = document.getElementById("deepLabBody");
let deepStream = null;
let deepToolsCache = null;
let deepResultsCache = null;

function deepStatusColor(status) {
  return status === "OK" ? "#34D399" : status === "MISSING" ? "#F59E0B" : "#F43F5E";
}

async function openToolCenter() {
  if (!toolCenterPanel) return;
  toolCenterPanel.classList.remove("hidden");
  toolCenterStats.textContent = "Running live WSL2 availability checks...";
  toolCenterBody.innerHTML = `<div class="log-line muted">Reading real tool state from the backend. Nothing is simulated.</div>`;
  await refreshToolCenter();
}

async function refreshToolCenter() {
  try {
    const res = await fetch("/api/tools");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    deepToolsCache = data.tools || {};
    renderToolCenter(data);
  } catch (exc) {
    toolCenterStats.textContent = "UNAVAILABLE";
    toolCenterBody.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function renderToolCenter(data) {
  const tools = data.tools || {};
  toolCenterStats.innerHTML = `
    <span>TOTAL: ${data.total}</span>
    <span>INSTALLED: <strong style="color:#34D399;">${data.installed}</strong></span>
    <span>MISSING: <strong style="color:#F59E0B;">${data.total - data.installed}</strong></span>
    <span>SOURCE: ${escapeHtml(data.source || "live")}</span>
  `;

  let html = `<div class="remediation-section">ALL MODULES — LIVE STATE</div>`;
  for (const name of (data.order || Object.keys(tools))) {
    const t = tools[name];
    if (!t) continue;
    const color = deepStatusColor(t.status);
    const execColor = t.execution_status === "OK" ? "#34D399" : t.execution_status === "FAILED" ? "#F43F5E" : "#9CA3AF";
    html += `<div class="intel-card tool-card" data-tool="${escapeHtml(name)}">
      <div class="tool-card-head">
        <strong>${escapeHtml(t.label || name)}</strong>
        <span class="tool-pill" style="border-color:${color};color:${color};">${escapeHtml(t.status)}</span>
      </div>
      <div class="verify-metric"><span>Category</span><strong>${escapeHtml(t.category || "-")}</strong></div>
      <div class="verify-metric"><span>Version</span><strong>${escapeHtml(t.version || "not available")}</strong></div>
      <div class="verify-metric"><span>Availability</span><strong>${t.kind === "builtin" ? "built-in" : escapeHtml(t.status)}</strong></div>
      <div class="verify-metric"><span>Last execution</span><strong>${escapeHtml(t.last_execution || "never")}</strong></div>
      <div class="verify-metric"><span>Execution status</span><strong style="color:${execColor};">${escapeHtml(t.execution_status || "NOT RUN")}</strong></div>
      <div class="verify-metric"><span>Findings</span><strong>${t.findings_count || 0}</strong></div>
      <div class="verify-metric"><span>Timeout / safety</span><strong>${t.timeout}s · destructive=${t.destructive ? "yes" : "no"}</strong></div>
      <div class="tool-note">${escapeHtml(t.note || "")}</div>
      <div class="tool-note muted">CONFIG: ${escapeHtml(JSON.stringify(t.configuration || {}))}</div>
      <div class="tool-note error">ERROR LOG: ${escapeHtml(t.error_log || t.error || "none")}</div>
      <div class="remediation-actions">
        <button class="btn-engine deep-open-module" data-tool="${escapeHtml(name)}" data-origin="tools">[ OPEN MODULE ]</button>
        <button class="btn-engine deep-tool-check" data-tool="${escapeHtml(name)}">[ CHECK ]</button>
        <button class="btn-engine deep-tool-guide" data-tool="${escapeHtml(name)}">[ INSTALL GUIDE ]</button>
      </div>
      <div class="tool-guide" id="guide-${escapeHtml(name)}"></div>
    </div>`;
  }
  toolCenterBody.innerHTML = html;

  toolCenterBody.querySelectorAll(".deep-tool-check").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const name = btn.dataset.tool;
      btn.disabled = true;
      btn.textContent = "[ CHECKING... ]";
      try {
        const res = await fetch(`/api/tools/${encodeURIComponent(name)}/check`, { method: "POST" });
        const entry = await res.json();
        if (!res.ok) throw new Error(entry.detail || "Check failed");
        const card = toolCenterBody.querySelector(`[data-tool="${CSS.escape(name)}"] .tool-pill`);
        if (card) {
          card.textContent = entry.status;
          card.style.color = deepStatusColor(entry.status);
          card.style.borderColor = deepStatusColor(entry.status);
        }
        appendLog(`[TOOL CENTER] ${name}: ${entry.status}${entry.version ? " (" + entry.version + ")" : ""}`);
      } catch (exc) {
        appendLog(`[TOOL CENTER] ${exc.message || exc}`, "error");
      } finally {
        btn.disabled = false;
        btn.textContent = "[ CHECK ]";
      }
    });
  });

  toolCenterBody.querySelectorAll(".deep-tool-guide").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const name = btn.dataset.tool;
      const target = document.getElementById(`guide-${name}`);
      if (!target) return;
      if (target.textContent) { target.textContent = ""; return; }
      try {
        const res = await fetch(`/api/tools/${encodeURIComponent(name)}/guide`);
        const data = await res.json();
        target.innerHTML = `<div class="tool-note">${escapeHtml(data.guide || "")}</div><div class="tool-note muted">${escapeHtml(data.note || "")}</div>`;
      } catch (exc) {
        target.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
      }
    });
  });
}

async function openDeepLab() {
  if (!deepLabPanel) return;
  deepLabPanel.classList.remove("hidden");
  deepLabStats.textContent = "Loading deep engine state...";
  deepFindingsRenderLoading();
  try {
    const [toolsRes, resultsRes] = await Promise.all([
      fetch("/api/tools"), fetch("/api/deep-results"),
    ]);
    const toolsData = await toolsRes.json();
    const resultsData = await resultsRes.json();
    if (!toolsRes.ok) throw new Error(toolsData.detail || "Tools request failed");
    deepToolsCache = toolsData.tools || {};
    deepResultsCache = resultsData.results || {};
    renderDeepLabPicker();
    renderDeepLabStats(resultsData.correlation);
    if (Object.keys(deepResultsCache).length) renderDeepResults(deepResultsCache);
    if (resultsData.correlation) renderDeepCorrelation(resultsData.correlation);
  } catch (exc) {
    deepLabStats.textContent = "UNAVAILABLE";
    deepFindings.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function deepFindingsRenderLoading() {
  const host = document.getElementById("deepFindings");
  if (host) host.innerHTML = `<div class="log-line muted">No deep scan run yet. Select real tools above and run them.</div>`;
}

function renderDeepLabPicker() {
  const picker = document.getElementById("deepToolPicker");
  if (!picker || !deepToolsCache) return;
  const defaults = new Set(["semgrep", "trivy", "gitleaks", "burp", "httpx", "katana", "api_security"]);
  picker.innerHTML = Object.entries(deepToolsCache).map(([name, t]) => `
    <div class="deep-tool-option-row">
      <label class="deep-tool-option" title="${escapeHtml(t.note || "")}">
        <input type="checkbox" value="${escapeHtml(name)}" ${defaults.has(name) ? "checked" : ""} />
        <span>${escapeHtml(t.label || name)}</span>
        <small style="color:${deepStatusColor(t.status)};">${escapeHtml(t.status)}</small>
      </label>
      <button type="button" class="btn-engine deep-open-module" data-tool="${escapeHtml(name)}" data-origin="deep-lab">[ OPEN ]</button>
    </div>`).join("");
}

function renderDeepLabStats(correlation) {
  const installed = Object.values(deepToolsCache || {}).filter((t) => t.status === "OK").length;
  deepLabStats.innerHTML = `
    <span>MODULES: ${Object.keys(deepToolsCache || {}).length}</span>
    <span>INSTALLED: <strong style="color:#34D399;">${installed}</strong></span>
    <span>RESULTS: ${Object.keys(deepResultsCache || {}).length}</span>
    <span>CORRELATION: ${correlation ? escapeHtml(correlation.mode || "ready") : "not run"}</span>
  `;
}

async function runDeepTools() {
  const btn = document.getElementById("deepRunBtn");
  const target = (document.getElementById("deepTargetInput")?.value || "").trim();
  const path = (document.getElementById("deepPathInput")?.value || "").trim();
  const selected = Array.from(document.querySelectorAll("#deepToolPicker input:checked")).map((el) => el.value);
  if (!selected.length) { appendLog("[DEEP LAB] Select at least one tool.", "error"); return; }
  if (deepStream) deepStream.close();
  const host = document.getElementById("deepFindings");
  host.innerHTML = `<div class="log-line muted">Starting real deep scan — ${selected.length} tool(s)...</div>`;
  if (btn) { btn.disabled = true; btn.textContent = "[ SCANNING... ]"; }
  const params = new URLSearchParams({ tools: selected.join(","), target });
  if (path) params.set("path", path);
  deepStream = new EventSource(`/api/deep-scan-stream?${params.toString()}`);

  deepStream.addEventListener("stage", (e) => {
    const d = JSON.parse(e.data || "{}");
    appendLog(`[DEEP LAB] stage ${d.name || ""} ${d.progress || ""}`);
    if (d.name) deepLabStats.textContent = `RUNNING: ${d.name} ${d.progress || ""}`;
  });
  deepStream.addEventListener("log", (e) => {
    const d = JSON.parse(e.data || "{}");
    if (d.message) appendLog(`[DEEP LAB] ${d.message}`);
  });
  // NOTE: `event: error` is a V1-compatible SSE event name and also collides
  // with EventSource's transport error handler. Only close on a real transport
  // error (no MessageEvent data); a named error event is just a tool failure.
  deepStream.addEventListener("error", (e) => {
    if (!e || e.data === undefined) return;
    let d = {};
    try { d = JSON.parse(e.data || "{}"); } catch (_) { /* ignore */ }
    if (d.message) appendLog(`[DEEP LAB] ${d.message}`, "error");
  });
  deepStream.addEventListener("complete", (e) => {
    const d = JSON.parse(e.data || "{}");
    deepResultsCache = d.results || deepResultsCache;
    renderDeepResults(deepResultsCache);
    if (d.correlation) renderDeepCorrelation(d.correlation);
    renderDeepLabStats(d.correlation);
    appendLog(`[DEEP LAB] complete: ${d.total_findings} real finding(s) across ${d.tools_run} tool(s).`, "ok");
    deepStream.close(); deepStream = null;
    if (btn) { btn.disabled = false; btn.textContent = "[ RUN SELECTED TOOLS ]"; }
  });
  deepStream.onerror = (e) => {
    if (e && e.data !== undefined) return; // named SSE `error` event, stream is alive
    if (deepStream) { deepStream.close(); deepStream = null; }
    if (btn) { btn.disabled = false; btn.textContent = "[ RUN SELECTED TOOLS ]"; }
  };
}

function renderDeepResults(results) {
  const host = document.getElementById("deepFindings");
  if (!host) return;
  let html = `<div class="remediation-section">REAL TOOL RESULTS</div>`;
  for (const [name, r] of Object.entries(results || {})) {
    const color = r.ok ? "#34D399" : "#F59E0B";
    const findings = r.findings || [];
    html += `<div class="intel-card finding-card">
      <div class="tool-card-head"><strong>${escapeHtml(name)}</strong>
        <span class="tool-pill" style="border-color:${color};color:${color};">${r.ok ? "OK" : "FAILED"}</span></div>
      <div class="verify-metric"><span>Available</span><strong>${r.available ? "yes" : "no (honest fallback / install guide)"}</strong></div>
      <div class="verify-metric"><span>Duration</span><strong>${r.duration_ms || 0} ms</strong></div>
      <div class="verify-metric"><span>Findings</span><strong>${findings.length}</strong></div>
      ${r.error ? `<div class="tool-note error">${escapeHtml(r.error)}</div>` : ""}
      ${r.raw_summary ? `<pre class="deep-raw">${escapeHtml(String(r.raw_summary).slice(0, 700))}</pre>` : ""}
      ${findings.slice(0, 30).map((f) => `<div class="deep-finding">
        <div class="deep-finding-head"><span class="sev sev-${escapeHtml(String(f.severity || "").toLowerCase())}">${escapeHtml(f.severity || "-")}</span>
          <strong>${escapeHtml(f.title || "")}</strong></div>
        <div class="tool-note">${escapeHtml([f.file && f.file + ":" + (f.line || "?"), f.endpoint].filter(Boolean).join(" · ") || "endpoint/file: -")}</div>
        ${f.cve ? `<div class="tool-note">CVE: ${escapeHtml(f.cve)}</div>` : ""}
        ${f.evidence ? `<pre class="deep-raw">${escapeHtml(String(f.evidence).slice(0, 500))}</pre>` : ""}
        ${f.remediation ? `<div class="tool-note muted">FIX: ${escapeHtml(f.remediation)}</div>` : ""}
      </div>`).join("")}
    </div>`;
  }
  host.innerHTML = html;
}

function renderDeepCorrelation(data) {
  const host = document.getElementById("deepFindings");
  if (!host) return;
  const s = data.stats || {};
  let html = `<div class="remediation-section">UNIFIED AI CORRELATION — ${escapeHtml(data.mode || "deterministic")}</div>
    <div class="intel-card">
      <div class="verify-metric"><span>Raw findings</span><strong>${s.raw_findings || 0}</strong></div>
      <div class="verify-metric"><span>Unified groups</span><strong>${s.unified_groups || 0}</strong></div>
      <div class="verify-metric"><span>Multi-tool correlations</span><strong style="color:#38BDF8;">${s.multi_tool_correlations || 0}</strong></div>
      <div class="verify-metric"><span>Severity</span><strong>${escapeHtml(JSON.stringify(s.severity_breakdown || {}))}</strong></div>
      ${data.ai_summary ? `<div class="tool-note">${escapeHtml(data.ai_summary)}</div>` : ""}
    </div>`;
  for (const g of (data.groups || []).slice(0, 30)) {
    html += `<div class="intel-card finding-card">
      <div class="tool-card-head"><strong>${escapeHtml(g.title || "")}</strong>
        <span class="tool-pill" style="border-color:#38BDF8;color:#38BDF8;">${escapeHtml(g.confidence || "")}</span></div>
      <div class="verify-metric"><span>Severity</span><strong>${escapeHtml(g.severity || "")}</strong></div>
      <div class="verify-metric"><span>Source tools</span><strong>${(g.source_tools || []).map(escapeHtml).join(", ")}</strong></div>
      ${(g.evidence || []).slice(0, 6).map((ev) => `<pre class="deep-raw">${escapeHtml(String(ev).slice(0, 450))}</pre>`).join("")}
    </div>`;
  }
  host.insertAdjacentHTML("beforeend", html);
}

async function correlateDeepResults() {
  const btn = document.getElementById("deepCorrelateBtn");
  if (btn) { btn.disabled = true; btn.textContent = "[ CORRELATING... ]"; }
  try {
    const res = await fetch("/api/deep-correlate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ use_stored: true }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Correlation failed");
    renderDeepResults(deepResultsCache || {});
    renderDeepCorrelation(data);
    renderDeepLabStats(data);
    appendLog(`[DEEP LAB] correlation ready: ${data.stats.unified_groups} unified group(s).`, "ok");
  } catch (exc) {
    appendLog(`[DEEP LAB] ${exc.message || exc}`, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "[ CORRELATE RESULTS ]"; }
  }
}

async function downloadDeepPdf() {
  const btn = document.getElementById("deepPdfBtn");
  if (btn) { btn.disabled = true; btn.textContent = "[ GENERATING... ]"; }
  try {
    const res = await fetch("/api/download-deep-report");
    if (!res.ok) {
      let detail = "Could not generate the deep report.";
      try { detail = (await res.json()).detail || detail; } catch (_) { /* non-JSON */ }
      throw new Error(detail);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const match = (res.headers.get("content-disposition") || "").match(/filename="?([^";]+)"?/i);
    const link = document.createElement("a");
    link.href = url;
    link.download = match?.[1] || "AegisAI_Deep_Report.pdf";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    appendLog("[DEEP LAB] deep PDF report generated from real findings.", "ok");
  } catch (exc) {
    appendLog(`[DEEP LAB] ${exc.message || exc}`, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "[ DOWNLOAD DEEP PDF ]"; }
  }
}

if (document.getElementById("toolCenterBtn")) {
  document.getElementById("toolCenterBtn").addEventListener("click", openToolCenter);
  document.getElementById("closeToolCenterBtn").addEventListener("click", () => {
    if (deepStream) { deepStream.close(); deepStream = null; }
    toolCenterPanel.classList.add("hidden");
  });
}
if (document.getElementById("deepLabBtn")) {
  document.getElementById("deepLabBtn").addEventListener("click", openDeepLab);
  document.getElementById("closeDeepLabBtn").addEventListener("click", () => {
    if (deepStream) { deepStream.close(); deepStream = null; }
    deepLabPanel.classList.add("hidden");
  });
  document.getElementById("deepRunBtn").addEventListener("click", runDeepTools);
  document.getElementById("deepCorrelateBtn").addEventListener("click", correlateDeepResults);
  document.getElementById("deepPdfBtn").addEventListener("click", downloadDeepPdf);
  document.getElementById("deepTargetInput").addEventListener("change", (e) => {
    if (targetInput) targetInput.value = e.target.value;
  });
}

/* ---------------------------------------------------------------------------
 * AEGIS AI V3 — Agent Mode.
 * Live SSE trace of the model-driven loop. Every rendered number comes from
 * the backend's real tool output; this code never fabricates findings.
 * ------------------------------------------------------------------------- */
const agentPanel = document.getElementById("agentPanel");
const agentModeBtn = document.getElementById("agentModeBtn");
const agentStats = document.getElementById("agentStats");
const agentTimeline = document.getElementById("agentTimeline");
const agentTools = document.getElementById("agentTools");
const agentToolCount = document.getElementById("agentToolCount");
const agentSeverity = document.getElementById("agentSeverity");
const agentModeBadge = document.getElementById("agentModeBadge");
const agentReportWrap = document.getElementById("agentReportWrap");
const agentReport = document.getElementById("agentReport");
const agentReportMeta = document.getElementById("agentReportMeta");
const agentVerified = document.getElementById("agentVerified");
const agentFindings = document.getElementById("agentFindings");
const agentRunBtn = document.getElementById("agentRunBtn");
const agentLoadLastBtn = document.getElementById("agentLoadLastBtn");
const agentStopBtn = document.getElementById("agentStopBtn");
const agentAiToggle = document.getElementById("agentAiToggle");

let agentStream = null;
let agentRunning = false;
let agentTimer = null;
const agentToolCards = new Map();

function agentNow() {
  return new Date().toLocaleTimeString([], { hour12: false });
}

function agentResetUI() {
  if (agentToolCards) agentToolCards.clear();
  if (agentTimeline) agentTimeline.innerHTML = `<div class="agent-empty">Connecting to the agent loop...</div>`;
  if (agentTools) agentTools.innerHTML = "";
  if (agentToolCount) agentToolCount.textContent = "0";
  if (agentSeverity) agentSeverity.innerHTML = "";
  if (agentReportWrap) agentReportWrap.classList.add("hidden");
  if (agentReport) agentReport.innerHTML = "";
  if (agentVerified) agentVerified.textContent = "";
  if (agentFindings) agentFindings.innerHTML = "";
  const counters = document.getElementById("agentCounters");
  if (counters) { counters.classList.add("hidden"); counters.innerHTML = ""; }
  if (agentModeBadge) {
    agentModeBadge.textContent = "PLANNING";
    agentModeBadge.className = "agent-mode-badge running";
  }
}

function agentSetRunning(running) {
  agentRunning = running;
  if (agentRunBtn) {
    agentRunBtn.disabled = running;
    agentRunBtn.textContent = running ? "[ AGENT RUNNING... ]" : "[ RUN AGENT ]";
  }
  if (agentStopBtn) agentStopBtn.classList.toggle("hidden", !running);
  if (!running && agentTimer) {
    clearInterval(agentTimer);
    agentTimer = null;
  }
}

function agentStartTimer() {
  const started = Date.now();
  if (agentTimer) clearInterval(agentTimer);
  agentTimer = setInterval(() => {
    if (!agentRunning) return;
    const el = document.getElementById("agentElapsed");
    if (el) el.textContent = `${((Date.now() - started) / 1000).toFixed(1)}s`;
  }, 200);
}

function agentAddEntry(kind, icon, text, sub) {
  if (!agentTimeline) return null;
  const empty = agentTimeline.querySelector(".agent-empty");
  if (empty) empty.remove();
  const row = document.createElement("div");
  row.className = `agent-entry ${kind}`;
  row.dataset.kind = kind;
  const time = document.createElement("span");
  time.className = "agent-time";
  time.textContent = agentNow();
  const glyph = document.createElement("span");
  glyph.className = "agent-icon";
  glyph.textContent = icon;
  const body = document.createElement("span");
  body.className = "agent-text";
  body.textContent = text;
  if (sub) {
    const detail = document.createElement("span");
    detail.className = "agent-sub";
    detail.textContent = sub;
    body.appendChild(detail);
  }
  row.append(time, glyph, body);
  agentTimeline.appendChild(row);
  agentTimeline.scrollTop = agentTimeline.scrollHeight;
  return row;
}

function agentCardFor(step, name) {
  const key = `${step || 0}:${name}`;
  let card = agentToolCards.get(key);
  if (card) return card;
  card = document.createElement("div");
  card.className = "agent-tool-card running";
  card.dataset.key = key;
  card.innerHTML = `
    <div class="agent-tool-head">
      <strong>${escapeHtml(name)}</strong>
      <span class="agent-tool-status running">RUNNING</span>
    </div>
    <div class="agent-tool-metrics">
      <span>findings <strong class="m-findings">—</strong></span>
      <span>duration <strong class="m-duration">—</strong></span>
      <span>status <strong class="m-available">—</strong></span>
    </div>
    <div class="agent-tool-error" hidden></div>`;
  agentTools.appendChild(card);
  agentToolCards.set(key, card);
  if (agentToolCount) agentToolCount.textContent = String(agentToolCards.size);
  agentTools.scrollTop = agentTools.scrollHeight;
  return card;
}

function agentUpdateCard(step, name, payload) {
  if (!agentTools) return;
  const empty = agentTools.querySelector(".agent-empty");
  if (empty) empty.remove();
  const card = agentCardFor(step, name);
  const done = payload.status === "done" || payload.status === "failed";
  const ok = payload.status === "done" && payload.ok !== false;
  const scopeBlocked = done && !ok && /^SCOPE BLOCKED:/i.test(String(payload.error || ""));
  card.classList.remove("running", "failed");
  if (!done) card.classList.add("running");
  else if (!ok) card.classList.add("failed");
  const pill = card.querySelector(".agent-tool-status");
  pill.textContent = !done ? "RUNNING" : ok ? "DONE" : scopeBlocked ? "BLOCKED" : "FAILED";
  pill.className = `agent-tool-status ${!done ? "running" : ok ? "ok" : "failed"}`;
  if (payload.findings_count !== undefined && payload.findings_count !== null) {
    card.querySelector(".m-findings").textContent = String(payload.findings_count);
  }
  if (payload.duration_ms !== undefined && payload.duration_ms !== null) {
    card.querySelector(".m-duration").textContent = `${payload.duration_ms} ms`;
  }
  if (scopeBlocked) {
    card.querySelector(".m-available").textContent = "outside scope";
  } else if (payload.available !== undefined) {
    card.querySelector(".m-available").textContent = payload.available ? "available" : "unavailable";
  }
  const err = card.querySelector(".agent-tool-error");
  if (payload.error) {
    err.hidden = false;
    err.textContent = String(payload.error).slice(0, 420);
  } else if (done) {
    err.hidden = true;
    err.textContent = "";
  }
}

function agentHandleTool(payload) {
  const name = payload.tool || "tool";
  const step = payload.step || 0;
  if (name !== "list_tools" && name !== "correlate_findings") {
    agentUpdateCard(step, name, payload);
  }
  if (payload.status === "running") {
    const args = payload.arguments && Object.keys(payload.arguments).length
      ? ` ${JSON.stringify(payload.arguments).slice(0, 160)}`
      : "";
    agentAddEntry("tool", "→", `CALL ${name}${args}`);
    return;
  }
  if (payload.status === "failed") {
    const reason = payload.error || "execution failed";
    agentAddEntry("failed", "✕", `OBSERVE ${name} — failed`, String(reason).slice(0, 300));
  } else {
    const bits = [];
    if (payload.findings_count !== undefined) bits.push(`${payload.findings_count} real finding(s)`);
    if (payload.duration_ms !== undefined) bits.push(`${payload.duration_ms} ms`);
    if (payload.observation && typeof payload.observation === "object") {
      bits.push(`unified ${payload.observation.unified_groups || 0} group(s)`);
    }
    agentAddEntry("done", "✓", `OBSERVE ${name} — complete`, bits.join(" · "));
  }
}

function agentSeverityHtml(counts) {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  return order.map((sev) => `
    <div class="agent-sev ${sev.toLowerCase()}">
      <b>${Number((counts || {})[sev] || 0)}</b>
      <span>${sev}</span>
    </div>`).join("");
}

function agentMarkdown(text) {
  const escaped = escapeHtml(text || "");
  const lines = escaped.split(/\r?\n/);
  const inline = (value) => value
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
  let html = "";
  let inList = false;
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (/^\s*[-*]\s+/.test(line)) {
      if (!inList) { html += "<ul>"; inList = true; }
      html += `<li>${inline(line.replace(/^\s*[-*]\s+/, ""))}</li>`;
      continue;
    }
    if (inList) { html += "</ul>"; inList = false; }
    if (/^####\s+/.test(line)) {
      html += `<h5>${inline(line.replace(/^####\s+/, ""))}</h5>`;
    } else if (/^###?\s+/.test(line)) {
      html += `<h4>${inline(line.replace(/^###?\s+/, ""))}</h4>`;
    } else if (/^---+$/.test(line)) {
      html += "<hr>";
    } else if (line.trim()) {
      html += `<p>${inline(line)}</p>`;
    }
  }
  if (inList) html += "</ul>";
  return html || `<p class="muted">No textual summary was returned.</p>`;
}

function agentFindingHtml(finding) {
  const location = [
    finding.file ? `${finding.file}:${finding.line || "?"}` : "",
    finding.endpoint || "",
  ].filter(Boolean).join(" · ") || "location: -";
  return `<div class="deep-finding">
    <div class="deep-finding-head">
      <span class="sev sev-${escapeHtml(String(finding.severity || "").toLowerCase())}">${escapeHtml(finding.severity || "-")}</span>
      <strong>${escapeHtml(finding.title || "")}</strong>
    </div>
    <div class="tool-note">${escapeHtml(location)}${finding.source_tool ? " · " + escapeHtml(finding.source_tool) : ""}${finding.id ? " · " + escapeHtml(finding.id) : ""}</div>
    ${finding.cve ? `<div class="tool-note">CVE: ${escapeHtml(finding.cve)}</div>` : ""}
    ${(finding.cwe || []).length ? `<div class="tool-note">CWE: ${escapeHtml((finding.cwe || []).join(", "))}</div>` : ""}
    ${finding.method || finding.parameter ? `<div class="tool-note">${escapeHtml(finding.method || "REQUEST")} ${finding.parameter ? "· parameter: " + escapeHtml(finding.parameter) : ""}</div>` : ""}
    ${finding.evidence ? `<pre class="deep-raw">${escapeHtml(String(finding.evidence).slice(0, 500))}</pre>` : ""}
    ${finding.remediation ? `<div class="tool-note muted">FIX: ${escapeHtml(finding.remediation)}</div>` : ""}
  </div>`;
}

function agentStatsHtml(result) {
  const mode = result.mode === "ollama-function-calling" ? "OLLAMA FUNCTION CALLING" : result.mode === "gemini-function-calling" ? "GEMINI FUNCTION CALLING" : "DETERMINISTIC FALLBACK";
  return `
    <span>MODE: <strong>${escapeHtml(mode)}</strong></span>
    <span>MODEL: <strong>${escapeHtml(result.model || "none")}</strong></span>
    <span>TOOLS: <strong>${(result.tools_used || []).length}</strong></span>
    <span>FINDINGS: <strong>${result.total_findings || 0}</strong></span>
    <span>DURATION: <strong>${((result.duration_ms || 0) / 1000).toFixed(1)}s</strong></span>
    <span>PROMPT: <strong>${escapeHtml(result.prompt_version || "3.1.0")}</strong></span>
    <span id="agentElapsed">0.0s</span>
    <span>TARGET: <strong>${escapeHtml(result.target || "-")}</strong></span>
  `;
}

function agentRenderCounters(c) {
  const el = document.getElementById("agentCounters");
  if (!el || !c) return;
  el.classList.remove("hidden");
  const progress = Math.max(0, Math.min(100, Number(c.progress || 0)));
  el.innerHTML = `
    <span>ITERATIONS <b>${Number(c.iterations || 0)}</b></span>
    <span>TOOL CALLS <b>${Number(c.tool_calls || 0)}</b></span>
    <span class="ok">SUCCESS <b>${Number(c.tool_success || 0)}</b></span>
    <span class="bad">FAILED <b>${Number(c.tool_failed || 0)}</b></span>
    <span>FINDINGS <b>${Number(c.findings_total || 0)}</b></span>
    <span>EVIDENCE-BACKED <b>${Number(c.findings_verified || 0)}</b></span>
    <div class="agent-progress"><i style="width:${progress}%"></i></div>`;
}

function agentSetModeBadge(result) {
  if (!agentModeBadge) return;
  const gemini = ["gemini-function-calling", "ollama-function-calling"].includes(result.mode);
  agentModeBadge.textContent = result.mode === "ollama-function-calling" ? "OLLAMA FUNCTION CALLING" : gemini ? "GEMINI FUNCTION CALLING" : "DETERMINISTIC FALLBACK";
  agentModeBadge.className = `agent-mode-badge ${gemini ? "gemini" : "fallback"}`;
}

function renderAgentResult(result, rebuildTimeline = false) {
  if (!result) return;
  agentSetModeBadge(result);
  agentStats.innerHTML = agentStatsHtml(result);
  if (result.counters) agentRenderCounters(result.counters);

  if (rebuildTimeline && agentTimeline) {
    agentTimeline.innerHTML = "";
    agentAddEntry("plan", "◎", "Scope validated", `${result.target || "-"} · ${result.path || "-"}`);
    for (const step of result.steps || []) {
      if (step.type === "plan") {
        agentAddEntry("plan", "◇", "MODEL PLAN", String(step.text || "").slice(0, 600));
      } else if (step.type === "tool") {
        const ok = step.ok !== false;
        const bits = [];
        if (step.findings_count !== undefined) bits.push(`${step.findings_count} finding(s)`);
        if (step.duration_ms !== undefined) bits.push(`${step.duration_ms} ms`);
        if (step.error) bits.push(String(step.error).slice(0, 220));
        agentAddEntry(ok ? "done" : "failed", ok ? "✓" : "✕",
          `${ok ? "OBSERVE" : "FAILED"} ${step.tool || "tool"}`, bits.join(" · "));
      }
    }
    if (result.ai_error) agentAddEntry("error", "!", "MODEL UNAVAILABLE — fallback used", result.ai_error);
    agentAddEntry("final", "★", "AGENT COMPLETE", (result.verified_summary || "").slice(0, 400));
  }

  if (rebuildTimeline) {
    agentToolCards.clear();
    if (agentTools) agentTools.innerHTML = "";
  }
  for (const step of result.steps || []) {
    if (step.type !== "tool") continue;
    const name = step.tool || "tool";
    if (name === "list_tools" || name === "correlate_findings") continue;
    agentUpdateCard(step.step, name, {
      status: step.ok === false ? "failed" : "done",
      ok: step.ok,
      available: step.available,
      findings_count: step.findings_count,
      duration_ms: step.duration_ms,
      error: step.error,
    });
  }

  agentSeverity.innerHTML = agentSeverityHtml(result.severity_counts);
  agentReport.innerHTML = agentMarkdown(result.summary);
  if ((result.browser_trace || []).length) {
    agentReport.innerHTML += '<h3>Browser observations</h3>' + result.browser_trace.map((step) => {
      const id = String(step.screenshot_url || '').split('/').pop();
      const image = /^[a-f0-9]{32}$/.test(id) ? `<img src="/api/browser-screenshot/${id}" alt="Browser observation" loading="lazy" style="max-width:100%;border-radius:8px">` : '';
      return `<details><summary>${escapeHtml(step.action || 'inspect')} · ${escapeHtml(step.title || step.url || '')}</summary>${image}<pre>${escapeHtml(String(step.text || '').slice(0, 2000))}</pre></details>`;
    }).join('');
  }
  agentVerified.textContent = result.verified_summary || "";
  agentReportMeta.textContent = `${result.total_findings || 0} real finding(s) · ${(result.tools_used || []).length} tool(s) · ${((result.duration_ms || 0) / 1000).toFixed(1)}s`;
  const findings = result.findings || [];
  agentFindings.innerHTML = findings.length
    ? `<div class="remediation-section">TOP REAL FINDINGS (${Math.min(findings.length, 12)} of ${findings.length})</div>` +
      findings.slice(0, 12).map(agentFindingHtml).join("")
    : `<div class="log-line muted">No findings were reported inside the authorized scope.</div>`;
  agentReportWrap.classList.remove("hidden");
}

async function openAgentMode() {
  if (!agentPanel) return;
  agentPanel.classList.remove("hidden");
  const targetField = document.getElementById("agentTargetInput");
  if (targetField && !targetField.value.trim()) {
    targetField.value = (targetInput?.value || "").trim();
  }
  if (!agentRunning) await loadLastAgent();
}

async function loadLastAgent() {
  try {
    const res = await fetch("/api/agent/last");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Agent state unavailable");
    if (data.last) {
      renderAgentResult(data.last, true);
      if (data.running) {
        agentModeBadge.textContent = "RUNNING IN BACKGROUND";
        agentModeBadge.className = "agent-mode-badge running";
      }
    } else {
      if (agentStats) agentStats.innerHTML = `<span>MODE: <strong>IDLE</strong></span><span>LAST RUN: <strong>none</strong></span><span>SCOPE: <strong>localhost only</strong></span>`;
      if (agentTimeline) agentTimeline.innerHTML = `<div class="agent-empty">No saved agent run yet. Start one above — each call below will be real.</div>`;
      if (agentTools) agentTools.innerHTML = `<div class="agent-empty">No tool has run in this session yet.</div>`;
    }
  } catch (exc) {
    if (agentTimeline) agentTimeline.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function stopAgentStream() {
  if (agentStream) {
    agentStream.close();
    agentStream = null;
  }
  agentSetRunning(false);
  agentAddEntry("error", "■", "Stream stopped by user", "Backend safety guardrails remain active.");
  if (agentModeBadge) {
    agentModeBadge.textContent = "STOPPED";
    agentModeBadge.className = "agent-mode-badge";
  }
}

function runAgentMode() {
  if (!agentPanel) return;
  if (agentStream) agentStream.close();
  agentResetUI();
  agentSetRunning(true);
  agentStartTimer();

  const task = (document.getElementById("agentTaskInput")?.value || "").trim();
  const target = (document.getElementById("agentTargetInput")?.value || "").trim();
  const path = (document.getElementById("agentPathInput")?.value || "").trim();
  const params = new URLSearchParams();
  params.set("task", task || "Audit the authorized local application and report the risks.");
  if (target) params.set("target", target);
  if (path) params.set("path", path);
  params.set("use_ai", agentAiToggle?.checked ? "true" : "false");

  agentStats.innerHTML = `<span>MODE: <strong>STARTING</strong></span><span>TARGET: <strong>${escapeHtml(target || "scope default")}</strong></span><span>PATH: <strong>${escapeHtml(path || "lab default")}</strong></span><span id="agentElapsed">0.0s</span>`;
  appendLog(`[AGENT] task accepted · target=${target || "scope default"} · ai=${agentAiToggle?.checked ? "on" : "off"}`);

  const stream = new EventSource(`/api/agent-stream?${params.toString()}`);
  agentStream = stream;
  let completed = false;

  stream.addEventListener("stage", (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.name) agentAddEntry("plan", "◎", String(data.name), [data.target, data.path].filter(Boolean).join(" · "));
    } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("log", (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.message) agentAddEntry("plan", "◇", String(data.message).slice(0, 700));
    } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("tool", (event) => {
    try { agentHandleTool(JSON.parse(event.data)); } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("decision", (event) => {
    try {
      const d = JSON.parse(event.data);
      agentAddEntry("decision", "◇", `AI DECISION → ${d.tool || "tool"}`,
        `${d.decision_id || ""} · ${d.reason || ""}`.slice(0, 600));
    } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("tool_result", (event) => {
    try {
      const d = JSON.parse(event.data);
      agentAddEntry(d.ok ? "done" : "failed", d.ok ? "✓" : "✕",
        `TOOL RESULT ${d.tool || "tool"}`,
        `${d.tool_call_id || ""} · ${d.findings_count || 0} finding(s) · ${d.duration_ms || 0} ms`.slice(0, 400));
    } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("verified_finding", (event) => {
    try {
      const d = JSON.parse(event.data);
      agentAddEntry("verified", "◆", `VERIFIED FINDING [${d.severity || "-"}] ${d.title || ""}`,
        `${d.finding_id || ""} · ${d.source_tool || ""} · ${d.location || ""} · ${d.verification_status || ""}`.slice(0, 600));
    } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("counters", (event) => {
    try { agentRenderCounters(JSON.parse(event.data)); } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("error", (event) => {
    if (!event.data) return;  // transport errors are handled by stream.onerror
    let message = "Agent stream error";
    try {
      const data = JSON.parse(event.data);
      if (data && data.message) message = data.message;
    } catch (_) { /* keep default */ }
    agentAddEntry("error", "!", String(message).slice(0, 500));
  });

  stream.addEventListener("final", (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.mode) {
        agentSetModeBadge(data);
      }
      appendLog(`[AGENT] final · mode=${data.mode} · tools=${(data.tools_used || []).length} · findings=${data.total_findings}`, "ok");
    } catch (_) { /* ignore malformed frame */ }
  });

  stream.addEventListener("complete", (event) => {
    completed = true;
    try {
      const result = JSON.parse(event.data);
      renderAgentResult(result);
      agentSetRunning(false);
      appendLog(`[AGENT] complete · ${result.total_findings} real finding(s) from ${(result.tools_used || []).length} tool(s)`, "ok");
    } catch (exc) {
      agentAddEntry("error", "!", `Could not parse final result: ${exc.message || exc}`);
      agentSetRunning(false);
    } finally {
      stream.close();
      if (agentStream === stream) agentStream = null;
    }
  });

  stream.onerror = () => {
    if (completed) return;
    if (stream.readyState === EventSource.CLOSED) {
      agentAddEntry("error", "!", "Connection closed before completion. Check the backend log.");
      agentSetRunning(false);
      agentStream = null;
    }
  };
}

if (agentModeBtn) {
  document.getElementById("agentModeBtn").addEventListener("click", openAgentMode);
  document.getElementById("closeAgentBtn").addEventListener("click", () => {
    if (agentStream) { agentStream.close(); agentStream = null; }
    agentSetRunning(false);
    agentPanel.classList.add("hidden");
  });
  agentRunBtn.addEventListener("click", runAgentMode);
  agentLoadLastBtn.addEventListener("click", loadLastAgent);
  agentStopBtn.addEventListener("click", stopAgentStream);
}

/* --- V3 per-module full page --------------------------------------------- */
const toolDetailPanel = document.getElementById("toolDetailPanel");
const toolDetailTitle = document.getElementById("toolDetailTitle");
const toolDetailStats = document.getElementById("toolDetailStats");
const moduleGuide = document.getElementById("moduleGuide");
const moduleStatus = document.getElementById("moduleStatus");
const moduleFindings = document.getElementById("moduleFindings");
const moduleRunBtn = document.getElementById("moduleRunBtn");
const moduleCheckBtn = document.getElementById("moduleCheckBtn");
const moduleGuideBtn = document.getElementById("moduleGuideBtn");
const moduleBackBtn = document.getElementById("moduleBackBtn");

let currentModuleName = null;
let currentModuleOrigin = "tools";

function moduleFindingHtml(f) {
  const loc = [f.file && `${f.file}:${f.line || "?"}`, f.endpoint].filter(Boolean).join(" · ") || "endpoint/file: -";
  return `<div class="deep-finding">
    <div class="deep-finding-head"><span class="sev sev-${escapeHtml(String(f.severity || "").toLowerCase())}">${escapeHtml(f.severity || "-")}</span>
      <strong>${escapeHtml(f.title || "")}</strong></div>
    <div class="tool-note">${escapeHtml(loc)}</div>
    ${f.cve ? `<div class="tool-note">CVE: ${escapeHtml(f.cve)}</div>` : ""}
    ${f.evidence ? `<pre class="deep-raw">${escapeHtml(String(f.evidence).slice(0, 500))}</pre>` : ""}
    ${f.remediation ? `<div class="tool-note muted">FIX: ${escapeHtml(f.remediation)}</div>` : ""}
  </div>`;
}

async function openToolDetail(name, origin) {
  if (!toolDetailPanel || !name) return;
  currentModuleName = name;
  currentModuleOrigin = origin === "deep-lab" ? "deep-lab" : "tools";
  toolDetailPanel.dataset.pageSlug = `module/${name}`;
  const t = (deepToolsCache || {})[name] || {};
  toolDetailTitle.textContent = (t.label || name).toUpperCase();
  const mt = document.getElementById("moduleTargetInput");
  const mp = document.getElementById("modulePathInput");
  if (mt) mt.value = (document.getElementById("deepTargetInput")?.value || targetInput?.value || "").trim();
  if (mp) mp.value = (document.getElementById("deepPathInput")?.value || "").trim();
  const mi = document.getElementById("moduleImageInput");
  if (mi) mi.value = "";
  if (moduleGuide) moduleGuide.innerHTML = "";
  if (moduleStatus) moduleStatus.innerHTML = `<div class="log-line muted">Reading live module state from the backend...</div>`;
  if (moduleFindings) moduleFindings.innerHTML = "";
  toolDetailPanel.classList.remove("hidden");
  await refreshModuleDetail();
}

async function refreshModuleDetail() {
  if (!currentModuleName) return;
  try {
    const [toolsRes, resultsRes] = await Promise.all([fetch("/api/tools"), fetch("/api/deep-results")]);
    const toolsData = await toolsRes.json();
    const resultsData = await resultsRes.json();
    if (!toolsRes.ok) throw new Error(toolsData.detail || "Tools request failed");
    if (!resultsRes.ok) throw new Error(resultsData.detail || "Results request failed");
    deepToolsCache = toolsData.tools || {};
    deepResultsCache = resultsData.results || {};
    const t = deepToolsCache[currentModuleName] || {};
    toolDetailTitle.textContent = (t.label || currentModuleName).toUpperCase();
    const color = deepStatusColor(t.status);
    toolDetailStats.innerHTML = `
      <span>MODULE: ${escapeHtml(currentModuleName)}</span>
      <span>STATUS: <strong style="color:${color};">${escapeHtml(t.status || "UNKNOWN")}</strong></span>
      <span>VERSION: ${escapeHtml(t.version || "not available")}</span>
      <span>CATEGORY: ${escapeHtml(t.category || "-")}</span>
    `;
    const execColor = t.execution_status === "OK" ? "#34D399" : t.execution_status === "FAILED" ? "#F43F5E" : "#9CA3AF";
    moduleStatus.innerHTML = `<div class="intel-card">
      <div class="remediation-section">REAL MODULE CONFIGURATION</div>
      <div class="verify-metric"><span>Module name</span><strong>${escapeHtml(currentModuleName)}</strong></div>
      <div class="verify-metric"><span>Kind</span><strong>${t.kind === "builtin" ? "built-in" : "external tool"}</strong></div>
      <div class="verify-metric"><span>Availability</span><strong style="color:${color};">${escapeHtml(t.status || "UNKNOWN")}</strong></div>
      <div class="verify-metric"><span>Version</span><strong>${escapeHtml(t.version || "not available")}</strong></div>
      <div class="verify-metric"><span>Execution status</span><strong style="color:${execColor};">${escapeHtml(t.execution_status || "NOT RUN")}</strong></div>
      <div class="verify-metric"><span>Last execution</span><strong>${escapeHtml(t.last_execution || "never")}</strong></div>
      <div class="verify-metric"><span>Findings count</span><strong>${t.findings_count || 0}</strong></div>
      <div class="tool-note">${escapeHtml(t.note || "")}</div>
      <div class="tool-note muted">CONFIG: ${escapeHtml(JSON.stringify(t.configuration || {}))}</div>
      <div class="tool-note error">ERROR LOG: ${escapeHtml(t.error_log || t.error || "none")}</div>
    </div>`;
    renderModuleResult(deepResultsCache[currentModuleName]);
  } catch (exc) {
    moduleStatus.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
    toolDetailStats.textContent = "UNAVAILABLE";
  }
}

function renderModuleResult(r) {
  if (!moduleFindings) return;
  if (!r) {
    moduleFindings.innerHTML = `<div class="remediation-section">LAST RESULT</div><div class="log-line muted">No execution recorded for this module yet. Use [ RUN THIS MODULE ] above.</div>`;
    return;
  }
  const findings = r.findings || [];
  const okColor = r.ok ? "#34D399" : "#F59E0B";
  let html = `<div class="remediation-section">LAST REAL RESULT — ${escapeHtml(r.tool || currentModuleName || "")}</div>
    <div class="intel-card">
      <div class="verify-metric"><span>Execution</span><strong style="color:${okColor};">${r.ok ? "OK" : "FAILED"}</strong></div>
      <div class="verify-metric"><span>Tool available</span><strong>${r.available ? "yes" : "no — install guide / honest fallback"}</strong></div>
      <div class="verify-metric"><span>Duration</span><strong>${r.duration_ms || 0} ms</strong></div>
      <div class="verify-metric"><span>Real findings</span><strong>${findings.length}</strong></div>
      ${r.error ? `<div class="tool-note error">${escapeHtml(r.error)}</div>` : ""}
      ${r.raw_summary ? `<pre class="deep-raw">${escapeHtml(String(r.raw_summary).slice(0, 700))}</pre>` : ""}
      ${r.command ? `<div class="tool-note muted">COMMAND: ${escapeHtml(String(r.command).slice(0, 300))}</div>` : ""}
    </div>`;
  for (const f of findings.slice(0, 80)) html += moduleFindingHtml(f);
  moduleFindings.innerHTML = html;
}

async function runCurrentModule() {
  if (!currentModuleName || !moduleRunBtn) return;
  const name = currentModuleName;
  moduleRunBtn.disabled = true;
  moduleRunBtn.textContent = "[ RUNNING... ]";
  moduleFindings.innerHTML = `<div class="log-line muted">Executing real ${escapeHtml(name)} scan — authorized local scope only...</div>`;
  try {
    const payload = { name };
    const target = (document.getElementById("moduleTargetInput")?.value || "").trim();
    const path = (document.getElementById("modulePathInput")?.value || "").trim();
    const image = (document.getElementById("moduleImageInput")?.value || "").trim();
    if (target) payload.target = target;
    if (path) payload.path = path;
    if (image) payload.image = image;
    const res = await fetch("/api/tools/run", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Module execution failed");
    deepResultsCache = deepResultsCache || {};
    deepResultsCache[name] = data;
    renderModuleResult(data);
    appendLog(`[MODULE:${name}] ${data.ok ? "OK" : "FAILED"} — ${(data.findings || []).length} real finding(s)`, data.ok ? "ok" : "error");
    await refreshModuleDetail();
  } catch (exc) {
    moduleFindings.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
    appendLog(`[MODULE:${name}] ${exc.message || exc}`, "error");
  } finally {
    moduleRunBtn.disabled = false;
    moduleRunBtn.textContent = "[ RUN THIS MODULE ]";
  }
}

async function recheckCurrentModule() {
  if (!currentModuleName || !moduleCheckBtn) return;
  const name = currentModuleName;
  moduleCheckBtn.disabled = true;
  moduleCheckBtn.textContent = "[ CHECKING... ]";
  try {
    const res = await fetch(`/api/tools/${encodeURIComponent(name)}/check`, { method: "POST" });
    const entry = await res.json();
    if (!res.ok) throw new Error(entry.detail || "Check failed");
    appendLog(`[MODULE:${name}] check: ${entry.status}${entry.version ? " (" + entry.version + ")" : ""}`, entry.status === "OK" ? "ok" : "error");
    await refreshModuleDetail();
  } catch (exc) {
    appendLog(`[MODULE:${name}] ${exc.message || exc}`, "error");
  } finally {
    moduleCheckBtn.disabled = false;
    moduleCheckBtn.textContent = "[ RECHECK STATUS ]";
  }
}

async function toggleCurrentModuleGuide() {
  if (!currentModuleName || !moduleGuide) return;
  if (moduleGuide.textContent) { moduleGuide.innerHTML = ""; return; }
  try {
    const res = await fetch(`/api/tools/${encodeURIComponent(currentModuleName)}/guide`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Guide unavailable");
    moduleGuide.innerHTML = `<div class="tool-note">${escapeHtml(data.guide || "")}</div><div class="tool-note muted">${escapeHtml(data.note || "")}</div>`;
  } catch (exc) {
    moduleGuide.innerHTML = `<div class="log-line error">${escapeHtml(exc.message || exc)}</div>`;
  }
}

function backFromModule() {
  if (toolDetailPanel) toolDetailPanel.classList.add("hidden");
  const originBtn = document.getElementById(currentModuleOrigin === "deep-lab" ? "deepLabBtn" : "toolCenterBtn");
  if (originBtn) originBtn.click();
}

// Cards and picker rows are re-rendered often; one delegated listener avoids duplicates.
document.addEventListener("click", (event) => {
  const btn = event.target.closest?.(".deep-open-module");
  if (!btn) return;
  event.preventDefault();
  event.stopPropagation();
  openToolDetail(btn.dataset.tool, btn.dataset.origin);
});

if (toolDetailPanel) {
  document.getElementById("closeToolDetailBtn").addEventListener("click", () => toolDetailPanel.classList.add("hidden"));
  moduleRunBtn.addEventListener("click", runCurrentModule);
  moduleCheckBtn.addEventListener("click", recheckCurrentModule);
  moduleGuideBtn.addEventListener("click", toggleCurrentModuleGuide);
  moduleBackBtn.addEventListener("click", backFromModule);
}

setupPageRouter();
startBrandTypewriter();
setupDevConsole();
