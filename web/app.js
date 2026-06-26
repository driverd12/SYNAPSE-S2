const DEFAULT_CONTEXT = "default";
const THEME_STORAGE_KEY = "synapse-s2-control-theme-v2";
const SNAPSHOT_LIMIT = 80;

const state = {
  context: new URLSearchParams(window.location.search).get("context_id")?.trim() || DEFAULT_CONTEXT,
  snapshot: null,
  lastQueryPayload: null,
};

const elements = collectElements([
  "apiState",
  "arrayCount",
  "arrayList",
  "backupButton",
  "chipLabel",
  "clearRecallButton",
  "contextApply",
  "contextInput",
  "contextUri",
  "coreVersion",
  "currentEnvelope",
  "engineState",
  "endpointLabel",
  "envelopeFill",
  "envelopeMarker",
  "envelopeState",
  "footerContexts",
  "footerGpu",
  "footerHealth",
  "footerMemory",
  "footerTime",
  "graphActiveCount",
  "graphEdgeCount",
  "graphLastPrune",
  "graphNodeCount",
  "graphSummary",
  "graphSvg",
  "headroomMb",
  "headroomState",
  "headerRuntime",
  "ingestForm",
  "ingestMinSentences",
  "ingestTag",
  "ingestText",
  "ingestThreshold",
  "lastTick",
  "latencyLabel",
  "memoryDbLabel",
  "memoryLedger",
  "memoryState",
  "modeLabel",
  "modelUri",
  "operationLog",
  "platformLabel",
  "profileButton",
  "pruneBudget",
  "pruneState",
  "queryForm",
  "queryInput",
  "queryResults",
  "quickPruneButton",
  "recallLimit",
  "refreshActionButton",
  "refreshButton",
  "rememberForm",
  "rememberTag",
  "rememberText",
  "resourceCurrent",
  "resourceMb",
  "resultCount",
  "routerState",
  "runtimeDetail",
  "sidebarStatus",
  "sleepButton",
  "themeButton",
  "toggleActionButton",
  "toggleActionState",
  "toggleButton",
  "toggleText",
  "traceCache",
  "uptimeLabel",
]);

elements.contextInput.value = state.context;
elements.endpointLabel.textContent = window.location.host || "127.0.0.1:8765";
applyTheme(loadTheme());

function collectElements(ids) {
  return Object.fromEntries(ids.map((id) => [id, requiredElement(id)]));
}

function requiredElement(id) {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing dashboard element: ${id}`);
  }
  return element;
}

function apiUrl(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  }
  return url;
}

async function requestJson(path, { method = "GET", params = {}, body = null } = {}) {
  const response = await fetch(apiUrl(path, params), {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

function loadTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return stored === "dark" || stored === "light" ? stored : "light";
  } catch {
    return "light";
  }
}

function storeTheme(theme) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Theme persistence is best-effort.
  }
}

function applyTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  const dark = normalized === "dark";
  document.documentElement.dataset.theme = normalized;
  elements.themeButton.setAttribute("aria-pressed", String(dark));
  elements.themeButton.setAttribute("aria-label", dark ? "Use light mode" : "Use dark mode");
  elements.themeButton.setAttribute("title", dark ? "Use light mode" : "Use dark mode");
}

async function refreshSnapshot() {
  elements.headerRuntime.textContent = "REFRESHING";
  const snapshot = await requestJson("/api/snapshot", {
    params: { context_id: state.context, limit: SNAPSHOT_LIMIT },
  });
  state.snapshot = snapshot;
  renderSnapshot(snapshot);
  return snapshot;
}

function renderSnapshot(snapshot) {
  const status = snapshot.status || {};
  const profile = snapshot.profile || {};
  const graph = snapshot.graph || {};
  const system = snapshot.system || {};
  const enabled = Boolean(status.effective_enabled);
  const runtimeReady = enabled && String(status.runtime || "").toLowerCase() === "ready";
  const modelUri = system.model_uri || `s2://local/${snapshot.context_id || state.context}`;
  const entryTotal = Number(status.memory_context_entry_count ?? graph.entry_count ?? 0);
  const relationshipTotal = Number(status.memory_context_relationship_count ?? graph.relationship_count ?? 0);
  const contexts = status.memory_contexts || {};
  const contextCount = Object.keys(contexts).length;

  elements.contextUri.textContent = modelUri;
  elements.modelUri.textContent = modelUri;
  elements.headerRuntime.textContent = runtimeReady ? "READY" : String(status.runtime || "PENDING").toUpperCase();
  elements.modeLabel.textContent = system.mode || "LOCAL ONLY";
  elements.platformLabel.textContent = platformLabel(system);
  elements.chipLabel.textContent = system.chip || system.machine || "unknown";
  elements.uptimeLabel.textContent = formatDuration(system.uptime_seconds);
  elements.coreVersion.textContent = system.project_version ? `v${system.project_version}` : "local";
  elements.sidebarStatus.textContent = runtimeReady ? "OPERATIONAL" : "DISABLED";
  elements.memoryDbLabel.textContent = compactPath(status.memory_db_path || graph.memory_db_path || "pending");

  elements.engineState.textContent = status.mlx_available ? "ACTIVE" : "UNAVAILABLE";
  elements.engineState.className = status.mlx_available ? "good" : "warn";
  elements.routerState.textContent = enabled ? "ACTIVE" : "PAUSED";
  elements.routerState.className = enabled ? "good" : "warn";
  elements.memoryState.textContent = "ACTIVE";
  elements.memoryState.className = "good";
  elements.apiState.textContent = "LISTENING";
  elements.apiState.className = "good";
  elements.runtimeDetail.textContent = `MLX ${status.mlx_available ? "ready" : "missing"} / mlxsnn ${status.mlxsnn_available ? "ready" : "missing"} / ${profile.mlxsnn_lif_execution_path ? "native LIF" : "fallback LIF"}`;
  elements.lastTick.textContent = `Last tick: ${formatGeneratedAt(snapshot.generated_at)}`;

  elements.toggleText.textContent = enabled ? "Enabled" : "Disabled";
  elements.toggleActionState.textContent = enabled ? "Enabled" : "Disabled";
  elements.toggleButton.classList.toggle("off", !enabled);
  elements.toggleButton.setAttribute("aria-pressed", String(enabled));

  elements.graphSummary.textContent = `${formatNumber(relationshipTotal)} edges`;
  elements.graphNodeCount.textContent = formatNumber(entryTotal);
  elements.graphEdgeCount.textContent = formatNumber(relationshipTotal);
  elements.graphActiveCount.textContent = formatNumber(countEventEntries(graph.entries || []));
  elements.graphLastPrune.textContent = formatAge(status.last_pruning_age_seconds);

  renderEnvelope(profile, status);
  renderArrays(profile.arrays || {});
  renderMaintenance(status, profile);
  renderGraph(graph, status);
  renderMemoryLedger(graph);
  renderFooter(snapshot, status, profile, contextCount);
}

function renderEnvelope(profile, status) {
  const min = Number(profile.target_envelope_mb?.min ?? 61);
  const max = Number(profile.target_envelope_mb?.max ?? 138);
  const current = Number(profile.estimated_total_mb ?? 0);
  const headroom = Math.max(0, max - current);
  const pct = max > min ? clamp(((current - min) / (max - min)) * 100, 0, 100) : 0;
  const trackPct = pct * 0.72;
  const currentText = `${formatNumber(current, 1)} MB`;

  elements.resourceMb.textContent = currentText;
  elements.resourceCurrent.textContent = currentText;
  elements.currentEnvelope.textContent = currentText;
  elements.envelopeFill.style.width = `${trackPct}%`;
  elements.envelopeMarker.style.left = `calc(14% + ${trackPct}%)`;
  elements.currentEnvelope.style.left = `calc(14% + ${trackPct}% - 28px)`;
  elements.envelopeState.textContent = profile.within_target_envelope ? "inside 61-138 MB" : "outside target";
  elements.headroomMb.textContent = `${formatNumber(headroom, 1)} MB`;
  elements.headroomState.textContent = `${formatNumber(max, 0)} MB ceiling`;
  elements.traceCache.textContent = formatNumber(status.registered_trace_cache_count);
  elements.arrayCount.textContent = formatNumber(Object.keys(profile.arrays || {}).length);
}

function renderArrays(arrays) {
  const rows = Object.entries(arrays)
    .sort((left, right) => Number(right[1].estimated_bytes) - Number(left[1].estimated_bytes))
    .map(([name, profile]) => {
      const shape = Array.isArray(profile.shape) ? profile.shape.join(" x ") : "--";
      return `
        <div>
          <dt>${escapeHtml(name)}</dt>
          <dd>${escapeHtml(shape)}</dd>
          <dd>${formatNumber(profile.estimated_mb, 3)} MB</dd>
        </div>
      `;
    })
    .join("");
  elements.arrayList.innerHTML = rows || "<div><dt>No arrays</dt><dd>--</dd><dd>--</dd></div>";
}

function renderMaintenance(status, profile) {
  const quick = profile.quick_pruning || (status.last_maintenance?.mode === "quick-pruning" ? status.last_maintenance : null);
  if (quick) {
    elements.pruneBudget.textContent = `${formatNumber(quick.elapsed_ms, 1)} ms`;
    elements.pruneState.textContent = quick.within_60ms_budget ? "within 60 ms target" : "outside 60 ms target";
    elements.pruneState.className = quick.within_60ms_budget ? "good" : "warn";
  } else {
    elements.pruneBudget.textContent = "standby";
    elements.pruneState.textContent = "benchmark available";
    elements.pruneState.className = "";
  }
}

function renderGraph(graph, status) {
  const entries = graph.entries || [];
  const relationships = graph.relationships || [];
  const svg = elements.graphSvg;
  svg.replaceChildren();

  if (!entries.length) {
    appendSvg(svg, "text", {
      x: 380,
      y: 208,
      "text-anchor": "middle",
      class: "graph-empty",
    }, "No memory entries");
    return;
  }

  const width = 760;
  const height = 420;
  const visible = entries.slice(0, 14);
  const positions = layoutGraph(visible, width, height);

  for (const relationship of relationships) {
    const source = positions.get(relationship.source_memory_id);
    const target = positions.get(relationship.target_memory_id);
    if (!source || !target) continue;
    const weight = Number(relationship.weight ?? 0.5);
    appendSvg(svg, "line", {
      x1: source.x,
      y1: source.y,
      x2: target.x,
      y2: target.y,
      class: edgeClass(relationship, weight),
      "stroke-width": String(clamp(1 + weight * 2.4, 1.2, 3.4)),
    });
  }

  const contextLabel = status.context_id || graph.context_id || state.context;
  appendSvg(svg, "circle", {
    cx: width / 2,
    cy: height / 2,
    r: 28,
    class: "graph-node context-node",
  });
  appendSvg(svg, "text", {
    x: width / 2,
    y: height / 2 + 4,
    "text-anchor": "middle",
    class: "graph-label context-label",
  }, compactTag(contextLabel, 18));

  for (const node of positions.values()) {
    appendSvg(svg, "circle", {
      cx: node.x,
      cy: node.y,
      r: node.entry.metadata?.event_segment ? 20 : 18,
      class: nodeClass(node.entry),
    });
    appendSvg(svg, "text", {
      x: node.x,
      y: node.y + 34,
      "text-anchor": "middle",
      class: "graph-label",
    }, compactTag(node.entry.tag, 22));
    const score = node.entry.spike_count ? `${formatNumber(node.entry.spike_count)} spikes` : "";
    if (score) {
      appendSvg(svg, "text", {
        x: node.x,
        y: node.y + 49,
        "text-anchor": "middle",
        class: "graph-sub-label",
      }, score);
    }
  }
}

function layoutGraph(entries, width, height) {
  const center = { x: width / 2, y: height / 2 };
  const radiusX = entries.length <= 6 ? 185 : 250;
  const radiusY = entries.length <= 6 ? 118 : 154;
  const positions = new Map();
  entries.forEach((entry, index) => {
    const angle = (-Math.PI / 2) + (index / entries.length) * Math.PI * 2;
    positions.set(entry.memory_id, {
      x: center.x + Math.cos(angle) * radiusX,
      y: center.y + Math.sin(angle) * radiusY,
      entry,
    });
  });
  return positions;
}

function edgeClass(relationship, weight) {
  const relation = String(relationship.relation_type || "");
  if (relation.includes("temporal")) return "graph-edge temporal";
  return weight >= 0.5 ? "graph-edge strong" : "graph-edge weak";
}

function nodeClass(entry) {
  if (entry.metadata?.event_segment) return "graph-node event-node";
  if (entry.metadata?.source_tag || entry.metadata?.source) return "graph-node concept-node";
  return "graph-node";
}

function renderMemoryLedger(graph) {
  const entries = (graph.entries || []).slice(0, 10);
  elements.memoryLedger.innerHTML = entries.length
    ? entries.map((entry) => {
      const source = entry.metadata?.source_tag || entry.metadata?.source || entry.context_id || "--";
      const sourceText = String(entry.source_text || "").trim();
      return `
        <div class="memory-ledger-row">
          <div>
            <strong>${escapeHtml(entry.tag)}</strong>
            <small>${escapeHtml(source)} / ${escapeHtml(compactMemoryId(entry.memory_id))}</small>
            ${sourceText ? `<p>${escapeHtml(compactTag(sourceText, 120))}</p>` : ""}
          </div>
          <span>${formatNumber(entry.spike_count)} spikes</span>
          <time>${escapeHtml(formatTimestamp(entry.updated_at || entry.created_at))}</time>
        </div>
      `;
    }).join("")
    : '<div class="memory-ledger-empty">No persisted traces</div>';
}

function renderFooter(snapshot, status, profile, contextCount) {
  const current = Number(profile.estimated_total_mb ?? 0);
  const max = Number(profile.target_envelope_mb?.max ?? 138);
  const healthy = Boolean(status.effective_enabled) && Boolean(profile.within_target_envelope);
  elements.footerHealth.textContent = healthy ? "GOOD" : "CHECK";
  elements.footerMemory.textContent = `${formatNumber(current, 1)} MB / ${formatNumber(max, 0)} MB`;
  elements.footerGpu.textContent = `MLX ${status.mlx_device || "default"}`;
  elements.footerContexts.textContent = formatNumber(contextCount);
  elements.footerTime.textContent = formatClock(snapshot.generated_at);
}

function renderQueryResult(payload) {
  const items = Array.isArray(payload.results) && payload.results.length
    ? payload.results
    : parseResultString(payload.result);
  const limit = Math.max(1, Math.trunc(Number(elements.recallLimit.value || 8)));
  const visible = items.slice(0, limit);

  elements.resultCount.textContent = `(${formatNumber(items.length)})`;
  elements.latencyLabel.textContent = `Latency: ${formatNumber(payload.latency_ms, 1)} ms`;
  elements.queryResults.innerHTML = visible.length
    ? visible.map((item) => resultCard(item)).join("")
    : '<div class="empty-result">No high-salience results returned.</div>';
}

function resultCard(item) {
  const score = Number.isFinite(Number(item.score))
    ? `score ${formatNumber(item.score, 3)}`
    : Number.isFinite(Number(item.weight))
      ? `weight ${formatNumber(item.weight, 3)}`
      : item.kind || "status";
  const relation = item.relation_type ? ` / ${item.relation_type}` : "";
  const context = item.context_id ? ` / ${item.context_id}` : "";
  return `
    <article class="result-card">
      <span>${formatNumber(item.rank || 0)}</span>
      <div>
        <strong>${escapeHtml(item.tag || item.label || item.raw || "--")}</strong>
        <small>${escapeHtml(`${score}${relation}${context}`)}</small>
      </div>
    </article>
  `;
}

function parseResultString(result) {
  return String(result || "")
    .split(" / ")
    .map((raw, index) => raw.trim() ? {
      rank: index + 1,
      kind: "status",
      tag: raw.trim(),
      raw: raw.trim(),
    } : null)
    .filter(Boolean);
}

function appendSvg(parent, tag, attrs, text = "") {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  if (text) node.textContent = text;
  parent.appendChild(node);
  return node;
}

function platformLabel(system) {
  const machine = String(system.machine || "");
  if (machine === "arm64" && String(system.platform || "").toLowerCase() === "darwin") {
    return "Apple Silicon";
  }
  return [system.platform, machine].filter(Boolean).join(" ") || "local";
}

function countEventEntries(entries) {
  return entries.filter((entry) => Boolean(entry.metadata?.event_segment)).length;
}

function formatNumber(value, digits = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "--";
  return numeric.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  });
}

function formatDuration(seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric) || numeric < 0) return "--:--:--";
  const total = Math.floor(numeric);
  const hrs = Math.floor(total / 3600);
  const mins = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  return [hrs, mins, secs].map((part) => String(part).padStart(2, "0")).join(":");
}

function formatAge(seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric)) return "--";
  if (numeric < 60) return `${formatNumber(numeric, 0)}s ago`;
  if (numeric < 3600) return `${formatNumber(numeric / 60, 0)}m ago`;
  return `${formatNumber(numeric / 3600, 1)}h ago`;
}

function formatTimestamp(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "--";
  return new Date(numeric * 1000).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatGeneratedAt(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "--";
  return new Date(numeric * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatClock(value) {
  const numeric = Number(value);
  const date = Number.isFinite(numeric) && numeric > 0 ? new Date(numeric * 1000) : new Date();
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function compactPath(path) {
  const text = String(path || "");
  if (text.length <= 28) return text;
  const parts = text.split("/");
  return parts.slice(-2).join("/") || text.slice(-28);
}

function compactTag(value, maxLength = 24) {
  const text = String(value || "");
  if (text.length <= maxLength) return text;
  const head = Math.max(6, Math.floor((maxLength - 3) * 0.55));
  const tail = Math.max(4, maxLength - head - 3);
  return `${text.slice(0, head)}...${text.slice(-tail)}`;
}

function compactMemoryId(memoryId) {
  const text = String(memoryId || "");
  return text.length > 12 ? `...${text.slice(-8)}` : text;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function logOperation(label, payload) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  elements.operationLog.textContent = `${label}\n${text}`;
}

async function withBusy(button, label, task, options = { refresh: true }) {
  const originalDisabled = button.disabled;
  button.disabled = true;
  try {
    const payload = await task();
    logOperation(label, payload);
    if (options.refresh) {
      await refreshSnapshot();
    }
    return payload;
  } catch (error) {
    logOperation(`${label} failed`, error.message);
    throw error;
  } finally {
    button.disabled = originalDisabled;
  }
}

async function toggleCore(button) {
  const enabled = !elements.toggleButton.classList.contains("off");
  await withBusy(button, "Toggle", () => (
    requestJson("/api/toggle", {
      method: "POST",
      body: { context_id: state.context, enabled: !enabled },
    })
  ));
}

elements.contextApply.addEventListener("click", async () => {
  state.context = elements.contextInput.value.trim() || DEFAULT_CONTEXT;
  elements.contextInput.value = state.context;
  const url = new URL(window.location.href);
  url.searchParams.set("context_id", state.context);
  history.replaceState(null, "", url);
  await withBusy(elements.contextApply, "Context", refreshSnapshot);
});

elements.contextInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    elements.contextApply.click();
  }
});

elements.themeButton.addEventListener("click", () => {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);
  storeTheme(nextTheme);
});

elements.refreshButton.addEventListener("click", () => {
  withBusy(elements.refreshButton, "Refresh", refreshSnapshot);
});

elements.refreshActionButton.addEventListener("click", () => {
  withBusy(elements.refreshActionButton, "Refresh", refreshSnapshot);
});

elements.profileButton.addEventListener("click", async () => {
  await withBusy(elements.profileButton, "Resource profile", async () => {
    const profile = await requestJson("/api/profile", {
      params: { benchmark_quick_prune: "true" },
    });
    state.snapshot.profile = profile;
    renderSnapshot(state.snapshot);
    return profile;
  }, { refresh: false });
});

elements.toggleButton.addEventListener("click", () => toggleCore(elements.toggleButton));
elements.toggleActionButton.addEventListener("click", () => toggleCore(elements.toggleActionButton));

elements.rememberForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const tag = elements.rememberTag.value.trim();
  const text = elements.rememberText.value.trim();
  if (!tag || !text) {
    logOperation("Remember rejected", "tag and text are required");
    (!tag ? elements.rememberTag : elements.rememberText).focus();
    return;
  }
  await withBusy(elements.rememberForm.querySelector("button"), "Remember trace", async () => {
    const payload = await requestJson("/api/remember", {
      method: "POST",
      body: {
        context_id: state.context,
        tag,
        text,
        metadata: { source: "dashboard" },
      },
    });
    elements.rememberText.value = "";
    return payload;
  });
});

elements.ingestForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const tag = elements.ingestTag.value.trim();
  const text = elements.ingestText.value.trim();
  const threshold = Number(elements.ingestThreshold.value || 0.58);
  const minSentences = Number(elements.ingestMinSentences.value || 1);
  if (!tag || !text) {
    logOperation("Ingest rejected", "source tag and text are required");
    (!tag ? elements.ingestTag : elements.ingestText).focus();
    return;
  }
  await withBusy(elements.ingestForm.querySelector("button"), "Ingest events", async () => {
    const payload = await requestJson("/api/ingest", {
      method: "POST",
      body: {
        context_id: state.context,
        tag,
        text,
        surprise_threshold: clamp(Number.isFinite(threshold) ? threshold : 0.58, 0.1, 1),
        min_segment_sentences: Math.max(1, Math.trunc(Number.isFinite(minSentences) ? minSentences : 1)),
      },
    });
    elements.ingestText.value = "";
    return payload;
  });
});

elements.queryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const prompt = elements.queryInput.value.trim();
  if (!prompt) {
    elements.queryResults.replaceChildren();
    elements.resultCount.textContent = "(0)";
    elements.latencyLabel.textContent = "Latency: -- ms";
    logOperation("Recall rejected", "prompt is required");
    elements.queryInput.focus();
    return;
  }
  await withBusy(elements.queryForm.querySelector("button"), "Recall", async () => {
    const payload = await requestJson("/api/query", {
      method: "POST",
      body: { context_id: state.context, prompt },
    });
    state.lastQueryPayload = payload;
    renderQueryResult(payload);
    return payload;
  }, { refresh: false });
});

elements.recallLimit.addEventListener("change", () => {
  if (state.lastQueryPayload) {
    renderQueryResult(state.lastQueryPayload);
  }
});

elements.clearRecallButton.addEventListener("click", () => {
  state.lastQueryPayload = null;
  elements.queryInput.value = "";
  elements.queryResults.replaceChildren();
  elements.resultCount.textContent = "(0)";
  elements.latencyLabel.textContent = "Latency: -- ms";
});

elements.quickPruneButton.addEventListener("click", () => {
  withBusy(elements.quickPruneButton, "Quick prune", () => (
    requestJson("/api/quick-prune", { method: "POST", body: {} })
  ));
});

elements.sleepButton.addEventListener("click", () => {
  withBusy(elements.sleepButton, "Deep sleep", () => (
    requestJson("/api/sleep", { method: "POST", body: {} })
  ));
});

elements.backupButton.addEventListener("click", () => {
  withBusy(elements.backupButton, "Backup", () => (
    requestJson("/api/backup", { method: "POST", body: {} })
  ));
});

refreshSnapshot()
  .catch((error) => {
    logOperation("Initial load failed", error.message);
  });
