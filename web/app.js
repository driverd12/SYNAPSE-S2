const DEFAULT_CONTEXT = "default";
const THEME_STORAGE_KEY = "synapse-s2-theme";

const state = {
  context: new URLSearchParams(window.location.search).get("context_id")?.trim() || DEFAULT_CONTEXT,
  snapshot: null,
};

const elements = {
  runtimeLine: document.getElementById("runtimeLine"),
  contextInput: document.getElementById("contextInput"),
  contextApply: document.getElementById("contextApply"),
  themeButton: document.getElementById("themeButton"),
  refreshButton: document.getElementById("refreshButton"),
  toggleButton: document.getElementById("toggleButton"),
  toggleText: document.getElementById("toggleText"),
  runtimeState: document.getElementById("runtimeState"),
  runtimeDetail: document.getElementById("runtimeDetail"),
  memoryCount: document.getElementById("memoryCount"),
  relationshipCount: document.getElementById("relationshipCount"),
  pruneBudget: document.getElementById("pruneBudget"),
  pruneState: document.getElementById("pruneState"),
  resourceMb: document.getElementById("resourceMb"),
  envelopeState: document.getElementById("envelopeState"),
  envelopeFill: document.getElementById("envelopeFill"),
  envelopeMarker: document.getElementById("envelopeMarker"),
  currentEnvelope: document.getElementById("currentEnvelope"),
  arrayList: document.getElementById("arrayList"),
  graphSvg: document.getElementById("graphSvg"),
  graphSummary: document.getElementById("graphSummary"),
  profileButton: document.getElementById("profileButton"),
  queryForm: document.getElementById("queryForm"),
  queryInput: document.getElementById("queryInput"),
  queryResults: document.getElementById("queryResults"),
  quickPruneButton: document.getElementById("quickPruneButton"),
  sleepButton: document.getElementById("sleepButton"),
  backupButton: document.getElementById("backupButton"),
  operationLog: document.getElementById("operationLog"),
};

elements.contextInput.value = state.context;
applyTheme(loadTheme());

function apiUrl(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
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

function formatNumber(value, digits = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "--";
  return numeric.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  });
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function logOperation(label, payload) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  elements.operationLog.textContent = `${label}\n${text}`;
}

function preferredTheme() {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function loadTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return stored === "dark" || stored === "light" ? stored : preferredTheme();
  } catch {
    return preferredTheme();
  }
}

function storeTheme(theme) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Theme persistence is best-effort; the control remains functional without storage.
  }
}

function applyTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = normalized;
  const dark = normalized === "dark";
  elements.themeButton.setAttribute("aria-pressed", String(dark));
  elements.themeButton.setAttribute("aria-label", dark ? "Use light mode" : "Use dark mode");
  elements.themeButton.setAttribute("title", dark ? "Use light mode" : "Use dark mode");
}

async function refreshSnapshot() {
  elements.runtimeLine.textContent = "refreshing";
  const snapshot = await requestJson("/api/snapshot", {
    params: { context_id: state.context, limit: 24 },
  });
  state.snapshot = snapshot;
  renderSnapshot(snapshot);
  return snapshot;
}

function renderSnapshot(snapshot) {
  const status = snapshot.status;
  const profile = snapshot.profile;
  const graph = snapshot.graph;
  const enabled = Boolean(status.effective_enabled);

  elements.runtimeLine.textContent = `${status.runtime} / ${status.mlx_device}`;
  elements.runtimeState.textContent = status.runtime || "--";
  elements.runtimeDetail.textContent = `MLX ${status.mlx_available ? "ready" : "missing"} / mlxsnn ${status.mlxsnn_available ? "ready" : "missing"}`;
  elements.memoryCount.textContent = formatNumber(status.memory_context_entry_count);
  elements.relationshipCount.textContent = `${formatNumber(status.memory_context_relationship_count)} relationships`;
  elements.pruneBudget.textContent = profile.quick_pruning
    ? `${formatNumber(profile.quick_pruning.elapsed_ms, 1)} ms`
    : "standby";
  elements.pruneState.textContent = profile.quick_pruning
    ? (profile.quick_pruning.within_60ms_budget ? "within 60 ms target" : "outside 60 ms target")
    : "benchmark available";
  elements.resourceMb.textContent = `${formatNumber(profile.estimated_total_mb, 1)} MB`;
  elements.envelopeState.textContent = profile.within_target_envelope ? "inside 61-138 MB" : "outside target";
  elements.toggleText.textContent = enabled ? "Enabled" : "Disabled";
  elements.toggleButton.classList.toggle("off", !enabled);
  elements.toggleButton.setAttribute("aria-pressed", String(enabled));

  renderEnvelope(profile);
  renderArrays(profile.arrays || {});
  renderGraph(graph);
}

function renderEnvelope(profile) {
  const min = Number(profile.target_envelope_mb?.min ?? 61);
  const max = Number(profile.target_envelope_mb?.max ?? 138);
  const current = Number(profile.estimated_total_mb ?? 0);
  const pct = clamp(((current - min) / (max - min)) * 100, 0, 100);
  elements.envelopeFill.style.width = `${pct}%`;
  elements.envelopeMarker.style.left = `${pct}%`;
  elements.currentEnvelope.textContent = `${formatNumber(current, 1)} MB`;
}

function renderArrays(arrays) {
  const rows = Object.entries(arrays)
    .sort((a, b) => Number(b[1].estimated_bytes) - Number(a[1].estimated_bytes))
    .map(([name, profile]) => {
      const shape = Array.isArray(profile.shape) ? profile.shape.join(" x ") : "--";
      return `<div><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(shape)}</dd><dd>${formatNumber(profile.estimated_mb, 3)} MB</dd></div>`;
    })
    .join("");
  elements.arrayList.innerHTML = rows || "<div><dt>No arrays</dt><dd>--</dd><dd>--</dd></div>";
}

function renderGraph(graph) {
  const entries = graph.entries || [];
  const relationships = graph.relationships || [];
  elements.graphSummary.textContent = `${relationships.length} edges`;
  const svg = elements.graphSvg;
  svg.replaceChildren();
  if (!entries.length) {
    appendSvg(svg, "text", {
      x: 380,
      y: 180,
      "text-anchor": "middle",
      class: "graph-empty",
    }, "No memory entries");
    return;
  }

  const width = 760;
  const height = 360;
  const visible = entries.slice(0, 10);
  const radius = Math.min(126, 42 + visible.length * 8);
  const center = { x: width / 2, y: height / 2 };
  const positions = new Map();

  visible.forEach((entry, index) => {
    const angle = (-Math.PI / 2) + (index / visible.length) * Math.PI * 2;
    positions.set(entry.memory_id, {
      x: center.x + Math.cos(angle) * radius,
      y: center.y + Math.sin(angle) * radius,
      entry,
    });
  });

  for (const relationship of relationships) {
    const source = positions.get(relationship.source_memory_id);
    const target = positions.get(relationship.target_memory_id);
    if (!source || !target) continue;
    appendSvg(svg, "line", {
      x1: source.x,
      y1: source.y,
      x2: target.x,
      y2: target.y,
      class: "graph-edge",
    });
  }

  for (const node of positions.values()) {
    appendSvg(svg, "circle", {
      cx: node.x,
      cy: node.y,
      r: 16,
      class: node.entry.metadata?.event_segment ? "graph-node primary" : "graph-node",
    });
    appendSvg(svg, "text", {
      x: node.x,
      y: node.y + 32,
      "text-anchor": "middle",
      class: "graph-label",
    }, compactTag(node.entry.tag));
  }
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

function compactTag(tag) {
  const text = String(tag || "");
  if (text.length <= 24) return text;
  return `${text.slice(0, 10)}…${text.slice(-10)}`;
}

function renderQueryResult(text) {
  const parts = String(text || "")
    .split(" / ")
    .map((item) => item.trim())
    .filter(Boolean);
  elements.queryResults.innerHTML = parts
    .map((item) => `<span class="result-chip">${escapeHtml(item)}</span>`)
    .join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
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

elements.contextApply.addEventListener("click", async () => {
  state.context = elements.contextInput.value.trim() || DEFAULT_CONTEXT;
  elements.contextInput.value = state.context;
  const url = new URL(window.location.href);
  url.searchParams.set("context_id", state.context);
  history.replaceState(null, "", url);
  await withBusy(elements.contextApply, "Context", refreshSnapshot);
});

elements.themeButton.addEventListener("click", () => {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);
  storeTheme(nextTheme);
});

elements.refreshButton.addEventListener("click", () => {
  withBusy(elements.refreshButton, "Refresh", refreshSnapshot);
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

elements.toggleButton.addEventListener("click", async () => {
  const enabled = !elements.toggleButton.classList.contains("off");
  await withBusy(elements.toggleButton, "Toggle", async () => (
    requestJson("/api/toggle", {
      method: "POST",
      body: { context_id: state.context, enabled: !enabled },
    })
  ));
});

elements.queryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const prompt = elements.queryInput.value.trim();
  if (!prompt) {
    elements.queryResults.replaceChildren();
    logOperation("Recall rejected", "prompt is required");
    elements.queryInput.focus();
    return;
  }
  await withBusy(elements.queryForm.querySelector("button"), "Recall", async () => {
    const payload = await requestJson("/api/query", {
      method: "POST",
      body: { context_id: state.context, prompt },
    });
    renderQueryResult(payload.result);
    return payload;
  });
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
