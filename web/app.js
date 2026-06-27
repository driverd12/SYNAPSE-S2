const DEFAULT_CONTEXT = "default";
const THEME_STORAGE_KEY = "synapse-s2-control-theme-v3";
const SNAPSHOT_LIMIT = 80;
const GRAPH_WIDTH = 760;
const GRAPH_HEIGHT = 420;
const GRAPH_MIN_SCALE = 0.45;
const GRAPH_MAX_SCALE = 3.2;
const CORE_TOGGLE_UNLOCK_WINDOW_MS = 10000;

const state = {
  context: new URLSearchParams(window.location.search).get("context_id")?.trim() || DEFAULT_CONTEXT,
  snapshot: null,
  lastQueryPayload: null,
  neuralInspector: false,
  graph: {
    nodePositions: new Map(),
    transform: { x: 0, y: 0, scale: 1 },
    visibleIds: new Set(),
    interaction: null,
  },
  nav: {
    lockedSection: null,
    lockUntilMs: 0,
  },
  coreToggle: {
    unlockedUntilMs: 0,
    lockTimer: null,
  },
  cortex: {
    sessionId: "",
  },
};

const elements = collectElements([
  "apiState",
  "arrayCount",
  "arrayList",
  "backupButton",
  "chipLabel",
  "clearRecallButton",
  "contextApply",
  "contextBusState",
  "contextEventLedger",
  "contextInput",
  "contextUri",
  "coreToggleGuardHint",
  "coreUnlockButton",
  "coreVersion",
  "cortexAgentId",
  "cortexCommitForm",
  "cortexConfidence",
  "cortexDecision",
  "cortexEnterForm",
  "cortexHighConfidence",
  "cortexAssumptions",
  "cortexCaptureQueue",
  "cortexMode",
  "cortexIntendedFiles",
  "cortexIntendedTools",
  "cortexMutationIntent",
  "cortexNextMove",
  "cortexObservation",
  "cortexPolicy",
  "cortexProposedAction",
  "cortexSessionCount",
  "cortexSessionId",
  "cortexTask",
  "cortexTickForm",
  "cortexTraceText",
  "cortexTraceType",
  "cortexTruthPosture",
  "cortexTypedCounts",
  "cortexWarnings",
  "cortexWorkingMemory",
  "captureForm",
  "captureInboxButton",
  "captureInboxState",
  "captureSpeaker",
  "captureTag",
  "captureText",
  "currentEnvelope",
  "engineState",
  "embeddingModelLabel",
  "endpointLabel",
  "envelopeFill",
  "envelopeMarker",
  "envelopeState",
  "evidencePackButton",
  "footerContexts",
  "footerGpu",
  "footerHealth",
  "footerMemory",
  "footerTime",
  "graphActiveCount",
  "graphEdgeCount",
  "graphLastPrune",
  "graphNodeCount",
  "graphFit",
  "graphReset",
  "graphSummary",
  "graphSvg",
  "graphAssociativeCount",
  "graphTemporalCount",
  "graphZoomIn",
  "graphZoomOut",
  "headroomMb",
  "headroomState",
  "headerRuntime",
  "hydrateLabel",
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
  "nativeCertifyButton",
  "neuralInspectorToggle",
  "neuralMathPanel",
  "modelUri",
  "operationLog",
  "platformLabel",
  "profileButton",
  "pruneBudget",
  "pruneAssociativeButton",
  "pruneEventId",
  "pruneForm",
  "pruneMemoryId",
  "pruneReason",
  "pruneRelationshipId",
  "pruneState",
  "pruneTag",
  "pruneTargetType",
  "pruneTemporalButton",
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
  "relationshipLedger",
  "resourceCurrent",
  "resourceMb",
  "resultCount",
  "routerState",
  "readinessAuditButton",
  "runtimeContextGraph",
  "runtimeContextMemory",
  "runtimeDetail",
  "runtimeDevice",
  "runtimeDeviceDetail",
  "runtimeGraphDetail",
  "runtimeGraphMode",
  "runtimeMaintenance",
  "runtimeMaintenanceDetail",
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
initializeGraphInteractions();
initializeSectionNavigation();

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
  const started = nowMs();
  elements.headerRuntime.textContent = "REFRESHING";
  const shellSnapshot = await requestJson("/api/snapshot", {
    params: { context_id: state.context, limit: SNAPSHOT_LIMIT, include_graph: "false" },
  });
  state.snapshot = withGraph(shellSnapshot, shellSnapshot.graph);
  const shellElapsedMs = elapsedMs(started);
  renderSnapshot(state.snapshot, shellElapsedMs);
  if (operationLogIsIdle()) {
    logSnapshotResponse(state.snapshot, shellElapsedMs);
  }

  try {
    const graph = await requestJson("/api/graph", {
      params: { context_id: state.context, limit: SNAPSHOT_LIMIT },
    });
    const contextDeployments = await pullContextDeployments(0, 20);
    state.snapshot = {
      ...withGraph(shellSnapshot, graph),
      context_deployments: contextDeployments,
    };
    renderSnapshot(state.snapshot, elapsedMs(started));
  } catch (error) {
    logOperation("Graph refresh failed", error.message);
  }
  return state.snapshot;
}

function renderSnapshot(snapshot, clientElapsedMs = null) {
  const status = snapshot.status || {};
  const profile = snapshot.profile || {};
  const graph = snapshot.graph || {};
  const system = snapshot.system || {};
  const enabled = Boolean(status.effective_enabled);
  const runtimeReady = enabled && String(status.runtime || "").toLowerCase() === "ready";
  const memoryUri = system.memory_uri || system.model_uri || `s2://local/${snapshot.context_id || state.context}`;
  const entryTotal = Number(status.memory_context_entry_count ?? graph.entry_count ?? 0);
  const relationshipTotal = Number(status.memory_context_relationship_count ?? graph.relationship_count ?? 0);
  const relationshipSummary = graph.relationship_summary || {};
  const graphDeferred = Boolean(graph.deferred);
  const temporalRelationships = graphDeferred ? null : Number(relationshipSummary.temporal ?? 0);
  const associativeRelationships = graphDeferred ? null : Number(relationshipSummary.associative ?? 0);
  const contexts = status.memory_contexts || {};
  const contextCount = Object.keys(contexts).length;

  elements.contextUri.textContent = memoryUri;
  elements.modelUri.textContent = memoryUri;
  elements.embeddingModelLabel.textContent = formatEmbeddingProvider(status.embedding_provider || {});
  elements.embeddingModelLabel.title = embeddingProviderTitle(status.embedding_provider || {});
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
  renderRuntimeHealth(status, profile, graph, {
    contextCount,
    entryTotal,
    relationshipTotal,
    temporalRelationships,
    associativeRelationships,
    graphDeferred,
  });

  elements.toggleText.textContent = enabled ? "Enabled" : "Disabled";
  elements.toggleActionState.textContent = enabled ? "Enabled" : "Disabled";
  elements.toggleButton.classList.toggle("off", !enabled);
  elements.toggleButton.setAttribute("aria-pressed", String(enabled));
  updateCoreToggleGuard();

  elements.graphSummary.textContent = graphDeferred
    ? "graph loading"
    : `${formatNumber(temporalRelationships)} temporal / ${formatNumber(associativeRelationships)} associative`;
  elements.graphNodeCount.textContent = formatNumber(entryTotal);
  elements.graphEdgeCount.textContent = formatNumber(relationshipTotal);
  elements.graphTemporalCount.textContent = formatNumber(temporalRelationships);
  elements.graphAssociativeCount.textContent = formatNumber(associativeRelationships);
  elements.graphActiveCount.textContent = formatNumber(countEventEntries(graph.entries || []));
  elements.graphLastPrune.textContent = formatAge(status.last_pruning_age_seconds);

  renderEnvelope(profile, status);
  renderArrays(profile.arrays || {});
  renderMaintenance(status, profile);
  renderGraph(graph, status);
  renderNeuralInspector(graph, status, profile);
  renderRelationshipLedger(graph);
  renderContextEventLedger(snapshot.context_deployments || {});
  renderMemoryLedger(graph);
  renderContextBus(status);
  renderCaptureInbox(snapshot.capture_inbox || null);
  renderCortexState(snapshot.cortex_state || {});
  renderFooter(snapshot, status, profile, contextCount);
  renderHydrationTiming(snapshot, clientElapsedMs);
}

function renderContextBus(status, deployment = null) {
  const eventCount = Number(status.context_bus_context_event_count ?? status.context_bus_event_count ?? 0);
  const latestEventId = Number(deployment?.event_id ?? status.context_bus_latest_event_id ?? 0);
  const receiptCount = Number(status.context_bus_ack_cursor_count ?? 0);
  const targets = Array.isArray(deployment?.agent_targets)
    ? deployment.agent_targets
    : Array.isArray(status.context_bus_agent_targets)
      ? status.context_bus_agent_targets
      : ["mcp-clients"];
  const targetText = targets.length ? targets.join(", ") : "mcp-clients";
  const ack = deployment?.ack;
  const receiptText = ack
    ? `${ack.agent_id || "agent"} acknowledged #${formatNumber(ack.last_event_id)}`
    : `${formatNumber(receiptCount)} delivery receipts`;
  const stateText = deployment
    ? `Published event #${formatNumber(latestEventId)}`
    : `${formatNumber(eventCount)} published context updates`;
  const detailText = deployment
    ? `${deployment.event_type || "context-update"} via ${deployment.delivery_mode || "durable-mcp-pull"} to ${targetText}; ${receiptText}`
    : `Ready for Remember/Ingest handoffs via ${status.context_bus_delivery_mode || "durable-mcp-pull"}; ${receiptText}`;
  elements.contextBusState.innerHTML = `
    <strong>${escapeHtml(stateText)}</strong>
    <span>${escapeHtml(detailText)}</span>
  `;
}

function renderCaptureInbox(captureInbox) {
  if (!captureInbox) {
    elements.captureInboxState.className = "capture-inbox-state";
    elements.captureInboxState.innerHTML = `
      <strong>Capture inbox unknown</strong>
      <small>Status has not been loaded yet.</small>
    `;
    return;
  }
  const pending = Number(captureInbox.pending_file_count ?? 0);
  const processed = Number(captureInbox.processed_file_count ?? 0);
  const errors = Number(captureInbox.error_file_count ?? 0);
  const last = captureInbox.last_result || {};
  const capturedEvents = Number(last.captured_event_count ?? 0);
  const capturedPayloads = Number(last.captured_payload_count ?? 0);
  const mode = errors > 0 ? "error" : pending > 0 ? "pending" : "ready";
  const headline = errors > 0
    ? `${formatNumber(errors)} capture error${errors === 1 ? "" : "s"}`
    : pending > 0
      ? `${formatNumber(pending)} pending capture file${pending === 1 ? "" : "s"}`
      : "Capture inbox armed";
  const detail = pending > 0
    ? `${formatNumber(processed)} processed. Press Process to ingest pending local session drops.`
    : `Processed ${formatNumber(processed)} files; last run captured ${formatNumber(capturedEvents)} events from ${formatNumber(capturedPayloads)} payloads.`;
  elements.captureInboxState.className = `capture-inbox-state ${mode}`;
  elements.captureInboxState.innerHTML = `
    <strong>${escapeHtml(headline)}</strong>
    <small>${escapeHtml(detail)}</small>
  `;
}

function renderCortexState(cortex) {
  const activeSessions = Array.isArray(cortex.active_sessions) ? cortex.active_sessions : [];
  const activeSession = activeSessions[0] || null;
  const policy = cortex.policy || {};
  const policyId = String(policy.policy_id || "cognitive_governance:strict");
  const typedCounts = cortex.typed_memory_counts || {};
  const highConfidence = Array.isArray(cortex.high_confidence_truths)
    ? cortex.high_confidence_truths
    : [];
  const assumptions = [
    ...(Array.isArray(cortex.unverified_assumptions) ? cortex.unverified_assumptions : []),
    ...(Array.isArray(cortex.contradictions) ? cortex.contradictions : []),
  ];
  const captureQueue = Array.isArray(cortex.capture_queue) ? cortex.capture_queue : [];
  const workingMemory = Array.isArray(cortex.working_memory) ? cortex.working_memory : [];
  const warnings = Array.isArray(activeSession?.last_warnings) ? activeSession.last_warnings : [];

  if (!state.cortex.sessionId && activeSession?.session_id) {
    state.cortex.sessionId = String(activeSession.session_id);
  }

  const currentSessionId = state.cortex.sessionId || String(activeSession?.session_id || "");
  const lastDecision = String(activeSession?.last_decision || "standby");

  elements.cortexPolicy.textContent = policyId;
  elements.cortexPolicy.title = Array.isArray(policy.contract)
    ? policy.contract.join(" / ")
    : policyId;
  elements.cortexSessionCount.textContent = formatNumber(cortex.active_session_count ?? activeSessions.length);
  elements.cortexSessionId.textContent = currentSessionId
    ? compactTag(currentSessionId, 34)
    : "no active session";
  elements.cortexSessionId.title = currentSessionId || "";
  elements.cortexDecision.textContent = lastDecision;
  elements.cortexDecision.className = decisionClass(lastDecision);

  const typedSummary = Object.entries(typedCounts)
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
    .map(([type, count]) => `${type}:${formatNumber(count)}`)
    .join(" / ");
  elements.cortexTypedCounts.textContent = typedSummary || "none";
  elements.cortexTypedCounts.title = typedSummary || "";

  elements.cortexWarnings.textContent = warnings.length
    ? warnings.map((warning) => warning.code || "warning").join(" / ")
    : "clear";
  elements.cortexWarnings.className = warnings.some((warning) => warning.severity === "critical")
    ? "bad"
    : warnings.length
      ? "warn"
      : "good";
  const nextMove = String(cortex.suggested_next_move || "Enter Cortex Governor before substantial work.");
  elements.cortexNextMove.textContent = compactTag(nextMove, 44);
  elements.cortexNextMove.title = nextMove;

  elements.cortexHighConfidence.innerHTML = renderCortexMemoryList(
    highConfidence,
    "No high-confidence governed truths yet",
  );
  elements.cortexAssumptions.innerHTML = renderCortexMemoryList(
    assumptions,
    "No unresolved assumptions or conflicts",
  );
  elements.cortexCaptureQueue.innerHTML = renderCortexCaptureQueue(
    captureQueue,
    "No pending capture recommendations",
  );
  elements.cortexWorkingMemory.innerHTML = renderCortexMemoryList(
    workingMemory,
    "No cortical traces yet",
  );
}

function renderCortexMemoryList(items, emptyLabel) {
  if (!items.length) {
    return `<div class="cortex-empty">${escapeHtml(emptyLabel)}</div>`;
  }
  return items.slice(0, 8).map((item) => {
    const confidence = Number(item.confidence ?? 0);
    const meta = [
      item.trace_type || "evidence",
      item.truth_posture || "observed",
      Number.isFinite(confidence) ? `${formatNumber(confidence, 2)} confidence` : "",
    ].filter(Boolean).join(" / ");
    const memoryId = String(item.memory_id || "");
    const label = item.tag || compactMemoryId(memoryId) || "cortex-trace";
    const actions = memoryId ? `
        <div class="cortex-memory-actions" aria-label="Cortex trace moderation">
          <button type="button" data-cortex-action="promote" data-memory-id="${escapeHtml(memoryId)}" data-cortex-label="${escapeHtml(label)}">Promote</button>
          <button type="button" data-cortex-action="demote" data-memory-id="${escapeHtml(memoryId)}" data-cortex-label="${escapeHtml(label)}">Demote</button>
          <button type="button" data-cortex-action="prune" data-memory-id="${escapeHtml(memoryId)}" data-cortex-label="${escapeHtml(label)}">Prune</button>
        </div>
      ` : "";
    return `
      <article class="cortex-memory-row">
        <div>
          <strong>${escapeHtml(label)}</strong>
          <small>${escapeHtml(meta)}</small>
        </div>
        <p>${escapeHtml(item.excerpt || "")}</p>
        ${actions}
      </article>
    `;
  }).join("");
}

function renderCortexCaptureQueue(items, emptyLabel) {
  if (!items.length) {
    return `<div class="cortex-empty">${escapeHtml(emptyLabel)}</div>`;
  }
  return items.slice(0, 8).map((item) => {
    const files = Array.isArray(item.intended_files) ? item.intended_files : [];
    const tools = Array.isArray(item.intended_tools) ? item.intended_tools : [];
    const scope = [
      files.length ? `files: ${files.slice(0, 3).join(", ")}` : "",
      tools.length ? `tools: ${tools.slice(0, 3).join(", ")}` : "",
    ].filter(Boolean).join(" / ");
    return `
      <article class="cortex-memory-row">
        <div>
          <strong>${escapeHtml(item.trace_type || "evidence")}</strong>
          <small>${escapeHtml(item.decision || "capture recommended")}</small>
        </div>
        <p>${escapeHtml(item.reason || "Capture the verified outcome after the action completes.")}</p>
        ${scope ? `<p>${escapeHtml(scope)}</p>` : ""}
      </article>
    `;
  }).join("");
}

function decisionClass(decision) {
  if (decision === "stop-and-sanitize") return "bad";
  if (decision === "verify-first" || decision === "proceed-with-verification") return "warn";
  if (decision === "proceed") return "good";
  return "";
}

function renderRuntimeHealth(status, profile, graph, counts) {
  const device = status.mlx_device || profile.mlx_device || "default";
  elements.runtimeDevice.textContent = `MLX ${device}`;
  elements.runtimeDeviceDetail.textContent = `${formatNumber(status.default_top_k)} top-k / ${formatNumber(status.num_neurons)} neurons`;

  elements.runtimeContextMemory.textContent = `${formatNumber(counts.entryTotal)} traces`;
  elements.runtimeContextGraph.textContent = `${formatNumber(counts.relationshipTotal)} relationships / ${formatNumber(counts.contextCount)} contexts`;

  elements.runtimeGraphMode.textContent = counts.graphDeferred
    ? "hydrating"
    : `${formatNumber(counts.temporalRelationships)} temporal / ${formatNumber(counts.associativeRelationships)} associative`;
  elements.runtimeGraphDetail.textContent = `${formatNumber(countEventEntries(graph.entries || []))} event traces visible`;

  const lastMode = status.last_maintenance?.mode
    ? compactTag(String(status.last_maintenance.mode), 20)
    : "standby";
  elements.runtimeMaintenance.textContent = lastMode;
  elements.runtimeMaintenanceDetail.textContent = `${formatAge(status.last_pruning_age_seconds)} / ${formatNumber(status.quick_pruning_interval_seconds, 0)}s interval`;
}

function withGraph(snapshot, graph) {
  return {
    ...snapshot,
    graph,
  };
}

function renderHydrationTiming(snapshot, clientElapsedMs) {
  const timings = snapshot.timings_ms || {};
  const serverMs = Number(timings.total);
  const clientMs = Number(clientElapsedMs);
  const serverText = Number.isFinite(serverMs) ? `${formatNumber(serverMs, 1)} ms api` : "-- ms api";
  const clientText = Number.isFinite(clientMs) ? `${formatNumber(clientMs, 0)} ms ui` : "-- ms ui";
  elements.hydrateLabel.textContent = `Hydrate: ${serverText} / ${clientText}`;
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

  if (graph.deferred) {
    appendSvg(svg, "text", {
      x: 380,
      y: 208,
      "text-anchor": "middle",
      class: "graph-empty",
    }, "Loading memory graph");
    return;
  }

  if (!entries.length) {
    state.graph.visibleIds = new Set();
    appendSvg(svg, "text", {
      x: 380,
      y: 208,
      "text-anchor": "middle",
      class: "graph-empty",
    }, "No memory entries");
    return;
  }

  const visible = entries.slice(0, 14);
  const visibleIds = new Set(visible.map((entry) => String(entry.memory_id)));
  state.graph.visibleIds = visibleIds;
  for (const memoryId of Array.from(state.graph.nodePositions.keys())) {
    if (!visibleIds.has(memoryId)) {
      state.graph.nodePositions.delete(memoryId);
    }
  }
  const layoutPositions = layoutGraph(visible, GRAPH_WIDTH, GRAPH_HEIGHT);
  for (const [memoryId, position] of layoutPositions) {
    if (!state.graph.nodePositions.has(memoryId)) {
      state.graph.nodePositions.set(memoryId, { x: position.x, y: position.y });
    }
  }

  const viewport = appendSvg(svg, "g", {
    id: "graphViewport",
    class: "graph-viewport",
    transform: graphTransformAttribute(),
  });
  const edgeLayer = appendSvg(viewport, "g", { id: "graphEdges", class: "graph-edge-layer" });
  const nodeLayer = appendSvg(viewport, "g", { id: "graphNodes", class: "graph-node-layer" });

  for (const relationship of relationships) {
    const source = state.graph.nodePositions.get(String(relationship.source_memory_id));
    const target = state.graph.nodePositions.get(String(relationship.target_memory_id));
    if (!source || !target) continue;
    const weight = Number(relationship.weight ?? 0.5);
    appendSvg(edgeLayer, "line", {
      "data-source-id": relationship.source_memory_id,
      "data-target-id": relationship.target_memory_id,
      x1: source.x,
      y1: source.y,
      x2: target.x,
      y2: target.y,
      class: edgeClass(relationship, weight),
      "stroke-width": String(clamp(1 + weight * 2.4, 1.2, 3.4)),
    });
  }

  const contextLabel = status.context_id || graph.context_id || state.context;
  const contextGroup = appendSvg(nodeLayer, "g", {
    class: "graph-node-group context-node-group",
    transform: `translate(${GRAPH_WIDTH / 2} ${GRAPH_HEIGHT / 2})`,
  });
  appendSvg(contextGroup, "circle", {
    r: 28,
    class: "graph-node context-node",
  });
  appendSvg(contextGroup, "text", {
    y: 4,
    "text-anchor": "middle",
    class: "graph-label context-label",
  }, compactTag(contextLabel, 18));

  for (const entry of visible) {
    const position = state.graph.nodePositions.get(String(entry.memory_id));
    if (!position) continue;
    const group = appendSvg(nodeLayer, "g", {
      class: "graph-node-group",
      "data-node-id": entry.memory_id,
      transform: `translate(${position.x} ${position.y})`,
      tabindex: "0",
      role: "button",
      "aria-label": `Move ${entry.tag}`,
    });
    appendSvg(group, "title", {}, `${entry.tag}\n${entry.source_text || ""}`.trim());
    appendSvg(group, "circle", {
      r: entry.metadata?.event_segment ? 20 : 18,
      class: nodeClass(entry),
    });
    appendSvg(group, "text", {
      y: 34,
      "text-anchor": "middle",
      class: "graph-label",
    }, compactTag(entry.tag, 22));
    const score = formatSpikeSubLabel(entry);
    if (score) {
      appendSvg(group, "text", {
        y: 49,
        "text-anchor": "middle",
        class: "graph-sub-label",
      }, score);
    }
  }

  applyGraphTransform();
}

function renderNeuralInspector(graph, status, profile) {
  elements.neuralInspectorToggle.setAttribute("aria-pressed", String(state.neuralInspector));
  elements.neuralInspectorToggle.textContent = state.neuralInspector ? "Hide Neural Inspector" : "Neural Inspector";
  elements.neuralMathPanel.hidden = !state.neuralInspector;
  if (!state.neuralInspector) return;

  const entries = graph.entries || [];
  const selected = entries.find((entry) => Number(entry.spike_count) > 0) || entries[0] || {};
  const spikeSample = formatIndexSample(selected.spike_coordinate_sample);
  const neuronSample = formatIndexSample(selected.neuron_index_sample);
  const arrays = profile.arrays || {};
  const provider = status.embedding_provider || {};
  const providerLabel = formatEmbeddingProvider(provider);
  const dimensions = Number(selected.embedding_dimensions || status.dimension);
  const topK = Number(selected.spike_count || status.default_top_k);
  const neurons = Number(status.num_neurons);
  const projected = Number(selected.neuron_count || 0);
  const traceLabel = selected.tag ? `${selected.tag} / ${compactMemoryId(selected.memory_id)}` : "No selected trace";

  elements.neuralMathPanel.innerHTML = `
    <div>
      <p class="section-label">Sparse spike code</p>
      <strong>${escapeHtml(formatNumber(topK))} active coordinates from ${escapeHtml(formatNumber(dimensions))} embedding dims</strong>
      <code>Z_i = (E_i - mu_E) / sigma_E; S_i = 1 for top-k coordinates</code>
      <small>${escapeHtml(providerLabel)} maps text to dense E, then top-k gating creates the sparse spike vector.</small>
    </div>
    <div>
      <p class="section-label">Active neuron sample</p>
      <strong>${escapeHtml(compactTag(traceLabel, 58))}</strong>
      <div class="neural-path" aria-label="Projected neuron sample">${formatNeuronSampleDots(selected.neuron_index_sample)}</div>
      <code>spike_coordinates=[${escapeHtml(spikeSample)}]</code>
      <code>projected_neurons=[${escapeHtml(neuronSample)}]</code>
      <small>${escapeHtml(formatNumber(projected))} projected neurons active inside a ${escapeHtml(formatNumber(neurons))}-neuron substrate.</small>
    </div>
    <div>
      <p class="section-label">LIF update</p>
      <strong>Functional membrane step</strong>
      <code>U[t+1] = beta * U[t] + X[t+1] - S[t] * V_thr</code>
      <small>beta=${escapeHtml(formatNumber(status.beta, 3))}; threshold=${escapeHtml(formatNumber(status.threshold, 3))}; arrays W_syn=${escapeHtml(formatArrayShape(arrays.W_syn?.shape))}, W_lateral=${escapeHtml(formatArrayShape(arrays.W_lateral?.shape))}</small>
    </div>
    <div>
      <p class="section-label">STDP update</p>
      <strong>Temporal association weights</strong>
      <code>dw = A+ exp(-dt/tau+) if dt &gt; 0; dw = -A- exp(dt/tau-) if dt &lt;= 0</code>
      <small>${escapeHtml(formatNumber(graph.relationship_summary?.temporal))} temporal / ${escapeHtml(formatNumber(graph.relationship_summary?.associative))} associative edges in this context.</small>
    </div>
  `;
}

function formatSpikeSubLabel(entry) {
  const spikeCount = Number(entry.spike_count || 0);
  if (!spikeCount) return "";
  const neuronCount = Number(entry.neuron_count || 0);
  if (state.neuralInspector) {
    return `${formatNumber(spikeCount)} coords / ${formatNumber(neuronCount)} neurons`;
  }
  return `${formatNumber(spikeCount)} active coords`;
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
  if (relation.includes("semantic") || relation.includes("associative")) {
    return weight >= 0.5 ? "graph-edge associative strong" : "graph-edge associative weak";
  }
  return weight >= 0.5 ? "graph-edge strong" : "graph-edge weak";
}

function nodeClass(entry) {
  if (entry.metadata?.event_segment) return "graph-node event-node";
  if (entry.metadata?.source_tag || entry.metadata?.source) return "graph-node concept-node";
  return "graph-node";
}

function graphTransformAttribute() {
  const transform = state.graph.transform;
  return `matrix(${transform.scale} 0 0 ${transform.scale} ${transform.x} ${transform.y})`;
}

function applyGraphTransform() {
  const viewport = document.getElementById("graphViewport");
  if (viewport) {
    viewport.setAttribute("transform", graphTransformAttribute());
  }
}

function svgLocalPoint(event) {
  const svg = elements.graphSvg;
  const point = svg.createSVGPoint();
  point.x = event.clientX;
  point.y = event.clientY;
  const matrix = svg.getScreenCTM();
  if (!matrix) return { x: 0, y: 0 };
  const local = point.matrixTransform(matrix.inverse());
  return { x: local.x, y: local.y };
}

function graphPointFromSvgPoint(point) {
  const transform = state.graph.transform;
  return {
    x: (point.x - transform.x) / transform.scale,
    y: (point.y - transform.y) / transform.scale,
  };
}

function setGraphScale(nextScale, anchor = { x: GRAPH_WIDTH / 2, y: GRAPH_HEIGHT / 2 }) {
  const transform = state.graph.transform;
  const scale = clamp(nextScale, GRAPH_MIN_SCALE, GRAPH_MAX_SCALE);
  const graphAnchor = graphPointFromSvgPoint(anchor);
  state.graph.transform = {
    scale,
    x: anchor.x - graphAnchor.x * scale,
    y: anchor.y - graphAnchor.y * scale,
  };
  applyGraphTransform();
}

function zoomGraphBy(factor, anchor = { x: GRAPH_WIDTH / 2, y: GRAPH_HEIGHT / 2 }) {
  setGraphScale(state.graph.transform.scale * factor, anchor);
}

function resetGraphView() {
  state.graph.transform = { x: 0, y: 0, scale: 1 };
  applyGraphTransform();
}

function resetGraphLayout() {
  state.graph.nodePositions.clear();
  resetGraphView();
  if (state.snapshot?.graph) {
    renderGraph(state.snapshot.graph, state.snapshot.status || {});
  }
}

function fitGraphToView() {
  const points = Array.from(state.graph.nodePositions.values());
  if (!points.length) {
    resetGraphView();
    return;
  }
  points.push({ x: GRAPH_WIDTH / 2, y: GRAPH_HEIGHT / 2 });
  const bounds = points.reduce((acc, point) => ({
    minX: Math.min(acc.minX, point.x),
    maxX: Math.max(acc.maxX, point.x),
    minY: Math.min(acc.minY, point.y),
    maxY: Math.max(acc.maxY, point.y),
  }), {
    minX: Number.POSITIVE_INFINITY,
    maxX: Number.NEGATIVE_INFINITY,
    minY: Number.POSITIVE_INFINITY,
    maxY: Number.NEGATIVE_INFINITY,
  });
  const padding = 88;
  const width = Math.max(1, bounds.maxX - bounds.minX);
  const height = Math.max(1, bounds.maxY - bounds.minY);
  const scale = clamp(
    Math.min((GRAPH_WIDTH - padding) / width, (GRAPH_HEIGHT - padding) / height),
    GRAPH_MIN_SCALE,
    Math.min(1.65, GRAPH_MAX_SCALE),
  );
  const centerX = bounds.minX + width / 2;
  const centerY = bounds.minY + height / 2;
  state.graph.transform = {
    scale,
    x: GRAPH_WIDTH / 2 - centerX * scale,
    y: GRAPH_HEIGHT / 2 - centerY * scale,
  };
  applyGraphTransform();
}

function moveGraphNode(memoryId, position) {
  state.graph.nodePositions.set(String(memoryId), position);
  const group = elements.graphSvg.querySelector(`[data-node-id="${cssEscape(String(memoryId))}"]`);
  if (group) {
    group.setAttribute("transform", `translate(${position.x} ${position.y})`);
  }
  updateGraphEdgesForNode(String(memoryId));
}

function updateGraphEdgesForNode(memoryId) {
  const edges = elements.graphSvg.querySelectorAll(
    `[data-source-id="${cssEscape(memoryId)}"], [data-target-id="${cssEscape(memoryId)}"]`,
  );
  for (const edge of edges) {
    const source = state.graph.nodePositions.get(String(edge.getAttribute("data-source-id")));
    const target = state.graph.nodePositions.get(String(edge.getAttribute("data-target-id")));
    if (!source || !target) continue;
    edge.setAttribute("x1", String(source.x));
    edge.setAttribute("y1", String(source.y));
    edge.setAttribute("x2", String(target.x));
    edge.setAttribute("y2", String(target.y));
  }
}

function initializeGraphInteractions() {
  const svg = elements.graphSvg;
  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    const local = svgLocalPoint(event);
    zoomGraphBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, local);
  }, { passive: false });

  svg.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    const nodeGroup = event.target.closest?.(".graph-node-group[data-node-id]");
    const local = svgLocalPoint(event);
    if (nodeGroup) {
      const nodeId = nodeGroup.getAttribute("data-node-id");
      const position = state.graph.nodePositions.get(String(nodeId));
      if (!nodeId || !position) return;
      state.graph.interaction = {
        type: "node",
        pointerId: event.pointerId,
        nodeId,
        startGraph: graphPointFromSvgPoint(local),
        startPosition: { ...position },
      };
      svg.classList.add("is-dragging-node");
    } else {
      state.graph.interaction = {
        type: "pan",
        pointerId: event.pointerId,
        startLocal: local,
        startTransform: { ...state.graph.transform },
      };
      svg.classList.add("is-panning");
    }
    svg.setPointerCapture?.(event.pointerId);
    event.preventDefault();
  });

  svg.addEventListener("pointermove", (event) => {
    const interaction = state.graph.interaction;
    if (!interaction || interaction.pointerId !== event.pointerId) return;
    const local = svgLocalPoint(event);
    if (interaction.type === "node") {
      const graphPoint = graphPointFromSvgPoint(local);
      moveGraphNode(interaction.nodeId, {
        x: interaction.startPosition.x + graphPoint.x - interaction.startGraph.x,
        y: interaction.startPosition.y + graphPoint.y - interaction.startGraph.y,
      });
    } else {
      state.graph.transform = {
        ...interaction.startTransform,
        x: interaction.startTransform.x + local.x - interaction.startLocal.x,
        y: interaction.startTransform.y + local.y - interaction.startLocal.y,
      };
      applyGraphTransform();
    }
  });

  const endInteraction = (event) => {
    const interaction = state.graph.interaction;
    if (!interaction || interaction.pointerId !== event.pointerId) return;
    state.graph.interaction = null;
    svg.classList.remove("is-panning", "is-dragging-node");
    svg.releasePointerCapture?.(event.pointerId);
  };
  svg.addEventListener("pointerup", endInteraction);
  svg.addEventListener("pointercancel", endInteraction);
  svg.addEventListener("lostpointercapture", () => {
    state.graph.interaction = null;
    svg.classList.remove("is-panning", "is-dragging-node");
  });
}

function initializeSectionNavigation() {
  const navItems = Array.from(document.querySelectorAll(".nav-item[data-section-target]"));
  if (!navItems.length) return;

  for (const item of navItems) {
    item.addEventListener("click", (event) => {
      event.preventDefault();
      const sectionId = item.getAttribute("data-section-target") || "";
      state.nav.lockedSection = sectionId;
      state.nav.lockUntilMs = nowMs() + 1400;
      scrollSectionIntoView(sectionId);
      setActiveNavItem(sectionId);
      history.replaceState(null, "", `#${sectionId}`);
    });
  }

  const updateActiveSection = () => setActiveNavItem(currentSectionId(navItems));
  const main = document.querySelector(".main");
  main?.addEventListener("scroll", updateActiveSection, { passive: true });
  window.addEventListener("scroll", updateActiveSection, { passive: true });

  if (window.location.hash) {
    const initial = window.location.hash.slice(1);
    requestAnimationFrame(() => {
      scrollSectionIntoView(initial);
      setActiveNavItem(initial);
    });
  } else {
    setActiveNavItem("overview");
  }
}

function scrollSectionIntoView(sectionId) {
  const scrollTarget = dashboardScrollTarget();
  if (!sectionId || sectionId === "overview") {
    scrollTarget.container.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }
  const target = document.getElementById(sectionId);
  if (!target) return;
  const mainRect = scrollTarget.rect();
  const targetRect = target.getBoundingClientRect();
  const targetTop = scrollTarget.scrollTop() + targetRect.top - mainRect.top - 12;
  scrollTarget.container.scrollTo({ top: Math.max(0, targetTop), behavior: "smooth" });
}

function setActiveNavItem(sectionId) {
  const normalized = sectionId || "overview";
  for (const item of document.querySelectorAll(".nav-item[data-section-target]")) {
    const active = item.getAttribute("data-section-target") === normalized;
    item.classList.toggle("active", active);
    if (active) {
      item.setAttribute("aria-current", "page");
    } else {
      item.removeAttribute("aria-current");
    }
  }
}

function currentSectionId(navItems) {
  const scrollTarget = dashboardScrollTarget();
  if (state.nav.lockedSection && nowMs() < state.nav.lockUntilMs) {
    return state.nav.lockedSection;
  }
  state.nav.lockedSection = null;
  if (scrollTarget.scrollTop() < 24) return "overview";
  let current = "runtime";
  const threshold = scrollTarget.rect().top + 90;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const item of navItems) {
    const sectionId = item.getAttribute("data-section-target") || "";
    if (sectionId === "overview") continue;
    const target = document.getElementById(sectionId);
    if (!target) continue;
    const rect = target.getBoundingClientRect();
    if (rect.bottom < scrollTarget.rect().top || rect.top > window.innerHeight) continue;
    const distance = Math.abs(rect.top - threshold);
    if (distance < bestDistance) {
      bestDistance = distance;
      current = sectionId;
    }
  }
  return current;
}

function dashboardScrollTarget() {
  const main = document.querySelector(".main");
  if (main && main.scrollHeight > main.clientHeight + 1) {
    return {
      container: main,
      rect: () => main.getBoundingClientRect(),
      scrollTop: () => main.scrollTop,
    };
  }
  const root = document.scrollingElement || document.documentElement;
  return {
    container: root,
    rect: () => ({ top: 0 }),
    scrollTop: () => root.scrollTop,
  };
}

function cssEscape(value) {
  return window.CSS?.escape ? window.CSS.escape(value) : String(value).replaceAll('"', '\\"');
}

function renderRelationshipLedger(graph) {
  const relationships = (graph.relationships || []).slice(0, 8);
  elements.relationshipLedger.innerHTML = relationships.length
    ? relationships.map((relationship) => `
        <div class="relationship-ledger-row">
          <div>
            <strong>${escapeHtml(relationship.relation_type || "relationship")}</strong>
            <small>${escapeHtml(relationship.source_tag || compactMemoryId(relationship.source_memory_id))} -> ${escapeHtml(relationship.target_tag || compactMemoryId(relationship.target_memory_id))}</small>
            <p>${escapeHtml(compactMemoryId(relationship.relationship_id))}</p>
          </div>
          <span>${escapeHtml(formatNumber(relationship.weight, 3))}</span>
          <time>${escapeHtml(formatTimestamp(relationship.updated_at || relationship.created_at))}</time>
          <button class="danger-button prune-row-button" type="button"
            data-prune-target="relationship"
            data-relationship-id="${escapeHtml(relationship.relationship_id)}"
            data-prune-label="${escapeHtml(relationship.relation_type || "relationship")}">
            Delete edge
          </button>
        </div>
      `).join("")
    : '<div class="memory-ledger-empty">No relationship edges</div>';
}

function renderContextEventLedger(deployments) {
  const events = (deployments.events || []).slice(-8).reverse();
  elements.contextEventLedger.innerHTML = events.length
    ? events.map((event) => `
        <div class="context-event-ledger-row">
          <div>
            <strong>#${escapeHtml(formatNumber(event.event_id))} ${escapeHtml(event.event_type || "context-update")}</strong>
            <small>${escapeHtml(event.source_surface || "surface")} / ${escapeHtml(event.delivery_mode || deployments.delivery_mode || "durable-mcp-pull")}</small>
            <p>${escapeHtml(event.summary || "")}</p>
          </div>
          <span>${escapeHtml(formatNumber((event.agent_targets || []).length))} targets</span>
          <time>${escapeHtml(formatTimestamp(event.created_at))}</time>
          <button class="danger-button prune-row-button" type="button"
            data-prune-target="context_event"
            data-event-id="${escapeHtml(event.event_id)}"
            data-prune-label="#${escapeHtml(formatNumber(event.event_id))}">
            Delete event
          </button>
        </div>
      `).join("")
    : '<div class="memory-ledger-empty">No context deployments</div>';
}

function renderMemoryLedger(graph) {
  const entries = (graph.entries || []).slice(0, 10);
  elements.memoryLedger.innerHTML = entries.length
    ? entries.map((entry) => {
      const source = entry.metadata?.source_tag || entry.metadata?.source || entry.context_id || "--";
      const sourceText = String(entry.source_text || "").trim();
      const targetType = entry.metadata?.event_segment ? "event" : "memory";
      return `
        <div class="memory-ledger-row">
          <div>
            <strong>${escapeHtml(entry.tag)}</strong>
            <small>${escapeHtml(source)} / ${escapeHtml(compactMemoryId(entry.memory_id))}</small>
            ${sourceText ? `<p>${escapeHtml(compactTag(sourceText, 120))}</p>` : ""}
          </div>
          <span>${formatNumber(entry.spike_count)} spikes</span>
          <time>${escapeHtml(formatTimestamp(entry.updated_at || entry.created_at))}</time>
          <button class="danger-button prune-row-button" type="button"
            data-prune-target="${targetType}"
            data-memory-id="${escapeHtml(entry.memory_id)}"
            data-tag="${escapeHtml(entry.tag)}"
            data-prune-label="${escapeHtml(entry.tag)}">
            Delete node
          </button>
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

function formatEmbeddingProvider(provider) {
  const providerId = String(provider.provider || "unknown");
  const modelId = String(provider.model_id || providerId);
  if (provider.provider_type === "mlx-neural") {
    return `MLX neural / ${compactModelId(modelId)}`;
  }
  if (provider.provider_type === "semantic-hash") {
    return "semantic hash";
  }
  if (provider.provider_type === "lexical-hash") {
    return "lexical hash";
  }
  return compactModelId(modelId);
}

function embeddingProviderTitle(provider) {
  const fields = [
    `provider=${provider.provider || "unknown"}`,
    `model=${provider.model_id || provider.provider || "unknown"}`,
    `local_only=${provider.local_only !== false}`,
  ];
  if (provider.native_mlx !== undefined) fields.push(`native_mlx=${Boolean(provider.native_mlx)}`);
  if (provider.loaded !== undefined) fields.push(`loaded=${Boolean(provider.loaded)}`);
  return fields.join(" / ");
}

function compactModelId(modelId) {
  const text = String(modelId || "unknown");
  const parts = text.split("/");
  return parts[parts.length - 1] || text;
}

function countEventEntries(entries) {
  return entries.filter((entry) => Boolean(entry.metadata?.event_segment)).length;
}

function formatIndexSample(values) {
  if (!Array.isArray(values) || !values.length) return "";
  return values
    .slice(0, 12)
    .map((value) => String(Math.trunc(Number(value))))
    .join(", ");
}

function formatNeuronSampleDots(values) {
  if (!Array.isArray(values) || !values.length) {
    return '<span class="neural-path-empty">No projected neurons</span>';
  }
  return values
    .slice(0, 12)
    .map((value) => {
      const index = Math.trunc(Number(value));
      const label = Number.isFinite(index) ? `n${index}` : "n?";
      return `<span title="projected neuron ${escapeHtml(label)}">${escapeHtml(label)}</span>`;
    })
    .join("");
}

function formatArrayShape(shape) {
  if (!Array.isArray(shape) || !shape.length) return "--";
  return shape.map((value) => formatNumber(value)).join(" x ");
}

function formatNumber(value, digits = 0) {
  if (value === null || value === undefined) return "--";
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

function nowMs() {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

function elapsedMs(started) {
  return Math.max(0, nowMs() - Number(started || nowMs()));
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

function splitIntentList(value) {
  return String(value || "")
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 24);
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

function operationLogIsIdle() {
  return elements.operationLog.textContent.trim() === "idle";
}

function logSnapshotResponse(snapshot, clientElapsedMs) {
  const status = snapshot.status || {};
  const profile = snapshot.profile || {};
  const timings = snapshot.timings_ms || {};
  logOperation("Backend snapshot", {
    context_id: snapshot.context_id,
    runtime: status.runtime,
    effective_enabled: status.effective_enabled,
    memory_entries: status.memory_context_entry_count,
    relationships: status.memory_context_relationship_count,
    context_bus_events: status.context_bus_context_event_count,
    memory_mb: profile.estimated_total_mb,
    server_total_ms: timings.total,
    client_hydrate_ms: Number.isFinite(Number(clientElapsedMs))
      ? Number(clientElapsedMs.toFixed(1))
      : null,
    generated_at: snapshot.generated_at,
  });
}

async function pullContextDeployments(sinceEventId = 0, limit = 10) {
  return requestJson("/api/context-events", {
    params: {
      context_id: state.context,
      since_event_id: Math.max(0, Math.trunc(Number(sinceEventId) || 0)),
      limit,
    },
  });
}

async function ackContextDeployment(lastEventId, agentId = "dashboard-ui") {
  return requestJson("/api/context-ack", {
    method: "POST",
    body: {
      context_id: state.context,
      agent_id: agentId,
      last_event_id: Math.max(0, Math.trunc(Number(lastEventId) || 0)),
    },
  });
}

async function publishAwareResult(payload) {
  if (payload.agent_deployment?.event_id) {
    payload.context_bus = await pullContextDeployments(
      payload.agent_deployment.event_id - 1,
      5,
    );
    payload.context_ack = await ackContextDeployment(
      payload.agent_deployment.event_id,
    );
  }
  return payload;
}

function currentCortexAgentId() {
  return elements.cortexAgentId.value.trim() || "dashboard-ui";
}

function currentCortexSessionId() {
  return state.cortex.sessionId || elements.cortexSessionId.title || "";
}

function setCortexSessionId(sessionId) {
  state.cortex.sessionId = String(sessionId || "");
  elements.cortexSessionId.textContent = state.cortex.sessionId
    ? compactTag(state.cortex.sessionId, 34)
    : "no active session";
  elements.cortexSessionId.title = state.cortex.sessionId;
}

async function enterCortexSession(button) {
  const task = elements.cortexTask.value.trim();
  if (!task) {
    logOperation("Cortex enter rejected", "current task is required");
    elements.cortexTask.focus();
    return null;
  }
  return withBusy(button, "Enter cortex", async () => {
    const payload = await requestJson("/api/cortex/enter", {
      method: "POST",
      body: {
        context_id: state.context,
        agent_id: currentCortexAgentId(),
        task,
        mode: elements.cortexMode.value,
      },
    });
    await publishAwareResult(payload);
    setCortexSessionId(payload.session_id);
    if (payload.cortex_state) renderCortexState(payload.cortex_state);
    return payload;
  });
}

async function tickCortexGovernor(button) {
  const sessionId = currentCortexSessionId();
  if (!sessionId) {
    logOperation("Cortex tick rejected", "enter a Cortex Governor session first");
    elements.cortexTask.focus();
    return null;
  }
  const confidence = clamp(Number(elements.cortexConfidence.value || 0.5), 0, 1);
  return withBusy(button, "Cortex tick", async () => {
    const payload = await requestJson("/api/cortex/tick", {
      method: "POST",
      body: {
        context_id: state.context,
        agent_id: currentCortexAgentId(),
        session_id: sessionId,
        observation: elements.cortexObservation.value.trim(),
        proposed_action: elements.cortexProposedAction.value.trim(),
        intended_files: splitIntentList(elements.cortexIntendedFiles.value),
        intended_tools: splitIntentList(elements.cortexIntendedTools.value),
        mutation_intent: elements.cortexMutationIntent.checked,
        confidence,
      },
    });
    await publishAwareResult(payload);
    if (payload.cortex_state) renderCortexState(payload.cortex_state);
    return payload;
  });
}

async function commitCorticalTrace(button) {
  const text = elements.cortexTraceText.value.trim();
  if (!text) {
    logOperation("Cortical trace rejected", "trace text is required");
    elements.cortexTraceText.focus();
    return null;
  }
  return withBusy(button, "Commit cortical trace", async () => {
    const payload = await requestJson("/api/cortex/commit", {
      method: "POST",
      body: {
        context_id: state.context,
        agent_id: currentCortexAgentId(),
        session_id: currentCortexSessionId(),
        trace_type: elements.cortexTraceType.value,
        truth_posture: elements.cortexTruthPosture.value,
        text,
        evidence: {
          source: "dashboard",
          session_id: currentCortexSessionId(),
          recorded_at: new Date().toISOString(),
        },
      },
    });
    await publishAwareResult(payload);
    elements.cortexTraceText.value = "";
    return payload;
  });
}

async function moderateCortexTrace(button) {
  const memoryId = button.dataset.memoryId || "";
  const action = button.dataset.cortexAction || "";
  const label = button.dataset.cortexLabel || compactMemoryId(memoryId);
  if (!memoryId || !action) return null;
  if (action === "prune" && !confirmPrune(label)) {
    logOperation("Cortex prune cancelled", label);
    return null;
  }
  return withBusy(button, `${action} trace`, async () => {
    const payload = await requestJson("/api/cortex/moderate", {
      method: "POST",
      body: {
        context_id: state.context,
        memory_id: memoryId,
        action,
        reason: `dashboard ${action} from Cortex Governor panel`,
      },
    });
    await publishAwareResult(payload);
    await refreshSnapshot();
    return payload;
  });
}

function confirmPrune(label) {
  return window.confirm(`Permanently prune ${label || "this graph item"} from SYNAPSE-S2 memory?`);
}

async function pruneGraphItem(payload, button, label = "selected graph data") {
  if (!confirmPrune(label)) {
    logOperation("Prune cancelled", label);
    return null;
  }
  return withBusy(button, "Prune memory", async () => (
    publishAwareResult(await requestJson("/api/prune-memory", {
      method: "POST",
      body: {
        context_id: state.context,
        confirm: true,
        reason: "operator-dashboard-prune",
        ...payload,
      },
    }))
  ));
}

function prunePayloadFromButton(button) {
  return {
    target_type: button.dataset.pruneTarget || "",
    memory_id: button.dataset.memoryId || "",
    tag: button.dataset.tag || "",
    relationship_id: button.dataset.relationshipId || "",
    event_id: Number(button.dataset.eventId || 0),
  };
}

function handleLedgerPruneClick(event) {
  const button = event.target.closest?.("button[data-prune-target]");
  if (!button) return;
  event.preventDefault();
  pruneGraphItem(
    prunePayloadFromButton(button),
    button,
    button.dataset.pruneLabel || button.textContent.trim(),
  );
}

async function withBusy(button, label, task, options = { refresh: true }) {
  const originalDisabled = button.disabled;
  button.disabled = true;
  try {
    const payload = await task();
    logOperation(label, payload);
    if (payload?.agent_deployment) {
      renderContextBus(state.snapshot?.status || {}, {
        ...payload.agent_deployment,
        ack: payload.context_ack || null,
      });
    }
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
  if (!isCoreToggleUnlocked()) {
    updateCoreToggleGuard();
    logOperation("Core toggle locked", "Press Unlock before enabling or disabling SYNAPSE-S2 Core.");
    return;
  }
  const enabled = !elements.toggleButton.classList.contains("off");
  try {
    await withBusy(button, "Toggle", () => (
      requestJson("/api/toggle", {
        method: "POST",
        body: { context_id: state.context, enabled: !enabled },
      })
    ));
  } finally {
    lockCoreToggleGuard();
  }
}

function isCoreToggleUnlocked() {
  return nowMs() < state.coreToggle.unlockedUntilMs;
}

function unlockCoreToggleGuard() {
  state.coreToggle.unlockedUntilMs = nowMs() + CORE_TOGGLE_UNLOCK_WINDOW_MS;
  if (state.coreToggle.lockTimer) {
    window.clearTimeout(state.coreToggle.lockTimer);
  }
  state.coreToggle.lockTimer = window.setTimeout(lockCoreToggleGuard, CORE_TOGGLE_UNLOCK_WINDOW_MS + 50);
  updateCoreToggleGuard();
  logOperation("Core toggle unlocked", "One SYNAPSE-S2 Core state change is available for 10 seconds.");
}

function lockCoreToggleGuard() {
  state.coreToggle.unlockedUntilMs = 0;
  if (state.coreToggle.lockTimer) {
    window.clearTimeout(state.coreToggle.lockTimer);
    state.coreToggle.lockTimer = null;
  }
  updateCoreToggleGuard();
}

function updateCoreToggleGuard() {
  const unlocked = isCoreToggleUnlocked();
  const enabled = !elements.toggleButton.classList.contains("off");
  const nextAction = enabled ? "Disable" : "Enable";
  const lockedHint = "Locked. Press Unlock before enabling or disabling SYNAPSE-S2 Core.";
  const unlockedHint = `Unlocked for one ${nextAction.toLowerCase()} action. Relocks after use or timeout.`;
  elements.toggleButton.disabled = !unlocked;
  elements.toggleActionButton.disabled = !unlocked;
  elements.coreUnlockButton.disabled = unlocked;
  elements.coreUnlockButton.textContent = unlocked ? "Unlocked" : "Unlock";
  elements.coreUnlockButton.setAttribute("aria-pressed", String(unlocked));
  elements.coreToggleGuardHint.textContent = unlocked ? unlockedHint : lockedHint;
  elements.toggleButton.title = unlocked
    ? `${nextAction} SYNAPSE-S2 Core`
    : "Unlock in Maintenance Controls before changing SYNAPSE-S2 Core";
  elements.toggleActionButton.title = unlocked
    ? `${nextAction} SYNAPSE-S2 Core`
    : "Unlock before changing SYNAPSE-S2 Core";
  elements.toggleButton.setAttribute("aria-label", `${nextAction} SYNAPSE-S2 Core`);
  elements.toggleActionButton.setAttribute("aria-label", `${nextAction} SYNAPSE-S2 Core`);
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

elements.nativeCertifyButton.addEventListener("click", () => {
  withBusy(elements.nativeCertifyButton, "Native certification", () => (
    requestJson("/api/certify-runtime", {
      method: "POST",
      body: {
        strict_native: true,
        benchmark_quick_prune: true,
        require_resource_envelope: true,
        write_evidence: true,
      },
    })
  ));
});

elements.graphZoomOut.addEventListener("click", () => zoomGraphBy(1 / 1.18));
elements.graphZoomIn.addEventListener("click", () => zoomGraphBy(1.18));
elements.graphFit.addEventListener("click", fitGraphToView);
elements.graphReset.addEventListener("click", resetGraphLayout);
elements.neuralInspectorToggle.addEventListener("click", () => {
  state.neuralInspector = !state.neuralInspector;
  if (state.snapshot?.graph) {
    renderGraph(state.snapshot.graph, state.snapshot.status || {});
    renderNeuralInspector(
      state.snapshot.graph,
      state.snapshot.status || {},
      state.snapshot.profile || {},
    );
  }
});

elements.coreUnlockButton.addEventListener("click", unlockCoreToggleGuard);
elements.toggleButton.addEventListener("click", () => toggleCore(elements.toggleButton));
elements.toggleActionButton.addEventListener("click", () => toggleCore(elements.toggleActionButton));

elements.cortexEnterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await enterCortexSession(elements.cortexEnterForm.querySelector("button"));
});

elements.cortexTickForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await tickCortexGovernor(elements.cortexTickForm.querySelector("button"));
});

elements.cortexCommitForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await commitCorticalTrace(elements.cortexCommitForm.querySelector("button"));
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-cortex-action]");
  if (!button) return;
  event.preventDefault();
  await moderateCortexTrace(button);
});

elements.rememberForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const tag = elements.rememberTag.value.trim();
  const text = elements.rememberText.value.trim();
  if (!tag || !text) {
    logOperation("Remember rejected", "tag and text are required");
    (!tag ? elements.rememberTag : elements.rememberText).focus();
    return;
  }
  await withBusy(elements.rememberForm.querySelector("button"), "Remember + publish", async () => {
    const payload = await requestJson("/api/remember", {
      method: "POST",
      body: {
        context_id: state.context,
        tag,
        text,
        metadata: { source: "dashboard" },
      },
    });
    await publishAwareResult(payload);
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
  await withBusy(elements.ingestForm.querySelector("button"), "Ingest + publish", async () => {
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
    await publishAwareResult(payload);
    elements.ingestText.value = "";
    return payload;
  });
});

elements.captureForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const tag = elements.captureTag.value.trim() || "codex-session";
  const speaker = elements.captureSpeaker.value.trim() || "operator";
  const text = elements.captureText.value.trim();
  if (!text) {
    logOperation("Conversation capture rejected", "conversation notes are required");
    elements.captureText.focus();
    return;
  }
  await withBusy(elements.captureForm.querySelector("button"), "Capture conversation", async () => {
    const payload = await requestJson("/api/capture-conversation", {
      method: "POST",
      body: {
        context_id: state.context,
        source_tag: tag,
        speaker,
        text,
        metadata: { source: "dashboard" },
      },
    });
    await publishAwareResult(payload);
    elements.captureText.value = "";
    return payload;
  });
});

elements.pruneForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    target_type: elements.pruneTargetType.value,
    memory_id: elements.pruneMemoryId.value.trim(),
    tag: elements.pruneTag.value.trim(),
    relationship_id: elements.pruneRelationshipId.value.trim(),
    event_id: Number(elements.pruneEventId.value || 0),
    reason: elements.pruneReason.value.trim() || "operator-dashboard-prune",
  };
  const button = elements.pruneForm.querySelector("button");
  const result = await pruneGraphItem(payload, button, payload.target_type);
  if (result) {
    elements.pruneMemoryId.value = "";
    elements.pruneRelationshipId.value = "";
    elements.pruneEventId.value = "";
    elements.pruneTag.value = "";
  }
});

elements.pruneTemporalButton.addEventListener("click", () => {
  pruneGraphItem(
    { target_type: "temporal", reason: "operator-cleared-temporal-edges" },
    elements.pruneTemporalButton,
    "all temporal relationship edges in this context",
  );
});

elements.pruneAssociativeButton.addEventListener("click", () => {
  pruneGraphItem(
    { target_type: "associative", reason: "operator-cleared-associative-edges" },
    elements.pruneAssociativeButton,
    "all associative relationship edges in this context",
  );
});

elements.memoryLedger.addEventListener("click", handleLedgerPruneClick);
elements.relationshipLedger.addEventListener("click", handleLedgerPruneClick);
elements.contextEventLedger.addEventListener("click", handleLedgerPruneClick);

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

elements.readinessAuditButton.addEventListener("click", () => {
  withBusy(elements.readinessAuditButton, "Readiness audit", () => (
    requestJson("/api/readiness-audit", {
      method: "POST",
      body: { context_id: state.context },
    })
  ));
});

elements.evidencePackButton.addEventListener("click", () => {
  withBusy(elements.evidencePackButton, "Evidence pack", () => (
    requestJson("/api/evidence-pack", {
      method: "POST",
      body: { context_id: state.context },
    })
  ));
});

elements.captureInboxButton.addEventListener("click", () => {
  withBusy(elements.captureInboxButton, "Magic capture", async () => {
    const payload = await requestJson("/api/capture-inbox/process", {
      method: "POST",
      body: { context_id: state.context, max_files: 50 },
    });
    renderCaptureInbox({
      ...(state.snapshot?.capture_inbox || {}),
      last_result: payload,
      pending_file_count: 0,
    });
    return payload;
  });
});

refreshSnapshot()
  .catch((error) => {
    logOperation("Initial load failed", error.message);
  });
