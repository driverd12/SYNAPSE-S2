const DEFAULT_CONTEXT = "default";
const THEME_STORAGE_KEY = "synapse-s2-control-theme-v4";
const SNAPSHOT_LIMIT = 80;
const GRAPH_WIDTH = 760;
const GRAPH_HEIGHT = 420;
const GRAPH_MIN_SCALE = 0.45;
const GRAPH_MAX_SCALE = 3.2;
const NAMESPACE_GALAXY_MIN_ZOOM = 0.48;
const NAMESPACE_GALAXY_MAX_ZOOM = 3.6;
const NAMESPACE_GALAXY_DEFAULT_ROTATION = Object.freeze({ x: -0.22, y: 0.48 });
const NAMESPACE_DETAIL_LIMIT = 500;
const NAMESPACE_DETAIL_GANGLION_ZOOM = 0.72;
const NAMESPACE_DETAIL_NEURON_ZOOM = 1.42;
const NAMESPACE_GALAXY_CONTEXT_PARAM = "galaxy_context";
const NAMESPACE_GALAXY_CLUSTER_PARAM = "galaxy_cluster";
const CORE_TOGGLE_UNLOCK_WINDOW_MS = 10000;
const WIZARD_FLOWS = {
  intro: {
    label: "First-time orientation",
    progressLabel: "Orientation",
    description: "Learn what each SYNAPSE-S2 surface does before operating it.",
    steps: [
  {
    selector: "#wizardToggleButton",
    title: "Start or stop the guide",
    body: "Use this top-right control whenever you want the live first-use guide. The wizard walks real dashboard controls and can be stopped at any time.",
    capability: "Guided onboarding: a live overlay for real local state, not a demo walkthrough.",
    items: [
      "Start Wizard opens the guide; Stop Wizard closes it.",
      "Use Next, Back, Escape, or the close button while walking the page.",
      "Each step points at a functioning SYNAPSE-S2 capability.",
    ],
  },
  {
    selector: "#modelUri",
    title: "Confirm the local memory target",
    body: "Start real work by checking the top readouts. They show the runtime, active memory URI, embedding provider, platform, and core state.",
    capability: "Setup: LaunchAgent dashboard, local SQLite memory, Codex/Claude MCP clients, and durable pull context bus.",
    items: [
      "Use the dashboard at 127.0.0.1:8765 for local operation.",
      "Check the Memory URI before relying on stored context.",
      "Use the Memory Context field when you need to isolate work.",
    ],
  },
  {
    selector: "#operatorActionBanner",
    title: "Follow the current required action",
    body: "This banner turns raw status into the next operator move. If Cortex says idle, that is not a failure; it means governed work has not been started for this task yet.",
    capability: "Run-order guidance: Start Work, Enter Cortex, Tick before risky actions, then Commit Trace or Wrap Session.",
    items: [
      "Use the banner first when a coworker asks what to do next.",
      "Idle Cortex means start a session before mutations or handoff claims.",
      "After validation, Commit Trace or Wrap Session, then End Session.",
    ],
  },
  {
    selector: "#operatorLoopPanel",
    title: "Run the Operator Trust Loop",
    body: "Use this band for the everyday path. Start Work gives the brief, health checks prove trust, and Wrap Session records what changed before handoff.",
    capability: "Daily workflow: Start Work, Context Health, Doctor / Repair, Memory Hygiene, Wrap Session, recipes, and receipts.",
    items: [
      "Run Start Work before relying on recall or starting risky work.",
      "Run Doctor or Memory Hygiene when confidence is degraded or the banner shows a blocker.",
      "Wrap Session before switching clients, threads, projects, or operators.",
    ],
  },
  {
    selector: "#mondayReadinessButton",
    title: "Run Monday Readiness first",
    body: "This scorecard checks real local state: runtime, memory, embeddings, capture inbox, App Connect, resource envelope, quick-prune budget, and recall.",
    capability: "Reliability: one operator-facing score before first use, handoff, or a live walkthrough.",
    items: [
      "Click Score and wait for the required checks.",
      "Resolve critical failures before writing or recalling memory.",
      "Use Self Test and Native Certify when you need lower-level evidence.",
    ],
  },
  {
    selector: "#contextSelect",
    title: "Choose the memory namespace",
    body: "Every capture, recall, graph query, and MCP hydration uses the active context. Choose an existing namespace from the menu, or type a new one when you need isolation.",
    capability: "Context bus: remembered traces publish durable updates for local MCP clients to pull.",
    items: [
      "Use default for general project work unless you need isolation.",
      "Pick a saved namespace from the menu, or enter a context name and press the check button.",
      "The Memory URI readout shows the active namespace.",
    ],
  },
  {
    selector: "#coreActionGroup",
    title: "Control the core deliberately",
    body: "There is one runtime enable/disable path. Unlock gives you a short window to change state, then it relocks.",
    capability: "Runtime control: guarded state mutation with visible ready/disabled status.",
    items: [
      "The top Runtime badge is read-only status.",
      "Use Unlock, then Enable or Disable only when you intend to pause recall/capture.",
      "Refresh Runtime State after changing state.",
    ],
  },
  {
    selector: "#rememberForm",
    title: "Write durable memory",
    body: "Use Memory Write for real facts, decisions, corrections, and validation evidence that should survive client restarts.",
    capability: "Memory write: Remember + publish, Ingest + publish, and Capture conversation.",
    items: [
      "Remember stores one concise trace with a tag.",
      "Ingest breaks sequential notes into event memories and relationships.",
      "Capture conversation records validated session summaries.",
    ],
  },
  {
    selector: "#queryForm",
    title: "Recall what has been captured",
    body: "Recall embeds your prompt locally, gates the spiking memory graph, and returns matching traces from the active context.",
    capability: "Recall: local neural embedding, sparse spiking attention, graph-backed results.",
    items: [
      "Ask for decisions, incidents, project state, or prior validation.",
      "If results are thin, capture better traces rather than broad filler.",
      "MCP clients use the same memory through the query tool.",
    ],
  },
  {
    selector: "#appConnect",
    title: "Attach a running app",
    body: "App Connect captures locally exposed Accessibility text. Preview first to see exactly what would be captured; selected-text capture is the exact-content fallback.",
    capability: "App intake: Detect, Connect app, Preview snapshot, Snapshot to memory, and selected-text capture.",
    items: [
      "Press Detect to list running apps.",
      "Connect the selected app, then preview before snapshotting.",
      "When an app exposes only window chrome, select the exact text and capture it here.",
    ],
  },
  {
    selector: "#captureInboxButton",
    title: "Process client session drops",
    body: "Magic Capture processes local inbox payloads dropped by MCP clients and the session bridge.",
    capability: "Capture daemon: sanitized local drops, startup hydration traces, and session-boundary notes.",
    items: [
      "Use this after client sessions have produced inbox files.",
      "The preflight confirmation names what will be processed.",
      "Errors stay visible until processed or repaired.",
    ],
  },
  {
    selector: "#cortexPanel",
    title: "Govern agent work",
    body: "Cortex Governor starts idle by design. Enter the current task when work becomes risky, tick before the next action, and commit only verified decisions or validation evidence.",
    capability: "Cortex: enter, tick, commit typed traces, and moderate working memory.",
    items: [
      "Not started means no agent is currently governed; it does not mean the system is broken.",
      "Start Cortex Session before file mutations, sensitive captures, or handoff claims.",
      "Tick before action, then Commit Trace, Wrap Session, and End Session after validation.",
    ],
  },
  {
    selector: "#memory",
    title: "Inspect the memory graph",
    body: "The graph shows temporal and associative relationships created from captures, ingested events, and typed traces.",
    capability: "Graph: event relationships, neural inspector, node ledger, and relationship ledger.",
    items: [
      "Use zoom and fit controls to inspect graph structure.",
      "Open Neural Inspector for sparse spike and LIF/STDP details.",
      "Use ledgers to verify exact nodes and relationships.",
    ],
  },
  {
    selector: ".graph-prune-panel",
    title: "Prune wrong or sensitive memory",
    body: "Bad memory should be removed rather than explained around. Prune the smallest bad node or relationship you can identify.",
    capability: "Memory hygiene: event, relationship, context event, temporal, and associative pruning.",
    items: [
      "Prefer a single node or edge over broad pruning.",
      "Always provide a concrete reason.",
      "Use temporal or associative clears only when the entire relationship class is bad.",
    ],
  },
  {
    selector: "#evidencePackButton",
    title: "Package evidence before sharing claims",
    body: "Evidence Pack writes a report and SQLite backup so another operator can inspect what was true at the time.",
    capability: "Operational evidence: readiness audit, snapshot, report, memory backup, and operation log.",
    items: [
      "Run this after a successful first-use flow or before a handoff.",
      "Use the Operation Log to inspect backend responses.",
      "Backups stay local inside the SYNAPSE-S2 export root.",
    ],
  },
  {
    selector: "#operationLog",
    title: "Audit each live action",
    body: "The Operation Log records dashboard requests, backend responses, cancellations, and errors as you try features in real time.",
    capability: "Operator audit: every guided action leaves visible local evidence for troubleshooting and handoff.",
    items: [
      "Check this panel after each wizard step you actively try.",
      "Use failures here to decide whether to rerun, repair, or capture a blocker.",
      "Package an Evidence Pack when the log proves the workflow is ready to share.",
    ],
  },
    ],
  },
  operator: {
    label: "Operator use",
    progressLabel: "Operator",
    description: "Walk through the required fields for a real governed work session.",
    steps: [
      {
        selector: "#operatorActionBanner",
        title: "Start with the required action",
        body: "Use the front banner as the current instruction. If it says Cortex is idle, that means you should start a governed session before risky work.",
        capability: "Run order: Start Work, Enter Cortex, Tick Action, Commit or Wrap.",
        items: [
          "Read this banner before using lower panels.",
          "Treat idle Cortex as an operator action, not a broken state.",
          "Use the shortcuts when you need to jump to the next surface.",
        ],
      },
      {
        selector: "#contextSelect",
        title: "Choose the memory context",
        body: "Confirm the context namespace before writing, recalling, or governing work. The menu shows saved namespaces; the text field remains available for a deliberate new namespace.",
        capability: "Required field: active memory context.",
        items: [
          "Use default for shared SYNAPSE-S2 project work.",
          "Choose a specific project or thread name when the memory should be isolated.",
          "Press the context check button and confirm the Memory URI updates.",
        ],
      },
      {
        selector: "#startWorkButton",
        title: "Generate the Start Work brief",
        body: "Run Start Work before relying on recall or beginning a handoff. It summarizes health, recent memory, recipes, and the next operator move.",
        capability: "Daily startup: briefing, context health, recipes, and receipts.",
        items: [
          "Click Start Work and wait for the output panel.",
          "Resolve Doctor or Context Health blockers before continuing.",
          "Use the recipe list as the live workflow checklist.",
        ],
      },
      {
        selector: "#cortexAgentId",
        title: "Confirm agent and mode",
        body: "The Agent field identifies who is being governed. The default dashboard-ui is correct for this UI; use strict mode for normal operator work.",
        capability: "Required fields: agent id and governance mode.",
        items: [
          "Leave dashboard-ui unless a named client or coworker is operating.",
          "Use strict for normal work and security for sensitive investigations.",
          "These values appear in Cortex state and committed trace evidence.",
        ],
      },
      {
        selector: "#cortexTask",
        title: "Describe the current task",
        body: "Enter the concrete work the agent is about to perform. This task becomes the governed session objective and helps future recall understand why traces were written.",
        capability: "Required field: current task before Start Cortex Session.",
        items: [
          "Write one clear outcome, not a vague project name.",
          "Include the app, repo, or customer surface when relevant.",
          "Start the session only after this field reflects the real task.",
        ],
      },
      {
        selector: "#cortexEnterForm",
        title: "Start Cortex Session",
        body: "Submit Enter Cortex after the agent, mode, and task are correct. This makes the session active and removes the idle operator warning.",
        capability: "Governance start: recall, policy, and session tracking.",
        items: [
          "Click Start Cortex Session.",
          "Check Active Sessions and Last Decision after the call returns.",
          "If it fails, use Doctor / Repair before continuing.",
        ],
      },
      {
        selector: "#cortexObservation",
        title: "Record what was observed",
        body: "Before a risky action, write the evidence or state you just observed. This makes the governor decision auditable instead of relying on memory.",
        capability: "Required tick field: observation.",
        items: [
          "Use concrete facts from the screen, test output, or app state.",
          "Do not paste secrets or unnecessary personal data.",
          "Keep it concise enough that another operator can scan it.",
        ],
      },
      {
        selector: "#cortexProposedAction",
        title: "Describe the next action",
        body: "Write the action you are about to take. The governor compares this against memory, warnings, file scope, and confidence before you mutate anything.",
        capability: "Required tick field: proposed action.",
        items: [
          "State the exact action, such as edit file, run test, attach app, or capture memory.",
          "Do this before mutations, sensitive captures, or handoff claims.",
          "If the action changes, tick again.",
        ],
      },
      {
        selector: "#cortexIntendedFiles",
        title: "Declare files and tools",
        body: "Add intended files and tools so the governor can warn when scope drifts. One path, glob, command, or tool belongs on each line.",
        capability: "Scope fields: intended files and intended tools.",
        items: [
          "Use file paths or globs for code and docs you expect to touch.",
          "List key commands or tools, such as unittest, browser QA, or app snapshot.",
          "Leave a field blank only when it truly does not apply.",
        ],
      },
      {
        selector: "#cortexConfidence",
        title: "Set confidence and mutation intent",
        body: "Mutation intent tells SYNAPSE-S2 that the next action can change state. Confidence below the safe threshold should trigger verification first.",
        capability: "Guardrails: mutation warnings and confidence thresholding.",
        items: [
          "Keep Mutation intent checked before edits, captures, pruning, or deploys.",
          "Use lower confidence when assumptions remain unresolved.",
          "Tick governor after these values match the planned action.",
        ],
      },
      {
        selector: "#cortexTickForm",
        title: "Tick the governor",
        body: "Submit the tick before acting. The response updates Last Decision, Guardrails, Next Move, and any capture recommendations.",
        capability: "Governed action check: memory-aware recommendation and warnings.",
        items: [
          "Click Tick governor and wait for the decision.",
          "Follow warnings before mutating state.",
          "Use capture recommendations when SYNAPSE-S2 asks for evidence.",
        ],
      },
      {
        selector: "#cortexTraceText",
        title: "Commit verified trace",
        body: "After the action is validated, commit a typed trace. Use observed for ordinary facts and test-validated only when you have concrete test or artifact evidence.",
        capability: "Required handoff field: verified trace text.",
        items: [
          "Choose a trace type that matches the fact: decision, validation, risk, correction, or evidence.",
          "Write the exact outcome and validation evidence.",
          "Commit only facts you want future agents to reuse.",
        ],
      },
      {
        selector: "#wrapSessionButton",
        title: "Wrap the session",
        body: "Use Wrap Session before switching tools, operators, threads, or projects. Preview first, then commit the handoff when the summary is accurate.",
        capability: "Handoff: preview, capture, receipt, and durable memory.",
        items: [
          "Add notes when the operation log does not tell the whole story.",
          "Preview the wrap before committing it to memory.",
          "End the Cortex session when the work block is complete.",
        ],
      },
      {
        selector: "#operationLog",
        title: "Verify the receipts",
        body: "The Operation Log is the final proof surface. It should show Start Work, Cortex, tick, commit, wrap, app capture, or repair actions as they happen.",
        capability: "Audit trail: visible receipts for first-use support and handoff.",
        items: [
          "Check the log after each guided action.",
          "Use failures here to rerun, repair, or capture a blocker.",
          "Restart the wizard anytime from the top-right button.",
        ],
      },
    ],
  },
};

const WIZARD_STEPS = WIZARD_FLOWS.intro.steps;

const state = {
  context: (
    new URLSearchParams(window.location.search).get(NAMESPACE_GALAXY_CONTEXT_PARAM)
    || new URLSearchParams(window.location.search).get("context_id")
  )?.trim() || DEFAULT_CONTEXT,
  snapshot: null,
  lastQueryPayload: null,
  neuralInspector: false,
  graph: {
    nodePositions: new Map(),
    transform: { x: 0, y: 0, scale: 1 },
    visibleIds: new Set(),
    interaction: null,
  },
  namespaceGalaxy: {
    status: "idle",
    view: "galaxy",
    data: { nodes: [], links: [], suggestions: [], stats: {} },
    detail: null,
    focusedDetail: null,
    detailContextId: "",
    focusedClusterId: "",
    detailPositions: new Map(),
    detailLayoutSignature: "",
    projectedGanglia: [],
    projectedMemories: [],
    projectedDetailEdges: [],
    detailSelection: null,
    detailHover: null,
    keyboardDetailId: "",
    detailRequestToken: 0,
    positions: new Map(),
    projectedNodes: [],
    projectedLinks: [],
    rotation: { ...NAMESPACE_GALAXY_DEFAULT_ROTATION },
    pan: { x: 0, y: 0 },
    zoom: 1,
    selection: null,
    hover: null,
    keyboardContextId: "",
    interaction: null,
    requestToken: 0,
    navigationToken: 0,
    pendingUrlRestore: Boolean(new URLSearchParams(window.location.search).get(NAMESPACE_GALAXY_CONTEXT_PARAM)),
    framePending: false,
    resizeObserver: null,
    reducedMotion: window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false,
  },
  nav: {
    lockedSection: null,
    lockUntilMs: 0,
  },
  coreToggle: {
    enabled: true,
    unlockedUntilMs: 0,
    lockTimer: null,
  },
  appConnect: {
    apps: [],
    connections: [],
  },
  operator: {
    receipts: [],
    lastWrapPreview: null,
  },
  cortex: {
    sessionId: "",
  },
  wizard: {
    active: false,
    flow: null,
    index: 0,
    target: null,
    scrollTimer: null,
  },
};

const elements = collectElements([
  "apiState",
  "appConnectButton",
  "appConnectForm",
  "appConnectState",
  "appConnectSubmitButton",
  "appConnectionSelect",
  "appManualName",
  "appPreviewButton",
  "appPreviewReceipt",
  "appRefreshButton",
  "appSelectionCaptureButton",
  "appSelectionText",
  "appSelect",
  "appSnapshotButton",
  "appSourceTag",
  "appSpeaker",
  "arrayCount",
  "arrayList",
  "backupButton",
  "chipLabel",
  "clearRecallButton",
  "contextApply",
  "contextBusState",
  "contextEventLedger",
  "contextHealthBadge",
  "contextHealthButton",
  "contextHealthOutput",
  "contextInput",
  "contextMenuDetails",
  "contextMenuList",
  "contextSelect",
  "contextUri",
  "coreToggleGuardHint",
  "coreStateIndicator",
  "coreUnlockButton",
  "coreVersion",
  "cortexAgentId",
  "cortexCloseButton",
  "cortexCloseText",
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
  "cortexSessionCallout",
  "cortexSessionCalloutBody",
  "cortexSessionCalloutTitle",
  "cortexSessionId",
  "cortexTask",
  "cortexTickForm",
  "cortexTraceText",
  "cortexTraceType",
  "cortexTruthPosture",
  "cortexTypedCounts",
  "cortexWarnings",
  "cortexWorkingMemory",
  "doctorReportButton",
  "doctorReportOutput",
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
  "goalLedger",
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
  "memoryHygieneButton",
  "memoryHygieneQueue",
  "memoryQualityBadge",
  "memoryLedger",
  "memoryState",
  "modeLabel",
  "mondayReadinessButton",
  "nativeCertifyButton",
  "neuralInspectorToggle",
  "neuralMathPanel",
  "namespaceGalaxyCanvas",
  "namespaceGalaxyAccessibleHelp",
  "namespaceGalaxyAccessibleSummary",
  "namespaceGalaxyBack",
  "namespaceGalaxyBreadcrumbAll",
  "namespaceGalaxyBreadcrumbGanglion",
  "namespaceGalaxyBreadcrumbGanglionWrap",
  "namespaceGalaxyBreadcrumbNamespace",
  "namespaceGalaxyBreadcrumbNamespaceWrap",
  "namespaceGalaxyDepthCortex",
  "namespaceGalaxyDepthGanglia",
  "namespaceGalaxyDepthNeurons",
  "namespaceGalaxyDepthValue",
  "namespaceGalaxyFit",
  "namespaceGalaxyHelp",
  "namespaceGalaxyInspector",
  "namespaceGalaxyInspectorActions",
  "namespaceGalaxyInspectorBody",
  "namespaceGalaxyInspectorFacts",
  "namespaceGalaxyInspectorTitle",
  "namespaceGalaxyLinkCount",
  "namespaceGalaxyLegend",
  "namespaceGalaxyList",
  "namespaceGalaxyNodeCount",
  "namespaceGalaxyOrbitLeft",
  "namespaceGalaxyOrbitRight",
  "namespaceGalaxyReset",
  "namespaceGalaxyState",
  "namespaceGalaxySuggestionCount",
  "namespaceGalaxySuggestionList",
  "namespaceGalaxyTooltip",
  "namespaceGalaxyZoomIn",
  "namespaceGalaxyZoomOut",
  "modelUri",
  "operationLog",
  "operatorReceipts",
  "operatorRecipes",
  "operatorActionBanner",
  "operatorActionBody",
  "operatorActionContext",
  "operatorActionStatus",
  "operatorActionTitle",
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
  "recallScopeAll",
  "recallScopeConnected",
  "recallScopeHelp",
  "recallScopeLocal",
  "recipeChecklist",
  "recipeDrawer",
  "recipesCloseButton",
  "recipesToggleButton",
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
  "selfTestButton",
  "selfTestGrid",
  "selfTestState",
  "sleepButton",
  "startWorkButton",
  "startWorkOutput",
  "themeButton",
  "toggleActionButton",
  "toggleActionState",
  "toggleText",
  "traceCache",
  "uptimeLabel",
  "wizardArrow",
  "wizardArrowPath",
  "wizardArrowTip",
  "wizardBackButton",
  "wizardBody",
  "wizardCapability",
  "wizardChecklist",
  "wizardCloseButton",
  "wizardEyebrow",
  "wizardFlowPicker",
  "wizardIntroFlowButton",
  "wizardLayer",
  "wizardNextButton",
  "wizardOperatorFlowButton",
  "wizardPanel",
  "wizardProgress",
  "wizardSpotlight",
  "wizardTitle",
  "wizardToggleButton",
  "wizardToggleText",
  "wrapSessionButton",
  "wrapSessionNotes",
  "wrapSessionOutput",
  "wrapSessionPreviewButton",
]);

elements.contextInput.value = state.context;
elements.endpointLabel.textContent = window.location.host || "127.0.0.1:8765";
applyTheme(loadTheme());
initializeGraphInteractions();
initializeNamespaceGalaxy();
initializeSectionNavigation();
initializeWizard();
renderOperatorRecipes(defaultOperatorRecipes());
renderRecipeDrawer(defaultOperatorRecipes());

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

function confirmPreflight(title, lines) {
  const cleanLines = lines
    .map((line) => String(line || "").trim())
    .filter(Boolean);
  return window.confirm([title, "", ...cleanLines].join("\n"));
}

function loadTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return stored === "dark" || stored === "light" ? stored : "dark";
  } catch {
    return "dark";
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
  requestNamespaceGalaxyDraw();
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
  const namespaceMapPromise = refreshNamespaceGalaxy();
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
  await namespaceMapPromise;
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

  renderContextSelector(contexts);
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

  state.coreToggle.enabled = enabled;
  elements.toggleText.textContent = enabled ? "Core enabled" : "Core disabled";
  elements.coreStateIndicator.classList.toggle("off", !enabled);
  elements.coreStateIndicator.setAttribute(
    "aria-label",
    `SYNAPSE-S2 Core currently ${enabled ? "enabled" : "disabled"}`,
  );
  elements.coreStateIndicator.title = `SYNAPSE-S2 Core is currently ${enabled ? "enabled" : "disabled"}`;
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

function renderContextSelector(contexts = {}) {
  const currentContext = state.context || DEFAULT_CONTEXT;
  const rows = Object.entries(contexts)
    .map(([name, count]) => ({
      name: String(name || "").trim(),
      count: Number(count),
    }))
    .filter((row) => row.name);

  if (!rows.some((row) => row.name === currentContext)) {
    rows.push({ name: currentContext, count: NaN });
  }

  rows.sort((left, right) => {
    if (left.name === DEFAULT_CONTEXT) return -1;
    if (right.name === DEFAULT_CONTEXT) return 1;
    return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
  });

  elements.contextSelect.innerHTML = rows
    .map((row) => {
      const selected = row.name === currentContext ? " selected" : "";
      return `<option value="${escapeHtml(row.name)}"${selected}>${escapeHtml(formatContextOption(row))}</option>`;
    })
    .join("");
  elements.contextSelect.disabled = rows.length === 0;
  elements.contextSelect.value = currentContext;
  elements.contextSelect.title = rows.length
    ? `${formatNumber(rows.length)} saved memory contexts`
    : "No saved contexts returned yet";
  elements.contextSelect.setAttribute(
    "aria-label",
    `Choose existing memory context. ${formatNumber(rows.length)} saved contexts available.`,
  );
  elements.contextMenuList.innerHTML = rows
    .map((row) => {
      const selected = row.name === currentContext ? "true" : "false";
      return [
        `<button type="button" class="context-choice-button" data-context="${escapeHtml(row.name)}" aria-current="${selected}" role="option" aria-selected="${selected}">`,
        `<span>${escapeHtml(row.name)}</span>`,
        `<span>${Number.isFinite(row.count) ? escapeHtml(formatNumber(row.count)) : "current"}</span>`,
        "</button>",
      ].join("");
    })
    .join("");
  elements.contextMenuDetails.hidden = rows.length === 0;
}

function formatContextOption(row) {
  if (!Number.isFinite(row.count)) {
    return `${row.name} (current)`;
  }
  return `${row.name} (${formatNumber(row.count)})`;
}

async function applySelectedContext(context, busyElement = elements.contextApply) {
  const nextContext = String(context || "").trim() || DEFAULT_CONTEXT;
  const galaxy = state.namespaceGalaxy;
  const switchingOpenNamespace = galaxy.view === "namespace"
    && Boolean(galaxy.detailContextId)
    && galaxy.detailContextId !== nextContext;
  if (switchingOpenNamespace) {
    galaxy.navigationToken += 1;
    galaxy.detailRequestToken += 1;
    galaxy.detailContextId = nextContext;
    galaxy.focusedClusterId = "";
    galaxy.detail = null;
    galaxy.focusedDetail = null;
    galaxy.detailSelection = null;
    galaxy.detailHover = null;
    updateNamespaceGalaxyUrl({ contextId: nextContext, replace: true });
    updateNamespaceGalaxyChrome();
  }
  state.context = nextContext;
  const galaxyNode = state.namespaceGalaxy.data.nodes.find((item) => item.contextId === nextContext);
  if (galaxyNode && state.namespaceGalaxy.view === "galaxy") {
    selectNamespaceGalaxyItem(galaxyNode, { focusCanvas: false });
  }
  elements.contextInput.value = nextContext;
  if ([...elements.contextSelect.options].some((option) => option.value === nextContext)) {
    elements.contextSelect.value = nextContext;
  }
  const url = new URL(window.location.href);
  url.searchParams.set("context_id", nextContext);
  // Context selection is also part of the drill-down route. Preserve its
  // history marker so browser Back/Escape still returns through the depth.
  history.replaceState(history.state, "", url);
  await withBusy(busyElement, "Context", refreshSnapshot, { refresh: false });
  if (switchingOpenNamespace && galaxy.view === "namespace" && galaxy.detailContextId === nextContext) {
    await refreshNamespaceDetail({ contextId: nextContext });
  }
}

function initializeNamespaceGalaxy() {
  const canvas = elements.namespaceGalaxyCanvas;
  const reducedMotionQuery = window.matchMedia?.("(prefers-reduced-motion: reduce)");
  const updateReducedMotion = (event) => {
    state.namespaceGalaxy.reducedMotion = Boolean(event.matches);
    requestNamespaceGalaxyDraw();
  };
  reducedMotionQuery?.addEventListener?.("change", updateReducedMotion);

  const resize = () => {
    resizeNamespaceGalaxyCanvas();
    requestNamespaceGalaxyDraw();
  };
  if (typeof ResizeObserver === "function") {
    state.namespaceGalaxy.resizeObserver = new ResizeObserver(resize);
    state.namespaceGalaxy.resizeObserver.observe(canvas);
  } else {
    window.addEventListener("resize", resize);
  }

  canvas.addEventListener("pointerdown", (event) => {
    const point = namespaceGalaxyPointerPoint(event);
    state.namespaceGalaxy.interaction = {
      pointerId: event.pointerId,
      startX: point.x,
      startY: point.y,
      lastX: point.x,
      lastY: point.y,
      mode: event.shiftKey || event.button === 1 ? "pan" : "orbit",
      moved: false,
    };
    canvas.setPointerCapture?.(event.pointerId);
    canvas.classList.add("is-interacting");
  });

  canvas.addEventListener("pointermove", (event) => {
    const point = namespaceGalaxyPointerPoint(event);
    const interaction = state.namespaceGalaxy.interaction;
    if (interaction && interaction.pointerId === event.pointerId) {
      const dx = point.x - interaction.lastX;
      const dy = point.y - interaction.lastY;
      if (Math.hypot(point.x - interaction.startX, point.y - interaction.startY) > 4) {
        interaction.moved = true;
      }
      if (interaction.mode === "pan") {
        state.namespaceGalaxy.pan.x += dx;
        state.namespaceGalaxy.pan.y += dy;
      } else {
        state.namespaceGalaxy.rotation.y += dx * 0.008;
        state.namespaceGalaxy.rotation.x = clamp(
          state.namespaceGalaxy.rotation.x + dy * 0.008,
          -Math.PI * 0.48,
          Math.PI * 0.48,
        );
      }
      interaction.lastX = point.x;
      interaction.lastY = point.y;
      hideNamespaceGalaxyTooltip();
      requestNamespaceGalaxyDraw();
      return;
    }
    if (state.namespaceGalaxy.view === "namespace") updateNamespaceDetailHover(point.x, point.y);
    else updateNamespaceGalaxyHover(point.x, point.y);
  });

  const finishPointer = (event) => {
    const interaction = state.namespaceGalaxy.interaction;
    if (!interaction || interaction.pointerId !== event.pointerId) return;
    const point = namespaceGalaxyPointerPoint(event);
    state.namespaceGalaxy.interaction = null;
    canvas.classList.remove("is-interacting");
    canvas.releasePointerCapture?.(event.pointerId);
    if (!interaction.moved) {
      const hit = state.namespaceGalaxy.view === "namespace"
        ? hitNamespaceDetail(point.x, point.y)
        : hitNamespaceGalaxy(point.x, point.y);
      if (hit) {
        if (state.namespaceGalaxy.view === "namespace") {
          selectNamespaceDetailItem(hit.item, { focusCanvas: false });
          if (hit.item.kind === "ganglion") {
            void focusNamespaceGanglion(hit.item.clusterId, { pushHistory: true });
          }
        } else {
          if (hit.item.kind === "node") {
            void enterNamespaceGalaxy(hit.item.contextId, { pushHistory: true });
          } else {
            selectNamespaceGalaxyItem(hit.item, { focusCanvas: false });
          }
        }
      }
    }
  };
  canvas.addEventListener("pointerup", finishPointer);
  canvas.addEventListener("pointercancel", finishPointer);
  canvas.addEventListener("pointerleave", () => {
    if (!state.namespaceGalaxy.interaction) {
      if (state.namespaceGalaxy.view === "namespace") state.namespaceGalaxy.detailHover = null;
      else state.namespaceGalaxy.hover = null;
      hideNamespaceGalaxyTooltip();
      requestNamespaceGalaxyDraw();
    }
  });
  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.1 : 1 / 1.1;
    setNamespaceGalaxyZoom(state.namespaceGalaxy.zoom * factor);
  }, { passive: false });
  canvas.addEventListener("keydown", handleNamespaceGalaxyKeydown);
  canvas.addEventListener("focus", () => {
    if (state.namespaceGalaxy.view === "namespace") {
      ensureNamespaceDetailKeyboardSelection();
      requestNamespaceGalaxyDraw();
      return;
    }
    const nodes = state.namespaceGalaxy.data.nodes;
    if (!state.namespaceGalaxy.keyboardContextId && nodes.length) {
      state.namespaceGalaxy.keyboardContextId = nodes.find((node) => node.contextId === state.context)?.contextId
        || nodes[0].contextId;
      const node = nodes.find((candidate) => candidate.contextId === state.namespaceGalaxy.keyboardContextId);
      if (node) selectNamespaceGalaxyItem(node, { focusCanvas: false });
    }
    requestNamespaceGalaxyDraw();
  });
  canvas.addEventListener("blur", requestNamespaceGalaxyDraw);

  elements.namespaceGalaxyOrbitLeft.addEventListener("click", () => orbitNamespaceGalaxy(-0.24));
  elements.namespaceGalaxyOrbitRight.addEventListener("click", () => orbitNamespaceGalaxy(0.24));
  elements.namespaceGalaxyZoomOut.addEventListener("click", () => setNamespaceGalaxyZoom(state.namespaceGalaxy.zoom / 1.18));
  elements.namespaceGalaxyZoomIn.addEventListener("click", () => setNamespaceGalaxyZoom(state.namespaceGalaxy.zoom * 1.18));
  elements.namespaceGalaxyFit.addEventListener("click", fitNamespaceGalaxy);
  elements.namespaceGalaxyReset.addEventListener("click", resetNamespaceGalaxyView);
  elements.namespaceGalaxyBack.addEventListener("click", () => {
    if (state.namespaceGalaxy.focusedClusterId) clearNamespaceGanglionFocus({ useHistory: true });
    else exitNamespaceGalaxy({ useHistory: true });
  });
  elements.namespaceGalaxyBreadcrumbAll.addEventListener("click", () => {
    exitNamespaceGalaxy({ useHistory: true });
  });
  elements.namespaceGalaxyBreadcrumbNamespace.addEventListener("click", () => {
    clearNamespaceGanglionFocus({ useHistory: true });
  });

  elements.namespaceGalaxyList.addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-galaxy-action], [data-galaxy-context]");
    if (!button) return;
    event.preventDefault();
    handleNamespaceGalaxyListAction(button);
  });
  elements.namespaceGalaxyInspector.addEventListener("click", handleNamespaceGalaxyInspectorClick);
  window.addEventListener("popstate", restoreNamespaceGalaxyFromUrl);
  resizeNamespaceGalaxyCanvas();
  updateRecallScopeHelp();
  updateNamespaceGalaxyChrome();
}

async function refreshNamespaceGalaxy() {
  const requestToken = ++state.namespaceGalaxy.requestToken;
  const contextId = state.context;
  const hasData = state.namespaceGalaxy.data.nodes.length > 0;
  if (!hasData) {
    setNamespaceGalaxyState("loading", "Loading Namespace Galaxy", "Reading contexts and approved bridges.");
  }
  try {
    const payload = await requestJson("/api/namespace-map", {
      params: { context_id: contextId },
    });
    if (requestToken !== state.namespaceGalaxy.requestToken || contextId !== state.context) return null;
    const data = normalizeNamespaceMap(payload);
    renderNamespaceGalaxy(data);
    if (data.nodes.length && state.namespaceGalaxy.view === "galaxy") {
      setNamespaceGalaxyState("ready", "Namespace Galaxy ready", "");
    } else if (state.namespaceGalaxy.view === "galaxy") {
      setNamespaceGalaxyState("empty", "No saved namespaces", "Capture memory in a context to place it in the galaxy.");
    }
    if (state.namespaceGalaxy.pendingUrlRestore) {
      state.namespaceGalaxy.pendingUrlRestore = false;
      restoreNamespaceGalaxyFromUrl();
    }
    return data;
  } catch (error) {
    if (requestToken !== state.namespaceGalaxy.requestToken || contextId !== state.context) return null;
    const fallback = namespaceMapFallbackFromSnapshot();
    if (fallback.nodes.length) {
      renderNamespaceGalaxy(fallback);
      if (state.namespaceGalaxy.view === "galaxy") {
        setNamespaceGalaxyState(
          "warning",
          "Bridge map unavailable",
          "Showing saved contexts from runtime status; relationship data could not be loaded.",
        );
      }
    } else {
      renderNamespaceGalaxy({ nodes: [], links: [], suggestions: [], stats: {} });
      setNamespaceGalaxyState("error", "Namespace Galaxy unavailable", error.message || "The namespace map could not be loaded.");
    }
    logOperation("Namespace Galaxy refresh failed", error.message);
    return fallback;
  }
}

async function enterNamespaceGalaxy(contextId, { pushHistory = false, clusterId = "" } = {}) {
  const nextContextId = String(contextId || "").trim();
  if (!nextContextId) return null;
  const galaxy = state.namespaceGalaxy;
  const navigationToken = ++galaxy.navigationToken;
  galaxy.view = "namespace";
  galaxy.detailContextId = nextContextId;
  galaxy.focusedClusterId = "";
  galaxy.focusedDetail = null;
  galaxy.detailSelection = null;
  galaxy.detailHover = null;
  galaxy.keyboardDetailId = "";
  galaxy.rotation = { x: -0.1, y: 0.12 };
  galaxy.pan = { x: 0, y: 0 };
  galaxy.zoom = 1;
  updateNamespaceGalaxyChrome();
  setNamespaceGalaxyState("loading", `Opening ${nextContextId}`, "Reading stored ganglia, neurons, and relationships.");
  if (pushHistory) updateNamespaceGalaxyUrl({ contextId: nextContextId, push: true });
  if (state.context !== nextContextId) {
    await applySelectedContext(nextContextId, elements.contextApply);
  }
  if (navigationToken !== galaxy.navigationToken || galaxy.view !== "namespace" || galaxy.detailContextId !== nextContextId) {
    return null;
  }
  const detail = await refreshNamespaceDetail({ contextId: nextContextId });
  if (detail && clusterId) {
    await focusNamespaceGanglion(clusterId, { pushHistory: false });
  }
  elements.namespaceGalaxyCanvas.focus({ preventScroll: true });
  return detail;
}

async function refreshNamespaceDetail({ contextId, clusterId = "" } = {}) {
  const galaxy = state.namespaceGalaxy;
  const nextContextId = String(contextId || galaxy.detailContextId || state.context).trim();
  const nextClusterId = String(clusterId || "").trim();
  const requestToken = ++galaxy.detailRequestToken;
  try {
    const payload = await requestJson("/api/namespace-detail", {
      params: {
        context_id: nextContextId,
        level: "neurons",
        ...(nextClusterId ? { cluster_id: nextClusterId } : {}),
        limit: NAMESPACE_DETAIL_LIMIT,
      },
    });
    if (requestToken !== galaxy.detailRequestToken || galaxy.view !== "namespace") return null;
    if (nextContextId !== galaxy.detailContextId) return null;
    if (nextClusterId !== galaxy.focusedClusterId) return null;
    const detail = normalizeNamespaceDetail(payload);
    if (nextClusterId) {
      galaxy.focusedDetail = detail;
    } else {
      galaxy.detail = detail;
    }
    renderNamespaceDetail();
    if (detail.empty || (!detail.clusters.length && !detail.nodes.length)) {
      setNamespaceGalaxyState("empty", `${nextContextId} has no stored neurons`, "This read-only namespace has no graph detail to display yet.");
    } else {
      setNamespaceGalaxyState("ready", `${nextContextId} detail ready`, "");
    }
    return detail;
  } catch (error) {
    if (requestToken !== galaxy.detailRequestToken || galaxy.view !== "namespace") return null;
    setNamespaceGalaxyState("error", "Namespace detail unavailable", error.message || "The read-only namespace detail could not be loaded.");
    renderNamespaceDetail();
    logOperation("Namespace detail refresh failed", error.message);
    return null;
  }
}

function normalizeNamespaceDetail(payload = {}) {
  const rawNamespace = payload.namespace && typeof payload.namespace === "object" ? payload.namespace : {};
  const contextId = String(payload.context_id ?? rawNamespace.context_id ?? state.namespaceGalaxy.detailContextId ?? "").trim();
  const namespace = {
    kind: "namespace-detail",
    id: String(rawNamespace.node_id || `s2ctx:${contextId}`),
    contextId,
    label: String(rawNamespace.display_label || contextId || "Unnamed namespace"),
    stored: rawNamespace.stored !== false,
    entryTotal: galaxyNumber(rawNamespace.entry_total ?? payload.counts?.memory_total, 0),
    relationshipTotal: galaxyNumber(rawNamespace.relationship_total ?? payload.counts?.relationship_total, 0),
    firstCreatedAt: rawNamespace.first_created_at ?? null,
    lastUpdatedAt: rawNamespace.last_updated_at ?? null,
    provenance: rawNamespace.provenance ?? null,
    raw: rawNamespace,
  };
  const clusters = (Array.isArray(payload.clusters) ? payload.clusters : [])
    .map((rawCluster) => {
      const clusterId = String(rawCluster?.cluster_id ?? "").trim();
      if (!clusterId) return null;
      return {
        kind: "ganglion",
        id: String(rawCluster?.node_id || `ganglion:${contextId}:${clusterId}`),
        clusterId,
        contextId,
        label: String(rawCluster?.display_label || clusterId),
        basis: String(rawCluster?.basis || "stored_type"),
        anchorMemoryId: rawCluster?.anchor_memory_id ?? null,
        memoryTotal: galaxyNumber(rawCluster?.memory_total, 0),
        memberMemoryIds: Array.isArray(rawCluster?.member_memory_id_sample) ? rawCluster.member_memory_id_sample.map(String) : [],
        nodeTypeCounts: rawCluster?.node_type_counts && typeof rawCluster.node_type_counts === "object" ? rawCluster.node_type_counts : {},
        firstCreatedAt: rawCluster?.first_created_at ?? null,
        lastUpdatedAt: rawCluster?.last_updated_at ?? null,
        semanticFacets: rawCluster?.semantic_facets ?? null,
        raw: rawCluster,
      };
    })
    .filter(Boolean);
  const nodes = (Array.isArray(payload.nodes) ? payload.nodes : [])
    .map((rawNode) => {
      const memoryId = String(rawNode?.memory_id ?? "").trim();
      if (!memoryId) return null;
      return {
        kind: "memory",
        id: String(rawNode?.node_id || memoryId),
        memoryId,
        contextId: String(rawNode?.context_id || contextId),
        clusterId: String(rawNode?.cluster_id || "").trim(),
        nodeType: String(rawNode?.node_type || "memory"),
        tag: String(rawNode?.tag || ""),
        label: String(rawNode?.display_label || rawNode?.excerpt || rawNode?.tag || memoryId),
        excerpt: String(rawNode?.excerpt || ""),
        createdAt: rawNode?.created_at ?? null,
        updatedAt: rawNode?.updated_at ?? null,
        source: rawNode?.source ?? null,
        provenance: rawNode?.provenance ?? null,
        semanticFacets: rawNode?.semantic_facets ?? null,
        detailBadges: Array.isArray(rawNode?.detail_badges) ? rawNode.detail_badges.map(String) : [],
        raw: rawNode,
      };
    })
    .filter(Boolean);
  const edges = (Array.isArray(payload.edges) ? payload.edges : [])
    .map((rawEdge, index) => {
      const sourceId = String(rawEdge?.source_id ?? rawEdge?.source ?? "").trim();
      const targetId = String(rawEdge?.target_id ?? rawEdge?.target ?? "").trim();
      if (!sourceId || !targetId || sourceId === targetId) return null;
      return {
        kind: "detail-edge",
        id: String(rawEdge?.edge_id || `detail-edge:${sourceId}:${targetId}:${index}`),
        sourceId,
        targetId,
        edgeType: String(rawEdge?.edge_type || "relationship"),
        direction: String(rawEdge?.direction || "directed"),
        weight: clamp(galaxyNumber(rawEdge?.weight, 0.5), 0, 1),
        createdAt: rawEdge?.created_at ?? null,
        updatedAt: rawEdge?.updated_at ?? null,
        provenance: rawEdge?.provenance ?? null,
        raw: rawEdge,
      };
    })
    .filter(Boolean);
  return {
    action: String(payload.action || "namespace-detail"),
    readOnly: payload.read_only !== false,
    contextId,
    level: String(payload.level || "neurons"),
    selectedClusterId: String(payload.selected_cluster_id || ""),
    empty: Boolean(payload.empty),
    namespace,
    counts: payload.counts && typeof payload.counts === "object" ? payload.counts : {},
    truncation: payload.truncation && typeof payload.truncation === "object" ? payload.truncation : {},
    clusters,
    nodes,
    edges,
  };
}

function combinedNamespaceDetail() {
  const base = state.namespaceGalaxy.detail;
  if (!base) return null;
  const focused = state.namespaceGalaxy.focusedDetail;
  if (!focused || !state.namespaceGalaxy.focusedClusterId) return base;
  const clusterId = state.namespaceGalaxy.focusedClusterId;
  const nodes = new Map(base.nodes.filter((node) => node.clusterId !== clusterId).map((node) => [node.id, node]));
  focused.nodes.forEach((node) => nodes.set(node.id, node));
  const edges = new Map(base.edges.map((edge) => [edge.id, edge]));
  focused.edges.forEach((edge) => edges.set(edge.id, edge));
  const clusters = new Map(base.clusters.map((cluster) => [cluster.clusterId, cluster]));
  focused.clusters.forEach((cluster) => clusters.set(cluster.clusterId, cluster));
  return { ...base, nodes: [...nodes.values()], edges: [...edges.values()], clusters: [...clusters.values()] };
}

async function focusNamespaceGanglion(clusterId, { pushHistory = false } = {}) {
  const galaxy = state.namespaceGalaxy;
  const nextClusterId = String(clusterId || "").trim();
  if (galaxy.view !== "namespace" || !nextClusterId) return null;
  const cluster = galaxy.detail?.clusters.find((item) => item.clusterId === nextClusterId);
  if (!cluster) return null;
  galaxy.focusedClusterId = nextClusterId;
  galaxy.detailSelection = cluster;
  galaxy.keyboardDetailId = cluster.id;
  galaxy.detailHover = null;
  galaxy.zoom = Math.max(galaxy.zoom, 1.58);
  galaxy.pan = { x: 0, y: 0 };
  rebuildNamespaceDetailLayout();
  renderNamespaceDetailInspector(cluster);
  updateNamespaceGalaxyChrome();
  renderNamespaceDetailList();
  requestNamespaceGalaxyDraw();
  if (pushHistory) updateNamespaceGalaxyUrl({ contextId: galaxy.detailContextId, clusterId: nextClusterId, push: true });
  setNamespaceGalaxyState("loading", `Expanding ${cluster.label}`, "Loading the bounded exact neurons and relationships for this ganglion.");
  return refreshNamespaceDetail({ contextId: galaxy.detailContextId, clusterId: nextClusterId });
}

function clearNamespaceGanglionFocus({ useHistory = false } = {}) {
  const galaxy = state.namespaceGalaxy;
  if (galaxy.view !== "namespace") return;
  if (useHistory && history.state?.namespaceGalaxyView === "ganglion") {
    history.back();
    return;
  }
  galaxy.focusedClusterId = "";
  galaxy.detailRequestToken += 1;
  galaxy.focusedDetail = null;
  galaxy.detailSelection = galaxy.detail?.namespace || null;
  galaxy.keyboardDetailId = galaxy.detail?.clusters[0]?.id || "";
  galaxy.zoom = 1;
  galaxy.pan = { x: 0, y: 0 };
  rebuildNamespaceDetailLayout();
  renderNamespaceDetailInspector(galaxy.detailSelection);
  renderNamespaceDetailList();
  updateNamespaceGalaxyChrome();
  requestNamespaceGalaxyDraw();
  updateNamespaceGalaxyUrl({ contextId: galaxy.detailContextId, replace: true });
}

function exitNamespaceGalaxy({ useHistory = false } = {}) {
  const galaxy = state.namespaceGalaxy;
  if (galaxy.view === "galaxy") return;
  if (useHistory && history.state?.namespaceGalaxyView && !history.state?.namespaceGalaxyDeepLink) {
    const steps = history.state.namespaceGalaxyView === "ganglion" ? -2 : -1;
    history.go(steps);
    return;
  }
  galaxy.view = "galaxy";
  galaxy.navigationToken += 1;
  galaxy.detailRequestToken += 1;
  galaxy.detailContextId = "";
  galaxy.focusedClusterId = "";
  galaxy.focusedDetail = null;
  galaxy.detailSelection = null;
  galaxy.detailHover = null;
  galaxy.zoom = 1;
  galaxy.pan = { x: 0, y: 0 };
  galaxy.rotation = { ...NAMESPACE_GALAXY_DEFAULT_ROTATION };
  updateNamespaceGalaxyUrl({ replace: true });
  updateNamespaceGalaxyChrome();
  const selection = galaxy.data.nodes.find((node) => node.contextId === state.context) || galaxy.data.nodes[0] || null;
  galaxy.selection = selection;
  renderNamespaceGalaxyInspector(selection);
  renderNamespaceGalaxyList(galaxy.data.nodes);
  setNamespaceGalaxyState(galaxy.data.nodes.length ? "ready" : "empty", galaxy.data.nodes.length ? "Namespace Galaxy ready" : "No saved namespaces", "");
  requestNamespaceGalaxyDraw();
}

function updateNamespaceGalaxyUrl({ contextId = "", clusterId = "", push = false, replace = false } = {}) {
  const url = new URL(window.location.href);
  if (contextId) {
    url.searchParams.set("context_id", contextId);
    url.searchParams.set(NAMESPACE_GALAXY_CONTEXT_PARAM, contextId);
    if (clusterId) url.searchParams.set(NAMESPACE_GALAXY_CLUSTER_PARAM, clusterId);
    else url.searchParams.delete(NAMESPACE_GALAXY_CLUSTER_PARAM);
  } else {
    url.searchParams.delete(NAMESPACE_GALAXY_CONTEXT_PARAM);
    url.searchParams.delete(NAMESPACE_GALAXY_CLUSTER_PARAM);
  }
  url.hash = "namespaceGalaxy";
  const marker = contextId ? (clusterId ? "ganglion" : "namespace") : "galaxy";
  const historyState = { namespaceGalaxyView: marker };
  if (push) history.pushState(historyState, "", url);
  else if (replace) history.replaceState(historyState, "", url);
}

async function restoreNamespaceGalaxyFromUrl() {
  const url = new URL(window.location.href);
  const contextId = String(url.searchParams.get(NAMESPACE_GALAXY_CONTEXT_PARAM) || "").trim();
  const clusterId = String(url.searchParams.get(NAMESPACE_GALAXY_CLUSTER_PARAM) || "").trim();
  if (!contextId) {
    const poppedContextId = String(url.searchParams.get("context_id") || DEFAULT_CONTEXT).trim()
      || DEFAULT_CONTEXT;
    state.namespaceGalaxy.pendingUrlRestore = false;
    exitNamespaceGalaxy({ useHistory: false });
    if (poppedContextId !== state.context) {
      try {
        await applySelectedContext(poppedContextId, elements.contextApply);
      } catch (error) {
        logOperation("Namespace context restore failed", error.message);
      }
    }
    return;
  }
  if (!state.namespaceGalaxy.data.nodes.length) {
    state.namespaceGalaxy.pendingUrlRestore = true;
    return;
  }
  if (!state.namespaceGalaxy.data.nodes.some((node) => node.contextId === contextId)) {
    setNamespaceGalaxyState("warning", "Namespace is not available", `The saved namespace “${contextId}” is not present in this map.`);
    return;
  }
  state.namespaceGalaxy.pendingUrlRestore = false;
  void enterNamespaceGalaxy(contextId, { pushHistory: false, clusterId });
}

function normalizeNamespaceMap(payload = {}) {
  const nodeMap = new Map();
  const sourceNodes = Array.isArray(payload.nodes) ? payload.nodes : [];
  sourceNodes.forEach((rawNode) => {
    const contextId = String(rawNode?.context_id ?? rawNode?.contextId ?? rawNode?.id ?? "").trim();
    if (!contextId) return;
    nodeMap.set(contextId, {
      kind: "node",
      id: `node:${contextId}`,
      contextId,
      entryCount: galaxyNumber(rawNode.entry_count ?? rawNode.memory_count ?? rawNode.count, 0),
      relationshipCount: galaxyOptionalNumber(rawNode.relationship_count ?? rawNode.edge_count),
      eventCount: galaxyOptionalNumber(rawNode.event_count ?? rawNode.context_event_count),
      updatedAt: rawNode.updated_at
        ?? rawNode.last_updated_at
        ?? rawNode.last_event_at
        ?? rawNode.last_activity_at
        ?? null,
      raw: rawNode,
    });
  });

  const selectedContextId = String(payload.selected_context_id || state.context || DEFAULT_CONTEXT).trim();

  const normalizeBridge = (rawLink, kind, index) => {
    const sourceContextId = String(
      rawLink?.source_context_id ?? rawLink?.source_context ?? rawLink?.source ?? "",
    ).trim();
    const targetContextId = String(
      rawLink?.target_context_id ?? rawLink?.target_context ?? rawLink?.target ?? "",
    ).trim();
    if (!sourceContextId || !targetContextId || sourceContextId === targetContextId) return null;
    const relationType = String(rawLink?.relation_type ?? rawLink?.relationship_type ?? "related_to").trim() || "related_to";
    const rawWeight = rawLink?.weight
      ?? rawLink?.score
      ?? rawLink?.dice_score
      ?? rawLink?.similarity
      ?? rawLink?.confidence;
    const weight = clamp(galaxyNumber(rawWeight, kind === "suggestion" ? 0 : 0.5), 0, 1);
    const directionValue = String(rawLink?.direction || "bidirectional").trim().toLowerCase();
    const direction = directionValue === "directed" ? "directed" : "bidirectional";
    const suggestedPhaseDelayTicks = Math.max(0, Math.trunc(galaxyNumber(
      rawLink?.suggested_phase_delay_ticks
        ?? rawLink?.evidence?.suggested_phase_delay_ticks,
      0,
    )));
    const suppliedId = rawLink?.context_link_id ?? rawLink?.relationship_id ?? rawLink?.suggestion_id;
    return {
      kind,
      id: String(suppliedId || `${kind}:${sourceContextId}:${targetContextId}:${relationType}:${index}`),
      sourceContextId,
      targetContextId,
      relationType,
      weight,
      direction,
      suggestedPhaseDelayTicks,
      enabled: kind === "suggestion" ? false : rawLink?.enabled !== false,
      approved: kind === "suggestion" ? false : rawLink?.approved !== false,
      evidence: namespaceEvidenceText(rawLink?.evidence ?? rawLink?.reason ?? rawLink?.provenance),
      verifiedAt: rawLink?.verified_at ?? rawLink?.updated_at ?? null,
      raw: rawLink,
    };
  };

  const links = (Array.isArray(payload.links) ? payload.links : [])
    .map((rawLink, index) => normalizeBridge(rawLink, "link", index))
    .filter(Boolean);
  const suggestions = (Array.isArray(payload.suggestions) ? payload.suggestions : [])
    .map((rawLink, index) => normalizeBridge(rawLink, "suggestion", index))
    .filter(Boolean)
    .sort((left, right) => right.weight - left.weight);

  // Links are meaningful only when both ends are actual stored contexts. Do not
  // manufacture planets for a stale link or a currently selected empty context.
  const hasStoredEndpoint = (link) => (
    nodeMap.has(link.sourceContextId) && nodeMap.has(link.targetContextId)
  );

  return {
    scope: String(payload.scope || "all"),
    selectedContextId,
    nodes: [...nodeMap.values()].sort((left, right) => (
      right.entryCount - left.entryCount
      || left.contextId.localeCompare(right.contextId, undefined, { sensitivity: "base" })
    )),
    links: links.filter(hasStoredEndpoint),
    suggestions: suggestions.filter(hasStoredEndpoint),
    stats: payload.stats && typeof payload.stats === "object" ? payload.stats : {},
  };
}

function namespaceMapFallbackFromSnapshot() {
  const contexts = state.snapshot?.status?.memory_contexts || {};
  return normalizeNamespaceMap({
    selected_context_id: state.context,
    nodes: Object.entries(contexts).map(([contextId, entryCount]) => ({
      context_id: contextId,
      entry_count: entryCount,
    })),
    links: [],
    suggestions: [],
    stats: { fallback: true },
  });
}

function galaxyNumber(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function galaxyOptionalNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function namespaceEvidenceText(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string") return compactNamespaceEvidence(value);
  if (Array.isArray(value)) {
    return compactNamespaceEvidence(value.slice(0, 6).map(namespaceEvidenceText).filter(Boolean).join("; "));
  }
  if (typeof value === "object") {
    const preferredKeys = [
      "summary",
      "reason",
      "source",
      "method",
      "dice_score",
      "surface_overlap_count",
      "spike_overlap_count",
      "delay_semantics",
    ];
    const rows = preferredKeys
      .filter((key) => value[key] !== undefined && value[key] !== null && value[key] !== "")
      .map((key) => `${key.replaceAll("_", " ")}: ${String(value[key])}`);
    if (!rows.length) {
      rows.push(...Object.entries(value)
        .filter(([, item]) => ["string", "number", "boolean"].includes(typeof item))
        .slice(0, 6)
        .map(([key, item]) => `${key.replaceAll("_", " ")}: ${String(item)}`));
    }
    return compactNamespaceEvidence(rows.join("; "));
  }
  return compactNamespaceEvidence(String(value));
}

function compactNamespaceEvidence(value, maxLength = 520) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function renderNamespaceGalaxy(data) {
  const galaxy = state.namespaceGalaxy;
  const previousSelection = galaxy.selection;
  galaxy.data = data;
  const layoutSignature = namespaceGalaxyLayoutSignature(data);
  if (galaxy.layoutSignature !== layoutSignature) {
    galaxy.layoutSignature = layoutSignature;
    galaxy.positions = buildNamespaceGalaxyLayout(data.nodes, data.links);
  }

  elements.namespaceGalaxyNodeCount.textContent = formatNumber(data.nodes.length);
  elements.namespaceGalaxyLinkCount.textContent = formatNumber(data.links.length);
  elements.namespaceGalaxySuggestionCount.textContent = formatNumber(data.suggestions.length);
  if (galaxy.view === "namespace") {
    updateNamespaceGalaxyChrome();
    if (galaxy.detail) renderNamespaceDetailList();
    resizeNamespaceGalaxyCanvas();
    requestNamespaceGalaxyDraw();
    return;
  }
  renderNamespaceGalaxyList(data.nodes);

  let selection = findNamespaceGalaxyItem(previousSelection?.kind, previousSelection?.id);
  if (!selection) {
    selection = data.nodes.find((node) => node.contextId === state.context) || data.nodes[0] || null;
  }
  galaxy.selection = selection;
  galaxy.keyboardContextId = selection?.kind === "node" ? selection.contextId : galaxy.keyboardContextId;
  renderNamespaceGalaxyInspector(selection);
  resizeNamespaceGalaxyCanvas();
  requestNamespaceGalaxyDraw();
}

function namespaceGalaxyLayoutSignature(data) {
  const nodes = data.nodes.map((node) => node.contextId).sort().join("|");
  const links = data.links
    .map((link) => `${link.sourceContextId}>${link.targetContextId}:${link.weight.toFixed(3)}`)
    .sort()
    .join("|");
  return `${nodes}::${links}`;
}

function buildNamespaceGalaxyLayout(nodes, links) {
  const positions = new Map();
  nodes.forEach((node, index) => {
    const vector = namespaceHashVector(node.contextId, index, nodes.length);
    positions.set(node.contextId, vector);
  });
  if (nodes.length <= 1) {
    const only = nodes[0];
    if (only) positions.set(only.contextId, { x: 0, y: 0, z: 0 });
    return positions;
  }

  const linkRows = links
    .map((link) => ({
      source: positions.get(link.sourceContextId),
      target: positions.get(link.targetContextId),
      weight: clamp(link.weight, 0.08, 1),
    }))
    .filter((link) => link.source && link.target && link.source !== link.target);
  const vectors = [...positions.values()];
  const iterations = Math.min(84, Math.max(36, nodes.length * 2));
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const cooling = 1 - iteration / iterations;
    const deltas = new Map(vectors.map((vector) => [vector, { x: 0, y: 0, z: 0 }]));
    for (let leftIndex = 0; leftIndex < vectors.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < vectors.length; rightIndex += 1) {
        const left = vectors[leftIndex];
        const right = vectors[rightIndex];
        const dx = left.x - right.x;
        const dy = left.y - right.y;
        const dz = left.z - right.z;
        const distanceSquared = dx * dx + dy * dy + dz * dz + 0.025;
        const force = Math.min(0.045, 0.0048 / distanceSquared) * cooling;
        const length = Math.sqrt(distanceSquared);
        const fx = (dx / length) * force;
        const fy = (dy / length) * force;
        const fz = (dz / length) * force;
        deltas.get(left).x += fx;
        deltas.get(left).y += fy;
        deltas.get(left).z += fz;
        deltas.get(right).x -= fx;
        deltas.get(right).y -= fy;
        deltas.get(right).z -= fz;
      }
    }
    linkRows.forEach((link) => {
      const dx = link.target.x - link.source.x;
      const dy = link.target.y - link.source.y;
      const dz = link.target.z - link.source.z;
      const distance = Math.max(0.001, Math.hypot(dx, dy, dz));
      const idealDistance = 0.46 + (1 - link.weight) * 0.26;
      const force = (distance - idealDistance) * 0.032 * link.weight * cooling;
      const fx = (dx / distance) * force;
      const fy = (dy / distance) * force;
      const fz = (dz / distance) * force;
      deltas.get(link.source).x += fx;
      deltas.get(link.source).y += fy;
      deltas.get(link.source).z += fz;
      deltas.get(link.target).x -= fx;
      deltas.get(link.target).y -= fy;
      deltas.get(link.target).z -= fz;
    });
    vectors.forEach((vector) => {
      const delta = deltas.get(vector);
      vector.x = clamp(vector.x + delta.x - vector.x * 0.005, -1.12, 1.12);
      vector.y = clamp(vector.y + delta.y - vector.y * 0.005, -1.12, 1.12);
      vector.z = clamp(vector.z + delta.z - vector.z * 0.005, -1.12, 1.12);
    });
  }
  return positions;
}

function namespaceHashVector(contextId, index, count) {
  let hash = 2166136261;
  for (const character of String(contextId)) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  const unit = (shift) => ((hash >>> shift) & 1023) / 1023;
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const angle = index * goldenAngle + unit(2) * 0.82;
  const z = count > 1 ? 1 - (2 * index) / (count - 1) : 0;
  const radial = Math.sqrt(Math.max(0, 1 - z * z));
  const shell = 0.48 + unit(12) * 0.5;
  return {
    x: Math.cos(angle) * radial * shell,
    y: Math.sin(angle) * radial * shell,
    z: z * shell + (unit(20) - 0.5) * 0.18,
  };
}

function renderNamespaceDetail() {
  const galaxy = state.namespaceGalaxy;
  const detail = combinedNamespaceDetail();
  updateNamespaceGalaxyChrome();
  if (!detail) {
    renderNamespaceDetailInspector(null);
    renderNamespaceDetailList();
    requestNamespaceGalaxyDraw();
    return;
  }
  rebuildNamespaceDetailLayout();
  let selection = findNamespaceDetailItem(galaxy.detailSelection?.kind, galaxy.detailSelection?.id);
  if (!selection && galaxy.focusedClusterId) {
    selection = detail.clusters.find((cluster) => cluster.clusterId === galaxy.focusedClusterId) || null;
  }
  if (!selection) selection = detail.namespace;
  galaxy.detailSelection = selection;
  galaxy.keyboardDetailId = selection?.kind === "namespace-detail"
    ? (detail.clusters[0]?.id || "")
    : selection?.id || galaxy.keyboardDetailId;
  renderNamespaceDetailInspector(selection);
  renderNamespaceDetailList();
  resizeNamespaceGalaxyCanvas();
  requestNamespaceGalaxyDraw();
}

function rebuildNamespaceDetailLayout() {
  const galaxy = state.namespaceGalaxy;
  const detail = combinedNamespaceDetail();
  if (!detail) {
    galaxy.detailPositions = new Map();
    galaxy.detailLayoutSignature = "";
    return;
  }
  const signature = [
    detail.contextId,
    galaxy.focusedClusterId,
    detail.clusters.map((cluster) => `${cluster.clusterId}:${cluster.memoryTotal}`).sort().join("|"),
    detail.nodes.map((node) => node.id).sort().join("|"),
  ].join("::");
  if (signature === galaxy.detailLayoutSignature) return;
  galaxy.detailLayoutSignature = signature;
  galaxy.detailPositions = buildNamespaceDetailLayout(detail, galaxy.focusedClusterId);
}

function buildNamespaceDetailLayout(detail, focusedClusterId = "") {
  const positions = new Map();
  const clusters = [...detail.clusters].sort((left, right) => (
    right.memoryTotal - left.memoryTotal
    || left.label.localeCompare(right.label, undefined, { sensitivity: "base" })
  ));
  const focusIndex = clusters.findIndex((cluster) => cluster.clusterId === focusedClusterId);
  const centerCluster = focusIndex >= 0 ? clusters.splice(focusIndex, 1)[0] : clusters.shift();
  if (centerCluster) positions.set(centerCluster.id, { x: 0, y: 0, z: 0.16 });
  const orbitCount = clusters.length;
  clusters.forEach((cluster, index) => {
    const hash = stableNamespaceHash(cluster.clusterId);
    const angle = orbitCount > 0 ? (index / orbitCount) * Math.PI * 2 - Math.PI * 0.62 : 0;
    const ring = focusedClusterId ? 0.88 : 0.76 + ((hash >>> 8) % 11) / 100;
    positions.set(cluster.id, {
      x: Math.cos(angle) * ring,
      y: Math.sin(angle) * ring * (focusedClusterId ? 0.72 : 0.64),
      z: (((hash >>> 18) & 255) / 255 - 0.5) * 0.42,
    });
  });

  const clusterById = new Map(detail.clusters.map((cluster) => [cluster.clusterId, cluster]));
  const grouped = new Map();
  detail.nodes.forEach((node) => {
    if (!grouped.has(node.clusterId)) grouped.set(node.clusterId, []);
    grouped.get(node.clusterId).push(node);
  });
  grouped.forEach((nodes, clusterId) => {
    const cluster = clusterById.get(clusterId);
    const center = positions.get(cluster?.id) || { x: 0, y: 0, z: -0.05 };
    const ordered = [...nodes].sort((left, right) => left.id.localeCompare(right.id));
    ordered.forEach((node, index) => {
      const hash = stableNamespaceHash(node.id);
      const angle = index * Math.PI * (3 - Math.sqrt(5)) + ((hash & 1023) / 1023) * 0.7;
      const expanded = clusterId === focusedClusterId;
      const radius = (expanded ? 0.045 : 0.032) + Math.sqrt(index + 1) * (expanded ? 0.022 : 0.0155);
      positions.set(node.id, {
        x: center.x + Math.cos(angle) * Math.min(radius, expanded ? 0.48 : 0.3),
        y: center.y + Math.sin(angle) * Math.min(radius, expanded ? 0.4 : 0.25) * 0.72,
        z: center.z + ((((hash >>> 12) & 255) / 255) - 0.5) * (expanded ? 0.34 : 0.2),
      });
    });
  });
  return positions;
}

function stableNamespaceHash(value) {
  let hash = 2166136261;
  for (const character of String(value || "")) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function currentNamespaceDetailLod() {
  if (state.namespaceGalaxy.zoom < NAMESPACE_DETAIL_GANGLION_ZOOM) return "cortex";
  if (state.namespaceGalaxy.zoom < NAMESPACE_DETAIL_NEURON_ZOOM) return "ganglia";
  return "neurons";
}

function drawNamespaceDetail(context, width, height, palette) {
  const galaxy = state.namespaceGalaxy;
  const detail = combinedNamespaceDetail();
  galaxy.projectedGanglia = [];
  galaxy.projectedMemories = [];
  galaxy.projectedDetailEdges = [];
  updateNamespaceDetailDepthChrome();
  if (!detail) return;
  const lod = currentNamespaceDetailLod();
  drawNamespaceDetailField(context, width, height, palette, lod);
  if (lod === "cortex") {
    drawNamespaceCortex(context, detail, width, height, palette);
    return;
  }

  const ganglia = detail.clusters
    .map((cluster) => projectNamespaceDetailItem(cluster, width, height))
    .filter(Boolean)
    .sort((left, right) => left.depth - right.depth);
  const visibleNodes = visibleNamespaceDetailNodes(detail, lod);
  const memories = visibleNodes
    .map((node) => projectNamespaceDetailItem(node, width, height))
    .filter(Boolean)
    .sort((left, right) => left.depth - right.depth);
  const ganglionByCluster = new Map(ganglia.map((item) => [item.item.clusterId, item]));
  const memoryById = new Map(memories.map((item) => [item.item.id, item]));

  drawNamespaceMembershipTendrils(context, memories, ganglionByCluster, palette, lod);
  const projectedEdges = lod === "neurons"
    ? projectExactNamespaceDetailEdges(detail.edges, memoryById, ganglionByCluster)
    : projectAggregateNamespaceDetailEdges(detail, ganglionByCluster);
  projectedEdges.sort((left, right) => left.depth - right.depth)
    .forEach((edge) => drawNamespaceDetailEdge(context, edge, palette, lod));
  memories.forEach((node) => drawNamespaceMemoryNode(context, node, palette, lod));
  ganglia.forEach((cluster) => drawNamespaceGanglion(context, cluster, palette));
  drawNamespaceDetailLabels(context, ganglia, memories, palette, width, height, lod);

  galaxy.projectedGanglia = ganglia;
  galaxy.projectedMemories = memories;
  galaxy.projectedDetailEdges = projectedEdges;
}

function drawNamespaceDetailField(context, width, height, palette, lod) {
  const centerX = width / 2 + state.namespaceGalaxy.pan.x;
  const centerY = height / 2 + state.namespaceGalaxy.pan.y;
  context.save();
  context.globalAlpha = lod === "neurons" ? 0.16 : 0.24;
  context.strokeStyle = palette.depth;
  context.lineWidth = 1;
  [0.34, 0.58, 0.82].forEach((amount) => {
    context.beginPath();
    context.ellipse(centerX, centerY, width * amount * 0.5, height * amount * 0.38, state.namespaceGalaxy.rotation.x * 0.2, 0, Math.PI * 2);
    context.stroke();
  });
  context.restore();
}

function drawNamespaceCortex(context, detail, width, height, palette) {
  const selected = state.namespaceGalaxy.detailSelection?.kind === "namespace-detail";
  const radius = clamp(30 + Math.log1p(detail.namespace.entryTotal) * 3.2, 34, 72);
  const x = width / 2 + state.namespaceGalaxy.pan.x;
  const y = height / 2 + state.namespaceGalaxy.pan.y;
  const gradient = context.createRadialGradient(x - radius * 0.28, y - radius * 0.28, 2, x, y, radius);
  gradient.addColorStop(0, palette.nodeHighlight);
  gradient.addColorStop(0.35, palette.node);
  gradient.addColorStop(1, palette.nodeShadow);
  context.save();
  context.shadowColor = selected ? palette.selected : palette.nodeHighlight;
  context.shadowBlur = selected ? 28 : 18;
  context.fillStyle = gradient;
  context.beginPath();
  context.arc(x, y, radius, 0, Math.PI * 2);
  context.fill();
  context.strokeStyle = selected ? palette.selected : palette.nodeHighlight;
  context.lineWidth = selected ? 3 : 1.5;
  context.stroke();
  context.shadowBlur = 0;
  context.fillStyle = palette.text;
  context.font = "600 13px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.textAlign = "center";
  context.fillText(truncateCanvasLabel(detail.namespace.label, 34), x, y + radius + 23);
  context.fillStyle = palette.muted;
  context.font = "11px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.fillText(`${formatNumber(detail.namespace.entryTotal)} stored memories`, x, y + radius + 40);
  context.restore();
}

function visibleNamespaceDetailNodes(detail, lod) {
  const focusId = state.namespaceGalaxy.focusedClusterId;
  if (lod === "neurons") {
    if (!focusId) return detail.nodes;
    const focused = detail.nodes.filter((node) => node.clusterId === focusId);
    const context = detail.nodes.filter((node) => node.clusterId !== focusId)
      .filter((node, index) => index % Math.max(1, Math.ceil(detail.nodes.length / 80)) === 0)
      .slice(0, 80);
    return [...focused, ...context];
  }
  const counts = new Map();
  return detail.nodes.filter((node) => {
    const count = counts.get(node.clusterId) || 0;
    const limit = node.clusterId === focusId ? 24 : 12;
    counts.set(node.clusterId, count + 1);
    return count < limit;
  });
}

function projectNamespaceDetailItem(item, width, height) {
  const position = state.namespaceGalaxy.detailPositions.get(item.id);
  if (!position) return null;
  const rotated = rotateNamespacePoint(position, state.namespaceGalaxy.rotation);
  const perspective = 2.7 / Math.max(1.35, 2.95 - rotated.z);
  const xScale = width * 0.43 * state.namespaceGalaxy.zoom;
  const yScale = height * 0.43 * state.namespaceGalaxy.zoom;
  const isGanglion = item.kind === "ganglion";
  const radius = isGanglion
    ? clamp((8 + Math.log1p(Math.max(0, item.memoryTotal)) * 1.45) * perspective, 8, 25)
    : clamp((1.45 + state.namespaceGalaxy.zoom * 0.72) * perspective, 1.5, 5.2);
  return {
    item,
    x: width / 2 + state.namespaceGalaxy.pan.x + rotated.x * xScale * perspective,
    y: height / 2 + state.namespaceGalaxy.pan.y + rotated.y * yScale * perspective,
    radius,
    depth: rotated.z,
    perspective,
  };
}

function drawNamespaceMembershipTendrils(context, memories, ganglionByCluster, palette, lod) {
  context.save();
  context.strokeStyle = palette.strong;
  context.lineWidth = lod === "neurons" ? 0.7 : 0.8;
  context.globalAlpha = lod === "neurons" ? 0.18 : 0.3;
  memories.forEach((memory) => {
    const ganglion = ganglionByCluster.get(memory.item.clusterId);
    if (!ganglion) return;
    const midX = (ganglion.x + memory.x) / 2 + (memory.y - ganglion.y) * 0.08;
    const midY = (ganglion.y + memory.y) / 2 - (memory.x - ganglion.x) * 0.04;
    context.beginPath();
    context.moveTo(ganglion.x, ganglion.y);
    context.quadraticCurveTo(midX, midY, memory.x, memory.y);
    context.stroke();
  });
  context.restore();
}

function projectExactNamespaceDetailEdges(edges, memoryById, ganglionByCluster) {
  return edges.map((edge) => {
    const source = memoryById.get(edge.sourceId)
      || [...ganglionByCluster.values()].find((item) => item.item.id === edge.sourceId);
    const target = memoryById.get(edge.targetId)
      || [...ganglionByCluster.values()].find((item) => item.item.id === edge.targetId);
    if (!source || !target) return null;
    return { item: edge, source, target, depth: (source.depth + target.depth) / 2, aggregateCount: 1 };
  }).filter(Boolean);
}

function projectAggregateNamespaceDetailEdges(detail, ganglionByCluster) {
  const clusterByNode = new Map(detail.nodes.map((node) => [node.id, node.clusterId]));
  const aggregate = new Map();
  detail.edges.forEach((edge) => {
    const sourceCluster = clusterByNode.get(edge.sourceId);
    const targetCluster = clusterByNode.get(edge.targetId);
    if (!sourceCluster || !targetCluster || sourceCluster === targetCluster) return;
    const key = [sourceCluster, targetCluster].sort().join("::");
    const row = aggregate.get(key) || {
      kind: "detail-edge",
      id: `aggregate:${key}`,
      sourceCluster,
      targetCluster,
      edgeType: edge.edgeType,
      direction: edge.direction,
      weight: 0,
      count: 0,
    };
    row.weight = Math.max(row.weight, edge.weight);
    row.count += 1;
    aggregate.set(key, row);
  });
  return [...aggregate.values()].map((edge) => {
    const source = ganglionByCluster.get(edge.sourceCluster);
    const target = ganglionByCluster.get(edge.targetCluster);
    if (!source || !target) return null;
    return { item: edge, source, target, depth: (source.depth + target.depth) / 2, aggregateCount: edge.count };
  }).filter(Boolean);
}

function drawNamespaceDetailEdge(context, projected, palette, lod) {
  const associative = /associative|semantic|overlap/i.test(projected.item.edgeType);
  context.save();
  context.strokeStyle = associative ? palette.associative : palette.strong;
  context.globalAlpha = associative ? 0.38 : 0.46;
  context.lineWidth = clamp(0.55 + projected.item.weight * 1.3 + Math.log1p(projected.aggregateCount) * 0.2, 0.6, 2.6);
  if (associative) context.setLineDash(lod === "neurons" ? [3, 4] : [2, 5]);
  const curve = (projected.target.x - projected.source.x) * 0.04;
  context.beginPath();
  context.moveTo(projected.source.x, projected.source.y);
  context.quadraticCurveTo(
    (projected.source.x + projected.target.x) / 2,
    (projected.source.y + projected.target.y) / 2 - curve,
    projected.target.x,
    projected.target.y,
  );
  context.stroke();
  context.restore();
}

function drawNamespaceGanglion(context, projected, palette) {
  const selected = state.namespaceGalaxy.detailSelection?.kind === "ganglion"
    && state.namespaceGalaxy.detailSelection.id === projected.item.id;
  const focused = state.namespaceGalaxy.focusedClusterId === projected.item.clusterId;
  const hovered = state.namespaceGalaxy.detailHover?.kind === "ganglion"
    && state.namespaceGalaxy.detailHover.id === projected.item.id;
  const active = selected || focused || hovered;
  const glow = active ? palette.selected : palette.nodeHighlight;
  const gradient = context.createRadialGradient(
    projected.x - projected.radius * 0.28,
    projected.y - projected.radius * 0.28,
    1,
    projected.x,
    projected.y,
    projected.radius,
  );
  gradient.addColorStop(0, active ? palette.selected : palette.nodeHighlight);
  gradient.addColorStop(0.42, palette.node);
  gradient.addColorStop(1, palette.nodeShadow);
  context.save();
  context.shadowColor = glow;
  context.shadowBlur = active ? 24 : 14;
  context.fillStyle = gradient;
  context.beginPath();
  context.arc(projected.x, projected.y, projected.radius, 0, Math.PI * 2);
  context.fill();
  context.shadowBlur = 0;
  context.strokeStyle = glow;
  context.globalAlpha = active ? 0.96 : 0.72;
  context.lineWidth = active ? 2.4 : 1.1;
  context.stroke();
  if (active) {
    context.globalAlpha = 0.45;
    context.beginPath();
    context.arc(projected.x, projected.y, projected.radius + 5, 0, Math.PI * 2);
    context.stroke();
  }
  context.restore();
}

function drawNamespaceMemoryNode(context, projected, palette, lod) {
  const selected = state.namespaceGalaxy.detailSelection?.kind === "memory"
    && state.namespaceGalaxy.detailSelection.id === projected.item.id;
  const hovered = state.namespaceGalaxy.detailHover?.kind === "memory"
    && state.namespaceGalaxy.detailHover.id === projected.item.id;
  context.save();
  context.fillStyle = selected ? palette.selected : palette.neuron;
  context.globalAlpha = selected || hovered ? 1 : lod === "neurons" ? 0.82 : 0.68;
  context.shadowColor = selected ? palette.selected : palette.neuron;
  context.shadowBlur = selected || hovered ? 10 : 4;
  context.beginPath();
  context.arc(projected.x, projected.y, projected.radius + (selected ? 1.3 : 0), 0, Math.PI * 2);
  context.fill();
  context.restore();
}

function drawNamespaceDetailLabels(context, ganglia, memories, palette, width, height, lod) {
  const occupied = [];
  const sorted = [...ganglia].sort((left, right) => {
    const leftPriority = left.item.clusterId === state.namespaceGalaxy.focusedClusterId ? 10_000 : left.item.memoryTotal;
    const rightPriority = right.item.clusterId === state.namespaceGalaxy.focusedClusterId ? 10_000 : right.item.memoryTotal;
    return rightPriority - leftPriority;
  });
  context.save();
  context.textBaseline = "middle";
  sorted.forEach((cluster, index) => {
    const focused = cluster.item.clusterId === state.namespaceGalaxy.focusedClusterId;
    const labelLimit = width < 540 ? 6 : width < 900 ? 12 : 18;
    if (!focused && index >= labelLimit) return;
    const label = truncateCanvasLabel(cluster.item.label, width < 620 ? 22 : 30);
    context.font = "600 11px ui-monospace, SFMono-Regular, Menlo, monospace";
    const labelWidth = context.measureText(label).width + 10;
    const labelHeight = 18;
    const preferredX = clamp(cluster.x + cluster.radius + 7, 5, width - labelWidth - 5);
    const preferredY = clamp(cluster.y - 9, 5, height - labelHeight - 5);
    const box = { x: preferredX, y: preferredY, width: labelWidth, height: labelHeight };
    const collisionBox = { ...box, height: width > 660 ? 30 : labelHeight };
    if (!focused && occupied.some((row) => rectanglesOverlap(row, collisionBox))) return;
    occupied.push(collisionBox);
    context.globalAlpha = 0.9;
    context.fillStyle = palette.labelBackground;
    context.fillRect(box.x, box.y, box.width, box.height);
    context.fillStyle = focused ? palette.selected : palette.text;
    context.fillText(label, box.x + 5, box.y + box.height / 2);
    if (width > 660) {
      context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
      context.fillStyle = palette.muted;
      context.fillText(`${formatNumber(cluster.item.memoryTotal)} neurons`, box.x + 5, box.y + box.height + 10);
    }
  });
  if (lod === "neurons") {
    const selected = memories.find((memory) => memory.item.id === state.namespaceGalaxy.detailSelection?.id)
      || memories.find((memory) => memory.item.id === state.namespaceGalaxy.detailHover?.id);
    if (selected) {
      const label = truncateCanvasLabel(selected.item.label, 36);
      context.font = "500 10px ui-monospace, SFMono-Regular, Menlo, monospace";
      const labelWidth = Math.min(width - 16, context.measureText(label).width + 10);
      const x = clamp(selected.x + 8, 6, width - labelWidth - 6);
      const y = clamp(selected.y - 20, 6, height - 24);
      context.fillStyle = palette.labelBackground;
      context.fillRect(x, y, labelWidth, 18);
      context.fillStyle = palette.selected;
      context.fillText(label, x + 5, y + 9);
    }
  }
  context.restore();
}

function truncateCanvasLabel(value, maxLength) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function resizeNamespaceGalaxyCanvas() {
  const canvas = elements.namespaceGalaxyCanvas;
  const rect = canvas.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return;
  const dpr = clamp(window.devicePixelRatio || 1, 1, 2.5);
  const nextWidth = Math.round(rect.width * dpr);
  const nextHeight = Math.round(rect.height * dpr);
  if (canvas.width !== nextWidth || canvas.height !== nextHeight) {
    canvas.width = nextWidth;
    canvas.height = nextHeight;
  }
}

function requestNamespaceGalaxyDraw() {
  if (state.namespaceGalaxy.framePending) return;
  state.namespaceGalaxy.framePending = true;
  window.requestAnimationFrame(() => {
    state.namespaceGalaxy.framePending = false;
    drawNamespaceGalaxy();
  });
}

function drawNamespaceGalaxy() {
  const canvas = elements.namespaceGalaxyCanvas;
  const context = canvas.getContext("2d");
  if (!context) return;
  resizeNamespaceGalaxyCanvas();
  const rect = canvas.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return;
  const dpr = canvas.width / rect.width;
  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  const width = rect.width;
  const height = rect.height;
  const palette = namespaceGalaxyPalette();
  context.clearRect(0, 0, width, height);
  context.fillStyle = palette.background;
  context.fillRect(0, 0, width, height);

  if (state.namespaceGalaxy.view === "namespace") {
    drawNamespaceDetail(context, width, height, palette);
    return;
  }

  drawNamespaceGalaxyDepthField(context, width, height, palette);
  const data = state.namespaceGalaxy.data;
  const maxEntries = Math.max(1, ...data.nodes.map((node) => node.entryCount));
  const projectedNodes = data.nodes
    .map((node) => projectNamespaceNode(node, maxEntries, width, height))
    .filter(Boolean)
    .sort((left, right) => left.depth - right.depth);
  const projectedById = new Map(projectedNodes.map((node) => [node.item.contextId, node]));
  const visibleSuggestions = visibleNamespaceSuggestions(data.suggestions);
  const projectedLinks = [...data.links, ...visibleSuggestions]
    .map((link) => projectNamespaceBridge(link, projectedById))
    .filter(Boolean)
    .sort((left, right) => left.depth - right.depth);

  projectedLinks.forEach((link) => drawNamespaceBridge(context, link, palette));
  projectedNodes.forEach((node) => drawNamespaceSphere(context, node, palette));
  drawNamespaceLabels(context, projectedNodes, palette, width, height);

  state.namespaceGalaxy.projectedNodes = projectedNodes;
  state.namespaceGalaxy.projectedLinks = projectedLinks;
}

function namespaceGalaxyPalette() {
  const styles = getComputedStyle(document.documentElement);
  const value = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
  return {
    background: value("--galaxy-bg", "#03080c"),
    depth: value("--galaxy-depth", "#123238"),
    bridge: value("--galaxy-bridge", "#00e6c7"),
    bridgeDisabled: value("--galaxy-bridge-disabled", "#65786e"),
    suggestion: value("--galaxy-suggestion", "#b88cff"),
    strong: value("--galaxy-strong", "#58dbc2"),
    associative: value("--galaxy-associative", "#955ae5"),
    node: value("--galaxy-node", "#1ca8a2"),
    nodeHighlight: value("--galaxy-node-highlight", "#8affdf"),
    nodeShadow: value("--galaxy-node-shadow", "#07383a"),
    nodeEmpty: value("--galaxy-node-empty", "#d38b2c"),
    selected: value("--galaxy-selected", "#9dff4f"),
    text: value("--galaxy-text", "#f0ffe8"),
    muted: value("--galaxy-muted", "#93aa9c"),
    labelBackground: value("--galaxy-label-bg", "rgba(3, 8, 12, 0.82)"),
    neuron: value("--galaxy-neuron", "#79f6ee"),
    neuronMuted: value("--galaxy-neuron-muted", "#2b6f70"),
  };
}

function drawNamespaceGalaxyDepthField(context, width, height, palette) {
  const centerX = width / 2 + state.namespaceGalaxy.pan.x;
  const centerY = height / 2 + state.namespaceGalaxy.pan.y;
  const base = Math.min(width, height) * 0.27 * state.namespaceGalaxy.zoom;
  context.save();
  context.strokeStyle = palette.depth;
  context.lineWidth = 1;
  context.globalAlpha = 0.38;
  [0.7, 1.08, 1.46].forEach((scale) => {
    context.beginPath();
    context.ellipse(centerX, centerY, base * scale, base * scale * 0.46, state.namespaceGalaxy.rotation.x * 0.42, 0, Math.PI * 2);
    context.stroke();
  });
  context.globalAlpha = 0.22;
  context.beginPath();
  context.moveTo(centerX - base * 1.6, centerY);
  context.lineTo(centerX + base * 1.6, centerY);
  context.moveTo(centerX, centerY - base * 0.95);
  context.lineTo(centerX, centerY + base * 0.95);
  context.stroke();
  context.restore();
}

function projectNamespaceNode(node, maxEntries, width, height) {
  const position = state.namespaceGalaxy.positions.get(node.contextId);
  if (!position) return null;
  const rotated = rotateNamespacePoint(position, state.namespaceGalaxy.rotation);
  const perspective = 2.65 / Math.max(1.25, 2.85 - rotated.z);
  const scale = Math.min(width, height) * 0.38 * state.namespaceGalaxy.zoom;
  const volume = Math.log1p(Math.max(0, node.entryCount)) / Math.log1p(maxEntries);
  const baseRadius = 7 + Math.sqrt(volume) * 18;
  return {
    item: node,
    x: width / 2 + state.namespaceGalaxy.pan.x + rotated.x * scale * perspective,
    y: height / 2 + state.namespaceGalaxy.pan.y + rotated.y * scale * perspective,
    radius: clamp(baseRadius * perspective, 5.5, 34),
    depth: rotated.z,
    perspective,
  };
}

function rotateNamespacePoint(position, rotation) {
  const cosY = Math.cos(rotation.y);
  const sinY = Math.sin(rotation.y);
  const xY = position.x * cosY + position.z * sinY;
  const zY = -position.x * sinY + position.z * cosY;
  const cosX = Math.cos(rotation.x);
  const sinX = Math.sin(rotation.x);
  return {
    x: xY,
    y: position.y * cosX - zY * sinX,
    z: position.y * sinX + zY * cosX,
  };
}

function visibleNamespaceSuggestions(suggestions) {
  const activeContext = state.namespaceGalaxy.selection?.kind === "node"
    ? state.namespaceGalaxy.selection.contextId
    : state.context;
  const related = suggestions.filter((suggestion) => (
    suggestion.sourceContextId === activeContext || suggestion.targetContextId === activeContext
  ));
  const chosen = (related.length ? related : suggestions).slice(0, 12);
  const selected = state.namespaceGalaxy.selection;
  if (selected?.kind === "suggestion" && !chosen.some((item) => item.id === selected.id)) {
    chosen.push(selected);
  }
  return chosen;
}

function projectNamespaceBridge(link, projectedById) {
  const source = projectedById.get(link.sourceContextId);
  const target = projectedById.get(link.targetContextId);
  if (!source || !target) return null;
  return {
    item: link,
    source,
    target,
    x1: source.x,
    y1: source.y,
    x2: target.x,
    y2: target.y,
    depth: (source.depth + target.depth) / 2,
    lineWidth: 0.8 + link.weight * 2.4,
  };
}

function drawNamespaceBridge(context, bridge, palette) {
  const { item } = bridge;
  const selected = state.namespaceGalaxy.selection?.id === item.id
    && state.namespaceGalaxy.selection?.kind === item.kind;
  const hovered = state.namespaceGalaxy.hover?.id === item.id
    && state.namespaceGalaxy.hover?.kind === item.kind;
  const isSuggestion = item.kind === "suggestion";
  context.save();
  context.strokeStyle = isSuggestion
    ? palette.suggestion
    : item.enabled
      ? palette.bridge
      : palette.bridgeDisabled;
  context.lineWidth = bridge.lineWidth + (selected || hovered ? 1.8 : 0);
  context.globalAlpha = selected || hovered
    ? 0.94
    : isSuggestion
      ? 0.42
      : item.enabled
        ? 0.28 + item.weight * 0.42
        : 0.34;
  const visualDelay = Math.max(0, Number(item.suggestedPhaseDelayTicks || 0));
  context.setLineDash(
    isSuggestion
      ? [2 + Math.min(visualDelay, 4), 7 + Math.min(visualDelay * 1.5, 6)]
      : item.enabled
        ? []
        : [8, 7],
  );
  context.beginPath();
  context.moveTo(bridge.x1, bridge.y1);
  context.lineTo(bridge.x2, bridge.y2);
  context.stroke();
  if (!isSuggestion && item.enabled) {
    drawNamespaceBridgeDirection(context, bridge);
    if (item.direction === "bidirectional") {
      drawNamespaceBridgeDirection(context, bridge, true);
    }
  }
  context.restore();
}

function drawNamespaceBridgeDirection(context, bridge, reverse = false) {
  const startX = reverse ? bridge.x2 : bridge.x1;
  const startY = reverse ? bridge.y2 : bridge.y1;
  const endX = reverse ? bridge.x1 : bridge.x2;
  const endY = reverse ? bridge.y1 : bridge.y2;
  const target = reverse ? bridge.source : bridge.target;
  const dx = endX - startX;
  const dy = endY - startY;
  const length = Math.hypot(dx, dy);
  if (length < 34) return;
  const unitX = dx / length;
  const unitY = dy / length;
  const targetDistance = Math.max(10, target.radius + 5);
  const x = endX - unitX * targetDistance;
  const y = endY - unitY * targetDistance;
  const size = 4.2;
  context.setLineDash([]);
  context.beginPath();
  context.moveTo(x, y);
  context.lineTo(x - unitX * size - unitY * size, y - unitY * size + unitX * size);
  context.moveTo(x, y);
  context.lineTo(x - unitX * size + unitY * size, y - unitY * size - unitX * size);
  context.stroke();
}

function drawNamespaceSphere(context, projected, palette) {
  const { item, x, y, radius, depth } = projected;
  const selected = state.namespaceGalaxy.selection?.kind === "node"
    && state.namespaceGalaxy.selection?.contextId === item.contextId;
  const hovered = state.namespaceGalaxy.hover?.kind === "node"
    && state.namespaceGalaxy.hover?.contextId === item.contextId;
  const keyboardFocused = document.activeElement === elements.namespaceGalaxyCanvas
    && state.namespaceGalaxy.keyboardContextId === item.contextId;
  const current = item.contextId === state.context;
  const baseColor = item.entryCount > 0 ? palette.node : palette.nodeEmpty;
  const gradient = context.createRadialGradient(
    x - radius * 0.34,
    y - radius * 0.38,
    Math.max(1, radius * 0.08),
    x,
    y,
    radius,
  );
  gradient.addColorStop(0, selected || current ? palette.selected : palette.nodeHighlight);
  gradient.addColorStop(0.36, baseColor);
  gradient.addColorStop(1, palette.nodeShadow);
  context.save();
  context.globalAlpha = clamp(0.55 + (depth + 1) * 0.2, 0.42, 1);
  context.shadowColor = selected || current ? palette.selected : baseColor;
  context.shadowBlur = selected || hovered || keyboardFocused ? 18 : 7;
  context.fillStyle = gradient;
  context.beginPath();
  context.arc(x, y, radius, 0, Math.PI * 2);
  context.fill();
  context.lineWidth = current ? 2.4 : 1.2;
  context.strokeStyle = current ? palette.selected : palette.nodeHighlight;
  context.globalAlpha = current ? 0.9 : 0.48;
  context.stroke();
  if (selected || hovered || keyboardFocused) {
    context.shadowBlur = 0;
    context.globalAlpha = 0.9;
    context.lineWidth = keyboardFocused ? 2.4 : 1.5;
    context.strokeStyle = selected ? palette.selected : palette.text;
    context.beginPath();
    context.arc(x, y, radius + 5, 0, Math.PI * 2);
    context.stroke();
  }
  context.restore();
}

function drawNamespaceLabels(context, projectedNodes, palette, width, height) {
  const occupied = [];
  const priorities = [...projectedNodes].sort((left, right) => {
    const leftPriority = namespaceLabelPriority(left);
    const rightPriority = namespaceLabelPriority(right);
    return rightPriority - leftPriority || right.item.entryCount - left.item.entryCount;
  });
  context.save();
  const terminalFont = getComputedStyle(document.documentElement).getPropertyValue("--terminal-font").trim()
    || "ui-monospace, monospace";
  context.font = `700 11px ${terminalFont}`;
  context.textBaseline = "middle";
  priorities.forEach((node, index) => {
    const forced = namespaceLabelPriority(node) >= 1000;
    if (!forced && projectedNodes.length > 34 && index > 27) return;
    const label = compactTag(node.item.contextId, 27);
    const textWidth = Math.ceil(context.measureText(label).width);
    const labelWidth = textWidth + 10;
    const labelHeight = 18;
    const candidates = [
      { x: node.x + node.radius + 5, y: node.y - labelHeight / 2 },
      { x: node.x - node.radius - labelWidth - 5, y: node.y - labelHeight / 2 },
      { x: node.x - labelWidth / 2, y: node.y + node.radius + 5 },
    ];
    let box = candidates.find((candidate) => (
      candidate.x >= 4
      && candidate.y >= 4
      && candidate.x + labelWidth <= width - 4
      && candidate.y + labelHeight <= height - 4
      && !occupied.some((existing) => rectanglesOverlap(
        { ...candidate, width: labelWidth, height: labelHeight },
        existing,
      ))
    ));
    if (!box && forced) {
      box = {
        x: clamp(candidates[0].x, 4, Math.max(4, width - labelWidth - 4)),
        y: clamp(candidates[0].y, 4, Math.max(4, height - labelHeight - 4)),
      };
    }
    if (!box) return;
    const rectangle = { ...box, width: labelWidth, height: labelHeight };
    occupied.push(rectangle);
    context.globalAlpha = forced ? 0.98 : 0.82;
    context.fillStyle = palette.labelBackground;
    context.fillRect(box.x, box.y, labelWidth, labelHeight);
    context.fillStyle = node.item.contextId === state.context ? palette.selected : palette.text;
    context.fillText(label, box.x + 5, box.y + labelHeight / 2 + 0.5);
  });
  context.restore();
}

function namespaceLabelPriority(projected) {
  if (projected.item.contextId === state.context) return 1400;
  if (state.namespaceGalaxy.hover?.kind === "node" && state.namespaceGalaxy.hover.contextId === projected.item.contextId) return 1300;
  if (state.namespaceGalaxy.selection?.kind === "node" && state.namespaceGalaxy.selection.contextId === projected.item.contextId) return 1200;
  if (state.namespaceGalaxy.keyboardContextId === projected.item.contextId) return 1100;
  return projected.item.entryCount + projected.depth * 0.1;
}

function rectanglesOverlap(left, right) {
  return !(
    left.x + left.width + 3 < right.x
    || right.x + right.width + 3 < left.x
    || left.y + left.height + 2 < right.y
    || right.y + right.height + 2 < left.y
  );
}

function namespaceGalaxyPointerPoint(event) {
  const rect = elements.namespaceGalaxyCanvas.getBoundingClientRect();
  return { x: event.clientX - rect.left, y: event.clientY - rect.top };
}

function hitNamespaceGalaxy(x, y) {
  const nodes = [...state.namespaceGalaxy.projectedNodes].sort((left, right) => right.depth - left.depth);
  const node = nodes.find((candidate) => Math.hypot(x - candidate.x, y - candidate.y) <= candidate.radius + 6);
  if (node) return node;
  const links = [...state.namespaceGalaxy.projectedLinks].sort((left, right) => right.depth - left.depth);
  return links.find((candidate) => (
    distanceToNamespaceSegment(x, y, candidate.x1, candidate.y1, candidate.x2, candidate.y2)
      <= Math.max(5, candidate.lineWidth + 3)
  )) || null;
}

function distanceToNamespaceSegment(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSquared = dx * dx + dy * dy;
  if (lengthSquared <= 0.0001) return Math.hypot(px - x1, py - y1);
  const amount = clamp(((px - x1) * dx + (py - y1) * dy) / lengthSquared, 0, 1);
  return Math.hypot(px - (x1 + amount * dx), py - (y1 + amount * dy));
}

function updateNamespaceGalaxyHover(x, y) {
  const hit = hitNamespaceGalaxy(x, y);
  const next = hit?.item || null;
  const previousKey = namespaceGalaxyItemKey(state.namespaceGalaxy.hover);
  const nextKey = namespaceGalaxyItemKey(next);
  if (previousKey !== nextKey) {
    state.namespaceGalaxy.hover = next;
    requestNamespaceGalaxyDraw();
  }
  if (next) {
    showNamespaceGalaxyTooltip(next, x, y);
  } else {
    hideNamespaceGalaxyTooltip();
  }
}

function namespaceGalaxyItemKey(item) {
  return item ? `${item.kind}:${item.id}` : "";
}

function showNamespaceGalaxyTooltip(item, x, y) {
  const tooltip = elements.namespaceGalaxyTooltip;
  if (item.kind === "node") {
    tooltip.innerHTML = `<strong>${escapeHtml(item.contextId)}</strong><span>${escapeHtml(formatNumber(item.entryCount))} memories</span>`;
  } else {
    const status = item.kind === "suggestion" ? "suggested" : item.enabled ? "approved" : "disabled";
    tooltip.innerHTML = `<strong>${escapeHtml(item.sourceContextId)} → ${escapeHtml(item.targetContextId)}</strong><span>${escapeHtml(item.relationType)} · ${escapeHtml(formatNumber(item.weight, 2))} · ${escapeHtml(status)}</span>`;
  }
  const stage = elements.namespaceGalaxyCanvas.parentElement;
  const maxX = Math.max(8, stage.clientWidth - 230);
  const maxY = Math.max(8, stage.clientHeight - 68);
  tooltip.style.left = `${clamp(x + 14, 8, maxX)}px`;
  tooltip.style.top = `${clamp(y + 14, 8, maxY)}px`;
  tooltip.hidden = false;
}

function hideNamespaceGalaxyTooltip() {
  elements.namespaceGalaxyTooltip.hidden = true;
}

function selectNamespaceGalaxyItem(item, { focusCanvas = false } = {}) {
  if (!item) return;
  state.namespaceGalaxy.selection = item;
  if (item.kind === "node") state.namespaceGalaxy.keyboardContextId = item.contextId;
  renderNamespaceGalaxyInspector(item);
  requestNamespaceGalaxyDraw();
  if (focusCanvas) elements.namespaceGalaxyCanvas.focus();
}

function findNamespaceGalaxyItem(kind, id) {
  if (!kind || !id) return null;
  if (kind === "node") return state.namespaceGalaxy.data.nodes.find((item) => item.id === id) || null;
  if (kind === "suggestion") return state.namespaceGalaxy.data.suggestions.find((item) => item.id === id) || null;
  return state.namespaceGalaxy.data.links.find((item) => item.id === id) || null;
}

function renderNamespaceGalaxyInspector(item) {
  const title = elements.namespaceGalaxyInspectorTitle;
  const body = elements.namespaceGalaxyInspectorBody;
  const facts = elements.namespaceGalaxyInspectorFacts;
  const actions = elements.namespaceGalaxyInspectorActions;
  if (!item) {
    title.textContent = "No namespace selected";
    body.textContent = "The namespace map is empty. Capture memory in a context to begin.";
    facts.replaceChildren();
    actions.replaceChildren();
    elements.namespaceGalaxySuggestionList.replaceChildren();
    return;
  }

  if (item.kind === "node") {
    const approvedLinks = state.namespaceGalaxy.data.links.filter((link) => (
      link.sourceContextId === item.contextId || link.targetContextId === item.contextId
    ));
    const activeLinks = approvedLinks.filter((link) => (
      link.enabled
      && link.approved
      && namespaceLinkIsRecallableFrom(link, item.contextId)
    ));
    title.textContent = item.contextId;
    body.textContent = item.contextId === state.context
      ? "This is the active sidebar namespace. Local recall stays here, with only explicitly global memory inherited."
      : "Load this namespace to make it the active context without removing the current approved bridges.";
    renderNamespaceGalaxyFacts([
      ["Memories", formatNumber(item.entryCount)],
      ["Active bridges", formatNumber(activeLinks.length)],
      ["Relationships", item.relationshipCount === null ? "Not reported" : formatNumber(item.relationshipCount)],
      ["Events", item.eventCount === null ? "Not reported" : formatNumber(item.eventCount)],
      ["Last update", formatNamespaceUpdatedAt(item.updatedAt)],
    ]);
    actions.innerHTML = [
      `<button type="button" class="primary-button" data-galaxy-action="enter" data-galaxy-context="${escapeHtml(item.contextId)}">Enter namespace</button>`,
      item.contextId === state.context
        ? '<span class="namespace-galaxy-current">Current sidebar context</span>'
        : `<button type="button" class="secondary-button" data-galaxy-action="load" data-galaxy-context="${escapeHtml(item.contextId)}">Load sidebar context</button>`,
    ].join("");
    renderNamespaceSuggestionList(item.contextId);
    return;
  }

  const isSuggestion = item.kind === "suggestion";
  title.textContent = isSuggestion ? "Suggested bridge" : "Approved bridge";
  body.textContent = isSuggestion
    ? (item.evidence || "Evidence-only density-normalized similarity candidate. It is not active until an operator connects it.")
    : (item.evidence || "This operator-approved bridge can participate in one-hop connected recall when enabled.");
  renderNamespaceGalaxyFacts([
    ["Source", item.sourceContextId],
    ["Target", item.targetContextId],
    ["Relationship", item.relationType],
    [isSuggestion ? "Similarity" : "Weight", formatNumber(item.weight, 2)],
    ["Direction", isSuggestion ? "Suggested only" : item.direction === "directed" ? "Source to target" : "Bidirectional"],
    [
      "Visual delay",
      item.suggestedPhaseDelayTicks > 0
        ? `${formatNumber(item.suggestedPhaseDelayTicks)} ticks (display only)`
        : "None",
    ],
    ["Status", isSuggestion ? "Suggested only" : item.enabled ? "Approved and enabled" : "Approved but disabled"],
    ["Verified", formatNamespaceUpdatedAt(item.verifiedAt)],
  ]);
  actions.innerHTML = [
    isSuggestion
      ? '<button type="button" class="primary-button" data-galaxy-action="connect">Connect</button>'
      : "",
    `<button type="button" class="secondary-button" data-galaxy-action="load" data-galaxy-context="${escapeHtml(item.sourceContextId)}">Load source</button>`,
    `<button type="button" class="secondary-button" data-galaxy-action="load" data-galaxy-context="${escapeHtml(item.targetContextId)}">Load target</button>`,
  ].join("");
  renderNamespaceSuggestionList(state.context);
}

function namespaceLinkIsRecallableFrom(link, contextId) {
  return link.sourceContextId === contextId
    || (link.direction === "bidirectional" && link.targetContextId === contextId);
}

function renderNamespaceGalaxyFacts(rows) {
  elements.namespaceGalaxyInspectorFacts.innerHTML = rows
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`)
    .join("");
}

function renderNamespaceSuggestionList(contextId) {
  const suggestions = state.namespaceGalaxy.data.suggestions
    .filter((suggestion) => (
      suggestion.sourceContextId === contextId || suggestion.targetContextId === contextId
    ))
    .slice(0, 4);
  if (!suggestions.length) {
    elements.namespaceGalaxySuggestionList.innerHTML = '<p>No evidence-only bridge suggestions for this namespace.</p>';
    return;
  }
  elements.namespaceGalaxySuggestionList.innerHTML = [
    "<strong>Evidence-only suggestions</strong>",
    "<p>Review first; suggestions never expand recall automatically.</p>",
    ...suggestions.map((suggestion) => {
      const peer = suggestion.sourceContextId === contextId
        ? suggestion.targetContextId
        : suggestion.sourceContextId;
      return `<button type="button" data-galaxy-suggestion-id="${escapeHtml(suggestion.id)}"><span>${escapeHtml(peer)}</span><small>${escapeHtml(suggestion.relationType)} · ${escapeHtml(formatNumber(suggestion.weight, 2))}</small></button>`;
    }),
  ].join("");
}

function renderNamespaceGalaxyList(nodes) {
  if (!nodes.length) {
    elements.namespaceGalaxyList.innerHTML = '<div class="namespace-galaxy-list-empty">No saved namespaces returned.</div>';
    return;
  }
  elements.namespaceGalaxyList.innerHTML = nodes
    .map((node) => {
      const current = node.contextId === state.context ? "true" : "false";
      return `<div role="listitem"><button type="button" data-galaxy-context="${escapeHtml(node.contextId)}" aria-current="${current}"><span>${escapeHtml(node.contextId)}</span><small>${escapeHtml(formatNumber(node.entryCount))} memories</small></button></div>`;
    })
    .join("");
}

function handleNamespaceGalaxyInspectorClick(event) {
  const suggestionButton = event.target.closest?.("[data-galaxy-suggestion-id]");
  if (suggestionButton) {
    event.preventDefault();
    const suggestion = state.namespaceGalaxy.data.suggestions.find((item) => item.id === suggestionButton.dataset.galaxySuggestionId);
    if (suggestion) selectNamespaceGalaxyItem(suggestion, { focusCanvas: false });
    return;
  }
  const button = event.target.closest?.("[data-galaxy-action]");
  if (!button) return;
  event.preventDefault();
  if (button.dataset.galaxyAction === "load") {
    void applySelectedContext(button.dataset.galaxyContext, button);
    return;
  }
  if (button.dataset.galaxyAction === "enter") {
    void enterNamespaceGalaxy(button.dataset.galaxyContext, { pushHistory: true });
    return;
  }
  if (button.dataset.galaxyAction === "focus-ganglion") {
    const clusterId = button.dataset.galaxyCluster;
    const cluster = combinedNamespaceDetail()?.clusters.find((item) => item.clusterId === clusterId);
    if (cluster) {
      selectNamespaceDetailItem(cluster, { focusCanvas: false });
      void focusNamespaceGanglion(clusterId, { pushHistory: true });
    }
    return;
  }
  if (button.dataset.galaxyAction === "connect") {
    void connectSelectedNamespaceSuggestion(button);
  }
}

async function connectSelectedNamespaceSuggestion(button) {
  const suggestion = state.namespaceGalaxy.selection;
  if (!suggestion || suggestion.kind !== "suggestion") return null;
  try {
    return await withBusy(button, "Connect namespace bridge", async () => {
      const payload = await requestJson("/api/namespace-links", {
        method: "POST",
        body: {
          source_context_id: suggestion.sourceContextId,
          target_context_id: suggestion.targetContextId,
          relation_type: suggestion.relationType,
          weight: suggestion.weight,
          confirm: true,
        },
      });
      state.namespaceGalaxy.selection = null;
      await refreshNamespaceGalaxy();
      return payload;
    }, { refresh: false });
  } catch {
    return null;
  }
}

function formatNamespaceUpdatedAt(value) {
  if (value === null || value === undefined || value === "") return "Not reported";
  const numeric = Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric > 10_000_000_000 ? numeric : numeric * 1000)
    : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function setNamespaceGalaxyState(mode, headline, detail) {
  state.namespaceGalaxy.status = mode;
  const element = elements.namespaceGalaxyState;
  element.className = `namespace-galaxy-state ${mode}`;
  element.innerHTML = `<strong>${escapeHtml(headline)}</strong>${detail ? `<span>${escapeHtml(detail)}</span>` : ""}`;
  element.hidden = mode === "ready";
}

function updateNamespaceGalaxyChrome() {
  const galaxy = state.namespaceGalaxy;
  const inNamespace = galaxy.view === "namespace";
  const detail = combinedNamespaceDetail();
  elements.namespaceGalaxyBreadcrumbNamespaceWrap.hidden = !inNamespace;
  elements.namespaceGalaxyBreadcrumbGanglionWrap.hidden = !inNamespace || !galaxy.focusedClusterId;
  elements.namespaceGalaxyBack.hidden = !inNamespace;
  elements.namespaceGalaxyBreadcrumbNamespace.textContent = detail?.namespace?.label || galaxy.detailContextId || "Namespace";
  const focused = detail?.clusters?.find((cluster) => cluster.clusterId === galaxy.focusedClusterId);
  elements.namespaceGalaxyBreadcrumbGanglion.textContent = focused?.label || galaxy.focusedClusterId;
  elements.namespaceGalaxyBack.textContent = galaxy.focusedClusterId ? "Back to namespace" : "Back to galaxy";
  elements.namespaceGalaxyFit.setAttribute("aria-label", inNamespace ? "Fit namespace view" : "Fit all namespaces");
  elements.namespaceGalaxyReset.setAttribute("aria-label", inNamespace ? "Reset namespace view" : "Reset galaxy view");
  elements.namespaceGalaxyAccessibleSummary.textContent = inNamespace
    ? `Browse ${detail?.namespace?.label || galaxy.detailContextId || "namespace"} as a list`
    : "Browse all namespaces as a list";
  elements.namespaceGalaxyAccessibleHelp.textContent = inNamespace
    ? "This list follows the current semantic zoom: cortex summary, ganglia, or exact returned neurons."
    : "Each saved namespace is listed from the backend map. Activate one to enter its read-only internal map.";
  elements.namespaceGalaxyHelp.textContent = inNamespace
    ? "Click a ganglion to focus it. Click a neuron to inspect it. Drag to orbit; Shift-drag to pan; scroll to change semantic zoom."
    : "Click a namespace sphere to enter it. Drag to orbit; Shift-drag to pan; scroll to zoom.";
  updateNamespaceDetailDepthChrome();
}

function updateNamespaceDetailDepthChrome() {
  const inNamespace = state.namespaceGalaxy.view === "namespace";
  const lod = inNamespace ? currentNamespaceDetailLod() : "cortex";
  const depth = lod === "neurons" ? 3 : lod === "ganglia" ? 2 : 1;
  const labels = [
    [elements.namespaceGalaxyDepthCortex, "cortex", 1],
    [elements.namespaceGalaxyDepthGanglia, "ganglia", 2],
    [elements.namespaceGalaxyDepthNeurons, "neurons", 3],
  ];
  labels.forEach(([element, name, value]) => {
    const active = name === lod;
    element.toggleAttribute("aria-current", active);
    element.classList.toggle("is-active", active);
    element.classList.toggle("is-reached", inNamespace && value <= depth);
  });
  elements.namespaceGalaxyDepthValue.textContent = inNamespace
    ? `Depth ${depth} / 3 · ${lod}`
    : "Galaxy overview";
}

function findNamespaceDetailItem(kind, id) {
  const detail = combinedNamespaceDetail();
  if (!detail || !kind || !id) return null;
  if (kind === "namespace-detail") return detail.namespace?.id === id ? detail.namespace : null;
  if (kind === "ganglion") return detail.clusters.find((item) => item.id === id) || null;
  if (kind === "memory") return detail.nodes.find((item) => item.id === id) || null;
  return null;
}

function selectNamespaceDetailItem(item, { focusCanvas = false } = {}) {
  if (!item) return;
  const galaxy = state.namespaceGalaxy;
  galaxy.detailSelection = item;
  galaxy.keyboardDetailId = item.kind === "namespace-detail"
    ? (combinedNamespaceDetail()?.clusters[0]?.id || "")
    : item.id;
  renderNamespaceDetailInspector(item);
  renderNamespaceDetailList();
  requestNamespaceGalaxyDraw();
  if (focusCanvas) elements.namespaceGalaxyCanvas.focus({ preventScroll: true });
}

function detailFactsFor(item) {
  if (!item) return [];
  if (item.kind === "namespace-detail") {
    return [
      ["Stored memories", formatNumber(item.entryTotal)],
      ["Relationships", formatNumber(item.relationshipTotal)],
      ["Stored", item.stored ? "Yes" : "No"],
      ["Last updated", formatNamespaceUpdatedAt(item.lastUpdatedAt)],
    ];
  }
  if (item.kind === "ganglion") {
    const types = Object.entries(item.nodeTypeCounts || {}).map(([type, count]) => `${type}: ${count}`).join(", ");
    return [
      ["Neurons (memories)", formatNumber(item.memoryTotal)],
      ["Cluster basis", item.basis],
      ["Stored types", types || "Not reported"],
      ["Last updated", formatNamespaceUpdatedAt(item.lastUpdatedAt)],
    ];
  }
  return [
    ["Type", item.nodeType],
    ["Tag", item.tag || "Not reported"],
    ["Source", typeof item.source === "string" ? item.source : namespaceEvidenceText(item.provenance) || "Not reported"],
    ["Created", formatNamespaceUpdatedAt(item.createdAt)],
  ];
}

function renderNamespaceDetailInspector(item) {
  const title = elements.namespaceGalaxyInspectorTitle;
  const body = elements.namespaceGalaxyInspectorBody;
  const actions = elements.namespaceGalaxyInspectorActions;
  elements.namespaceGalaxySuggestionList.replaceChildren();
  if (!item) {
    title.textContent = "No stored detail selected";
    body.textContent = "Open a saved namespace to inspect its stored ganglia and neurons.";
    elements.namespaceGalaxyInspectorFacts.replaceChildren();
    actions.replaceChildren();
    return;
  }
  title.textContent = item.label || item.contextId || "Stored detail";
  if (item.kind === "namespace-detail") {
    body.textContent = "Cortex overview. Zoom in to reveal backend-returned ganglia, then exact returned neurons.";
  } else if (item.kind === "ganglion") {
    body.textContent = "Stored semantic cluster. Focusing loads the bounded exact neuron and relationship projection for this ganglion.";
  } else {
    body.textContent = item.excerpt || "Stored memory node. This inspector reports only metadata returned by the namespace detail endpoint.";
  }
  renderNamespaceGalaxyFacts(detailFactsFor(item));
  actions.innerHTML = item.kind === "ganglion"
    ? `<button type="button" class="primary-button" data-galaxy-action="focus-ganglion" data-galaxy-cluster="${escapeHtml(item.clusterId)}">Focus this ganglion</button>`
    : item.kind === "memory"
      ? `<span class="namespace-galaxy-current">Read-only neuron inspection</span>`
      : "";
}

function renderNamespaceDetailList() {
  const detail = combinedNamespaceDetail();
  if (!detail) {
    elements.namespaceGalaxyList.innerHTML = '<div class="namespace-galaxy-list-empty">No stored namespace detail returned.</div>';
    return;
  }
  const lod = currentNamespaceDetailLod();
  if (lod === "cortex") {
    elements.namespaceGalaxyList.innerHTML = `<div role="listitem"><button type="button" data-galaxy-action="inspect-cortex" aria-current="${state.namespaceGalaxy.detailSelection?.kind === "namespace-detail"}"><span>${escapeHtml(detail.namespace.label)}</span><small>${escapeHtml(formatNumber(detail.namespace.entryTotal))} stored memories</small></button></div>`;
    return;
  }
  const clusters = [...detail.clusters].sort((left, right) => right.memoryTotal - left.memoryTotal || left.label.localeCompare(right.label));
  const rows = clusters.map((cluster) => {
    const current = state.namespaceGalaxy.detailSelection?.id === cluster.id ? "true" : "false";
    return `<div role="listitem"><button type="button" data-galaxy-action="focus-ganglion" data-galaxy-cluster="${escapeHtml(cluster.clusterId)}" aria-current="${current}"><span>${escapeHtml(cluster.label)}</span><small>${escapeHtml(formatNumber(cluster.memoryTotal))} neurons</small></button></div>`;
  });
  if (lod === "neurons") {
    const visible = visibleNamespaceDetailNodes(detail, lod);
    rows.push(...visible.map((node) => {
      const current = state.namespaceGalaxy.detailSelection?.id === node.id ? "true" : "false";
      return `<div role="listitem"><button type="button" data-galaxy-action="inspect-neuron" data-galaxy-neuron="${escapeHtml(node.id)}" aria-current="${current}"><span>${escapeHtml(node.label)}</span><small>${escapeHtml(node.nodeType)}</small></button></div>`;
    }));
  }
  elements.namespaceGalaxyList.innerHTML = rows.length
    ? rows.join("")
    : '<div class="namespace-galaxy-list-empty">No stored ganglia or neurons were returned.</div>';
}

function handleNamespaceGalaxyListAction(button) {
  const action = button.dataset.galaxyAction;
  if (!action && button.dataset.galaxyContext) {
    void enterNamespaceGalaxy(button.dataset.galaxyContext, { pushHistory: true });
    return;
  }
  if (action === "focus-ganglion") {
    const clusterId = button.dataset.galaxyCluster;
    const cluster = combinedNamespaceDetail()?.clusters.find((item) => item.clusterId === clusterId);
    if (cluster) {
      selectNamespaceDetailItem(cluster, { focusCanvas: false });
      void focusNamespaceGanglion(clusterId, { pushHistory: true });
    }
    return;
  }
  if (action === "inspect-neuron") {
    const node = combinedNamespaceDetail()?.nodes.find((item) => item.id === button.dataset.galaxyNeuron);
    if (node) selectNamespaceDetailItem(node, { focusCanvas: false });
    return;
  }
  if (action === "inspect-cortex") {
    const namespace = combinedNamespaceDetail()?.namespace;
    if (namespace) selectNamespaceDetailItem(namespace, { focusCanvas: false });
  }
}

function hitNamespaceDetail(x, y) {
  const candidates = [
    ...state.namespaceGalaxy.projectedMemories,
    ...state.namespaceGalaxy.projectedGanglia,
  ].sort((left, right) => right.depth - left.depth || right.radius - left.radius);
  return candidates.find((candidate) => Math.hypot(x - candidate.x, y - candidate.y) <= candidate.radius + 6) || null;
}

function updateNamespaceDetailHover(x, y) {
  const hit = hitNamespaceDetail(x, y);
  const next = hit?.item || null;
  if (namespaceGalaxyItemKey(next) !== namespaceGalaxyItemKey(state.namespaceGalaxy.detailHover)) {
    state.namespaceGalaxy.detailHover = next;
    requestNamespaceGalaxyDraw();
  }
  if (next) showNamespaceDetailTooltip(next, x, y);
  else hideNamespaceGalaxyTooltip();
}

function showNamespaceDetailTooltip(item, x, y) {
  const tooltip = elements.namespaceGalaxyTooltip;
  const subline = item.kind === "ganglion"
    ? `${formatNumber(item.memoryTotal)} stored neurons`
    : item.nodeType || "stored neuron";
  tooltip.innerHTML = `<strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(subline)}</span>`;
  const stage = elements.namespaceGalaxyCanvas.parentElement;
  tooltip.style.left = `${clamp(x + 14, 8, Math.max(8, stage.clientWidth - 230))}px`;
  tooltip.style.top = `${clamp(y + 14, 8, Math.max(8, stage.clientHeight - 68))}px`;
  tooltip.hidden = false;
}

function ensureNamespaceDetailKeyboardSelection() {
  const detail = combinedNamespaceDetail();
  if (!detail) return;
  const selectable = namespaceDetailKeyboardItems(detail);
  if (!selectable.length) return;
  if (!selectable.some((item) => item.id === state.namespaceGalaxy.keyboardDetailId)) {
    state.namespaceGalaxy.keyboardDetailId = selectable[0].id;
  }
}

function namespaceDetailKeyboardItems(detail) {
  const lod = currentNamespaceDetailLod();
  if (lod === "cortex") return [detail.namespace];
  const clusters = [...detail.clusters];
  return lod === "neurons" ? [...clusters, ...visibleNamespaceDetailNodes(detail, lod)] : clusters;
}

function handleNamespaceGalaxyKeydown(event) {
  if (state.namespaceGalaxy.view === "namespace") {
    handleNamespaceDetailKeydown(event);
    return;
  }
  const nodes = [...state.namespaceGalaxy.data.nodes].sort((left, right) => (
    left.contextId.localeCompare(right.contextId, undefined, { sensitivity: "base" })
  ));
  if (!nodes.length) return;
  const currentIndex = Math.max(0, nodes.findIndex((node) => node.contextId === state.namespaceGalaxy.keyboardContextId));
  let nextIndex = currentIndex;
  if (event.key === "ArrowRight" || event.key === "ArrowDown") nextIndex = (currentIndex + 1) % nodes.length;
  if (event.key === "ArrowLeft" || event.key === "ArrowUp") nextIndex = (currentIndex - 1 + nodes.length) % nodes.length;
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = nodes.length - 1;
  if (nextIndex !== currentIndex || ["Home", "End"].includes(event.key)) {
    event.preventDefault();
    const node = nodes[nextIndex];
    state.namespaceGalaxy.keyboardContextId = node.contextId;
    selectNamespaceGalaxyItem(node, { focusCanvas: false });
    return;
  }
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    const node = nodes[currentIndex];
    void enterNamespaceGalaxy(node.contextId, { pushHistory: true });
    return;
  }
  if (event.key === "+" || event.key === "=") {
    event.preventDefault();
    setNamespaceGalaxyZoom(state.namespaceGalaxy.zoom * 1.14);
  } else if (event.key === "-" || event.key === "_") {
    event.preventDefault();
    setNamespaceGalaxyZoom(state.namespaceGalaxy.zoom / 1.14);
  } else if (event.key.toLowerCase() === "f") {
    event.preventDefault();
    fitNamespaceGalaxy();
  } else if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    resetNamespaceGalaxyView();
  }
}

function handleNamespaceDetailKeydown(event) {
  const galaxy = state.namespaceGalaxy;
  if (event.key === "Escape") {
    event.preventDefault();
    if (galaxy.focusedClusterId) clearNamespaceGanglionFocus({ useHistory: true });
    else exitNamespaceGalaxy({ useHistory: true });
    return;
  }
  const detail = combinedNamespaceDetail();
  if (!detail) return;
  const items = namespaceDetailKeyboardItems(detail);
  if (!items.length) return;
  const currentIndex = Math.max(0, items.findIndex((item) => item.id === galaxy.keyboardDetailId));
  let nextIndex = currentIndex;
  if (event.key === "ArrowRight" || event.key === "ArrowDown") nextIndex = (currentIndex + 1) % items.length;
  if (event.key === "ArrowLeft" || event.key === "ArrowUp") nextIndex = (currentIndex - 1 + items.length) % items.length;
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = items.length - 1;
  if (nextIndex !== currentIndex || event.key === "Home" || event.key === "End") {
    event.preventDefault();
    selectNamespaceDetailItem(items[nextIndex], { focusCanvas: false });
    return;
  }
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    const item = items[currentIndex];
    selectNamespaceDetailItem(item, { focusCanvas: false });
    if (item.kind === "ganglion") void focusNamespaceGanglion(item.clusterId, { pushHistory: true });
    return;
  }
  if (event.key === "+" || event.key === "=") {
    event.preventDefault();
    setNamespaceGalaxyZoom(galaxy.zoom * 1.14);
  } else if (event.key === "-" || event.key === "_") {
    event.preventDefault();
    setNamespaceGalaxyZoom(galaxy.zoom / 1.14);
  } else if (event.key.toLowerCase() === "f") {
    event.preventDefault();
    fitNamespaceGalaxy();
  } else if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    resetNamespaceGalaxyView();
  }
}

function orbitNamespaceGalaxy(delta) {
  state.namespaceGalaxy.rotation.y += delta;
  requestNamespaceGalaxyDraw();
}

function setNamespaceGalaxyZoom(value) {
  state.namespaceGalaxy.zoom = clamp(value, NAMESPACE_GALAXY_MIN_ZOOM, NAMESPACE_GALAXY_MAX_ZOOM);
  if (state.namespaceGalaxy.view === "namespace") {
    updateNamespaceGalaxyChrome();
    renderNamespaceDetailList();
  }
  requestNamespaceGalaxyDraw();
}

function fitNamespaceGalaxy() {
  state.namespaceGalaxy.pan = { x: 0, y: 0 };
  setNamespaceGalaxyZoom(state.namespaceGalaxy.view === "namespace"
    ? 1
    : state.namespaceGalaxy.data.nodes.length > 60 ? 0.72 : 0.9);
}

function resetNamespaceGalaxyView() {
  state.namespaceGalaxy.rotation = { ...NAMESPACE_GALAXY_DEFAULT_ROTATION };
  state.namespaceGalaxy.pan = { x: 0, y: 0 };
  setNamespaceGalaxyZoom(1);
}

function currentRecallScope() {
  const selected = document.querySelector('input[name="recallScope"]:checked');
  return ["local", "connected", "all"].includes(selected?.value) ? selected.value : "local";
}

function updateRecallScopeHelp() {
  const messages = {
    local: "Local searches the active namespace plus explicitly global memory. This is the safe default.",
    connected: "Connected adds approved, enabled one-hop bridges to Local. Suggestions remain excluded.",
    all: "All searches every saved namespace plus global memory. Use it deliberately when project boundaries are not useful.",
  };
  elements.recallScopeHelp.textContent = messages[currentRecallScope()];
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

function setAppConnectState(headline, detail, mode = "") {
  elements.appConnectState.className = `capture-inbox-state ${mode}`.trim();
  elements.appConnectState.innerHTML = `
    <strong>${escapeHtml(headline)}</strong>
    <small>${escapeHtml(detail)}</small>
  `;
}

function renderAppConnect(appPayload = null, connectionPayload = null) {
  if (appPayload?.apps) {
    state.appConnect.apps = appPayload.apps;
  }
  if (connectionPayload?.connections) {
    state.appConnect.connections = connectionPayload.connections;
  }

  const previousAppValue = elements.appSelect.value;
  const appOptions = [
    new Option(
      state.appConnect.apps.length
        ? "Select a detected app"
        : "Press Detect to list running apps",
      "",
    ),
  ];
  state.appConnect.apps.forEach((app, index) => {
    const option = new Option(appOptionLabel(app), String(index));
    option.title = `${app.bundle_id || "no bundle id"} pid:${app.pid || 0}`;
    appOptions.push(option);
  });
  elements.appSelect.replaceChildren(...appOptions);
  if ([...elements.appSelect.options].some((option) => option.value === previousAppValue)) {
    elements.appSelect.value = previousAppValue;
  }

  const previousConnection = elements.appConnectionSelect.value;
  const connectionOptions = [
    new Option(
      state.appConnect.connections.length
        ? "Select attached connection"
        : "No apps attached",
      "",
    ),
  ];
  state.appConnect.connections.forEach((connection) => {
    const option = new Option(
      `${connection.app_name} -> ${connection.source_tag} / ${appCapabilityLabel(connection)}`,
      connection.connection_id,
    );
    option.title = `${connection.bundle_id || "no bundle id"} pid:${connection.pid || 0} / ${connection.capability_badge?.detail || ""}`;
    connectionOptions.push(option);
  });
  elements.appConnectionSelect.replaceChildren(...connectionOptions);
  if ([...elements.appConnectionSelect.options].some((option) => option.value === previousConnection)) {
    elements.appConnectionSelect.value = previousConnection;
  }

  const detected = Number(appPayload?.app_count ?? state.appConnect.apps.length);
  const connected = Number(connectionPayload?.connection_count ?? state.appConnect.connections.length);
  const headline = connected
    ? `${formatNumber(connected)} app connection${connected === 1 ? "" : "s"} armed`
    : detected
      ? `${formatNumber(detected)} running app${detected === 1 ? "" : "s"} detected`
      : "App Connect idle";
  const detail = connected
    ? `Choose an attached connection and preview before capture. ${appCapabilityLabel(state.appConnect.connections[0])}: ${state.appConnect.connections[0]?.capability_badge?.recommended_capture || "Use selected-text fallback for exact content."}`
    : detected
      ? "Select a detected app, set a source tag, then connect it before capturing exposed UI text."
      : "Detect local apps, attach one, then capture locally exposed Accessibility text into SYNAPSE-S2 memory.";
  setAppConnectState(headline, detail, connected || detected ? "ready" : "");
}

function setSelfTestState(headline, detail, mode = "") {
  elements.selfTestState.className = `capture-inbox-state ${mode}`.trim();
  elements.selfTestState.innerHTML = `
    <strong>${escapeHtml(headline)}</strong>
    <small>${escapeHtml(detail)}</small>
  `;
}

function renderSelfTest(payload) {
  if (!payload) {
    elements.selfTestGrid.replaceChildren();
    return;
  }
  const status = String(payload.overall_status || "degraded");
  const statusMode = status === "blocked" ? "error" : status === "degraded" ? "pending" : "ready";
  setSelfTestState(
    `Self test ${status}`,
    `${formatNumber(payload.elapsed_ms || 0, 1)} ms across ${formatNumber(Object.keys(payload.components || {}).length)} components.`,
    statusMode,
  );
  const order = [
    "runtime",
    "memory",
    "embedding",
    "context_bus",
    "capture_inbox",
    "app_connect",
  ];
  const components = payload.components || {};
  const cards = order
    .filter((name) => components[name])
    .map((name) => {
      const component = components[name];
      const item = document.createElement("article");
      const itemStatus = String(component.status || "degraded");
      const itemMode = itemStatus === "blocked" ? "blocked" : itemStatus === "degraded" ? "pending" : "ready";
      item.className = `self-test-item ${itemMode}`;
      item.innerHTML = `
        <span>${escapeHtml(itemStatus)}</span>
        <strong>${escapeHtml(component.label || name.replaceAll("_", " "))}</strong>
        <small>${escapeHtml(component.detail || "")}</small>
      `;
      return item;
    });
  elements.selfTestGrid.replaceChildren(...cards);
}

function renderMondayReadiness(payload) {
  if (!payload) {
    elements.selfTestGrid.replaceChildren();
    return;
  }
  const status = String(payload.overall_status || "degraded");
  const statusMode = status === "blocked" ? "error" : status === "degraded" ? "pending" : "ready";
  const summary = payload.summary || {};
  setSelfTestState(
    `Monday readiness ${payload.score ?? "--"} / 100`,
    `${formatNumber(summary.required_ready)} of ${formatNumber(summary.required_total)} required checks ready.`,
    statusMode,
  );
  const cards = (payload.checks || []).map((check) => {
    const item = document.createElement("article");
    const itemStatus = String(check.status || "degraded");
    const itemMode = itemStatus === "blocked" ? "blocked" : itemStatus === "degraded" ? "pending" : "ready";
    const scope = check.required ? "required" : "optional";
    item.className = `self-test-item ${itemMode}`;
    item.innerHTML = `
      <span>${escapeHtml(itemStatus)}</span>
      <strong>${escapeHtml(check.label || check.id || "check")}</strong>
      <small>${escapeHtml(`${scope} / ${check.detail || ""}`)}</small>
    `;
    return item;
  });
  elements.selfTestGrid.replaceChildren(...cards);
}

function runStartWork(button) {
  return withBusy(button, "Start Work", async () => {
    elements.startWorkOutput.textContent = "Generating Start Work brief...";
    const payload = await requestJson("/api/start-work", {
      params: {
        context_id: state.context,
        agent_id: "dashboard-ui",
        prompt: elements.queryInput.value.trim() || "Daily SYNAPSE-S2 operator brief",
      },
    });
    renderStartWork(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    elements.startWorkOutput.textContent = `Start Work failed: ${error.message}`;
    return null;
  });
}

function runContextHealth(button) {
  return withBusy(button, "Context Health", async () => {
    const payload = await requestJson("/api/context-health", {
      params: { context_id: state.context },
    });
    renderContextHealth(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    elements.contextHealthOutput.textContent = `Context Health failed: ${error.message}`;
    elements.contextHealthBadge.textContent = "Context Health blocked";
    elements.contextHealthBadge.className = "quality-badge blocked";
    return null;
  });
}

function runDoctorReport(button) {
  return withBusy(button, "Doctor / Repair", async () => {
    elements.doctorReportOutput.textContent = "Running Doctor...";
    const payload = await requestJson("/api/doctor", {
      params: {
        context_id: state.context,
        include_apps: "true",
        repair_plan: "true",
      },
    });
    renderDoctorReport(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    elements.doctorReportOutput.textContent = `Doctor failed: ${error.message}`;
    return null;
  });
}

function runMemoryHygiene(button) {
  return withBusy(button, "Memory Hygiene", async () => {
    const payload = await requestJson("/api/memory-hygiene", {
      params: { context_id: state.context, limit: 12 },
    });
    renderMemoryHygiene(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    elements.memoryHygieneQueue.textContent = `Memory Hygiene failed: ${error.message}`;
    return null;
  });
}

function runWrapSession(button, { previewOnly = false } = {}) {
  const text = elements.wrapSessionNotes.value.trim();
  if (!text) {
    logOperation("Wrap Session rejected", "session notes are required");
    elements.wrapSessionNotes.focus();
    return Promise.resolve(null);
  }
  return withBusy(button, previewOnly ? "Wrap Session preview" : "Wrap Session", async () => {
    const body = {
      context_id: state.context,
      agent_id: "dashboard-ui",
      text,
      operation_log: operationLogForWrap(),
    };
    const preview = await requestJson("/api/wrap-session/preview", {
      method: "POST",
      body,
    });
    renderWrapSessionPreview(preview);
    if (previewOnly) return preview;
    const firstLine = preview.preview_text.split("\n").find(Boolean) || "Wrap Session";
    if (!confirmPreflight("Write Wrap Session to SYNAPSE-S2 memory?", [
      firstLine,
      preview.receipt?.summary || "",
      "This creates durable local memory for handoff.",
    ])) {
      logOperation("Wrap Session cancelled", preview);
      return preview;
    }
    const payload = await requestJson("/api/wrap-session", {
      method: "POST",
      body: {
        ...body,
        confirm: true,
      },
    });
    await publishAwareResult(payload);
    state.operator.lastWrapPreview = null;
    elements.wrapSessionNotes.value = "";
    elements.wrapSessionOutput.innerHTML = renderReceiptCard(payload.receipt);
    return payload;
  }).catch((error) => {
    elements.wrapSessionOutput.textContent = `Wrap Session failed: ${error.message}`;
    return null;
  });
}

function renderStartWork(payload) {
  renderContextHealth(payload.context_health);
  renderMemoryHygiene(payload.memory_hygiene);
  renderOperatorRecipes(payload.recipes || []);
  renderRecipeDrawer(payload.recipes || []);
  renderGoalLedger(payload.goals_ledger || payload.agent_brief?.cortex_state || null);
  const sections = (payload.brief_sections || []).slice(0, 5);
  elements.startWorkOutput.innerHTML = sections.map((section) => `
    <article class="brief-section ${escapeHtml(section.status || "degraded")}">
      <span>${escapeHtml(section.status || "degraded")}</span>
      <strong>${escapeHtml(section.title || section.id || "Brief section")}</strong>
      <small class="brief-meta">
        <b>${escapeHtml(`confidence ${formatNumber(section.confidence, 2)}`)}</b>
        <b>${escapeHtml(`${(section.source_memories || []).length} source memories`)}</b>
      </small>
      <p>${escapeHtml(section.body || "")}</p>
    </article>
  `).join("") || "No Start Work sections returned";
}

function renderContextHealth(payload) {
  if (!payload) return;
  const status = String(payload.status || "degraded");
  elements.contextHealthBadge.textContent = `Context Health ${formatNumber(payload.score)} / 100`;
  elements.contextHealthBadge.className = `quality-badge ${status}`;
  elements.memoryQualityBadge.textContent = `Memory Quality ${formatNumber(payload.memory_quality_score)} / 100`;
  elements.memoryQualityBadge.className = `quality-badge ${status}`;
  elements.contextHealthOutput.innerHTML = `
    <strong>${escapeHtml(status)}</strong>
    <small>Memory quality ${escapeHtml(formatNumber(payload.memory_quality_score))} / 100</small>
    <p>${escapeHtml((payload.recommended_actions || [])[0] || "No immediate action required.")}</p>
  `;
}

function renderDoctorReport(payload) {
  const status = String(payload.overall_status || "degraded");
  const checks = payload.checks || [];
  const failures = checks.filter((check) => check.status !== "ready");
  elements.doctorReportOutput.innerHTML = `
    <strong>Doctor ${escapeHtml(status)}</strong>
    <small>${formatNumber(checks.length)} checks / ${formatNumber(failures.length)} need attention</small>
    <ul>${(payload.repair_plan || []).slice(0, 4).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
  `;
}

function renderMemoryHygiene(payload) {
  if (!payload) return;
  const items = payload.review_items || [];
  elements.memoryHygieneQueue.innerHTML = items.length
    ? items.slice(0, 6).map((item) => `
        <article class="hygiene-item ${escapeHtml(item.severity || "low")}">
          <div>
            <strong>${escapeHtml(item.tag || compactMemoryId(item.memory_id))}</strong>
            <small>${escapeHtml((item.categories || []).join(" / "))}</small>
            <p>${escapeHtml(item.reason || item.source_excerpt || "")}</p>
          </div>
          <button type="button"
            data-hygiene-action="acknowledge"
            data-memory-id="${escapeHtml(item.memory_id)}"
            data-hygiene-label="${escapeHtml(item.tag || item.memory_id)}">
            Ack
          </button>
        </article>
      `).join("")
    : '<div class="memory-ledger-empty">No memory hygiene review items</div>';
}

function renderOperatorRecipes(recipes) {
  const visible = recipes.length ? recipes : defaultOperatorRecipes();
  elements.operatorRecipes.innerHTML = visible.slice(0, 4).map((recipe) => `
    <article class="recipe-row">
      <strong>${escapeHtml(recipe.title || recipe.id || "Recipe")}</strong>
      <small>${escapeHtml((recipe.steps || []).slice(0, 3).join(" / "))}</small>
    </article>
  `).join("");
  renderRecipeDrawer(visible);
}

function defaultOperatorRecipes() {
  return [
    {
      title: "Start daily work",
      steps: ["Run Start Work", "Resolve health blockers", "Recall prior decisions"],
    },
    {
      title: "Resume yesterday's work",
      steps: ["Run Start Work", "Open recent session traces", "Pin relevant memory", "Enter Cortex"],
    },
    {
      title: "Capture from an app",
      steps: ["Connect app", "Preview snapshot", "Capture only useful text"],
    },
    {
      title: "Capture exact selected text",
      steps: ["Select text in the source app", "Paste into selected-text fallback", "Capture selected text"],
    },
    {
      title: "Verify before claiming success",
      steps: ["Run Doctor / Repair", "Check operation receipts", "Commit validation trace"],
    },
    {
      title: "Clean bad memory",
      steps: ["Run Memory Hygiene", "Review stale or noisy traces", "Promote, demote, prune, or mark resolved"],
    },
    {
      title: "Wrap a session",
      steps: ["Summarize decisions", "Preview wrap", "Confirm capture"],
    },
    {
      title: "Create evidence pack",
      steps: ["Run Doctor", "Run Evidence Pack", "Keep receipt with backup path"],
    },
  ];
}

function renderRecipeDrawer(recipes) {
  const visible = recipes.length ? recipes : defaultOperatorRecipes();
  elements.recipeChecklist.innerHTML = visible.map((recipe) => `
    <article class="recipe-card">
      <strong>${escapeHtml(recipe.title || recipe.id || "Recipe")}</strong>
      <p>${escapeHtml(recipe.description || "Follow this checklist against the live dashboard controls.")}</p>
      <ol>
        ${(recipe.steps || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
      </ol>
    </article>
  `).join("");
}

function renderGoalLedger(goals) {
  const ledgerGoals = Array.isArray(goals?.goals)
    ? goals.goals
    : Array.isArray(goals)
      ? goals
      : [];
  const source = goals?.active_goal || goals?.current_goal || "";
  const activeSessions = Array.isArray(goals?.active_sessions) ? goals.active_sessions : [];
  const risks = [
    ...(Array.isArray(goals?.risks) ? goals.risks : []),
    ...(Array.isArray(goals?.stale_or_uncertain_memories) ? goals.stale_or_uncertain_memories : []),
  ];
  const nextMove = goals?.suggested_next_move || "Run Start Work, define the task, then enter Cortex before risky work.";
  if (ledgerGoals.length) {
    elements.goalLedger.innerHTML = ledgerGoals.slice(0, 4).map((goal) => {
      const stateLabel = String(goal.state || "planned").replaceAll("_", " ");
      const confidence = Number(goal.confidence ?? NaN);
      const meta = [
        stateLabel,
        goal.owner ? `owner: ${goal.owner}` : "",
        Number.isFinite(confidence) ? `${formatNumber(confidence, 2)} confidence` : "",
      ].filter(Boolean);
      const evidence = goal.last_verified_evidence
        ? `<p><b>Evidence:</b> ${escapeHtml(compactTag(goal.last_verified_evidence, 180))}</p>`
        : "";
      return `
        <article class="goal-item">
          <strong>${escapeHtml(goal.title || goal.goal_id || "Untitled goal")}</strong>
          <small class="goal-meta">
            ${meta.map((item) => `<b>${escapeHtml(item)}</b>`).join("")}
          </small>
          <p>${escapeHtml(goal.next_action || nextMove)}</p>
          ${evidence}
        </article>
      `;
    }).join("");
    return;
  }
  const activeGoal = source || "No active goal recorded.";
  elements.goalLedger.innerHTML = `
    <article class="goal-item">
      <strong>${escapeHtml(activeGoal)}</strong>
      <small class="goal-meta">
        <b>${escapeHtml(activeSessions.length ? "in progress" : "planned")}</b>
        <b>${escapeHtml(`${formatNumber(risks.length)} open risks`)}</b>
      </small>
      <p>${escapeHtml(nextMove)}</p>
    </article>
  `;
}

function renderWrapSessionPreview(payload) {
  state.operator.lastWrapPreview = payload;
  elements.wrapSessionOutput.innerHTML = `
    ${renderReceiptCard(payload.receipt)}
    <pre>${escapeHtml(payload.preview_text || "")}</pre>
  `;
}

function renderOperationReceipt(receipt) {
  if (!receipt) return;
  state.operator.receipts = [receipt, ...state.operator.receipts].slice(0, 5);
  elements.operatorReceipts.innerHTML = state.operator.receipts.map(renderReceiptCard).join("");
}

function renderReceiptCard(receipt) {
  if (!receipt) return "";
  const status = String(receipt.status || "degraded");
  const meta = [
    receipt.context_id || "",
    receipt.source_tag || "",
    receipt.event_count ? `${formatNumber(receipt.event_count)} events` : "",
    receipt.relationship_count ? `${formatNumber(receipt.relationship_count)} links` : "",
  ].filter(Boolean).join(" / ");
  return `
    <article class="receipt-card ${escapeHtml(status)}">
      <span>${escapeHtml(status)}</span>
      <strong>${escapeHtml(receipt.title || receipt.action || "Receipt")}</strong>
      <small>${escapeHtml(meta || receipt.quality || "")}</small>
      <p>${escapeHtml(receipt.summary || "")}</p>
      ${receipt.next_action ? `<em>${escapeHtml(receipt.next_action)}</em>` : ""}
    </article>
  `;
}

function operationLogForWrap() {
  const logText = elements.operationLog.textContent.trim();
  if (!logText || logText === "idle") return [];
  return [
    {
      action: "dashboard-operation-log",
      summary: logText.slice(0, 1800),
    },
  ];
}

function appOptionLabel(app) {
  const pid = Number(app.pid || 0);
  const bundle = app.bundle_id ? ` / ${app.bundle_id}` : "";
  return `${app.app_name}${bundle}${pid ? ` / pid ${pid}` : ""}`;
}

function appCapabilityLabel(record) {
  return record?.capability_badge?.label || "Selection capture recommended";
}

function renderOperatorActionBanner(cortex, derived = {}) {
  const status = state.snapshot?.status || {};
  const contextId = state.snapshot?.context_id || state.context;
  const activeCount = Number(derived.activeCount ?? 0);
  const hasSession = activeCount > 0 && Boolean(derived.currentSessionId || derived.activeSession);
  const lastDecision = String(derived.lastDecision || "standby");
  const warnings = Array.isArray(derived.warnings) ? derived.warnings : [];
  const criticalWarning = warnings.find((warning) => warning.severity === "critical");
  const enabled = status.effective_enabled !== false;

  let mode = "pending";
  let statusText = "Action required";
  let title = "Start governed work before risky actions";
  let body = "Cortex is idle, which is normal before work starts. Run Start Work for context, then start a Cortex session before file mutations, sensitive captures, or handoff claims.";
  let calloutTitle = "Cortex is idle, not broken";
  let calloutBody = "No agent is currently governed. Enter the current task before mutating files, capturing risky data, or making handoff claims.";

  if (!enabled) {
    mode = "blocked";
    statusText = "Runtime paused";
    title = "Enable SYNAPSE-S2 Core before relying on memory";
    body = "The core is disabled, so recall and capture are intentionally paused. Unlock the core control, enable the runtime, then refresh and rerun Start Work.";
    calloutTitle = "Cortex is paused with the core";
    calloutBody = "Enable the core before starting a governed Cortex session.";
  } else if (criticalWarning || lastDecision === "stop-and-sanitize") {
    mode = "blocked";
    statusText = "Stop";
    title = "Cortex guardrail requires operator attention";
    body = criticalWarning?.message || "The last governor tick detected a high-risk action. Sanitize sensitive data or resolve the blocker before continuing.";
    calloutTitle = "Guardrail is blocking the next action";
    calloutBody = body;
  } else if (hasSession) {
    const sessionLabel = compactTag(String(derived.currentSessionId || ""), 28);
    mode = lastDecision === "verify-first" || lastDecision === "proceed-with-verification"
      ? "pending"
      : "ready";
    statusText = mode === "ready" ? "Governed" : "Verify first";
    title = `Cortex session active${sessionLabel ? `: ${sessionLabel}` : ""}`;
    body = mode === "ready"
      ? "This work is attached to a governed session. Tick before each risky action, then commit verified decisions, validation evidence, constraints, or risks."
      : "The last governor decision requires verification. Capture the evidence, adjust the proposed action if needed, then tick again before continuing.";
    calloutTitle = mode === "ready" ? "Cortex is governing this work" : "Verification required before continuing";
    calloutBody = body;
  }

  elements.operatorActionBanner.className = `operator-action-banner ${mode}`;
  elements.operatorActionStatus.textContent = statusText;
  elements.operatorActionContext.textContent = `s2://local/${contextId}`;
  elements.operatorActionTitle.textContent = title;
  elements.operatorActionBody.textContent = body;

  elements.cortexSessionCallout.className = `cortex-session-callout ${mode}`;
  elements.cortexSessionCalloutTitle.textContent = calloutTitle;
  elements.cortexSessionCalloutBody.textContent = calloutBody;
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
  const activeCount = Number(cortex.active_session_count ?? activeSessions.length);

  if (!state.cortex.sessionId && activeSession?.session_id) {
    state.cortex.sessionId = String(activeSession.session_id);
  } else if (activeCount <= 0) {
    state.cortex.sessionId = "";
  }

  const currentSessionId = activeCount > 0
    ? state.cortex.sessionId || String(activeSession?.session_id || "")
    : "";
  const lastDecision = String(activeSession?.last_decision || "standby");

  elements.cortexPolicy.textContent = policyId;
  elements.cortexPolicy.title = Array.isArray(policy.contract)
    ? policy.contract.join(" / ")
    : policyId;
  elements.cortexSessionCount.textContent = activeCount > 0
    ? `${formatNumber(activeCount)} active`
    : "Not started";
  elements.cortexSessionCount.className = activeCount > 0 ? "good" : "warn";
  elements.cortexCloseButton.disabled = !currentSessionId;
  elements.cortexCloseText.textContent = currentSessionId ? "End Session" : "No Session";
  elements.cortexSessionId.textContent = currentSessionId
    ? compactTag(currentSessionId, 34)
    : "Start Cortex Session before risky work";
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
  renderOperatorActionBanner(cortex, {
    activeCount,
    activeSession,
    currentSessionId,
    lastDecision,
    warnings,
  });
  renderGoalLedger(cortex);

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
  const min = Number(profile.target_envelope_mb?.min ?? 96);
  const max = Number(profile.target_envelope_mb?.max ?? 256);
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
  elements.envelopeState.textContent = profile.within_target_envelope
    ? `inside ${formatNumber(min, 0)}-${formatNumber(max, 0)} MB`
    : "outside target";
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
      "aria-label": `Move ${graphNodeLabel(entry)}`,
    });
    appendSvg(group, "title", {}, graphNodeTitle(entry));
    appendSvg(group, "circle", {
      r: entry.metadata?.event_segment ? 20 : 18,
      class: nodeClass(entry),
    });
    appendSvg(group, "text", {
      y: 34,
      "text-anchor": "middle",
      class: "graph-label",
    }, compactTag(graphNodeLabel(entry), 28));
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
  const facets = semanticFacets(entry).slice(0, state.neuralInspector ? 3 : 2);
  if (facets.length) {
    return facets.join(" / ");
  }
  const contextMemoryType = entry.metadata?.context_memory_type;
  if (contextMemoryType) {
    return String(contextMemoryType).replaceAll("_", " ");
  }
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
  if (relation.includes("namespace") || relation.includes("typed_context")) {
    return "graph-edge namespace";
  }
  if (relation.includes("semantic") || relation.includes("associative")) {
    return weight >= 0.5 ? "graph-edge associative strong" : "graph-edge associative weak";
  }
  return weight >= 0.5 ? "graph-edge strong" : "graph-edge weak";
}

function nodeClass(entry) {
  const contextMemoryType = entry.metadata?.context_memory_type;
  if (contextMemoryType === "namespace") return "graph-node namespace-node";
  if (contextMemoryType === "topic") return "graph-node topic-node";
  if (contextMemoryType === "goal") return "graph-node goal-node";
  if (contextMemoryType === "objective") return "graph-node objective-node";
  if (contextMemoryType === "event") return "graph-node namespace-event-node";
  if (entry.metadata?.event_segment) return "graph-node event-node";
  if (entry.metadata?.source_tag || entry.metadata?.source) return "graph-node concept-node";
  return "graph-node";
}

function graphNodeLabel(entry) {
  if (entry.metadata?.display_label) {
    return entry.metadata.display_label;
  }
  const contextMemoryType = entry.metadata?.context_memory_type;
  if (!contextMemoryType) return entry.tag;
  if (contextMemoryType === "namespace") {
    return entry.metadata?.context_namespace_title || entry.tag;
  }
  return entry.metadata?.context_label || entry.source_text || entry.tag;
}

function graphNodeTitle(entry) {
  const facets = semanticFacets(entry);
  const lines = [
    graphNodeLabel(entry),
    entry.metadata?.display_summary || entry.source_text || "",
    facets.length ? `facets: ${facets.join(" / ")}` : "",
    `tag: ${entry.tag}`,
    entry.memory_id ? `id: ${entry.memory_id}` : "",
  ].filter(Boolean);
  return lines.join("\n");
}

function semanticFacets(entry) {
  const facets = entry.metadata?.semantic_facets;
  return Array.isArray(facets)
    ? facets.map((facet) => String(facet).trim()).filter(Boolean)
    : [];
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

function initializeWizard() {
  elements.wizardToggleButton.addEventListener("click", () => {
    if (state.wizard.active) {
      stopWizard();
    } else {
      startWizard();
    }
  });
  elements.wizardFlowPicker.addEventListener("click", (event) => {
    const button = event.target.closest("[data-wizard-flow]");
    if (!button) return;
    startWizardFlow(button.dataset.wizardFlow);
  });
  elements.wizardCloseButton.addEventListener("click", stopWizard);
  elements.wizardBackButton.addEventListener("click", previousWizardStep);
  elements.wizardNextButton.addEventListener("click", nextWizardStep);
  window.addEventListener("resize", scheduleWizardPosition, { passive: true });
  document.addEventListener("scroll", scheduleWizardPosition, { passive: true, capture: true });
  document.addEventListener("keydown", (event) => {
    if (!state.wizard.active) return;
    if (event.key === "Escape") {
      stopWizard();
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      nextWizardStep();
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      previousWizardStep();
    }
  });
}

function startWizard() {
  state.wizard.active = true;
  state.wizard.flow = null;
  state.wizard.index = 0;
  elements.wizardLayer.hidden = false;
  elements.wizardLayer.setAttribute("aria-hidden", "false");
  elements.wizardToggleButton.setAttribute("aria-pressed", "true");
  elements.wizardToggleText.textContent = "Stop Wizard";
  renderWizardChoice();
}

function startWizardFlow(flowKey = "intro") {
  const flow = WIZARD_FLOWS[flowKey] ? flowKey : "intro";
  state.wizard.flow = flow;
  state.wizard.index = 0;
  renderWizardStep();
}

function stopWizard() {
  state.wizard.active = false;
  state.wizard.flow = null;
  state.wizard.index = 0;
  elements.wizardLayer.hidden = true;
  elements.wizardLayer.setAttribute("aria-hidden", "true");
  elements.wizardToggleButton.setAttribute("aria-pressed", "false");
  elements.wizardToggleText.textContent = "Start Wizard";
  if (state.wizard.target) {
    state.wizard.target.classList.remove("wizard-highlight-target");
    state.wizard.target = null;
  }
}

function nextWizardStep() {
  if (!state.wizard.active) return;
  if (!state.wizard.flow) {
    startWizardFlow("intro");
    return;
  }
  const steps = currentWizardSteps();
  if (state.wizard.index >= steps.length - 1) {
    stopWizard();
    return;
  }
  state.wizard.index += 1;
  renderWizardStep();
}

function previousWizardStep() {
  if (!state.wizard.active) return;
  if (!state.wizard.flow) return;
  if (state.wizard.index <= 0) {
    renderWizardChoice();
    return;
  }
  state.wizard.index -= 1;
  renderWizardStep();
}

function currentWizardFlow() {
  return WIZARD_FLOWS[state.wizard.flow] || WIZARD_FLOWS.intro;
}

function currentWizardSteps() {
  return currentWizardFlow().steps;
}

function renderWizardChoice() {
  state.wizard.flow = null;
  state.wizard.index = 0;
  const target = elements.wizardToggleButton || document.getElementById("overview");
  updateWizardTarget(target);
  elements.wizardEyebrow.textContent = "Choose wizard flow";
  elements.wizardTitle.textContent = "How do you want to start?";
  elements.wizardBody.textContent = "Use the orientation guide for first-time learning, or skip directly into the operator workflow when you are ready to enter fields and run SYNAPSE-S2.";
  elements.wizardFlowPicker.hidden = false;
  elements.wizardChecklist.replaceChildren();
  elements.wizardChecklist.hidden = true;
  elements.wizardCapability.hidden = true;
  elements.wizardProgress.textContent = "Choose a flow";
  elements.wizardBackButton.disabled = true;
  elements.wizardBackButton.textContent = "Back";
  elements.wizardNextButton.textContent = "Start orientation";
  scrollWizardTargetIntoView(target);
  elements.wizardPanel.focus({ preventScroll: true });
  window.setTimeout(positionWizardOverlay, 220);
}

function renderWizardStep() {
  const flow = currentWizardFlow();
  const steps = currentWizardSteps();
  const step = steps[state.wizard.index] || steps[0];
  const target = document.querySelector(step.selector) || document.getElementById("overview");
  updateWizardTarget(target);

  elements.wizardEyebrow.textContent = flow.label;
  elements.wizardTitle.textContent = step.title;
  elements.wizardBody.textContent = step.body;
  elements.wizardFlowPicker.hidden = true;
  elements.wizardChecklist.hidden = false;
  elements.wizardCapability.hidden = false;
  elements.wizardCapability.textContent = step.capability;
  elements.wizardProgress.textContent = `${flow.progressLabel} step ${state.wizard.index + 1} / ${steps.length}`;
  elements.wizardBackButton.disabled = false;
  elements.wizardBackButton.textContent = state.wizard.index === 0 ? "Flows" : "Back";
  elements.wizardNextButton.textContent = state.wizard.index === steps.length - 1 ? "Finish" : "Next";
  elements.wizardChecklist.replaceChildren(
    ...step.items.map((item) => {
      const node = document.createElement("li");
      node.textContent = item;
      return node;
    }),
  );
  scrollWizardTargetIntoView(target);
  elements.wizardPanel.focus({ preventScroll: true });
  window.setTimeout(positionWizardOverlay, 220);
}

function updateWizardTarget(target) {
  if (state.wizard.target && state.wizard.target !== target) {
    state.wizard.target.classList.remove("wizard-highlight-target");
  }
  state.wizard.target = target;
  state.wizard.target?.classList.add("wizard-highlight-target");
}

function scrollWizardTargetIntoView(target) {
  if (!target) return;
  target.scrollIntoView({
    behavior: "smooth",
    block: window.innerWidth <= 760 ? "start" : "center",
    inline: "center",
  });
}

function scheduleWizardPosition() {
  if (!state.wizard.active) return;
  if (state.wizard.scrollTimer) {
    window.cancelAnimationFrame(state.wizard.scrollTimer);
  }
  state.wizard.scrollTimer = window.requestAnimationFrame(() => {
    state.wizard.scrollTimer = null;
    positionWizardOverlay();
  });
}

function positionWizardOverlay() {
  if (!state.wizard.active || !state.wizard.target) return;
  const viewportWidth = document.documentElement.clientWidth;
  const viewportHeight = window.innerHeight;
  const targetRect = visibleRect(state.wizard.target.getBoundingClientRect(), viewportWidth, viewportHeight);
  const spotlightPadding = 8;
  const spotlightLeft = clamp(targetRect.left - spotlightPadding, 8, viewportWidth - 16);
  const spotlightTop = clamp(targetRect.top - spotlightPadding, 8, viewportHeight - 16);
  const spotlightRight = clamp(targetRect.right + spotlightPadding, spotlightLeft + 12, viewportWidth - 8);
  const spotlightBottom = clamp(targetRect.bottom + spotlightPadding, spotlightTop + 12, viewportHeight - 8);

  Object.assign(elements.wizardSpotlight.style, {
    left: `${spotlightLeft}px`,
    top: `${spotlightTop}px`,
    width: `${spotlightRight - spotlightLeft}px`,
    height: `${spotlightBottom - spotlightTop}px`,
  });

  const panelWidth = Math.min(430, Math.max(288, viewportWidth - 24));
  elements.wizardPanel.style.width = `${panelWidth}px`;
  elements.wizardPanel.style.maxHeight = "calc(100vh - 96px)";
  const panelHeight = elements.wizardPanel.offsetHeight || 320;
  let panelLeft = targetRect.right + 24;
  if (panelLeft + panelWidth > viewportWidth - 12) {
    panelLeft = targetRect.left - panelWidth - 24;
  }
  if (panelLeft < 12) {
    panelLeft = clamp(targetRect.left, 12, viewportWidth - panelWidth - 12);
  }
  let panelTop = clamp(
    targetRect.top + targetRect.height / 2 - panelHeight / 2,
    84,
    viewportHeight - panelHeight - 12,
  );
  if (viewportWidth <= 760) {
    panelLeft = 12;
    const belowTop = targetRect.bottom + 16;
    const belowSpace = viewportHeight - belowTop - 12;
    const aboveTop = 72;
    const aboveSpace = targetRect.top - aboveTop - 16;
    if (belowSpace >= 240 || belowSpace >= aboveSpace) {
      panelTop = belowTop;
      elements.wizardPanel.style.maxHeight = `${Math.max(220, belowSpace)}px`;
    } else {
      panelTop = aboveTop;
      elements.wizardPanel.style.maxHeight = `${Math.max(220, aboveSpace)}px`;
    }
  }

  Object.assign(elements.wizardPanel.style, {
    left: `${panelLeft}px`,
    top: `${panelTop}px`,
  });
  positionWizardArrow(targetRect);
}

function visibleRect(rect, viewportWidth, viewportHeight) {
  const left = clamp(rect.left, 0, viewportWidth);
  const top = clamp(rect.top, 0, viewportHeight);
  const right = clamp(rect.right, left + 1, viewportWidth);
  const bottom = clamp(rect.bottom, top + 1, viewportHeight);
  return {
    left,
    top,
    right,
    bottom,
    width: right - left,
    height: bottom - top,
  };
}

function positionWizardArrow(targetRect) {
  const panelRect = elements.wizardPanel.getBoundingClientRect();
  const targetX = targetRect.left + targetRect.width / 2;
  const targetY = targetRect.top + targetRect.height / 2;
  const panelX = panelRect.left + panelRect.width / 2;
  const panelY = panelRect.top + panelRect.height / 2;
  const controlX = (targetX + panelX) / 2;
  const controlY = Math.min(targetY, panelY) - 30;
  elements.wizardArrowPath.setAttribute(
    "d",
    `M ${panelX} ${panelY} Q ${controlX} ${controlY} ${targetX} ${targetY}`,
  );
  elements.wizardArrowTip.setAttribute("cx", String(targetX));
  elements.wizardArrowTip.setAttribute("cy", String(targetY));
}

function cssEscape(value) {
  return window.CSS?.escape ? window.CSS.escape(value) : String(value).replaceAll('"', '\\"');
}

function renderRelationshipLedger(graph) {
  const relationships = (graph.relationships || []).slice(0, 8);
  elements.relationshipLedger.innerHTML = relationships.length
    ? relationships.map((relationship) => {
      const sourceLabel = relationship.source_label || relationship.source_tag || compactMemoryId(relationship.source_memory_id);
      const targetLabel = relationship.target_label || relationship.target_tag || compactMemoryId(relationship.target_memory_id);
      const sourceFacets = Array.isArray(relationship.source_facets) ? relationship.source_facets.slice(0, 2) : [];
      const targetFacets = Array.isArray(relationship.target_facets) ? relationship.target_facets.slice(0, 2) : [];
      const facetLine = [...sourceFacets, ...targetFacets].filter(Boolean).join(" / ");
      const pruneLabel = `${relationship.relation_type || "relationship"} ${sourceLabel} to ${targetLabel}`;
      return `
        <div class="relationship-ledger-row">
          <div>
            <strong>${escapeHtml(relationship.relation_type || "relationship")}</strong>
            <small>${escapeHtml(sourceLabel)} -> ${escapeHtml(targetLabel)}</small>
            <p>${escapeHtml(facetLine || compactMemoryId(relationship.relationship_id))}</p>
          </div>
          <span>${escapeHtml(formatNumber(relationship.weight, 3))}</span>
          <time>${escapeHtml(formatTimestamp(relationship.updated_at || relationship.created_at))}</time>
          <button class="danger-button prune-row-button" type="button"
            data-prune-target="relationship"
            data-relationship-id="${escapeHtml(relationship.relationship_id)}"
            data-prune-label="${escapeHtml(pruneLabel)}">
            Delete edge
          </button>
        </div>
      `;
    }).join("")
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
      const sourceText = String(entry.metadata?.display_summary || entry.source_text || "").trim();
      const facets = semanticFacets(entry).slice(0, 4).join(" / ");
      const label = graphNodeLabel(entry);
      const targetType = entry.metadata?.event_segment ? "event" : "memory";
      return `
        <div class="memory-ledger-row">
          <div>
            <strong>${escapeHtml(label)}</strong>
            <small>${escapeHtml(source)} / ${escapeHtml(facets || entry.tag)} / ${escapeHtml(compactMemoryId(entry.memory_id))}</small>
            ${sourceText ? `<p>${escapeHtml(compactTag(sourceText, 120))}</p>` : ""}
          </div>
          <span>${formatNumber(entry.spike_count)} spikes</span>
          <time>${escapeHtml(formatTimestamp(entry.updated_at || entry.created_at))}</time>
          <button class="danger-button prune-row-button" type="button"
            data-prune-target="${targetType}"
            data-memory-id="${escapeHtml(entry.memory_id)}"
            data-tag="${escapeHtml(entry.tag)}"
            data-prune-label="${escapeHtml(label)}">
            Delete node
          </button>
        </div>
      `;
    }).join("")
    : '<div class="memory-ledger-empty">No persisted traces</div>';
}

function renderFooter(snapshot, status, profile, contextCount) {
  const current = Number(profile.estimated_total_mb ?? 0);
  const max = Number(profile.target_envelope_mb?.max ?? 256);
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
  const recallScope = ["local", "connected", "all"].includes(payload.recall_scope)
    ? payload.recall_scope
    : currentRecallScope();

  elements.resultCount.textContent = `(${formatNumber(items.length)})`;
  elements.latencyLabel.textContent = `Latency: ${formatNumber(payload.latency_ms, 1)} ms · ${recallScope} scope`;
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
  const facets = Array.isArray(item.facets) && item.facets.length
    ? ` / ${item.facets.slice(0, 4).join(" / ")}`
    : "";
  const title = item.label || item.tag || item.raw || "--";
  const identity = item.tag && item.tag !== title ? `${item.tag}${facets}` : facets.replace(/^ \/ /, "");
  const memoryId = String(item.memory_id || "");
  const memoryContext = String(item.context_id || state.context || DEFAULT_CONTEXT);
  const recallScope = String(item.recall_scope || "local");
  const recallProvenance = String(item.recall_provenance || "local");
  const viaRelation = String(item.via_relation_type || "");
  const viaContextLinkId = String(item.via_context_link_id || "");
  const pinActionLabel = memoryContext === state.context
    ? "Use this memory now"
    : `Pin in ${memoryContext}`;
  const provenance = [
    item.tag ? `source ${item.tag}` : "",
    `context ${memoryContext}`,
    `scope ${recallScope}`,
    `provenance ${recallProvenance}`,
    viaRelation ? `via ${viaRelation}` : "",
    viaContextLinkId ? `link ${compactMemoryId(viaContextLinkId)}` : "",
    memoryId ? `id ${compactMemoryId(memoryId)}` : "",
  ].filter(Boolean).join(" / ");
  const whyMatched = [
    Number.isFinite(Number(item.score)) ? "embedding score" : "",
    Number.isFinite(Number(item.weight)) ? "graph relationship weight" : "",
    item.relation_type ? `related by ${item.relation_type}` : "",
    Array.isArray(item.facets) && item.facets.length ? "facet overlap" : "",
    item.context_id ? "namespace provenance" : "",
    recallProvenance === "connected" ? "approved one-hop bridge" : "",
  ].filter(Boolean).join(" / ") || "status result";
  const recallAction = memoryId
    ? `<div class="result-actions">
        <button type="button"
          class="secondary-button recall-pin-button"
          data-recall-action="pin"
          data-memory-id="${escapeHtml(memoryId)}"
          data-memory-context="${escapeHtml(memoryContext)}"
          data-recall-label="${escapeHtml(title)}">
          ${escapeHtml(pinActionLabel)}
        </button>
        <button type="button"
          class="recall-moderate-button"
          data-recall-action="promote"
          data-memory-id="${escapeHtml(memoryId)}"
          data-memory-context="${escapeHtml(memoryContext)}"
          data-recall-label="${escapeHtml(title)}">
          Promote
        </button>
        <button type="button"
          class="recall-moderate-button"
          data-recall-action="demote"
          data-memory-id="${escapeHtml(memoryId)}"
          data-memory-context="${escapeHtml(memoryContext)}"
          data-recall-label="${escapeHtml(title)}">
          Demote
        </button>
        <button type="button"
          class="recall-moderate-button danger-button"
          data-recall-action="prune"
          data-memory-id="${escapeHtml(memoryId)}"
          data-memory-context="${escapeHtml(memoryContext)}"
          data-recall-label="${escapeHtml(title)}">
          Prune
        </button>
      </div>`
    : "";
  return `
    <article class="result-card">
      <span>${formatNumber(item.rank || 0)}</span>
      <div class="result-body">
        <strong>${escapeHtml(title)}</strong>
        <small>${escapeHtml(`${score}${relation}${context}${identity ? ` / ${identity}` : ""}`)}</small>
        <small class="recall-evidence"><b>Why this matched</b> ${escapeHtml(whyMatched)}</small>
        <small class="recall-evidence">${escapeHtml(provenance || "No source memory id available")}</small>
        ${item.summary ? `<p>${escapeHtml(compactTag(item.summary, 120))}</p>` : ""}
      </div>
      ${recallAction}
    </article>
  `;
}

async function pinRecallMemory(button) {
  const memoryId = button.dataset.memoryId || "";
  const memoryContext = button.dataset.memoryContext || state.context;
  const label = button.dataset.recallLabel || compactMemoryId(memoryId);
  if (!memoryId) {
    logOperation("Pin recall rejected", "recall result is missing a memory id");
    return null;
  }
  const prompt = elements.queryInput.value.trim();
  return withBusy(button, "Pin recall", async () => {
    const payload = await requestJson("/api/pin-memory", {
      method: "POST",
      body: {
        context_id: memoryContext,
        memory_id: memoryId,
        agent_id: "dashboard-ui",
        note: prompt
          ? `Pinned from recall prompt: ${compactTag(prompt, 180)}`
          : `Pinned from recall result: ${compactTag(label, 180)}`,
      },
    });
    await publishAwareResult(payload);
    return payload;
  }).catch((error) => {
    logOperation("Pin recall failed", error.message);
    return null;
  });
}

async function moderateRecallMemory(button) {
  const memoryId = button.dataset.memoryId || "";
  const memoryContext = button.dataset.memoryContext || state.context;
  const action = button.dataset.recallAction || "";
  const label = button.dataset.recallLabel || compactMemoryId(memoryId);
  if (!memoryId || !["promote", "demote", "prune"].includes(action)) return null;
  if (action === "prune" && !confirmPrune(label)) {
    logOperation("Recall prune cancelled", label);
    return null;
  }
  return withBusy(button, `${action} recall`, async () => {
    const payload = await requestJson("/api/cortex/moderate", {
      method: "POST",
      body: {
        context_id: memoryContext,
        memory_id: memoryId,
        action,
        reason: `dashboard ${action} from Recall Console`,
        confirm: action === "prune",
      },
    });
    await publishAwareResult(payload);
    logOperation(`Recall ${action}`, payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    logOperation(`Recall ${action} failed`, error.message);
    return null;
  });
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

async function refreshAppConnect({ detect = true } = {}) {
  const [apps, connections] = await Promise.all([
    detect ? requestJson("/api/apps") : Promise.resolve(null),
    requestJson("/api/app-connections"),
  ]);
  renderAppConnect(apps, connections);
  return {
    action: "refresh-app-connect",
    detected_apps: apps?.app_count ?? state.appConnect.apps.length,
    app_connections: connections.connection_count,
    apps: apps?.apps ?? state.appConnect.apps,
    connections: connections.connections,
  };
}

async function runSelfTest(button) {
  return withBusy(button, "Self test", async () => {
    setSelfTestState("Self test running", "Checking local runtime, memory, capture, and app intake.", "pending");
    const payload = await requestJson("/api/self-test", {
      params: {
        context_id: state.context,
        include_apps: "true",
      },
    });
    renderSelfTest(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    setSelfTestState("Self test failed", error.message, "error");
    return null;
  });
}

function selectedDetectedApp() {
  if (elements.appSelect.value === "") {
    return null;
  }
  const index = Number(elements.appSelect.value);
  if (!Number.isInteger(index) || index < 0) {
    return null;
  }
  return state.appConnect.apps[index] || null;
}

async function connectSelectedApp(button) {
  const selected = selectedDetectedApp();
  const manualName = elements.appManualName.value.trim();
  const appName = selected?.app_name || manualName;
  if (!appName) {
    logOperation("App Connect rejected", "detect and select a running app, or enter a manual app name");
    setAppConnectState(
      "App Connect needs a target",
      "Detect and select a running app, or enter a manual app name.",
      "error",
    );
    elements.appManualName.focus();
    return null;
  }
  const connectBody = {
    context_id: state.context,
    app_name: appName,
    bundle_id: selected?.bundle_id || "",
    pid: Number(selected?.pid || 0),
    source_tag: elements.appSourceTag.value.trim() || "app-connect",
    speaker: elements.appSpeaker.value.trim() || "operator",
    allow_manual: !selected,
    metadata: { source: "dashboard-app-connect" },
  };
  return withBusy(button, "App Connect", async () => {
    setAppConnectState("Preparing app attach", `${appName} -> ${connectBody.source_tag}`, "pending");
    const preflight = await requestJson("/api/app-connect/preflight", {
      method: "POST",
      body: connectBody,
    });
    setAppConnectState(
      "Connecting app",
      `${preflight.app_name} is being attached to ${preflight.context_id} with source ${preflight.source_tag}.`,
      "pending",
    );
    const payload = await requestJson("/api/app-connect", {
      method: "POST",
      body: {
        ...connectBody,
        confirmation_token: preflight.confirmation_token,
      },
    });
    await refreshAppConnect({ detect: false });
    elements.appConnectionSelect.value = payload.connection_id || "";
    setAppConnectState(
      "App connection armed",
      `${payload.app_name} is attached and ready for an Accessibility snapshot.`,
      "ready",
    );
    return payload;
  }, { refresh: false }).catch((error) => {
    setAppConnectState("App Connect failed", error.message, "error");
    return null;
  });
}

async function previewConnectedAppSnapshot(button) {
  const connectionId = elements.appConnectionSelect.value.trim();
  if (!connectionId) {
    logOperation("App preview rejected", "connect an app first, then choose the attached connection");
    setAppConnectState(
      "Preview needs a connection",
      "Connect an app first, then choose the attached connection.",
      "error",
    );
    elements.appConnectionSelect.focus();
    return null;
  }
  return withBusy(button, "App snapshot preview", async () => {
    const payload = await requestJson("/api/app-snapshot/preview", {
      method: "POST",
      body: {
        connection_id: connectionId,
        metadata: { source: "dashboard-app-snapshot-preview" },
      },
    });
    renderAppSnapshotPreview(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    elements.appPreviewReceipt.textContent = `Preview failed: ${error.message}`;
    setAppConnectState("App preview failed", error.message, "error");
    return null;
  });
}

function renderAppSnapshotPreview(payload) {
  const badge = payload.quality_badge || {};
  const capability = payload.capability_badge || {};
  const status = String(badge.status || "degraded");
  const quality = payload.snapshot_quality || {};
  elements.appPreviewReceipt.innerHTML = `
    <article class="receipt-card ${escapeHtml(status)}">
      <span>${escapeHtml(status)}</span>
      <strong>${escapeHtml(badge.label || "Snapshot preview")}</strong>
      <small>${escapeHtml(`${capability.label || "Capability unknown"} / ${formatNumber(quality.line_count)} lines / ${formatNumber(quality.signal_chars)} signal chars`)}</small>
      <p>${escapeHtml((payload.capture_guidance || []).join(" "))}</p>
      <pre>${escapeHtml(payload.preview_text || "")}</pre>
    </article>
  `;
  setAppConnectState(
    `${payload.app_name} preview ${badge.label || status}`,
    badge.next_action || "Capture snapshot only if the preview matches the intended content.",
    status === "blocked" ? "error" : status === "degraded" ? "pending" : "ready",
  );
}

async function snapshotConnectedApp(button) {
  const connectionId = elements.appConnectionSelect.value.trim();
  if (!connectionId) {
    logOperation("App snapshot rejected", "connect an app first, then choose the attached connection");
    setAppConnectState(
      "Snapshot needs a connection",
      "Connect an app first, then choose the attached connection.",
      "error",
    );
    elements.appConnectionSelect.focus();
    return null;
  }
  return withBusy(button, "App snapshot", async () => {
    const snapshotBody = {
      connection_id: connectionId,
      metadata: { source: "dashboard-app-snapshot" },
    };
    setAppConnectState("Preparing snapshot", "Checking the attached app connection.", "pending");
    const preflight = await requestJson("/api/app-snapshot/preflight", {
      method: "POST",
      body: snapshotBody,
    });
    const connection = preflight.connection || {};
    setAppConnectState(
      "Capturing app snapshot",
      `${connection.app_name || connectionId} is being read through locally exposed Accessibility text and redacted before memory ingest.`,
      "pending",
    );
    const payload = await requestJson("/api/app-snapshot", {
      method: "POST",
      body: {
        ...snapshotBody,
        confirmation_token: preflight.confirmation_token,
      },
    });
    await publishAwareResult(payload);
    await refreshAppConnect({ detect: false });
    const lowSignal = payload.snapshot_quality?.low_signal === true;
    setAppConnectState(
      lowSignal ? "Low-signal snapshot captured" : "Snapshot captured",
      lowSignal
        ? `${payload.app_name} wrote ${formatNumber(payload.event_count || 0)} memory event${Number(payload.event_count || 0) === 1 ? "" : "s"} from limited Accessibility text. Use selected-text fallback for exact content.`
        : `${payload.app_name} wrote ${formatNumber(payload.event_count || 0)} memory event${Number(payload.event_count || 0) === 1 ? "" : "s"}.`,
      "ready",
    );
    return payload;
  }).catch((error) => {
    setAppConnectState("App snapshot failed", error.message, "error");
    return null;
  });
}

async function captureSelectedAppText(button) {
  const connectionId = elements.appConnectionSelect.value.trim();
  const text = elements.appSelectionText.value.trim();
  if (!connectionId) {
    logOperation("App selection rejected", "connect an app first, then choose the attached connection");
    setAppConnectState(
      "Selection needs a connection",
      "Connect an app first, then choose the attached connection.",
      "error",
    );
    elements.appConnectionSelect.focus();
    return null;
  }
  if (!text) {
    logOperation("App selection rejected", "paste selected text from the attached app before capture");
    setAppConnectState(
      "Selection text is empty",
      "Paste selected app text before capture.",
      "error",
    );
    elements.appSelectionText.focus();
    return null;
  }
  return withBusy(button, "App selection capture", async () => {
    setAppConnectState("Capturing selected text", "Redacting selected app text before memory ingest.", "pending");
    const payload = await requestJson("/api/app-selection-capture", {
      method: "POST",
      body: {
        connection_id: connectionId,
        text,
        confirm: true,
        metadata: { source: "dashboard-app-selected-text" },
      },
    });
    await publishAwareResult(payload);
    await refreshAppConnect({ detect: false });
    elements.appConnectionSelect.value = connectionId;
    elements.appSelectionText.value = "";
    setAppConnectState(
      "Selected text captured",
      `${payload.app_name} wrote ${formatNumber(payload.event_count || 0)} memory event${Number(payload.event_count || 0) === 1 ? "" : "s"}.`,
      "ready",
    );
    return payload;
  }).catch((error) => {
    setAppConnectState("Selection capture failed", error.message, "error");
    return null;
  });
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
    : "Start Cortex Session before risky work";
  elements.cortexSessionId.title = state.cortex.sessionId;
}

async function enterCortexSession(button) {
  const task = elements.cortexTask.value.trim();
  if (!task) {
    logOperation("Cortex enter rejected", "current task is required");
    elements.cortexTask.focus();
    return null;
  }
  return withBusy(button, "Start Cortex", async () => {
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

async function closeCortexSession(button) {
  const sessionId = currentCortexSessionId();
  if (!sessionId) {
    logOperation("Cortex close rejected", "there is no active Cortex session to end");
    elements.cortexTask.focus();
    return null;
  }
  return withBusy(button, "End Cortex Session", async () => {
    const payload = await requestJson("/api/cortex/close", {
      method: "POST",
      body: {
        context_id: state.context,
        agent_id: currentCortexAgentId(),
        session_id: sessionId,
        reason: "operator-ended-dashboard-session",
      },
    });
    await publishAwareResult(payload);
    setCortexSessionId("");
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
        confirm: action === "prune",
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
    if (payload?.receipt) {
      renderOperationReceipt(payload.receipt);
    }
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
  const enabled = Boolean(state.coreToggle.enabled);
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
  const enabled = Boolean(state.coreToggle.enabled);
  const nextAction = enabled ? "Disable" : "Enable";
  const lockedHint = "Locked. Press Unlock before enabling or disabling SYNAPSE-S2 Core.";
  const unlockedHint = `Unlocked for one ${nextAction.toLowerCase()} action. Relocks after use or timeout.`;
  elements.toggleActionButton.disabled = !unlocked;
  elements.toggleActionState.textContent = nextAction;
  elements.coreUnlockButton.disabled = unlocked;
  elements.coreUnlockButton.textContent = unlocked ? "Unlocked" : "Unlock";
  elements.coreUnlockButton.setAttribute("aria-pressed", String(unlocked));
  elements.coreToggleGuardHint.textContent = unlocked ? unlockedHint : lockedHint;
  elements.toggleActionButton.title = unlocked
    ? `${nextAction} SYNAPSE-S2 Core`
    : "Unlock before changing SYNAPSE-S2 Core";
  elements.toggleActionButton.setAttribute("aria-label", `${nextAction} SYNAPSE-S2 Core`);
}

elements.contextApply.addEventListener("click", () => {
  void applySelectedContext(elements.contextInput.value, elements.contextApply);
});

elements.contextInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    elements.contextApply.click();
  }
});

elements.contextSelect.addEventListener("change", () => {
  void applySelectedContext(elements.contextSelect.value, elements.contextSelect);
});

elements.contextMenuList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-context]");
  if (!button) {
    return;
  }
  event.preventDefault();
  elements.contextMenuDetails.open = false;
  void applySelectedContext(button.dataset.context, button);
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

elements.recipesToggleButton.addEventListener("click", () => {
  const nextOpen = elements.recipeDrawer.hidden;
  elements.recipeDrawer.hidden = !nextOpen;
  elements.recipesToggleButton.setAttribute("aria-expanded", String(nextOpen));
});

elements.recipesCloseButton.addEventListener("click", () => {
  elements.recipeDrawer.hidden = true;
  elements.recipesToggleButton.setAttribute("aria-expanded", "false");
});

elements.startWorkButton.addEventListener("click", () => {
  runStartWork(elements.startWorkButton);
});

elements.contextHealthButton.addEventListener("click", () => {
  runContextHealth(elements.contextHealthButton);
});

elements.doctorReportButton.addEventListener("click", () => {
  runDoctorReport(elements.doctorReportButton);
});

elements.memoryHygieneButton.addEventListener("click", () => {
  runMemoryHygiene(elements.memoryHygieneButton);
});

elements.wrapSessionPreviewButton.addEventListener("click", () => {
  runWrapSession(elements.wrapSessionPreviewButton, { previewOnly: true });
});

elements.wrapSessionButton.addEventListener("click", () => {
  runWrapSession(elements.wrapSessionButton, { previewOnly: false });
});

elements.memoryHygieneQueue.addEventListener("click", (event) => {
  const button = event.target.closest?.("[data-hygiene-action]");
  if (!button) return;
  event.preventDefault();
  withBusy(button, "Memory hygiene action", async () => {
    const payload = await requestJson("/api/memory-hygiene/action", {
      method: "POST",
      body: {
        context_id: state.context,
        action: button.dataset.hygieneAction || "acknowledge",
        memory_id: button.dataset.memoryId || "",
        reason: `dashboard acknowledged ${button.dataset.hygieneLabel || "memory item"}`,
      },
    });
    await runMemoryHygiene(elements.memoryHygieneButton);
    return payload;
  }, { refresh: false });
});

elements.mondayReadinessButton.addEventListener("click", () => {
  withBusy(elements.mondayReadinessButton, "Monday readiness", async () => {
    setSelfTestState("Monday readiness running", "Scoring runtime, memory, embeddings, App Connect, and recall.", "pending");
    const payload = await requestJson("/api/monday-readiness", {
      params: {
        context_id: state.context,
        include_apps: "true",
      },
    });
    renderMondayReadiness(payload);
    return payload;
  }, { refresh: false }).catch((error) => {
    setSelfTestState("Monday readiness failed", error.message, "error");
    return null;
  });
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
elements.toggleActionButton.addEventListener("click", () => toggleCore(elements.toggleActionButton));

elements.cortexEnterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await enterCortexSession(elements.cortexEnterForm.querySelector("button"));
});

elements.cortexCloseButton.addEventListener("click", async () => {
  await closeCortexSession(elements.cortexCloseButton);
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
      body: {
        context_id: state.context,
        prompt,
        recall_scope: currentRecallScope(),
      },
    });
    state.lastQueryPayload = payload;
    renderQueryResult(payload);
    return payload;
  }, { refresh: false });
});

elements.queryResults.addEventListener("click", (event) => {
  const button = event.target.closest?.("[data-recall-action]");
  if (!button) return;
  event.preventDefault();
  if (button.dataset.recallAction === "pin") {
    pinRecallMemory(button);
    return;
  }
  moderateRecallMemory(button);
});

elements.recallLimit.addEventListener("change", () => {
  if (state.lastQueryPayload) {
    renderQueryResult(state.lastQueryPayload);
  }
});

[elements.recallScopeLocal, elements.recallScopeConnected, elements.recallScopeAll].forEach((control) => {
  control.addEventListener("change", updateRecallScopeHelp);
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

elements.selfTestButton.addEventListener("click", () => {
  runSelfTest(elements.selfTestButton);
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
    const maxFiles = 50;
    const preflight = await requestJson("/api/capture-inbox/preflight", {
      method: "POST",
      body: { context_id: state.context, max_files: maxFiles },
    });
    if (Number(preflight.selected_file_count || 0) <= 0) {
      logOperation("Magic capture idle", preflight);
      return preflight;
    }
    if (!confirmPreflight("Process pending capture inbox files?", [
      `Files: ${preflight.selected_file_count} of ${preflight.pending_file_count}`,
      `Bytes: ${formatNumber(preflight.selected_total_bytes || 0)}`,
      `Root: ${preflight.root}`,
    ])) {
      logOperation("Magic capture cancelled", preflight);
      return preflight;
    }
    const payload = await requestJson("/api/capture-inbox/process", {
      method: "POST",
      body: {
        context_id: state.context,
        max_files: maxFiles,
        confirmation_token: preflight.confirmation_token,
      },
    });
    renderCaptureInbox({
      ...(state.snapshot?.capture_inbox || {}),
      last_result: payload,
      pending_file_count: 0,
    });
    return payload;
  });
});

elements.appConnectButton.addEventListener("click", () => {
  document.getElementById("appConnect")?.scrollIntoView({ behavior: "smooth", block: "start" });
  withBusy(elements.appConnectButton, "App Connect detect", () => (
    refreshAppConnect({ detect: true })
  ), { refresh: false });
});

elements.appRefreshButton.addEventListener("click", () => {
  withBusy(elements.appRefreshButton, "Detect apps", () => (
    refreshAppConnect({ detect: true })
  ), { refresh: false });
});

elements.appConnectForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await connectSelectedApp(elements.appConnectSubmitButton);
});

elements.appPreviewButton.addEventListener("click", () => {
  previewConnectedAppSnapshot(elements.appPreviewButton);
});

elements.appSnapshotButton.addEventListener("click", () => {
  snapshotConnectedApp(elements.appSnapshotButton);
});

elements.appSelectionCaptureButton.addEventListener("click", () => {
  captureSelectedAppText(elements.appSelectionCaptureButton);
});

refreshSnapshot()
  .catch((error) => {
    logOperation("Initial load failed", error.message);
  });

refreshAppConnect({ detect: false })
  .catch((error) => {
    logOperation("App Connect init failed", error.message);
  });
