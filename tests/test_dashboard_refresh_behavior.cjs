// Exercise production health and request coordination with controlled clocks and responses.
// No source-string-only assertion substitutes for the behavioral checks below.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const appPath = process.env.SYNAPSE_DASHBOARD_APP || path.resolve(__dirname, '..', 'web', 'app.js');
const source = fs.readFileSync(appPath, 'utf8');
function functionSource(name) {
  const start = source.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  assert.notEqual(start, -1, `Production function ${name} exists`);
  const tail = source.slice(start);
  const next = tail.slice(1).search(/\n(?:async )?function \w+\(/);
  assert.notEqual(next, -1);
  return tail.slice(0, next + 1);
}
const functionNames = [
  'dashboardHealthModel', 'renderCoreHealth', 'renderProcessMemory', 'refreshCoreHealth',
  'dashboardPanel', 'dashboardPanelNeedsRefresh', 'renderDashboardPanelStates', 'runDashboardPanel',
  'refreshMissingSnapshot', 'refreshRuntimePanel', 'refreshGraphPanel', 'refreshSnapshot',
  'refreshImageGallery', 'refreshNamespaceGalaxy', 'refreshNamespaceGalaxyRequest',
  'pullContextDeployments', 'withGraph', 'applySelectedContext', 'renderFooter',
  'isDashboardAuthorizationError', 'renderDashboardAccessRequired', 'refreshCaptureInboxStatus',
  'recordCaptureInboxStatus', 'renderCaptureInbox', 'withBusy',
  'formatCalculationTime', 'renderAnalysisControls', 'renderHygieneScan', 'advanceHygieneScan',
  'stopNamespaceEnrichmentPolling', 'renderNamespaceEnrichment', 'refreshNamespaceEnrichment', 'requestNamespaceEnrichment',
  'clearImageSimilarObjectUrls', 'setImageSimilarState', 'imageSimilarRequestIsCurrent',
  'loadImageSimilarThumbnail', 'renderImageSimilarWarnings', 'renderImageSimilarResults', 'openImageSimilar', 'closeImageSimilar',
];
const stateStart = source.indexOf('const state = {');
const stateEnd = source.indexOf('\nconst elements = ', stateStart);
const production = source.slice(stateStart, stateEnd) + '\n' + functionNames.map(functionSource).join('\n')
  + `\nglobalThis.dashboard = { state, ${functionNames.join(', ')} };`;
const flush = () => new Promise(resolve => setImmediate(resolve));
const shell = (context, version = context) => ({ context_id: context, version, graph: { deferred: true } });
const graph = version => ({ deferred: false, version, entries: [] });
const healthy = (overrides = {}) => ({
  ready: true, operational_state: 'ready', authority: { ready: true },
  capture: { ready: true, last_success_age_ms: 20 },
  backend_lane: { ready: true, active: false, accepting_ordinary_operations: true }, ...overrides,
});
const authError = () => Object.assign(new Error('dashboard authorization required'), { dashboardAuthorizationRequired: true, status: 403 });
function harness() {
  let clock = 100000;
  const requests = [], snapshots = [], galleries = [], logs = [], maps = [], timers = [];
  const objectUrls = [], revokedUrls = [];
  const makeElement = () => ({
    textContent: '', title: '', value: '', options: [], dataset: {}, hidden: false,
    classList: { add() {}, toggle() {} }, setAttribute() {}, children: [], focus() {}, isConnected: true,
    replaceChildren(...nodes) { this.children = nodes; }, append(...nodes) { this.children.push(...nodes); },
  });
  const elements = new Proxy({}, { get(target, name) { return target[name] ||= makeElement(); } });
  const sandbox = {
    URL: class extends URL {
      static createObjectURL(blob) { const url = `blob:test-${objectUrls.length}`; objectUrls.push({ url, blob }); return url; }
      static revokeObjectURL(url) { revokedUrls.push(url); }
    }, URLSearchParams, Date: class extends Date { static now() { return clock; } },
    document: { visibilityState: 'visible', documentElement: { dataset: {}, classList: { add() {} } }, querySelectorAll: () => [], createElement: makeElement },
    DEFAULT_CONTEXT: 'A', NAMESPACE_GALAXY_CONTEXT_PARAM: 'namespace', NAMESPACE_GALAXY_DEFAULT_ROTATION: {},
    SNAPSHOT_LIMIT: 20, CORE_HEALTH_FRESH_MS: 15000, DASHBOARD_PANEL_FRESH_MS: 60000,
    DASHBOARD_PANEL_RETRY_MS: 5000, READ_REQUEST_TIMEOUT_MS: 10000,
    window: { location: { search: '', href: 'http://localhost/?context_id=A' }, clearTimeout(id) { if (timers[id]) timers[id].cleared = true; }, setTimeout(fn, ms) { timers.push({ fn, ms }); return timers.length - 1; } },
    history: { state: null, replaceState() {} }, elements,
    nowMs: () => clock, elapsedMs: () => 0, formatNumber: (n, digits = 0) => Number(n).toFixed(digits), formatClock: () => '',
    requestJson: (url, options = {}) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject, taken: false })),
    requestBlob: (url, options = {}) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject, taken: false })),
    renderSnapshot: snapshot => { snapshots.push(structuredClone(snapshot)); },
    renderImageGallery: gallery => galleries.push(structuredClone(gallery)),
    renderNamespaceGalaxy: data => { api.state.namespaceGalaxy.data = data; maps.push(data); },
    normalizeNamespaceMap: payload => payload,
    applyNamespaceGalaxyMetrics: nodes => nodes,
    namespaceMapFallbackFromSnapshot: () => ({ nodes: [], links: [], proposals: [], suggestions: [], stats: {} }),
    setNamespaceGalaxyState() {}, restoreNamespaceGalaxyFromUrl() {}, escapeHtml: value => String(value),
    operationLogIsIdle: () => false, logSnapshotResponse() {}, logOperation: (label, detail) => logs.push({ label, detail }),
    lockMemoraGovernanceGuard() {}, resetRecallResults() {}, selectNamespaceGalaxyItem() {},
  };
  vm.createContext(sandbox);
  vm.runInContext(production, sandbox, { filename: appPath });
  const api = sandbox.dashboard;
  function take(url, context) {
    const request = requests.find(item => !item.taken && item.url === url && (context === undefined || item.options.params?.context_id === context));
    assert.ok(request, `Pending ${url} for ${context}; saw ${requests.map(item => `${item.url}:${item.options.params?.context_id}:${item.taken}`).join(', ')}`);
    request.taken = true; return request;
  }
  function map(context) { return { nodes: [{ contextId: context }], links: [], proposals: [], suggestions: [], stats: {} }; }
  async function finishPanels(context, version = context, { failGraph = false, failMap = false, failGallery = false } = {}) {
    const g = take('/api/graph', context);
    const m = take('/api/namespace-map', context);
    const image = take('/api/media-cache', context);
    if (failGallery) image.reject(new Error('gallery unavailable')); else image.resolve({ context_id: context, version });
    if (failMap) m.reject(new Error('map unavailable')); else m.resolve(map(context));
    if (failGraph) g.reject(new Error('graph unavailable'));
    else { g.resolve(graph(version)); await flush(); take('/api/context-events', context).resolve({ context_id: context, version, events: [] }); }
    await flush();
  }
  async function finish(context, version = context, failures) {
    take('/api/snapshot', context).resolve(shell(context, version)); await flush();
    await finishPanels(context, version, failures);
  }
  function seedHealth(value = healthy()) { api.state.coreHealth.latest = value; api.state.coreHealth.lastSuccessfulRefreshAt = clock; api.state.coreHealth.error = null; }
  return { ...api, requests, snapshots, galleries, logs, maps, timers, objectUrls, revokedUrls, elements, document: sandbox.document, take, finish, finishPanels, map, seedHealth, advance: ms => { clock += ms; } };
}

test('initial indicators and footer require fresh authoritative evidence, regardless of topology budget', () => {
  const h = harness();
  h.renderFooter({}, { effective_enabled: true }, { estimated_total_mb: 288, within_target_envelope: true }, 3);
  for (const name of ['headerRuntime', 'sidebarStatus', 'footerHealth', 'engineState', 'routerState', 'memoryState', 'apiState']) assert.equal(h.elements[name].textContent, 'INITIALIZING');
  assert.equal(h.elements.healthConfirmedAt.textContent, 'Not yet confirmed');
  h.seedHealth(); h.renderCoreHealth();
  assert.equal(h.elements.footerHealth.textContent, 'READY');
  h.state.coreHealth.error = 'socket unavailable'; h.renderFooter({}, { effective_enabled: true }, { within_target_envelope: true }, 3);
  assert.equal(h.elements.footerHealth.textContent, 'STALE');
  assert.equal(h.elements.headerRuntime.textContent, 'STALE');
});

for (const [name, evidence, expected] of [
  ['missing authority', { authority: {} }, 'unavailable'],
  ['missing capture', { capture: {} }, 'unavailable'],
  ['unready capture', { capture: { ready: false, last_success_age_ms: 1 } }, 'unavailable'],
  ['missing capture timestamp', { capture: { ready: true } }, 'stale'],
  ['null capture timestamp', { capture: { ready: true, last_success_age_ms: null } }, 'stale'],
  ['string capture timestamp', { capture: { ready: true, last_success_age_ms: '0' } }, 'stale'],
  ['future capture timestamp', { capture: { ready: true, last_success_age_ms: -1 } }, 'stale'],
  ['old capture timestamp', { capture: { ready: true, last_success_age_ms: 16000 } }, 'stale'],
  ['missing lane readiness', { backend_lane: { accepting_ordinary_operations: true } }, 'unavailable'],
  ['busy lane', { backend_lane: { ready: true, active: true, accepting_ordinary_operations: false } }, 'busy'],
  ['maintenance', { operational_state: 'maintenance', backend_lane: { maintenance: true } }, 'busy'],
]) test(`${name} cannot produce a green health indicator`, () => {
  const h = harness(); h.seedHealth(healthy(evidence));
  assert.equal(h.renderCoreHealth().status, expected);
  assert.notEqual(h.elements.footerHealth.textContent, 'READY');
});

test('health expires without another response and shows age on all indicators', () => {
  const h = harness(); h.seedHealth(); h.advance(16000); h.renderCoreHealth();
  assert.equal(h.elements.headerRuntime.textContent, 'STALE');
  assert.equal(h.elements.footerHealthConfirmedAt.textContent, 'Last confirmed 16s ago');
  assert.match(h.elements.memoryState.title, /16s ago/);
});

test('health requests never overlap, including a foreground check during a background request', async () => {
  const h = harness(); h.document.visibilityState = 'hidden';
  const poll = h.refreshCoreHealth({ background: true });
  assert.equal(await h.refreshCoreHealth(), null); assert.equal(h.requests.length, 1);
  h.take('/api/core-health').resolve(healthy()); await poll;
  assert.equal(h.state.coreHealth.refreshPending, false);
});

test('process memory is independent from the topology estimate, with unavailable values explicit', () => {
  const h = harness(); h.seedHealth(healthy({ process_memory: { footprint_bytes: 4.3 * 1024 ** 3 } }));
  h.renderFooter({}, { effective_enabled: true }, { estimated_total_mb: 288, within_target_envelope: true }, 3);
  assert.match(h.elements.processMemory.textContent, /4403.2 MiB/);
  assert.match(h.elements.footerMemory.textContent, /288.0 MB estimated/);
  h.seedHealth(healthy({ process_memory: { footprint_bytes: null, resident_bytes: null } })); h.renderCoreHealth();
  assert.equal(h.elements.processMemory.textContent, 'Unavailable');
});

test('failed shell releases bootstrap guard; backoff prevents a hot loop then health recovers', async () => {
  const h = harness(); const pending = h.refreshMissingSnapshot(); const rejection = assert.rejects(pending, /shell unavailable/);
  h.take('/api/snapshot', 'A').reject(new Error('shell unavailable')); await rejection;
  assert.equal(h.state.snapshotBootstrapPending, false);
  await h.refreshMissingSnapshot(); assert.equal(h.requests.length, 1);
  h.advance(5000);
  const health = h.refreshCoreHealth(); h.take('/api/core-health').resolve(healthy()); await health;
  await h.finish('A', 'recovered');
  assert.equal(h.state.snapshot.graph.version, 'recovered');
});

test('overlapping bootstrap and manual refresh do not duplicate component requests', async () => {
  const h = harness(); const first = h.refreshMissingSnapshot();
  assert.equal(await h.refreshMissingSnapshot(), null); assert.equal(await h.refreshSnapshot(), null);
  assert.equal(h.requests.length, 1);
  await h.finish('A'); await first;
});

test('failed graph after a successful shell retries only the graph and preserves other panels', async () => {
  const h = harness(); const first = h.refreshSnapshot(); await h.finish('A', 'first', { failGraph: true }); await first;
  assert.equal(h.state.snapshot.graph.deferred, true);
  assert.ok(h.state.panels.runtime.lastSuccessfulRefreshAt);
  const before = h.requests.length; h.advance(5000); const retry = h.refreshMissingSnapshot();
  assert.deepEqual(h.requests.slice(before).map(x => x.url), ['/api/graph']);
  h.take('/api/graph', 'A').resolve(graph('recovered')); await flush();
  h.take('/api/context-events', 'A').resolve({ events: [] }); await retry;
  assert.equal(h.state.snapshot.graph.version, 'recovered'); assert.equal(h.state.panels.graph.error, null);
});

for (const [name, url, failure] of [['namespaceMap', '/api/namespace-map', 'failMap'], ['gallery', '/api/media-cache', 'failGallery']]) {
  test(`failed ${name} retries independently without reloading a successful graph or shell`, async () => {
    const h = harness(); const initial = h.refreshSnapshot(); await h.finish('A', 'first', { [failure]: true }); await initial;
    assert.ok(h.state.panels[name].error); const before = h.requests.length; h.advance(5000);
    const retry = h.refreshMissingSnapshot(); assert.deepEqual(h.requests.slice(before).map(x => x.url), [url]);
    h.take(url, 'A').resolve(name === 'namespaceMap' ? h.map('A') : { version: 'recovered' }); await retry;
    assert.equal(h.state.panels[name].error, null); assert.equal(h.state.snapshot.graph.version, 'first');
  });
}

test('map requests remain lightweight and a concurrent periodic map refresh is coalesced', async () => {
  const h = harness(); const first = h.refreshNamespaceGalaxy();
  assert.equal(await h.refreshNamespaceGalaxy({ background: true }), null);
  const req = h.take('/api/namespace-map', 'A');
  assert.equal(req.options.params.include_density_metrics, 'false'); assert.equal(req.options.params.include_suggestions, 'false');
  req.resolve(h.map('A')); await first; assert.equal(h.requests.length, 1);
});

test('successful graph survives deployment failure and is not marked for graph retry', async () => {
  const h = harness(); const first = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A')); await flush();
  h.take('/api/media-cache', 'A').resolve({ version: 'gallery' }); h.take('/api/namespace-map', 'A').resolve(h.map('A'));
  h.take('/api/graph', 'A').resolve(graph('complete')); await flush();
  assert.equal(h.snapshots.at(-1).graph.version, 'complete');
  h.take('/api/context-events', 'A').reject(new Error('deployment read failed')); await first;
  assert.equal(h.state.panels.graph.error, null); assert.ok(h.state.panels.graph.lastSuccessfulRefreshAt);
  assert.deepEqual(h.logs.map(x => x.label), ['Context deployment refresh failed']);
});

test('periodic runtime refresh retains a successful graph even while the replacement graph fails', async () => {
  const h = harness(); const first = h.refreshSnapshot(); await h.finish('A', 'old'); await first;
  const again = h.refreshSnapshot(); h.take('/api/snapshot', 'A').resolve(shell('A', 'new')); await flush();
  assert.equal(h.state.snapshot.graph.version, 'old');
  await h.finishPanels('A', 'new', { failGraph: true }); await again;
  assert.equal(h.state.snapshot.version, 'new'); assert.equal(h.state.snapshot.graph.version, 'old');
});

test('late shell response cannot overwrite a new namespace or start follow-up requests', async () => {
  const h = harness(); const old = h.refreshSnapshot(); const oldShell = h.take('/api/snapshot', 'A');
  const selected = h.applySelectedContext('B'); await h.finish('B'); await selected;
  oldShell.resolve(shell('A')); assert.equal(await old, null);
  assert.ok(h.snapshots.every(x => x.context_id === 'B'));
  assert.equal(h.requests.filter(x => x.options.params?.context_id === 'A').length, 1);
});

test('late graph, map and gallery cannot cross a context generation, including A to B to A', async () => {
  const h = harness(); const first = h.refreshSnapshot(); h.take('/api/snapshot', 'A').resolve(shell('A', 'old')); await flush();
  const oldGraph = h.take('/api/graph', 'A'), oldMap = h.take('/api/namespace-map', 'A'), oldGallery = h.take('/api/media-cache', 'A');
  const visit = h.applySelectedContext('B'); const bShell = h.take('/api/snapshot', 'B');
  const back = h.applySelectedContext('A'); await h.finish('A', 'new'); await back;
  oldGraph.resolve(graph('old')); oldMap.resolve(h.map('old')); oldGallery.resolve({ version: 'old' }); bShell.resolve(shell('B'));
  assert.equal(await first, null); await visit;
  assert.equal(h.state.snapshot.version, 'new'); assert.equal(h.state.snapshot.graph.version, 'new');
  assert.ok(!h.maps.some(x => x.nodes[0]?.contextId === 'old')); assert.ok(!h.galleries.some(x => x.version === 'old'));
});

test('late deployment response cannot merge into a newly selected namespace', async () => {
  const h = harness(); const old = h.refreshSnapshot(); h.take('/api/snapshot', 'A').resolve(shell('A')); await flush();
  h.take('/api/graph', 'A').resolve(graph('A')); h.take('/api/namespace-map', 'A').resolve(h.map('A')); h.take('/api/media-cache', 'A').resolve({}); await flush();
  const events = h.take('/api/context-events', 'A'); const selected = h.applySelectedContext('B'); await h.finish('B'); await selected;
  events.resolve({ events: ['old'] }); assert.equal(await old, null); assert.equal(h.state.snapshot.context_deployments.context_id, 'B');
});

for (const scenario of ['auth', 'maintenance', 'unavailable', 'hidden']) test(`${scenario} suppresses automatic panel retries`, async () => {
  const h = harness(); const loaded = h.refreshSnapshot(); await h.finish('A', 'first', { failGraph: true }); await loaded; h.advance(5000);
  if (scenario === 'hidden') h.document.visibilityState = 'hidden';
  const before = h.requests.length; const poll = h.refreshCoreHealth(); const req = h.take('/api/core-health');
  if (scenario === 'auth') req.reject(authError());
  else req.resolve(scenario === 'maintenance' ? healthy({ operational_state: 'maintenance', backend_lane: { active: true, maintenance: true } }) : scenario === 'unavailable' ? healthy({ ready: false }) : healthy());
  await poll; assert.equal(h.requests.length, before + 1);
  if (scenario === 'auth') { assert.equal(h.elements.footerHealth.textContent, 'AUTH REQUIRED'); assert.equal(await h.refreshSnapshot(), null); }
});

test('authentication failure in a panel locks the page and late successful responses cannot turn it green', async () => {
  const h = harness(); const load = h.refreshSnapshot(); h.take('/api/snapshot', 'A').resolve(shell('A')); await flush();
  const graphReq = h.take('/api/graph', 'A'), mapReq = h.take('/api/namespace-map', 'A'), galleryReq = h.take('/api/media-cache', 'A');
  mapReq.reject(authError()); await flush(); graphReq.resolve(graph('late')); galleryReq.resolve({ version: 'late' }); await load;
  assert.equal(h.state.dashboardAccessRequired, true); assert.equal(h.elements.headerRuntime.textContent, 'AUTH REQUIRED');
  assert.equal(h.state.snapshot.graph.deferred, true); assert.equal(h.galleries.length, 0);
});

test('stale component timestamps are visible and refresh without erasing last good data', async () => {
  const h = harness(); const first = h.refreshSnapshot(); await h.finish('A'); await first; h.advance(61000); h.renderDashboardPanelStates();
  assert.match(h.elements.graphLoadState.textContent, /stale.*61s/);
  const again = h.refreshMissingSnapshot(); await h.finish('A', 'fresh'); await again;
  assert.equal(h.state.snapshot.graph.version, 'fresh'); assert.equal(h.elements.graphLoadState.dataset.loadState, 'ready');
});

test('capture queue checks use only the read-only status path and do not overlap', async () => {
  const h = harness(); const first = h.refreshCaptureInboxStatus(); assert.equal(await h.refreshCaptureInboxStatus(), null);
  assert.equal(h.requests.length, 1); const req = h.take('/api/capture-inbox'); assert.equal(req.options.method, undefined);
  req.resolve({ pending_file_count: 2 }); await first;
  assert.equal(h.state.captureInboxRefreshPending, false);
});


test('runtime panel failure cannot suppress independently due graph, map or gallery work', async () => {
  const h = harness(); const first = h.refreshSnapshot(); await h.finish('A', 'old'); await first;
  const again = h.refreshSnapshot(); const failed = assert.rejects(again, /runtime failed/);
  h.take('/api/snapshot', 'A').reject(new Error('runtime failed')); await flush();
  await h.finishPanels('A', 'new'); await failed;
  assert.equal(h.state.snapshot.graph.version, 'new'); assert.equal(h.state.panels.runtime.error, 'runtime failed');
});

test('partial hygiene scan cannot imply a clean namespace and only advances once per click', async () => {
  const h = harness(); h.seedHealth(); const first = h.advanceHygieneScan();
  assert.equal(await h.advanceHygieneScan(), null);
  const request = h.take('/api/memory-hygiene/scan'); assert.equal(request.options.method, 'POST');
  assert.deepEqual(JSON.parse(JSON.stringify(request.options.body)), { context_id: 'A' });
  request.resolve({ context_id: 'A', scan_id: 'scan-one', status: 'partial', scan_complete: false,
    scanned_entry_count: 250, total_entry_count: 4988, coverage_fraction: 250 / 4988,
    category_counts: {}, candidate_survivor_mapping: [], calculated_at: 100 }); await first;
  assert.match(h.elements.hygieneScanStatus.textContent, /Partial scan.*cleanliness not established.*250 \/ 4988/);
  assert.equal(h.elements.hygieneScanButton.textContent, 'Continue scan');
  assert.equal(h.requests.length, 1);
  const next = h.advanceHygieneScan(); const page = h.take('/api/memory-hygiene/scan'); assert.equal(page.options.body.scan_id, 'scan-one');
  page.resolve({ context_id: 'A', scan_id: 'scan-one', status: 'complete', scan_complete: true,
    scanned_entry_count: 4988, total_entry_count: 4988, coverage_fraction: 1, category_counts: { duplicates: 2 },
    candidate_survivor_mapping: [{ candidate_id: 'candidate', survivor_id: 'survivor' }], calculated_at: 101 }); await next;
  assert.match(h.elements.hygieneScanStatus.textContent, /Scan complete/);
  assert.match(h.elements.hygieneScanDetails.textContent, /duplicates: 2.*1 candidate-to-survivor mappings for review/);
});

test('hygiene revision drift restarts without reusing the old scan ID', async () => {
  const h = harness(); h.seedHealth(); h.state.hygieneScan.scanId = 'old'; h.state.hygieneScan.payload = { status: 'partial' };
  const first = h.advanceHygieneScan(); h.take('/api/memory-hygiene/scan').resolve({ status: 'restart_required' }); await first;
  assert.equal(h.elements.hygieneScanButton.textContent, 'Restart scan'); assert.equal(h.state.hygieneScan.scanId, null);
  const restart = h.advanceHygieneScan(); const req = h.take('/api/memory-hygiene/scan'); assert.equal(req.options.body.scan_id, undefined);
  req.reject(new Error('temporarily unavailable')); await restart;
  assert.match(h.elements.hygieneScanStatus.textContent, /temporarily unavailable/);
});

test('a late hygiene response cannot install a scan handle after a context change', async () => {
  const h = harness(); h.seedHealth(); const scan = h.advanceHygieneScan(); const req = h.take('/api/memory-hygiene/scan');
  const selected = h.applySelectedContext('B'); await h.finish('B'); await selected;
  req.resolve({ context_id: 'A', scan_id: 'wrong', status: 'partial' }); assert.equal(await scan, null);
  assert.equal(h.state.hygieneScan.scanId, null); assert.equal(h.state.hygieneScan.payload, null);
});

test('enrichment starts only explicitly, polls a bounded status path, and retains a separate calculated view', async () => {
  const h = harness(); h.seedHealth(); const load = h.refreshSnapshot(); await h.finish('A'); await load;
  assert.equal(h.requests.filter(x => x.url === '/api/namespace-enrichment').length, 0);
  const calculation = h.requestNamespaceEnrichment(); const req = h.take('/api/namespace-enrichment'); assert.equal(req.options.method, 'POST');
  assert.equal(await h.requestNamespaceEnrichment(), null);
  req.resolve({ state: 'queued', context_id: 'A' }); await calculation;
  assert.equal(h.timers.at(-1).ms, 5000); h.timers.at(-1).fn();
  const status = h.take('/api/namespace-enrichment', 'A'); assert.equal(status.options.method, undefined);
  status.resolve({ state: 'ready', context_id: 'A', calculated_at: 123,
    data: { nodes: [{ context_id: 'A', entry_count: 7, surface_term_count: 42 }], suggestions: [] } }); await flush();
  assert.equal(h.state.namespaceEnrichment.polling, false);
  assert.match(h.elements.namespaceEnrichmentStatus.textContent, /ready.*Calculated at/);
  assert.equal(h.maps.length, 1); // Rich details never overwrite a newer lightweight map.
  assert.ok(h.elements.namespaceEnrichmentOutput.children.length);
});

test('enrichment polling stops on auth and old responses cannot cross context generations', async () => {
  const h = harness(); h.seedHealth(); const first = h.requestNamespaceEnrichment(); const req = h.take('/api/namespace-enrichment');
  const selected = h.applySelectedContext('B'); await h.finish('B'); await selected;
  req.resolve({ state: 'ready', context_id: 'A', calculated_at: 123, data: { nodes: [] } }); assert.equal(await first, null);
  assert.equal(h.state.namespaceEnrichment.payload, null);
  const current = h.requestNamespaceEnrichment(); h.take('/api/namespace-enrichment').reject(authError()); await current;
  assert.equal(h.state.namespaceEnrichment.polling, false); assert.equal(h.elements.footerHealth.textContent, 'AUTH REQUIRED');
});

test('enrichment has a bounded poll budget and stopping checks makes no cancellation mutation', async () => {
  const h = harness(); h.seedHealth(); h.state.namespaceEnrichment.polls = 24;
  const poll = h.refreshNamespaceEnrichment(); h.take('/api/namespace-enrichment', 'A').resolve({ state: 'running' }); await poll;
  assert.equal(h.state.namespaceEnrichment.polling, false); assert.equal(h.timers.length, 0);
  const before = h.requests.length; h.stopNamespaceEnrichmentPolling(); assert.equal(h.requests.length, before);
});


test('capture queue readiness expires independently and never certifies an individual receipt', () => {
  const h = harness();
  h.recordCaptureInboxStatus({ pending_file_count: 0, processing_file_count: 0, error_file_count: 0 });
  h.renderCoreHealth(); assert.notEqual(h.elements.captureInboxState.className, 'capture-inbox-state ready');
  h.seedHealth(); h.renderCoreHealth(); assert.equal(h.elements.captureInboxState.className, 'capture-inbox-state ready');
  assert.match(h.elements.captureInboxState.innerHTML, /does not establish an individual capture receipt/);
  h.advance(16000); h.seedHealth(); h.renderCoreHealth();
  assert.notEqual(h.elements.captureInboxState.className, 'capture-inbox-state ready');
  assert.match(h.elements.captureInboxState.innerHTML, /last observed empty.*stale/);
  h.recordCaptureInboxStatus({}); h.renderCoreHealth(); assert.match(h.elements.captureInboxState.innerHTML, /unknown/);
});

test('lightweight maps never inherit stale density metrics or suggestions', async () => {
  const h = harness();
  h.state.namespaceGalaxy.data = { nodes: [{ contextId: 'A', surfaceTermCount: 42 }], suggestions: [{ sourceContextId: 'A', targetContextId: 'B' }] };
  const refresh = h.refreshNamespaceGalaxy();
  h.take('/api/namespace-map', 'A').resolve(h.map('A')); await refresh;
  assert.equal(h.maps[0].nodes[0].surfaceTermCount, undefined); assert.equal(h.maps[0].suggestions.length, 0);
});

test('health transport delay consumes the freshness window', async () => {
  const h = harness(); h.document.visibilityState = 'hidden';
  const request = h.refreshCoreHealth(); h.advance(3000);
  h.take('/api/core-health').resolve(healthy({ capture: { ready: true, last_success_age_ms: 14000 } })); await request;
  assert.equal(h.renderCoreHealth().status, 'stale'); assert.equal(h.elements.healthConfirmedAt.textContent, 'Last confirmed 3s ago');
});


test('hygiene unavailable error is not displayed as partial progress or zero coverage', async () => {
  const h = harness(); h.seedHealth(); const scan = h.advanceHygieneScan();
  h.take('/api/memory-hygiene/scan').resolve({ status: 'unavailable', error_code: 'scan_busy', scan_complete: false }); await scan;
  assert.match(h.elements.hygieneScanStatus.textContent, /Scan unavailable.*Coverage unavailable.*scan_busy/);
  assert.equal(h.elements.hygieneScanButton.textContent, 'Retry scan page');
});

test('inconsistent complete flag cannot certify full coverage', () => {
  const h = harness(); h.state.hygieneScan.payload = { status: 'complete', scan_complete: true, scanned_entry_count: 1, total_entry_count: 50, coverage_fraction: 0.02 };
  h.renderHygieneScan(); assert.match(h.elements.hygieneScanStatus.textContent, /Partial scan.*cleanliness not established/);
});

test('another namespace busy job is never polled or represented as this context calculation', async () => {
  const h = harness(); h.seedHealth(); const first = h.requestNamespaceEnrichment();
  h.take('/api/namespace-enrichment').resolve({ state: 'busy', job_id: null, error_code: 'another_job_active' }); await first;
  assert.equal(h.state.namespaceEnrichment.polling, false); assert.equal(h.timers.length, 0);
  assert.match(h.elements.namespaceEnrichmentStatus.textContent, /another job active/);
  assert.equal(h.elements.namespaceEnrichmentButton.textContent, 'Calculate details');
  const retry = h.requestNamespaceEnrichment(); const req = h.take('/api/namespace-enrichment'); assert.equal(req.options.method, 'POST');
  req.resolve({ state: 'failed', error_code: 'worker_unavailable' }); await retry;
});

test('deadline-exceeded enrichment stops polling and preserves an explicit uncertainty', async () => {
  const h = harness(); h.seedHealth(); const first = h.requestNamespaceEnrichment();
  h.take('/api/namespace-enrichment').resolve({ state: 'running', job_id: 'job', deadline_exceeded: true }); await first;
  assert.equal(h.state.namespaceEnrichment.polling, false); assert.equal(h.timers.length, 0);
  assert.match(h.elements.namespaceEnrichmentStatus.textContent, /exceeded its deadline; no result is certified/);
  assert.equal(h.elements.namespaceEnrichmentButton.textContent, 'Check calculation');
});

test('a completed action cannot re-enable its control after an auth failure', async () => {
  const h = harness(); const button = { disabled: false };
  await assert.rejects(h.withBusy(button, 'queue', async () => { h.renderDashboardAccessRequired(authError()); throw authError(); }), /authorization required/);
  assert.equal(button.disabled, true);
});


test('stopping enrichment checks retains the in-flight slot until its response returns', async () => {
  const h = harness(); h.seedHealth(); h.state.namespaceEnrichment.payload = { state: 'running', job_id: 'job' }; h.state.namespaceEnrichment.polling = true;
  const poll = h.refreshNamespaceEnrichment(); const response = h.take('/api/namespace-enrichment', 'A');
  h.stopNamespaceEnrichmentPolling(); assert.equal(h.state.namespaceEnrichment.pending, true);
  assert.equal(h.requestNamespaceEnrichment(), null); assert.equal(h.requests.length, 1);
  response.resolve({ state: 'ready', data: { nodes: [] } }); await poll;
  assert.equal(h.state.namespaceEnrichment.pending, false); assert.equal(h.state.namespaceEnrichment.payload.state, 'running');
});


test('completed enrichment becomes visibly stale without fresh revision evidence', () => {
  const h = harness(); h.seedHealth();
  h.state.namespaceEnrichment.payload = { state: 'ready', calculated_at: 100, data: { nodes: [] } };
  h.state.namespaceEnrichment.lastSuccessfulRefreshAt = 100000;
  h.renderCoreHealth(); assert.match(h.elements.namespaceEnrichmentStatus.textContent, /^ready/);
  h.advance(16000); h.renderCoreHealth();
  assert.match(h.elements.namespaceEnrichmentStatus.textContent, /stale calculation.*Calculated at/);
});

test('lightweight map refresh rechecks only an explicitly requested enrichment via GET', async () => {
  const h = harness(); h.seedHealth();
  h.state.namespaceEnrichment.payload = { state: 'ready', calculated_at: 100, data: { nodes: [] } };
  const refresh = h.refreshNamespaceGalaxy(); h.take('/api/namespace-map', 'A').resolve(h.map('A')); await refresh;
  const check = h.take('/api/namespace-enrichment', 'A'); assert.equal(check.options.method, undefined);
  check.resolve({ state: 'stale', error_code: 'revision_changed', data: null }); await flush();
  assert.match(h.elements.namespaceEnrichmentStatus.textContent, /^stale.*revision changed/);
  assert.equal(h.elements.namespaceEnrichmentOutput.children.length, 0);
  assert.equal(h.requests.filter(x => x.url === '/api/namespace-enrichment' && x.options.method === 'POST').length, 0);
});

const similarMediaA = `s2img_${'a'.repeat(32)}`;
const similarMediaB = `s2img_${'b'.repeat(32)}`;
const similarResult = { results: [{ media_id: similarMediaB, rank: 1, distance: 0.25 }] };

async function replaceSimilarView(h, transition) {
  if (transition === 'namespace switch') {
    const switching = h.applySelectedContext('B');
    assert.equal(h.state.imageCapture.similarOpen, false);
    assert.equal(h.elements.imageSimilarPanel.hidden, true);
    await h.finish('B'); await switching;
  } else if (transition === 'close and reopen') {
    h.closeImageSimilar();
  }
  const pending = h.openImageSimilar(transition === 'different media' ? similarMediaB : similarMediaA, 'New image');
  return { pending, request: h.take('/api/media-similar', h.state.context) };
}

for (const transition of ['namespace switch', 'close and reopen', 'different media']) {
  test(`similarity results and errors cannot overwrite a new view after ${transition}`, async () => {
    for (const failOld of [false, true]) {
      const h = harness();
      const old = h.openImageSimilar(similarMediaA, 'Old image');
      const oldRequest = h.take('/api/media-similar', 'A');
      const current = await replaceSimilarView(h, transition);
      assert.equal(current.request.options.params.context_id, h.state.context);
      current.request.resolve({ results: [] }); await current.pending;
      if (failOld) oldRequest.reject(new Error('Old request failed'));
      else oldRequest.resolve(similarResult);
      await old;
      assert.match(h.elements.imageSimilarTitle.textContent, /New image/);
      assert.match(h.elements.imageSimilarState.innerHTML, /No similar images/);
      assert.equal(h.elements.imageSimilarResults.children.length, 0);
      assert.equal(h.requests.filter(x => x.url === '/api/media-thumbnail').length, 0);
    }
  });

  test(`pending similarity thumbnails cannot populate or allocate URLs after ${transition}`, async () => {
    for (const failOld of [false, true]) {
      const h = harness();
      const old = h.openImageSimilar(similarMediaA, 'Old image');
      h.take('/api/media-similar', 'A').resolve(similarResult); await old;
      const oldImage = h.elements.imageSimilarResults.children[0].children[0];
      const priorAlt = oldImage.alt;
      const thumbnail = h.take('/api/media-thumbnail');
      const current = await replaceSimilarView(h, transition);
      current.request.resolve({ results: [] }); await current.pending;
      if (failOld) thumbnail.reject(new Error('Old thumbnail failed'));
      else thumbnail.resolve({ oldBlob: true });
      await flush();
      assert.equal(oldImage.src, undefined);
      assert.equal(oldImage.alt, priorAlt);
      assert.equal(h.objectUrls.length, 0);
      assert.equal(h.state.imageCapture.similarObjectUrls.length, 0);
    }
  });
}

test('current similarity thumbnail displays and is revoked when the panel closes', async () => {
  const h = harness(); const search = h.openImageSimilar(similarMediaA, 'Current image');
  h.take('/api/media-similar', 'A').resolve(similarResult); await search;
  const image = h.elements.imageSimilarResults.children[0].children[0];
  h.take('/api/media-thumbnail').resolve({ currentBlob: true }); await flush();
  assert.equal(image.src, 'blob:test-0'); assert.equal(h.state.imageCapture.similarObjectUrls.length, 1);
  h.closeImageSimilar();
  assert.deepEqual(h.revokedUrls, ['blob:test-0']);
  assert.equal(h.state.imageCapture.similarObjectUrls.length, 0);
});

test('authentication failure closes similarity and suppresses pending thumbnails', async () => {
  const h = harness(); const search = h.openImageSimilar(similarMediaA, 'Current image');
  h.take('/api/media-similar', 'A').resolve(similarResult); await search;
  const thumbnail = h.take('/api/media-thumbnail');
  h.renderDashboardAccessRequired(authError());
  thumbnail.resolve({ oldBlob: true }); await flush();
  assert.equal(h.elements.imageSimilarPanel.hidden, true);
  assert.equal(h.objectUrls.length, 0);
  const count = h.requests.length; await h.openImageSimilar(similarMediaA, 'Unavailable');
  assert.equal(h.requests.length, count);
});
