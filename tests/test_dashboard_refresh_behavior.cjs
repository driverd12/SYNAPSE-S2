// Execute the production refresh functions; no browser or third-party test dependencies.
// Override SYNAPSE_DASHBOARD_APP to validate a staged or independently served app.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const appPath = process.env.SYNAPSE_DASHBOARD_APP
  || path.resolve(__dirname, '..', 'web', 'app.js');
const source = fs.readFileSync(appPath, 'utf8');
function functionSource(name) {
  const pattern = new RegExp(`^(?:async )?function ${name}\\(`, 'm');
  const start = source.search(pattern);
  assert.notEqual(start, -1, `Production function ${name} exists`);
  const tail = source.slice(start);
  const next = tail.slice(1).search(/\n(?:async )?function \w+\(/);
  assert.notEqual(next, -1, `Production function ${name} has a boundary`);
  return tail.slice(0, next + 1);
}
const stateStart = source.indexOf('const state = {');
const stateEnd = source.indexOf('\nconst elements = ', stateStart);
assert.ok(stateStart >= 0 && stateEnd > stateStart);
const production = source.slice(stateStart, stateEnd) + '\n'
  + ['refreshSnapshot', 'refreshImageGallery', 'pullContextDeployments', 'withGraph', 'applySelectedContext']
    .map(functionSource).join('\n')
  + '\nglobalThis.dashboard = { state, refreshSnapshot, refreshImageGallery, pullContextDeployments, applySelectedContext };';

const flush = () => new Promise((resolve) => setImmediate(resolve));
const shell = (context, version = context) => ({ context_id: context, version, graph: { deferred: true } });
const graph = (version) => ({ deferred: false, version, entries: [] });

function harness() {
  const requests = [];
  const snapshots = [];
  const galleries = [];
  const logs = [];
  const elements = {
    headerRuntime: { textContent: '' },
    contextApply: {},
    contextInput: { value: '' },
    contextSelect: { value: '', options: [] },
  };
  const sandbox = {
    URL, URLSearchParams,
    DEFAULT_CONTEXT: 'A',
    NAMESPACE_GALAXY_CONTEXT_PARAM: 'namespace',
    NAMESPACE_GALAXY_DEFAULT_ROTATION: {},
    SNAPSHOT_LIMIT: 20,
    window: { location: { search: '', href: 'http://localhost/?context_id=A' } },
    history: { state: null, replaceState() {} },
    elements,
    nowMs: () => 1,
    elapsedMs: () => 0,
    requestJson: (url, options = {}) => new Promise((resolve, reject) => {
      requests.push({ url, options, resolve, reject, taken: false });
    }),
    renderSnapshot: (snapshot) => snapshots.push(structuredClone(snapshot)),
    renderImageGallery: (gallery) => galleries.push(structuredClone(gallery)),
    refreshNamespaceGalaxy: async () => null,
    operationLogIsIdle: () => false,
    logSnapshotResponse() {},
    logOperation: (label, detail) => logs.push({ label, detail }),
    lockMemoraGovernanceGuard() {},
    resetRecallResults() {},
    selectNamespaceGalaxyItem() {},
    withBusy: async (_button, _label, task) => task(),
  };
  vm.createContext(sandbox);
  vm.runInContext(production, sandbox, { filename: appPath });
  const api = sandbox.dashboard;
  function take(url, context) {
    const request = requests.find((item) => !item.taken && item.url === url
      && (context === undefined || item.options.params?.context_id === context));
    assert.ok(request, `Pending ${url} for ${context}; saw ${requests.map((item) => `${item.url}:${item.options.params?.context_id}:${item.taken}`).join(', ')}`);
    request.taken = true;
    return request;
  }
  async function finish(context, version = context) {
    take('/api/snapshot', context).resolve(shell(context, version));
    await flush();
    take('/api/media-cache', context).resolve({ context_id: context, version });
    take('/api/graph', context).resolve(graph(version));
    await flush();
    take('/api/context-events', context).resolve({ context_id: context, version, events: [] });
    await flush();
  }
  return { ...api, requests, snapshots, galleries, logs, elements, take, finish };
}

test('late shell response cannot overwrite a newly selected namespace or start follow-up reads', async () => {
  const h = harness();
  const old = h.refreshSnapshot();
  const oldShell = h.take('/api/snapshot', 'A');
  const selected = h.applySelectedContext('B');
  await h.finish('B');
  await selected;
  oldShell.resolve(shell('A'));
  assert.equal(await old, null);
  assert.equal(h.state.snapshot.context_id, 'B');
  assert.ok(h.snapshots.every((item) => item.context_id === 'B'));
  assert.equal(h.requests.filter((item) => item.options.params.context_id === 'A').length, 1);
});

test('late graph and gallery from a prior namespace cannot overwrite the new namespace', async () => {
  const h = harness();
  const old = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A'));
  await flush();
  const oldGraph = h.take('/api/graph', 'A');
  const oldGallery = h.take('/api/media-cache', 'A');
  const afterSwitch = h.snapshots.length;
  const selected = h.applySelectedContext('B');
  await h.finish('B');
  await selected;
  oldGallery.resolve({ context_id: 'A' });
  oldGraph.resolve(graph('A'));
  assert.equal(await old, null);
  await flush();
  assert.ok(h.snapshots.slice(afterSwitch).every((item) => item.context_id === 'B'));
  assert.deepEqual(h.galleries.map((item) => item.context_id), ['B']);
  assert.equal(h.requests.filter((item) => item.url === '/api/context-events' && item.options.params.context_id === 'A').length, 0);
});

test('overlapping refreshes in the same namespace keep the latest snapshot and gallery', async () => {
  const h = harness();
  const old = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A', 'old'));
  await flush();
  const oldGraph = h.take('/api/graph', 'A');
  const oldGallery = h.take('/api/media-cache', 'A');
  const latest = h.refreshSnapshot();
  await h.finish('A', 'latest');
  await latest;
  oldGraph.resolve(graph('old'));
  oldGallery.resolve({ context_id: 'A', version: 'old' });
  assert.equal(await old, null);
  await flush();
  assert.equal(h.state.snapshot.version, 'latest');
  assert.equal(h.state.snapshot.graph.version, 'latest');
  assert.deepEqual(h.galleries.map((item) => item.version), ['latest']);
});

test('a successful graph renders before deployment completion and survives deployment failure', async () => {
  const h = harness();
  const pending = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A'));
  await flush();
  h.take('/api/media-cache', 'A').resolve({ context_id: 'A' });
  h.take('/api/graph', 'A').resolve(graph('complete'));
  await flush();
  assert.equal(h.snapshots.at(-1).graph.version, 'complete');
  h.take('/api/context-events', 'A').reject(new Error('deployment read failed'));
  const result = await pending;
  assert.equal(result.graph.version, 'complete');
  assert.deepEqual(h.logs.map((item) => item.label), ['Context deployment refresh failed']);
});

test('late deployment response cannot merge old events into a new snapshot', async () => {
  const h = harness();
  const old = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A'));
  await flush();
  h.take('/api/media-cache', 'A').resolve({ context_id: 'A' });
  h.take('/api/graph', 'A').resolve(graph('A'));
  await flush();
  const oldEvents = h.take('/api/context-events', 'A');
  const selected = h.applySelectedContext('B');
  await h.finish('B');
  await selected;
  oldEvents.resolve({ context_id: 'A', events: ['old'] });
  assert.equal(await old, null);
  assert.equal(h.state.snapshot.context_deployments.context_id, 'B');
});

test('standalone gallery refreshes reject same-context out-of-order responses', async () => {
  const h = harness();
  const old = h.refreshImageGallery();
  const oldRequest = h.take('/api/media-cache', 'A');
  const current = h.refreshImageGallery();
  h.take('/api/media-cache', 'A').resolve({ version: 'current' });
  assert.equal((await current).version, 'current');
  oldRequest.resolve({ version: 'old' });
  assert.equal(await old, null);
  assert.deepEqual(h.galleries.map((item) => item.version), ['current']);
});

test('A to B to A invalidates an old gallery even before replacement shells finish', async () => {
  const h = harness();
  const old = h.refreshImageGallery();
  const oldRequest = h.take('/api/media-cache', 'A');
  const visitB = h.applySelectedContext('B');
  const bShell = h.take('/api/snapshot', 'B');
  const returnA = h.applySelectedContext('A');
  oldRequest.resolve({ version: 'old' });
  assert.equal(await old, null);
  assert.equal(h.galleries.length, 0);
  bShell.resolve(shell('B'));
  await visitB;
  await h.finish('A', 'new');
  await returnA;
  assert.deepEqual(h.galleries.map((item) => item.version), ['new']);
});

test('authorization failure suppresses pending shell, graph, and gallery renders', async () => {
  const h = harness();
  const pending = h.refreshSnapshot();
  h.state.dashboardAccessRequired = true;
  h.elements.headerRuntime.textContent = 'AUTH REQUIRED';
  h.take('/api/snapshot', 'A').resolve(shell('A'));
  assert.equal(await pending, null);
  assert.equal(h.snapshots.length, 0);
  assert.equal(h.elements.headerRuntime.textContent, 'AUTH REQUIRED');

  const loaded = harness();
  const second = loaded.refreshSnapshot();
  loaded.take('/api/snapshot', 'A').resolve(shell('A'));
  await flush();
  const count = loaded.snapshots.length;
  loaded.state.dashboardAccessRequired = true;
  loaded.elements.headerRuntime.textContent = 'AUTH REQUIRED';
  loaded.take('/api/graph', 'A').resolve(graph('late'));
  loaded.take('/api/media-cache', 'A').resolve({ version: 'late' });
  assert.equal(await second, null);
  await flush();
  assert.equal(loaded.snapshots.length, count);
  assert.equal(loaded.galleries.length, 0);
  assert.equal(loaded.elements.headerRuntime.textContent, 'AUTH REQUIRED');
});

test('graph failure is isolated and does not discard the shell or successful gallery', async () => {
  const h = harness();
  const pending = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A'));
  await flush();
  h.take('/api/media-cache', 'A').resolve({ version: 'gallery' });
  h.take('/api/graph', 'A').reject(new Error('graph unavailable'));
  assert.equal((await pending).context_id, 'A');
  assert.deepEqual(h.galleries.map((item) => item.version), ['gallery']);
  assert.deepEqual(h.logs.map((item) => item.label), ['Graph refresh failed']);
});

test('late graph failure does not overwrite the current operation status', async () => {
  const h = harness();
  const old = h.refreshSnapshot();
  h.take('/api/snapshot', 'A').resolve(shell('A'));
  await flush();
  const oldGraph = h.take('/api/graph', 'A');
  const oldGallery = h.take('/api/media-cache', 'A');
  const selected = h.applySelectedContext('B');
  await h.finish('B');
  await selected;
  oldGraph.reject(new Error('old failure'));
  oldGallery.reject(new Error('old gallery failure'));
  assert.equal(await old, null);
  assert.deepEqual(h.logs, []);
});

test('deployment reads retain the existing default and support a captured context', async () => {
  const h = harness();
  h.state.context = 'B';
  const explicit = h.pullContextDeployments(-1, 20, 'A');
  const explicitRequest = h.take('/api/context-events', 'A');
  assert.equal(explicitRequest.options.params.since_event_id, 0);
  assert.equal(explicitRequest.options.params.limit, 20);
  explicitRequest.resolve({ version: 'explicit' });
  assert.equal((await explicit).version, 'explicit');
  const current = h.pullContextDeployments();
  h.take('/api/context-events', 'B').resolve({ version: 'default' });
  assert.equal((await current).version, 'default');
});
