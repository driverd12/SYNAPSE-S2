# SYNAPSE-S2 Visual Operator Manual

Paper demonstration and field guide for the Namespace Galaxy, semantic drill-down, governed memory operations, and reliability controls.

Interface shown: SYNAPSE-S2 release `018cd32db4013dee7763f1517f953eb956b7fa0d`, July 29, 2026.

Companion artifacts:

- [Annotated visual manual (PDF)](../pdf/SYNAPSE-S2_Visual_User_Manual.pdf)
- [One-page operator reference (PDF)](../pdf/SYNAPSE-S2_Quick_Reference.pdf)
- [One-page operator reference (PNG)](SYNAPSE-S2_Quick_Reference.png)
- `plates/` contains one presentation-ready PNG for each annotated manual page.

## The one-sentence model

The Namespace Galaxy is a read-only neural atlas: use it to find and understand memory; use Cortex Governor, Memory Write, Recall, Memory Graph, and governed bridge controls to change durable state.

## 1. Memory anatomy

`All namespaces -> namespace / cortex -> ganglion -> neuron`

- **Namespace / memory context:** a durable isolation and recall boundary such as `default`, `PTZPLZ`, or `CASP-Control-Room`.
- **Cortex view:** the outer visual summary of one namespace.
- **Ganglion:** a derived semantic or type cluster inside a namespace. It is recalculated from stored metadata and relationships; it is not a separately stored object.
- **Neuron:** one durable memory entry.
- **Relationship edge:** a stored temporal or associative relationship between memories.
- **Bridge:** reviewed permission for bounded, one-hop, read-only recall between namespaces. It does not copy or synchronize memory.
- **Cortex Governor:** the governed work-session lifecycle. This is different from the visual cortex view.

### Visual size is not a truth score

- Galaxy sphere area combines 58% relative log memory volume, 27% indexed term/relationship density, and 15% enabled approved bridge centrality.
- Cortex area combines 72% bounded log memory total and 28% relationships per memory.
- Ganglion area combines 68% relative log memory total and 32% relative log stored relationship weight per memory.
- Neuron area reflects relative log visible weighted degree in the returned sample.

Size helps compare structure. It does not mean a memory is more true, important, recent, or confident.

## 2. Navigate the Namespace Galaxy

The Galaxy shows all observed namespaces, approved bridges, pending proposals, and evidence-only suggestions.

- Click a namespace sphere or choose **Enter namespace** to open its internal cortex view.
- **Load sidebar context** changes the active context used by later capture, recall, graph, and Cortex actions.
- Drag to orbit, Shift-drag to pan, and scroll to change semantic depth.
- Arrow keys select. Enter or Space enters/focuses. Escape or Back moves outward. `F` fits and `R` resets.
- Browser history and breadcrumbs preserve the Galaxy -> namespace -> ganglion path.
- The accessible list below the canvas offers the same navigation without the 3D canvas.

Entering a namespace changes the active operating scope, but it does not move, duplicate, link, or edit stored memories.

## 3. Cortex, ganglia, and neurons

At Depth 1 of 3, one sphere summarizes the selected namespace. Zoom inward to show derived ganglia at Depth 2. Select a ganglion and focus it to load bounded neuron detail at Depth 3.

The detail request is intentionally bounded. The current implementation scans bounded source sets and returns at most 500 nodes and 2,000 edges; visible degree is therefore a property of the returned sample, not necessarily the entire database.

### What **Focus this ganglion** does

1. Selects one derived cluster.
2. Centers it and resets pan.
3. Raises the view to neuron depth.
4. Fetches a bounded neuron and relationship projection for that cluster.
5. Keeps dim outside-cluster context for orientation.
6. Updates breadcrumbs and browser history.

It does **not** regroup, connect, bridge, acknowledge, copy, promote, demote, prune, or otherwise mutate memory.

`Stored memories without a typed namespace` is the `fallback_untyped` cluster. It means those memories do not carry a typed sub-namespace label; it does not mean they are invalid or broken.

### Neuron inspection

Clicking a neuron shows its stored type, tag, provenance/source, creation time, visible edge count, visible weighted degree, comparative size, excerpt, and returned relationships. The inspector is read-only.

## 4. Connect namespaces safely

The bridge lifecycle is deliberately governed:

`evidence-only suggestion -> pending proposal -> exact approve/reject -> approved enabled bridge -> disable/revoke/expire`

- A suggestion is evidence only. It never expands recall or affects sphere size.
- Propose creates an isolated governance record; it still grants no recall authority.
- Approve or reject reviews the exact proposal revision and fails closed if evidence changed.
- An approved, enabled bridge becomes eligible only for **Connected** recall.
- Connected recall is one hop and read-only. It never copies memories or creates cross-namespace writes.
- **All** recall deliberately searches every namespace, bypassing bridge boundaries for that read-only query.

Dashboard bridge controls currently support suggestion review, proposal creation, and pending approve/reject. Disable, expiry materialization, revocation, and full audit history are guarded CLI/core operations. Approved weight, direction, and relation are not edited in place; issue a newly reviewed proposal.

## 5. Recall and capture

### Recall scopes

- **Local:** the active namespace plus explicitly global memory. This is the safe default.
- **Connected:** Local plus approved, enabled, one-hop bridges.
- **All:** every saved namespace for an explicit read-only search.

Retrieval v2 is deterministic and read-only. It does not run recurrent updates, STDP, pruning, or activity mutation.

### Durable creation paths

- **Remember + publish:** store one durable trace and publish a context update.
- **Ingest + publish:** segment source text into structured events and relationships.
- **Capture conversation:** exactly-once capture of a bounded conversation payload.
- **App Connect:** detect a running app, preview exposed UI text, then explicitly snapshot or capture selected text.

The active sidebar context determines where new durable memory is written.

## 6. Governed work and memory moderation

The Cortex Governor supports a disciplined agent workflow:

1. **Start Cortex Session:** identify agent, mode, and current task.
2. **Tick governor:** evaluate observation, proposed action, intended files/tools, mutation intent, and confidence.
3. **Commit trace:** preserve verified evidence, decision, constraint, implementation, risk, validation, correction, or follow-up.
4. **End / Wrap:** close the session and optionally persist a handoff.

Working-memory cards support:

- **Promote:** raise a governed trace to at least 0.90 confidence and operator-confirmed posture unless it is already test-validated.
- **Demote:** cap confidence at 0.35 and mark the governed trace stale.
- **Prune:** permanently remove the governed trace after confirmation.

Promote and Demote apply only to Cortex Governor traces. Arbitrary memories are corrected by capturing a replacement and then surgically pruning the incorrect neuron or edge.

## 7. Graph management and pruning

The Memory Graph is an inspectable projection, not a complete context dump. Dragging nodes only changes the local layout; it does not rewire durable relationships.

Supported destructive targets are:

- One memory/event node.
- One relationship edge.
- One context/deployment event.
- Every temporal relationship in the selected context.
- Every associative relationship in the selected context.

Prefer the smallest exact target. Broad temporal or associative clears are appropriate only when the entire relationship class is wrong.

### Safe destructive checklist

1. Confirm the active namespace.
2. Inspect the exact ID, type, provenance, and dependent edges.
3. Create a verified paired recovery point before broad changes.
4. Prefer one neuron or one edge.
5. Enter a concrete reason.
6. Confirm once.
7. Inspect the operation receipt, run Doctor, and recall the corrected topic.

Ganglia are derived projections, so there is no direct **Delete ganglion** function. Change a cluster by correcting or pruning its member neurons and relationships; the ganglion then recomputes.

## 8. Maintenance, reliability, and recovery

- **Context Health:** independent health score and recommendations.
- **Quick Doctor:** bounded runtime, SQLite, embedding, delivery, capture, and App Connect diagnosis; it does not auto-repair.
- **Self Test:** checks runtime, store, embeddings, context bus, capture, and apps.
- **Readiness Audit:** probes runtime, graph, resource envelope, and non-memory-bearing retrieval.
- **Monday Readiness:** runs the broader readiness and transient-state benchmark workflow.
- **Native Certify:** verifies MLX/native/resource/prune budget and writes local evidence.
- **Create Recovery Point:** creates paired, verified database/capture recovery artifacts.
- **Evidence Pack:** writes a snapshot/readiness report plus a pinned recovery bundle.
- **Quick Prune:** decays transient neural state; it does not delete durable SQLite neurons.
- **Deep Sleep:** consolidates transient runtime state and rebuilds the in-memory semantic hierarchy; it does not directly delete durable memories.
- **Core Enable / Disable:** runtime control protected by a short Unlock window, not a routine memory-management tool.

Dashboard READY alone is not proof of capture, hygiene, backup, delivery acknowledgement, or recovery readiness. Treat those as independent gates.

## 9. Practical daily loop

`Choose context -> Start Work -> Enter Cortex -> Tick before risky actions -> Capture / Recall -> Inspect -> Moderate or prune if needed -> Wrap Session -> Create evidence / recovery point`

- **Start Work** leases relevant context events and acknowledges each exact receipt only after it is visibly rendered.
- **Context Health** and **Doctor** establish current truth before risky work.
- Capture concise decisions, corrections, evidence, risks, and next actions.
- Recall locally first; expand to Connected or All only when needed.
- Finish with a wrap receipt and use a paired recovery point before substantial repair.

## 10. Expected-function matrix

| Operator intent | Surface | What happens | State class |
|---|---|---|---|
| Browse all memory contexts | Namespace Galaxy | Select, orbit, zoom, inspect | Read-only |
| Enter one context | Galaxy / sidebar | Changes active operating scope | Scope only |
| Focus a ganglion | Namespace drill-down | Centers cluster and loads bounded neuron detail | Read-only |
| Inspect a neuron | Neuron inspector | Shows provenance, degree, excerpt, and edges | Read-only |
| Search current memory | Recall Local | Active context plus explicit global memory | Read-only |
| Search reviewed neighbors | Recall Connected | Adds approved enabled one-hop bridges | Read-only |
| Search everything | Recall All | Explicit cross-catalog search | Read-only |
| Store one trace | Memory Write | Durable neuron plus context update | Durable write |
| Ingest structured text | Memory Write | Durable events and relationships | Durable write |
| Capture a conversation | Memory Write / App Connect | Exactly-once durable capture | Durable write |
| Govern risky work | Cortex Governor | Start, tick, commit, close | Governed write |
| Raise/lower confidence | Cortex trace card | Promote or demote a governed trace | Governed write |
| Remove one bad item | Memory Graph | Exact node, edge, or event prune | Destructive |
| Clear a bad edge class | Memory Graph | Delete all temporal or associative edges in context | Broad destructive |
| Connect namespaces | Galaxy bridge controls | Suggest, propose, exact review | Governed write |
| Expand connected recall | Recall Connected | Read across approved one-hop bridge | Read-only |
| Check reliability | Health / Doctor / Audit / Self Test | Independent diagnostic evidence | Diagnostic |
| Protect recovery state | Recovery Point / Evidence Pack | Paired verified artifacts | Filesystem write |

## 11. Current capability boundaries

The current release intentionally does not provide:

- Direct ganglion create, rename, edit, merge, or delete.
- Neuron-to-ganglion reassignment.
- In-place stored-text editing.
- A freeform relationship topology or weight editor.
- Namespace rename, archive, or delete lifecycle.
- Neuron-to-neuron or ganglion-to-ganglion cross-namespace bridges.
- In-place approved bridge editing.
- Dashboard bridge disable/revoke/history controls.
- Arbitrary-memory Promote/Demote outside Cortex Governor traces.

These boundaries are important product controls, not merely missing buttons. The visual atlas remains explainable and non-mutating; durable changes pass through explicit, auditable surfaces.

## Source anchors

- `README.md`, Namespace Galaxy semantic drill-down and operating guidance.
- `web/app.js`, Galaxy rendering, LOD thresholds, inspectors, navigation, recall, moderation, and health behavior.
- `web/index.html`, visible controls and operator surfaces.
- `mlx_backend.py`, derived ganglia, recall, moderation, prune, Quick Prune, and Deep Sleep semantics.
- `docs/BRIDGE_GOVERNANCE.md`, bridge lifecycle and isolation contract.
- Live dashboard screenshots supplied July 29, 2026.
