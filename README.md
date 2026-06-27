# **SYNAPSE-S2: Spiking STDP Transformer MCP Server**

SYNAPSE-S2 (Synaptic Plasticity & Spiking Encoding via $S^2$) is an Apple Silicon-optimized Model Context Protocol (MCP) server. It provides local large language models (LLMs) with high-efficiency, associative memory capabilities using a persistent, biologically grounded Spiking Neural Network (SNN) substrate.

Unlike traditional vector similarity retrieval methods, SYNAPSE-S2 runs natively on M-series GPUs, completely eliminating the $O(N^2)$ memory wall of traditional self-attention by implementing the Spiking STDP Transformer ($S^2TDPT$) mathematical framework. It operates as a multiplication-free, addition-only system that embeds query-key correlations directly in synaptic weights using Spike-Timing-Dependent Plasticity (STDP).

## **Operational Quickstart**

This repository now includes a working local MCP server, a SQLite-backed persistent memory store, runtime toggle controls, and a CLI for validation outside an MCP client.
Text recall is routed through a pluggable local embedding provider. The default client/launcher path is `mlx-neural-v1`, backed by the local MLX model `mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`; it runs on Apple Silicon through `mlx-lm`, stores weights under `.synapse_s2/models`, and emits provider provenance on every text memory. `semantic-hash-v1` remains available as the deterministic offline fallback, `lexical-hash-v1` is available for strict legacy behavior, and `python:/path/to/module.py:function` can point SYNAPSE-S2 at an IT-managed local encoder.

### 1. Install Runtime Dependencies

```bash
brew install uv
uv sync
scripts/install_local_launcher.sh
scripts/install_client_configs.py
scripts/install_capture_daemon.sh
```

The launcher installs `/Users/dan.driver/.local/bin/synapse-s2-mcp`. It exists because this checked-out workspace path contains spaces and a colon, which can break tools that split command strings or PATH entries. The launcher executes the synced virtual environment directly:

```bash
/Users/dan.driver/.local/bin/synapse-s2-mcp
```

The launcher enters through `mcp_client_wrapper.py`, which hydrates SYNAPSE-S2 at MCP process startup, enters a strict Cortex Governor session for that client, and drops a sanitized session-boundary note into `.synapse_s2/capture_inbox` when the client disconnects. The same exit path also commits a typed `follow_up` cortical trace so the client lifecycle is visible in governed memory, not only the inbox. `scripts/install_client_configs.py` stamps distinct delivery cursors for Codex, Claude Desktop, Claude Code, and the project `.mcp.json` manifest so one client does not consume another client's context deployments.

### 2. Verify the Local Engine

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python synapse_cli.py --json doctor --context default
.venv/bin/python synapse_cli.py --json \
  --embedding-provider mlx-neural \
  provider-benchmark \
  --text "SYNAPSE-S2 neural embedding benchmark" \
  --runs 3
.venv/bin/python synapse_cli.py --json certify-runtime \
  --strict-native \
  --benchmark-quick-prune \
  --require-resource-envelope
```

For the full morning readiness path, run:

```bash
scripts/prep_tomorrow.sh
```

For a no-install/no-ingest audit pass first:

```bash
scripts/prep_tomorrow.sh --verify-only
```

The detailed operator runbook is in `docs/TOMORROW_RUNBOOK.md`.
The strict proposal coverage matrix is in `docs/PROPOSAL_COMPLIANCE.md`.
The production gap audit is in `docs/PRODUCTION_GAP_AUDIT.md`.

### Hardened Local Operating Contract

- Dashboard HTTP binds to loopback only by default. Non-loopback demos must set `SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD=true` explicitly.
- Capture inbox drops are redacted before they are written to disk; inbox, processed, error, backup, export, and SQLite files are kept private to the local user where the filesystem permits it.
- Capture processing rejects symlink payloads and over-large payloads instead of following arbitrary files.
- Direct conversation capture, context-bus deployments, graph metadata, and returned API/MCP payloads use the same redaction path, so sanitized storage does not mask a raw response leak.
- MCP memory and Cortex pruning require explicit `confirm=true`; CLI memory and Cortex pruning require `--confirm`; the dashboard requires a confirmation control before destructive graph operations and governed-trace deletion.
- `test-validated` Cortex traces require concrete validation evidence such as a test command, test list, output summary, artifact path, commit, or verification report. Dashboard typed-memory defaults stay at `observed` evidence.
- Spike recall and surface-text recall both use durable SQLite indexes (`memory_spikes` and `memory_surface_terms`) maintained on every memory write, so recall does not need to scan the full memory table as the graph grows.
- Client config installation refuses malformed existing JSON instead of silently overwriting it.

### 3. Write and Query Persistent Memory

```bash
.venv/bin/python synapse_cli.py --json remember-text \
  --context default \
  --tag production-memory-contract \
  --text "SYNAPSE-S2 stores durable local memory in the shared .synapse_s2 SQLite substrate. Codex, Claude Desktop, Claude Code, the CLI, the dashboard, and direct FastMCP launches use the same local launcher and memory database."
.venv/bin/python synapse_cli.py --json ingest-text \
  --context default \
  --tag production-preflight-brief \
  --text "The SYNAPSE-S2 backend imports mlx.core and mlxsnn on Apple Silicon. The recurrent LIF backend uses z-score top-k spike coding, immutable MLX state updates, STDP relationship updates, quick-pruning maintenance, and deep-sleep consolidation. The context bus stores durable deployment events that connected local clients can pull and acknowledge with delivery cursors." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1
.venv/bin/python synapse_cli.py --json query-text \
  --context default \
  --text "Which clients share the SYNAPSE-S2 memory database and launcher?"
.venv/bin/python synapse_cli.py --json graph --context default --limit 10
```

Expected query output returns ranked registered traces such as `production-memory-contract` and linked event traces from `production-preflight-brief`.
Event ingestion additionally creates segmented memories such as `production-preflight-brief-event-001` and relationship edges such as `temporal_next` and `semantic_overlap`. Event boundaries are driven by the configured local embedding provider's cosine-distance surprise when available, while retaining lexical surprise as an auditable fallback.

Real memory is stored locally in `.synapse_s2/memory.sqlite3`. Runtime toggles and client state live in `.synapse_s2/runtime_state.json`. Both `.mcp.json` and `/Users/dan.driver/.codex/config.toml` set `SYNAPSE_S2_MEMORY_DB` so Codex, Claude, and direct CLI runs target the same durable substrate. MCP export and backup paths are constrained to `.synapse_s2` by default through `SYNAPSE_S2_EXPORT_DIR`; the CLI remains available for explicit operator-chosen local paths.
Each text memory stores `metadata.embedding_provider` provenance including provider id, provider type, model id, local-only status, semantic flag, dimensions, vector hash, and neural runtime fields when applicable (`native_mlx`, `pooling`, `source_dimensions`). Set `--embedding-provider semantic-hash` for the deterministic no-model fallback, `--embedding-provider lexical-hash` for exact legacy behavior, or `--embedding-provider python:/absolute/path/encoder.py:embed` to use a local callable that returns a vector or `{ "vector": [...], "model_id": "...", "semantic": true }`.
Each event memory also stores `metadata.surprise_model`, `metadata.surprise_mode`, `metadata.semantic_surprise_score`, and `metadata.lexical_surprise_score`, so operators can tell whether a boundary was cut by semantic embedding distance or by lexical fallback.
SQLite maintains a durable sparse spike index and a durable surface-term index for prompt recall. The surface index is built from tags, display labels, display summaries, semantic facets, detail badges, keywords, and bounded source text, and existing memory databases are backfilled automatically on startup.

Inspect, export, and back up the memory store:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 20
.venv/bin/python synapse_cli.py --json export-memory \
  --context default \
  --output .synapse_s2/default-memory-export.json
.venv/bin/python synapse_cli.py --json backup-memory \
  --output .synapse_s2/default-memory-backup.sqlite3
```

Connected MCP clients now hydrate automatically when their SYNAPSE-S2 server process starts. To run the same hydration manually for diagnostics:

```bash
.venv/bin/python synapse_cli.py --json agent-brief \
  --context default \
  --agent-id codex-desktop \
  --prompt "Summarize the current SYNAPSE-S2 work and next implementation gap."
```

`agent-brief` composes `pull-context`, text recall, graph summary, and `ack-context` into one agent-ready briefing. The client wrapper calls the same backend behavior at startup. Use the lower-level commands when diagnosing delivery state directly:

```bash
.venv/bin/python synapse_cli.py --json pull-context --context default --since-event-id 0 --limit 10
LATEST_EVENT_ID=$(.venv/bin/python synapse_cli.py --json status --context default | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["context_bus_latest_event_id"])')
.venv/bin/python synapse_cli.py --json ack-context --context default --agent-id cli-operator --last-event-id "$LATEST_EVENT_ID"
.venv/bin/python synapse_cli.py --json list-context-cursors --context default
```

Run a governed agent session when you want SYNAPSE-S2 to act as a live cognitive control plane instead of passive recall only:

```bash
SESSION_ID=$(.venv/bin/python synapse_cli.py --json enter-cortex \
  --context default \
  --agent-id codex-desktop \
  --task "Implement the next SYNAPSE-S2 change with verification before mutation." \
  --mode strict | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
.venv/bin/python synapse_cli.py --json cortex-tick \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --observation "About to edit backend and dashboard files." \
  --proposed-action "Patch code, run focused tests, then run full validation." \
  --intended-file mlx_backend.py \
  --intended-file web/app.js \
  --intended-tool "python -m unittest discover -s tests -v" \
  --mutation-intent \
  --confidence 0.62
.venv/bin/python synapse_cli.py --json commit-cortex \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --type validation \
  --truth-posture test-validated \
  --text "Focused and full validation passed for the governed change." \
  --evidence '{"tests":["unittest discover"],"surface":"cli"}'
.venv/bin/python synapse_cli.py --json cortex-state --context default --agent-id codex-desktop
```

The Cortex Governor state is also included in `agent-brief`, MCP hydration, and the dashboard snapshot. It is intentionally typed: `goal`, `objective`, `decision`, `constraint`, `implementation`, `validation`, `risk`, `correction`, and `follow_up` traces carry truth posture, confidence, evidence, agent id, and session id. Each governor tick can also declare intended files and tools; SYNAPSE-S2 persists that scope, warns on undeclared mutations, sensitive paths, and high-impact tool use, and surfaces active goal, assumptions, contradictions, suggested next move, and capture queue in Cortex state.

Capture real operator/Codex conversation notes into the event graph:

```bash
.venv/bin/python synapse_cli.py --json capture-session \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "User asked for future conversation details to appear in the event relationship graph. Codex added durable session capture plus surgical memory pruning. Operators can remove sensitive, wrong, or partial-truth graph data by node, edge, deployment event, or relationship mode."
```

Conversation capture automatically builds a local context namespace for the active topic or feature. Prefixes such as `Thread:`, `Feature:`, `Topic:`, `Goal:`, `Objective:`, and `Event:` become typed graph nodes, while the original conversation events receive the same `context_namespace` metadata and are linked back to the namespace anchor with `namespace_contains` edges. This is what makes new topics, current features, objectives, and temporal session details visibly grow in the relationship visualizer.

For the always-on "magic" capture lane, run the launchd sidecar and drop session payloads into the local inbox. This is still opt-in and local: clients, hooks, or operators write a payload, then the sidecar redacts common secret shapes and ingests it into the same real graph used by MCP, CLI, and the dashboard.

```bash
scripts/install_capture_daemon.sh
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "Capture a concise factual session note here."
.venv/bin/python synapse_cli.py --json capture-inbox-status
.venv/bin/python synapse_cli.py --json capture-inbox-process --confirm
.venv/bin/python synapse_cli.py --json graph --context default --limit 30
```

Manual inbox processing is confirmation-gated. The launchd sidecar can process its own local queue continuously, but CLI and MCP one-shot processing require `--confirm` / `confirm=true`, and the dashboard Magic Capture button performs a preflight with a short-lived confirmation token before committing pending files.

App Connect gives operators a local attach path for already-running apps. It detects attachable local apps through a fast filtered process-list scan, records a confirmed attachment, and can capture either intentionally selected text or a redacted Accessibility snapshot into the same temporal event graph and context bus. Dashboard app attach and snapshot actions use preflight confirmation tokens bound to the selected app/connection so a stale click cannot silently retarget capture. This is a hardened local connector, not a remote control plane.

```bash
.venv/bin/python synapse_cli.py --json app-list
.venv/bin/python synapse_cli.py --json app-connect \
  --context default \
  --app-name "Google Chrome" \
  --tag chrome-live \
  --speaker operator \
  --confirm
.venv/bin/python synapse_cli.py --json app-connections
.venv/bin/python synapse_cli.py --json app-snapshot \
  --connection-id "<connection-id-from-app-connections>" \
  --confirm
scripts/capture_frontmost_selection.sh default frontmost-selection operator
```

If a target application blocks Accessibility introspection, select the relevant visible text in that app and run the frontmost-selection helper. The helper copies the selection once, calls `capture-clipboard`, restores the prior clipboard, and exits.

Local transcript files can also be registered as bounded delta sources for clients or tools that write their own logs:

```bash
.venv/bin/python synapse_cli.py --json transcript-source-add \
  --context default \
  --source-id codex-live \
  --path /path/to/session.log \
  --tag codex-live \
  --speaker codex \
  --confirm
.venv/bin/python synapse_cli.py --json transcript-source-poll --source-id codex-live
```

Hand-prune bad or sensitive memory from the same durable store:

```bash
.venv/bin/python synapse_cli.py --json graph --context default --limit 30
.venv/bin/python synapse_cli.py --json prune-memory \
  --context default \
  --target-type event \
  --memory-id "<memory-id-from-graph>" \
  --reason "remove sensitive or partial-truth event" \
  --confirm
.venv/bin/python synapse_cli.py --json prune-memory \
  --context default \
  --target-type relationship \
  --relationship-id "<relationship-id-from-graph>" \
  --reason "remove bad edge" \
  --confirm
```

Supported prune targets are `event`, `memory`, `relationship`, `context_event`, `temporal`, and `associative`. Mode-wide `temporal` and `associative` pruning removes all matching edges in the selected context, so prefer a single node or relationship ID when possible.

### 4. Toggle Runtime Behavior

```bash
.venv/bin/python synapse_cli.py --json disable --context default
.venv/bin/python synapse_cli.py --json query-text --context default --text "anything"
.venv/bin/python synapse_cli.py --json enable --context default
```

When disabled, queries return a disabled status instead of mutating or recalling memory.

### 5. MCP Tool Surface

The MCP server exposes these tools:

| Tool | Purpose |
| :--- | :--- |
| `query_spiking_attention` | Query with a dense embedding vector. |
| `query_spiking_attention_text` | Query text through the configured local embedding provider, defaulting to MLX neural embeddings in installed clients. |
| `remember_spiking_context` | Persist a named context trace from text and/or an embedding. |
| `set_spiking_attention_enabled` | Enable or disable SYNAPSE-S2 globally or per context id. |
| `get_spiking_attention_status` | Report health, dependency state, memory counts, and toggle state. |
| `list_spiking_memory` | List persisted SQLite memory entries for a context. |
| `ingest_spiking_memory_text` | Segment long text into event memories and persist graph relationships. |
| `capture_spiking_conversation` | Capture real operator/agent conversation notes as temporal event memories. |
| `drop_spiking_capture_inbox` | Drop opt-in session text into the local capture inbox sidecar. |
| `get_spiking_capture_inbox_status` | Show pending, processed, and failed inbox file counts. |
| `process_spiking_capture_inbox` | Process pending inbox drops into the real memory graph; requires `confirm=true`. |
| `register_spiking_transcript_source` | Register a confirmed local transcript/log file for bounded delta capture. |
| `list_spiking_transcript_sources` | List registered local transcript sources. |
| `poll_spiking_transcript_sources` | Poll registered transcript deltas into temporal event memory. |
| `capture_spiking_clipboard` | Capture intentionally selected/copied text as a one-shot redacted memory payload. |
| `list_spiking_running_apps` | Detect locally visible foreground apps for App Connect. |
| `connect_spiking_app` | Attach a confirmed local app connection for snapshot/selection capture. |
| `list_spiking_app_connections` | List App Connect attachments. |
| `capture_spiking_app_snapshot` | Capture a confirmed redacted local app Accessibility snapshot into memory. |
| `list_spiking_memory_graph` | List compact memory entries and relationship edges for a context. |
| `prune_spiking_memory` | Remove one memory node, relationship edge, context deployment event, or relationship mode. |
| `pull_spiking_context_deployments` | Pull durable context-bus events published by GUI and MCP write actions. |
| `ack_spiking_context_deployments` | Record the last context-bus event consumed by a local agent. |
| `list_spiking_context_cursors` | List per-agent delivery cursors and pending deployment counts. |
| `hydrate_spiking_agent_context` | Return an agent-ready briefing with new deployments, prompt recall, graph highlights, and optional ack. |
| `enter_spiking_cortex` | Start a governed agent session with policy, recall, and a context-bus deployment. |
| `tick_spiking_cortex` | Evaluate the current observation, proposed action, intended files, and intended tools against governed memory before proceeding. |
| `commit_spiking_cortical_trace` | Persist a typed governed trace with truth posture, confidence, and evidence. |
| `moderate_spiking_cortical_trace` | Promote, demote, or prune a governed trace from MCP clients by memory id. |
| `get_spiking_cortex_state` | Inspect active governed sessions and typed cortical memory for a context. |
| `benchmark_spiking_embedding_provider` | Benchmark the configured local embedding provider and return latency plus provenance. |
| `profile_spiking_resources` | Report actual topology array memory estimates and optional quick-pruning timing. |
| `certify_spiking_runtime` | Emit native runtime certification evidence for MLX, mlxsnn, envelope, provider, and quick-prune checks. |
| `export_spiking_memory` | Export persisted memory entries as JSON, optionally to a local file. |
| `backup_spiking_memory` | Create a SQLite backup of the durable memory store. |
| `trigger_sleep_consolidation` | Run deep-sleep consolidation and semantic hierarchy extraction. |
| `trigger_idle_maintenance` | Run due maintenance or force idle deep-sleep consolidation. |

FastMCP smoke check:

```bash
.venv/bin/fastmcp list --command /Users/dan.driver/.local/bin/synapse-s2-mcp --json --timeout 15
.venv/bin/fastmcp call --command /Users/dan.driver/.local/bin/synapse-s2-mcp \
  --target get_spiking_attention_status \
  --input-json '{"context_id":"default"}' \
  --json --timeout 15
```

Project `.mcp.json`, `/Users/dan.driver/.codex/config.toml`, Claude Desktop, and Claude Code can be refreshed with:

```bash
scripts/install_client_configs.py
```

The installer preserves existing client settings, writes timestamped backups before mutating existing JSON/TOML files, and points every client at `/Users/dan.driver/.local/bin/synapse-s2-mcp` plus the shared `.synapse_s2` state directory. It also assigns per-client `SYNAPSE_S2_CLIENT_AGENT_ID` values: `codex-desktop`, `claude-desktop`, `claude-code`, and `project-mcp`, and stamps `SYNAPSE_S2_CLIENT_CORTEX=1` with `SYNAPSE_S2_CLIENT_CORTEX_MODE=strict`. Restart Codex, Claude Desktop, and Claude Code after running it so each client reloads its MCP server registry and starts using the startup/Cortex/session-boundary bridge.

### 6. Maintenance Lifecycle

Quick-pruning is configured for the proposal's five-minute interval (`300` seconds) and automatically runs from the live query/register path when due. It is also available as an explicit operator command:

```bash
.venv/bin/python synapse_cli.py --json quick-prune
```

Resource profiling reports the MLX topology footprint from the live arrays (`W_syn`, `W_lateral`, membrane state, spike state, and active traces). With the default 1,024 x 5,000 topology it is expected to land inside the proposal's 61-138 MB operating envelope; tiny test topologies correctly report a smaller footprint.

```bash
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune
.venv/bin/python synapse_cli.py --json preflight --require-resource-envelope
.venv/bin/python synapse_cli.py --json certify-runtime \
  --strict-native \
  --benchmark-quick-prune \
  --require-resource-envelope \
  --output .synapse_s2/native-certification.json
```

Idle deep-sleep consolidation is available from MCP and CLI:

```bash
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep
.venv/bin/python synapse_cli.py --json sleep
```

Deep sleep returns all seven proposal lifecycle phases: connection weight decay, synaptic clustering, semantic merging, threshold rescoring, trace promotion, relationship extraction, and neurogenesis.

### 7. Local Control Dashboard

The dashboard is a loopback-only operator surface for the same runtime and memory store used by MCP and the CLI. It exposes live status, context toggles, resource envelope profiling, native certification, durable trace capture, conversation capture, tokenized App Connect local app attachment/snapshot capture, tokenized magic capture inbox processing, event ingestion, Cortex Governor enter/tick/commit plus promote/demote/prune controls, graph memory inspection, surgical graph pruning, recall, quick-pruning, deep-sleep, and backups.

```bash
.venv/bin/python dashboard_server.py --host 127.0.0.1 --port 8765 --context default
open "http://127.0.0.1:8765/?context_id=default"
```

For non-interactive readiness checks:

```bash
.venv/bin/python scripts/smoke_dashboard.py default
```

## **System Architecture**

The plugin acts as a middleware daemon communicating with local editor interfaces and LLM desktop wrappers via JSON-RPC 2.0 over standard input/output (stdio) channels.

```
+-----------------------------------------------------------+
|                      LOCAL LLM CLIENT                     |
|         (Codex Client / Claude Desktop / Claude Code)     |
+-----------------------------+-----------------------------+
                              |
                              | Invokes Tool Calls (JSON-RPC)
                              v
+-----------------------------------------------------------+
|                FASTMCP MODEL CONTEXT LAYER                |
|             (Native Background Process Daemon)            |
+-----------------------------+-----------------------------+
                              |
                              | Projects prompt embeddings
                              | to sparse sensory spikes
                              v
+-----------------------------------------------------------+
|              SYNAPSE-S2 SPIKING SUBSTRATE                 |
|        (Metal-Accelerated Recurrent mlx-snn Model)        |
+-----------------------------------------------------------+
```

## **Hierarchical Neural Network Topology**

The SNN is organized into a multi-tiered hierarchical network designed to route, associate, and gate conceptual activations dynamically.

```
            
                             |
                             v
+-----------------------------------------------------------+
| LAYER 1: Sensory Population (5,000 Neurons)               |
| (Translates dense coordinates to sparse z-score spike top-k) |
|  o   o   o   x   o   o   x   o   x   o   o   o   x   o   o    | <-- Active Spikes (x)
+----------------------------+------------------------------+
                             |
                             | Synaptic Projection (W_syn)
                             v
+-----------------------------------------------------------+
| LAYER 2: Associative Fabric (150,000 Neurons)             |
| (Recurrent synaptic loops modified dynamically via STDP)  |
|      /--- o <=======> o <-------\                         | <-- Plastic Synapses
|     |     ^           ^         |                         |
|     v     |           |         v                         |
|     o <---+           +-------> o                         |
+----------------------------+------------------------------+
                             |
                             | Lateral Spreading Activation
                             v
+-----------------------------------------------------------+
| LAYER 3: Categorical & Concept Groups (25,000 Neurons)    |
| (Prefrontal cortex-inspired contextual gating maps)       |
|   [Concept A]                 [Concept C]     |
+----------------------------+------------------------------+
                             |
                             | High-salience Context Injection
                             v
+-----------------------------------------------------------+
|            LLM REASONING CONTEXT FILTER                   |
+-----------------------------------------------------------+
```

## **Core Mathematical Formulation**

### **1\. Dimension-Independent Population Coding**

Dense embeddings $E$ are mapped into discrete binary spike states $S\_i \\in \\{0, 1\\}$ using coordinate-wise standardized z-scores to ensure consistent representation across varying dimensionality boundaries :

$$Z\_i \= \\frac{E\_i \- \\mu\_E}{\\sigma\_E}$$  
Neurons corresponding to indices within the top-$k$ percentile fire a spike ($S\_i \= 1$), while the remainder stay silent ($S\_i \= 0$).

### **2\. Leaky Integrate-and-Fire (LIF) Dynamics**

Individual neuron potentials are processed dynamically using discrete-time updates :

$$U\[t+1\] \= \\beta \\cdot U\[t\] \+ X\[t+1\] \- S\[t\] \\cdot V\_{\\text{thr}}$$  
where $U$ is the membrane potential, $X$ is the input synaptic current, $\\beta \\in (0,1)$ is the decay factor, and $V\_{\\text{thr}}$ is the constant spike threshold. Updates are strictly immutable to compile efficiently on Apple Silicon GPUs.

### **3\. Asymmetric Temporal STDP**

Rather than storing dense attention matrices, correlation values are updated inside the associative fabric according to biological temporal differences ($\\Delta t$) :

$$\\Delta w \= \\begin{cases} A\_+ \\exp\\left(-\\frac{\\Delta t}{\\tau\_+}\\right) & \\text{if } \\Delta t \> 0 \\\\ \-A\_- \\exp\\left(\\frac{\\Delta t}{\\tau\_-}\\right) & \\text{if } \\Delta t \\le 0 \\end{cases}$$

## **Memory Consolidation and Pruning Lifecycle**

The SNN maintains long-term structural efficiency and manages Apple Silicon VRAM limitations by executing a scheduled multi-phase pruning pipeline.

| Phase | System Process | Core Mathematical Operation | Downstream Cognitive Function |
| :---- | :---- | :---- | :---- |
| Phase 1 | Connection Weight Decay | $W\_{ij} \\leftarrow W\_{ij} \\cdot \\gamma\_{\\text{decay}}$ | Lowers weight values for weak connections |
| Phase 2 | Synaptic Clustering | Density-based connection profiling | Identifies overlapping spiking patterns |
| Phase 3 | Semantic Merging | Mathematical node pooling | Consolidates redundant memory paths |
| Phase 4 | Threshold Rescoring | Adaptive adjustments to $V\_{\\text{thr}}$ | Keeps firing rates in healthy, balanced ranges |
| Phase 5 | Trace Promotion | Long-term Synaptic Facilitation | Moves active traces to persistent storage |
| Phase 6 | Relationship Extraction | Hebbian Distillation | Builds structured semantic connection graphs |
| Phase 7 | Neurogenesis | State re-initialization | Frees up inactive nodes for new memory traces |

## **Hardware Integration Optimization**

By executing directly inside Apple's Unified Memory Architecture via mlx-snn, SYNAPSE-S2 resolves the physical memory limitations that plague CUDA-emulated systems :

* **Metal JIT Acceleration**: Synaptic weight updates are compiled natively into GPU kernels using mx.compile to prevent execution overhead on the CPU.  
* **No-Copy Memory Sharing**: The host CPU pre-processes input embeddings, while the integrated M-series GPU computes the spiking networks inside the same physical RAM, completely avoiding costly PCIe bus data copies.  
* **Footprint Control**: Peak VRAM consumption remains constrained between $61\\text{ MB}$ and $138\\text{ MB}$, compared to the heavy allocations required by traditional tensor frameworks.

## **Verification and Diagnostics**

To verify the transport layer, launch the interactive MCP Inspector interface with the launcher:

```
npx @anthropic-ai/mcp-inspector /Users/dan.driver/.local/bin/synapse-s2-mcp
```

This verifies the stdio JSON-RPC endpoints and ensures structural tool definitions are fully accessible before registering the server to your primary client environments.
