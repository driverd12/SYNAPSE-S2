# **SYNAPSE-S2: Spiking STDP Transformer MCP Server**

SYNAPSE-S2 (Synaptic Plasticity & Spiking Encoding via $S^2$) is an Apple Silicon-optimized Model Context Protocol (MCP) server. It provides local large language models (LLMs) with high-efficiency, associative memory capabilities using a persistent, biologically grounded Spiking Neural Network (SNN) substrate.

Unlike traditional vector similarity retrieval methods, SYNAPSE-S2 runs natively on M-series GPUs, completely eliminating the $O(N^2)$ memory wall of traditional self-attention by implementing the Spiking STDP Transformer ($S^2TDPT$) mathematical framework. It operates as a multiplication-free, addition-only system that embeds query-key correlations directly in synaptic weights using Spike-Timing-Dependent Plasticity (STDP).

## **Operational Quickstart**

This repository now includes a working local MCP server, a SQLite-backed persistent memory store, runtime toggle controls, and a CLI for validation outside an MCP client.

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

The launcher enters through `mcp_client_wrapper.py`, which hydrates SYNAPSE-S2 at MCP process startup and drops a sanitized session-boundary note into `.synapse_s2/capture_inbox` when the client disconnects. `scripts/install_client_configs.py` stamps distinct delivery cursors for Codex, Claude Desktop, Claude Code, and the project `.mcp.json` manifest so one client does not consume another client's context deployments.

### 2. Verify the Local Engine

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python synapse_cli.py --json doctor --context default
```

For the full morning readiness path, run:

```bash
scripts/prep_tomorrow.sh
```

The detailed operator runbook is in `docs/TOMORROW_RUNBOOK.md`.
The strict proposal coverage matrix is in `docs/PROPOSAL_COMPLIANCE.md`.
The production gap audit is in `docs/PRODUCTION_GAP_AUDIT.md`.

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
Event ingestion additionally creates segmented memories such as `production-preflight-brief-event-001` and relationship edges such as `temporal_next` and `semantic_overlap`.

Real memory is stored locally in `.synapse_s2/memory.sqlite3`. Runtime toggles and client state live in `.synapse_s2/runtime_state.json`. Both `.mcp.json` and `/Users/dan.driver/.codex/config.toml` set `SYNAPSE_S2_MEMORY_DB` so Codex, Claude, and direct CLI runs target the same durable substrate. MCP export and backup paths are constrained to `.synapse_s2` by default through `SYNAPSE_S2_EXPORT_DIR`; the CLI remains available for explicit operator-chosen local paths.

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

Capture real operator/Codex conversation notes into the event graph:

```bash
.venv/bin/python synapse_cli.py --json capture-session \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "User asked for future conversation details to appear in the event relationship graph. Codex added durable session capture plus surgical memory pruning. Operators can remove sensitive, wrong, or partial-truth graph data by node, edge, deployment event, or relationship mode."
```

For the always-on "magic" capture lane, run the launchd sidecar and drop session payloads into the local inbox. This is still opt-in and local: clients, hooks, or operators write a payload, then the sidecar redacts common secret shapes and ingests it into the same real graph used by MCP, CLI, and the dashboard.

```bash
scripts/install_capture_daemon.sh
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "Capture a concise factual session note here."
.venv/bin/python synapse_cli.py --json capture-inbox-status
.venv/bin/python synapse_cli.py --json graph --context default --limit 30
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
| `query_spiking_attention_text` | Query with local deterministic text projection when no embedding model is available. |
| `remember_spiking_context` | Persist a named context trace from text and/or an embedding. |
| `set_spiking_attention_enabled` | Enable or disable SYNAPSE-S2 globally or per context id. |
| `get_spiking_attention_status` | Report health, dependency state, memory counts, and toggle state. |
| `list_spiking_memory` | List persisted SQLite memory entries for a context. |
| `ingest_spiking_memory_text` | Segment long text into event memories and persist graph relationships. |
| `capture_spiking_conversation` | Capture real operator/agent conversation notes as temporal event memories. |
| `drop_spiking_capture_inbox` | Drop opt-in session text into the local capture inbox sidecar. |
| `get_spiking_capture_inbox_status` | Show pending, processed, and failed inbox file counts. |
| `process_spiking_capture_inbox` | Process pending inbox drops into the real memory graph. |
| `list_spiking_memory_graph` | List compact memory entries and relationship edges for a context. |
| `prune_spiking_memory` | Remove one memory node, relationship edge, context deployment event, or relationship mode. |
| `pull_spiking_context_deployments` | Pull durable context-bus events published by GUI and MCP write actions. |
| `ack_spiking_context_deployments` | Record the last context-bus event consumed by a local agent. |
| `list_spiking_context_cursors` | List per-agent delivery cursors and pending deployment counts. |
| `hydrate_spiking_agent_context` | Return an agent-ready briefing with new deployments, prompt recall, graph highlights, and optional ack. |
| `profile_spiking_resources` | Report actual topology array memory estimates and optional quick-pruning timing. |
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

The installer preserves existing client settings, writes timestamped backups before mutating existing JSON/TOML files, and points every client at `/Users/dan.driver/.local/bin/synapse-s2-mcp` plus the shared `.synapse_s2` state directory. It also assigns per-client `SYNAPSE_S2_CLIENT_AGENT_ID` values: `codex-desktop`, `claude-desktop`, `claude-code`, and `project-mcp`. Restart Codex, Claude Desktop, and Claude Code after running it so each client reloads its MCP server registry and starts using the startup/session-boundary bridge.

### 6. Maintenance Lifecycle

Quick-pruning is configured for the proposal's five-minute interval (`300` seconds) and automatically runs from the live query/register path when due. It is also available as an explicit operator command:

```bash
.venv/bin/python synapse_cli.py --json quick-prune
```

Resource profiling reports the MLX topology footprint from the live arrays (`W_syn`, `W_lateral`, membrane state, spike state, and active traces). With the default 1,024 x 5,000 topology it is expected to land inside the proposal's 61-138 MB operating envelope; tiny test topologies correctly report a smaller footprint.

```bash
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune
.venv/bin/python synapse_cli.py --json preflight --require-resource-envelope
```

Idle deep-sleep consolidation is available from MCP and CLI:

```bash
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep
.venv/bin/python synapse_cli.py --json sleep
```

Deep sleep returns all seven proposal lifecycle phases: connection weight decay, synaptic clustering, semantic merging, threshold rescoring, trace promotion, relationship extraction, and neurogenesis.

### 7. Local Control Dashboard

The dashboard is a loopback-only operator surface for the same runtime and memory store used by MCP and the CLI. It exposes live status, context toggles, resource envelope profiling, durable trace capture, conversation capture, magic capture inbox processing, event ingestion, graph memory inspection, surgical graph pruning, recall, quick-pruning, deep-sleep, and backups.

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
