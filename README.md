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
```

The launcher installs `/Users/dan.driver/.local/bin/synapse-s2-mcp`. It exists because this checked-out workspace path contains spaces and a colon, which can break tools that split command strings or PATH entries. The launcher executes the synced virtual environment directly:

```bash
/Users/dan.driver/.local/bin/synapse-s2-mcp
```

### 2. Verify the Local Engine

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python synapse_cli.py --json doctor --context board-demo
```

For the full morning readiness path, run:

```bash
scripts/prep_tomorrow.sh
```

The detailed operator runbook is in `docs/TOMORROW_RUNBOOK.md`.
The strict proposal coverage matrix is in `docs/PROPOSAL_COMPLIANCE.md`.

### 3. Seed and Query Persistent Memory

```bash
.venv/bin/python synapse_cli.py --json seed-demo --context board-demo
.venv/bin/python synapse_cli.py --json query-text \
  --context board-demo \
  --text "Apple Silicon local spiking memory can reduce context pressure for Codex and Claude"
```

Expected query output returns ranked registered traces such as `ops-toggle`, `metal-runtime`, and `executive-briefing`.

Real memory is stored locally in `.synapse_s2/memory.sqlite3`. Runtime toggles and client state live in `.synapse_s2/runtime_state.json`. Both `.mcp.json` and `/Users/dan.driver/.codex/config.toml` set `SYNAPSE_S2_MEMORY_DB` so Codex, Claude, and direct CLI runs target the same durable substrate. MCP export and backup paths are constrained to `.synapse_s2` by default through `SYNAPSE_S2_EXPORT_DIR`; the CLI remains available for explicit operator-chosen local paths.

Inspect, export, and back up the memory store:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context board-demo --limit 20
.venv/bin/python synapse_cli.py --json export-memory \
  --context board-demo \
  --output .synapse_s2/board-demo-memory-export.json
.venv/bin/python synapse_cli.py --json backup-memory \
  --output .synapse_s2/board-demo-memory-backup.sqlite3
```

### 4. Toggle Runtime Behavior

```bash
.venv/bin/python synapse_cli.py --json disable --context board-demo
.venv/bin/python synapse_cli.py --json query-text --context board-demo --text "anything"
.venv/bin/python synapse_cli.py --json enable --context board-demo
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
| `export_spiking_memory` | Export persisted memory entries as JSON, optionally to a local file. |
| `backup_spiking_memory` | Create a SQLite backup of the durable memory store. |
| `trigger_sleep_consolidation` | Run deep-sleep consolidation and semantic hierarchy extraction. |
| `trigger_idle_maintenance` | Run due maintenance or force idle deep-sleep consolidation. |

FastMCP smoke check:

```bash
.venv/bin/fastmcp list --command /Users/dan.driver/.local/bin/synapse-s2-mcp --json --timeout 15
.venv/bin/fastmcp call --command /Users/dan.driver/.local/bin/synapse-s2-mcp \
  --target get_spiking_attention_status \
  --input-json '{"context_id":"board-demo"}' \
  --json --timeout 15
```

Project `.mcp.json` and `/Users/dan.driver/.codex/config.toml` are configured to use the launcher directly.

### 6. Maintenance Lifecycle

Quick-pruning is configured for the proposal's five-minute interval (`300` seconds) and automatically runs from the live query/register path when due. It is also available as an explicit operator command:

```bash
.venv/bin/python synapse_cli.py --json quick-prune
```

Idle deep-sleep consolidation is available from MCP and CLI:

```bash
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep
.venv/bin/python synapse_cli.py --json sleep
```

Deep sleep returns all seven proposal lifecycle phases: connection weight decay, synaptic clustering, semantic merging, threshold rescoring, trace promotion, relationship extraction, and neurogenesis.

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
