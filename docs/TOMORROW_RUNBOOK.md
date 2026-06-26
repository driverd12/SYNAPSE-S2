# SYNAPSE-S2 Tomorrow Runbook

This is the fast operator path for using SYNAPSE-S2 from this Mac tomorrow.

## One-command preflight

```bash
cd "/Users/dan.driver/Documents/Neuromorphic Spiking Attention Plugin for Local AI Clients: An Apple Silicon Optimized MCP Architecture"
scripts/prep_tomorrow.sh
```

The script installs or refreshes the local launcher, runs the unit suite, checks bytecode compilation, seeds the `board-demo` memory context, verifies graph ingestion, profiles the runtime resource envelope, runs CLI preflight, exercises the FastMCP launcher, smokes the local dashboard, and writes a SQLite backup into `.synapse_s2`.

## Expected ready signal

The CLI preflight JSON should include:

```json
{
  "ready": true,
  "failed_checks": []
}
```

If `ready` is false, inspect `failed_checks` first. The common checks are:

| Check | Meaning | Fix |
| :--- | :--- | :--- |
| `dependencies_importable` | `mlx.core`, `mlxsnn`, `fastmcp`, or `mcp` is not importable. | Run `uv sync`. |
| `launcher_executable` | `/Users/dan.driver/.local/bin/synapse-s2-mcp` is missing or not executable. | Run `scripts/install_local_launcher.sh`. |
| `memory_minimum_met` | The selected context has fewer persisted memories than requested. | Run `synapse_cli.py --json seed-demo --context board-demo`. |
| `relationship_minimum_met` | The selected context has too few persisted event relationships for the requested gate. | Run the event graph ingestion command below. |
| `resource_envelope_met` | The default topology is outside the configured 61-138 MB estimated resource envelope. | Inspect `synapse_cli.py --json profile --benchmark-quick-prune`, then adjust `SYNAPSE_S2_NEURONS` or topology CLI args. |
| `effective_enabled` | The selected context is disabled. | Run `synapse_cli.py --json enable --context board-demo`. |
| `query_returned_context` | Recall did not return a registered context. | Seed or remember a matching trace, then query again. |

## Operator commands

Status:

```bash
.venv/bin/python synapse_cli.py --json status --context board-demo
```

Compact memory list:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context board-demo --limit 10
```

Full vector details, only when needed:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context board-demo --limit 2 --include-vectors
```

Recall smoke:

```bash
.venv/bin/python synapse_cli.py --json query-text \
  --context board-demo \
  --text "durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients"
```

Event graph ingestion:

```bash
.venv/bin/python synapse_cli.py --json ingest-text \
  --context board-demo \
  --tag proposal-event-brief \
  --text "Apple Silicon MLX compiles spiking neural kernels into Metal for local recall. Sparse top-k spike populations reduce context pressure and keep associative traces on-device. Procurement reviews supplier budget exposure, renewal timing, and contract risk. Operators need graph relationships that connect technical runtime evidence to tomorrow morning approval actions." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1
.venv/bin/python synapse_cli.py --json graph --context board-demo --limit 10
```

The graph output should show event tags like `proposal-event-brief-event-001` and at least one `temporal_next` relationship.

Resource envelope:

```bash
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune
```

The default topology should report `within_target_envelope: true` for the proposal's 61-138 MB target and a quick-pruning result with `within_60ms_budget: true`. This is an implementation-level memory estimate from the live MLX arrays, not an external Metal profiler trace.

Backup:

```bash
.venv/bin/python synapse_cli.py --json backup-memory \
  --output .synapse_s2/manual-memory-backup.sqlite3
```

Proposal lifecycle smoke:

```bash
.venv/bin/python synapse_cli.py --json quick-prune
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep
```

The deep-sleep response should include `phase_count: 7` and phase names for connection weight decay, synaptic clustering, semantic merging, threshold rescoring, trace promotion, relationship extraction, and neurogenesis.

## Local Dashboard

Launch the loopback dashboard:

```bash
.venv/bin/python dashboard_server.py --host 127.0.0.1 --port 8765 --context default
open "http://127.0.0.1:8765/?context_id=default"
```

The dashboard shows runtime status, context enablement, topology resource envelope, memory graph edges, recall results, quick-pruning, deep-sleep, and backup controls. Its API smoke check can run without a fixed port:

```bash
.venv/bin/python scripts/smoke_dashboard.py default
```

## MCP Inspector

Use the launcher directly:

```bash
npx @anthropic-ai/mcp-inspector /Users/dan.driver/.local/bin/synapse-s2-mcp
```

Useful tool calls:

| Tool | Use |
| :--- | :--- |
| `get_spiking_attention_status` | Proves the runtime is enabled and shows memory counts. |
| `remember_spiking_context` | Stores a new local memory trace. |
| `query_spiking_attention_text` | Recalls local memory from text without external embedding calls. |
| `ingest_spiking_memory_text` | Segments a long briefing into event memories and relationship edges. |
| `list_spiking_memory` | Lists compact persisted memory records. |
| `list_spiking_memory_graph` | Lists compact records plus graph relationships. |
| `profile_spiking_resources` | Shows topology footprint and optional quick-pruning benchmark. |
| `backup_spiking_memory` | Writes a guarded SQLite backup under `.synapse_s2`. |
| `trigger_idle_maintenance` | Forces or checks maintenance from MCP Inspector. |

## Proposal compliance

Before calling the build ready, inspect:

```bash
open docs/PROPOSAL_COMPLIANCE.md
```

The matrix maps each proposal requirement to implementation evidence and separates verified prototype gates from longer-horizon research extensions.

## Local state

| Path | Purpose |
| :--- | :--- |
| `.synapse_s2/memory.sqlite3` | Durable memory store. |
| `.synapse_s2/runtime_state.json` | Toggle/runtime state. |
| `.synapse_s2/*backup*.sqlite3` | Local backups. |
| `/Users/dan.driver/.local/bin/synapse-s2-mcp` | Launcher used by Codex, FastMCP, and inspector tools. |
