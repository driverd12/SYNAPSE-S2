# SYNAPSE-S2 Tomorrow Runbook

This is the fast operator path for using SYNAPSE-S2 from this Mac tomorrow.

## One-command preflight

```bash
cd "/Users/dan.driver/Documents/Neuromorphic Spiking Attention Plugin for Local AI Clients: An Apple Silicon Optimized MCP Architecture"
scripts/prep_tomorrow.sh
```

The script installs or refreshes the local launcher and capture sidecar, runs the unit suite, checks bytecode compilation, writes factual preflight evidence into the selected context, verifies graph ingestion, profiles the runtime resource envelope, writes a native certification evidence payload, runs CLI preflight, exercises the FastMCP launcher and client-session bridge, verifies context-bus pull and acknowledgement, smokes the local dashboard, and writes a SQLite backup into `.synapse_s2`.

To refresh local client registration directly:

```bash
scripts/install_local_launcher.sh
scripts/install_client_configs.py
scripts/install_capture_daemon.sh
```

Restart Codex, Claude Desktop, and Claude Code after the client-config installer reports changes. Existing sessions usually do not hot-reload newly added MCP server definitions. New SYNAPSE-S2 MCP server processes hydrate their own cursor at startup, enter a strict Cortex Governor session, and drop a sanitized session-boundary note into `.synapse_s2/capture_inbox` when the process exits. The exit path also commits a typed `follow_up` cortical trace so the lifecycle is visible in Cortex state.

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
| `memory_minimum_met` | The selected context has fewer persisted memories than requested. | Capture a real trace with `synapse_cli.py --json remember-text --context default --tag <tag> --text <text>`. |
| `relationship_minimum_met` | The selected context has too few persisted event relationships for the requested gate. | Run the event graph ingestion command below. |
| `resource_envelope_met` | The default topology is outside the configured 61-138 MB estimated resource envelope. | Inspect `synapse_cli.py --json profile --benchmark-quick-prune`, then adjust `SYNAPSE_S2_NEURONS` or topology CLI args. |
| `native_certification_ready` | Strict MLX/mlxsnn certification failed. | Run `synapse_cli.py --json certify-runtime --strict-native --benchmark-quick-prune --require-resource-envelope` and inspect `failed_checks`. |
| `effective_enabled` | The selected context is disabled. | Run `synapse_cli.py --json enable --context default`. |
| `query_returned_context` | Recall did not return a registered context. | Seed or remember a matching trace, then query again. |

## Operator commands

Status:

```bash
.venv/bin/python synapse_cli.py --json status --context default
```

Compact memory list:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 10
```

Full vector details, only when needed:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 2 --include-vectors
```

Recall smoke:

```bash
.venv/bin/python synapse_cli.py --json query-text \
  --context default \
  --text "durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients"
```

Event graph ingestion:

```bash
.venv/bin/python synapse_cli.py --json ingest-text \
  --context default \
  --tag production-preflight-brief \
  --text "The SYNAPSE-S2 backend imports mlx.core and mlxsnn on Apple Silicon. The recurrent LIF backend uses z-score top-k spike coding, immutable MLX state updates, STDP relationship updates, quick-pruning maintenance, and deep-sleep consolidation. The context bus stores durable deployment events that connected local clients can pull and acknowledge with delivery cursors." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1
.venv/bin/python synapse_cli.py --json graph --context default --limit 10
```

The graph output should show event tags like `production-preflight-brief-event-001` and at least one `temporal_next` relationship.

Agent context hydration:

```bash
.venv/bin/python synapse_cli.py --json agent-brief \
  --context default \
  --agent-id codex-desktop \
  --prompt "Prepare SYNAPSE-S2 for the next live operator session."
```

This returns a compact Markdown briefing plus structured JSON for new deployments, recall hits, graph highlights, and an ack cursor. The client wrapper runs the same hydration automatically on MCP server startup; this command remains useful for manual diagnostics. Use raw receipts when validating the delivery protocol directly:

```bash
.venv/bin/python synapse_cli.py --json pull-context --context default --since-event-id 0 --limit 10
LATEST_EVENT_ID=$(.venv/bin/python synapse_cli.py --json status --context default | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["context_bus_latest_event_id"])')
.venv/bin/python synapse_cli.py --json ack-context --context default --agent-id cli-operator --last-event-id "$LATEST_EVENT_ID"
.venv/bin/python synapse_cli.py --json list-context-cursors --context default
```

Conversation capture:

```bash
.venv/bin/python synapse_cli.py --json capture-session \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "Capture real decisions, corrections, temporal order, validation evidence, and follow-up constraints from the current operator or agent session."
```

This creates event nodes in the relationship visualizer and publishes a durable context-bus event for connected clients to pull. Do not capture secrets, credentials, raw tokens, private keys, or speculative claims.

Always-on capture inbox:

```bash
scripts/install_capture_daemon.sh
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "Capture a concise factual session boundary note here."
.venv/bin/python synapse_cli.py --json capture-inbox-status
```

The sidecar watches `.synapse_s2/capture_inbox`, redacts common secret patterns, ingests pending payloads into real temporal event memories, then moves files to `.synapse_s2/capture_processed`. This is the production-safe "magic" layer: clients and hooks still opt in by writing payloads, but no running dashboard or terminal session has to stay open for ingestion.

Hand pruning:

```bash
.venv/bin/python synapse_cli.py --json graph --context default --limit 30
.venv/bin/python synapse_cli.py --json prune-memory \
  --context default \
  --target-type event \
  --memory-id "<memory-id-from-graph>" \
  --reason "remove sensitive or incorrect event" \
  --confirm
.venv/bin/python synapse_cli.py --json prune-memory \
  --context default \
  --target-type relationship \
  --relationship-id "<relationship-id-from-graph>" \
  --reason "remove bad relationship edge" \
  --confirm
```

Supported prune targets are `event`, `memory`, `relationship`, `context_event`, `temporal`, and `associative`. Use single-node or single-edge pruning first; mode-wide `temporal` and `associative` pruning clears all matching relationship edges in the selected context.

Resource envelope:

```bash
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune
```

Native certification:

```bash
.venv/bin/python synapse_cli.py --json certify-runtime \
  --strict-native \
  --benchmark-quick-prune \
  --require-resource-envelope \
  --output .synapse_s2/native-certification.json
```

The default topology should report `within_target_envelope: true` for the proposal's 61-138 MB target and a quick-pruning result with `within_60ms_budget: true`. Certification additionally checks MLX availability, `mx.compile`, `mlxsnn`, active `mlxsnn.Leaky` execution path, local embedding provider provenance, and any requested GPU/envelope gates. This is implementation-level runtime evidence from the live MLX arrays, not an external Apple Instruments profiler trace.

Embedding provider provenance:

```bash
.venv/bin/python synapse_cli.py --json \
  --embedding-provider mlx-neural \
  provider-benchmark \
  --text "Apple Silicon Metal acceleration should recall M-series MLX GPU compute context." \
  --runs 3
.venv/bin/python synapse_cli.py --json remember-text \
  --embedding-provider mlx-neural \
  --context default \
  --tag neural-provider-check \
  --text "Apple Silicon Metal acceleration should recall M-series MLX GPU compute context."
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 1
```

The benchmark should report `embedding_provider.provider: mlx-neural-v1`, `model_id: mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`, and `native_mlx: true`. First run may include model download or cache load cost; warm in-process runs should show the steady-state embedding latency. The memory entry metadata should carry the same neural provider provenance. For deterministic no-model fallback, set `--embedding-provider semantic-hash`; for an IT-managed local encoder, set `--embedding-provider python:/absolute/path/encoder.py:embed` or `SYNAPSE_S2_EMBEDDING_PROVIDER` to the same value.

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

The dashboard shows runtime status, context enablement, topology resource envelope, durable trace capture, conversation capture, event ingestion, Cortex Governor enter/tick/commit plus promote/demote/prune controls, memory graph edges, context deployments, guarded graph pruning, recall results, quick-pruning, deep-sleep, and backup controls. Its API smoke check can run without a fixed port:

```bash
.venv/bin/python scripts/smoke_dashboard.py default
```

Governed agent session smoke:

```bash
SESSION_ID=$(.venv/bin/python synapse_cli.py --json enter-cortex \
  --context default \
  --agent-id codex-desktop \
  --task "Use SYNAPSE-S2 as a live governor before making a code mutation." \
  --mode strict | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
.venv/bin/python synapse_cli.py --json cortex-tick \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --observation "The agent is preparing a mutation." \
  --proposed-action "Edit files and run validation before claiming completion." \
  --mutation-intent \
  --confidence 0.65
.venv/bin/python synapse_cli.py --json commit-cortex \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --type validation \
  --truth-posture test-validated \
  --text "The governed session path entered, ticked, and committed a typed validation trace." \
  --evidence '{"surface":"runbook"}'
.venv/bin/python synapse_cli.py --json cortex-state --context default --agent-id codex-desktop
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
| `query_spiking_attention_text` | Recalls local memory from text using the configured local provider; installed clients default to MLX neural embeddings without external inference calls. |
| `ingest_spiking_memory_text` | Segments a long briefing into event memories and relationship edges. |
| `capture_spiking_conversation` | Captures real operator/agent session notes into event memory. |
| `drop_spiking_capture_inbox` | Drops opt-in session notes for the always-on local sidecar. |
| `get_spiking_capture_inbox_status` | Shows pending and processed capture inbox counts. |
| `process_spiking_capture_inbox` | Manually processes pending capture inbox files. |
| `list_spiking_memory` | Lists compact persisted memory records. |
| `list_spiking_memory_graph` | Lists compact records plus graph relationships. |
| `prune_spiking_memory` | Removes a node, relationship edge, deployment event, or relationship mode. |
| `pull_spiking_context_deployments` | Pulls context-bus events published by GUI and MCP write actions. |
| `ack_spiking_context_deployments` | Records the last deployment event consumed by a local client. |
| `list_spiking_context_cursors` | Lists per-agent delivery cursors and pending deployment counts. |
| `hydrate_spiking_agent_context` | Hydrates a restarted client with new deployments, prompt recall, graph highlights, and an optional ack cursor update. |
| `enter_spiking_cortex` | Starts a governed agent session with recall and policy. |
| `tick_spiking_cortex` | Checks the current observation and proposed action for mutation, confidence, and sensitive-data warnings. |
| `commit_spiking_cortical_trace` | Persists typed validation, decision, constraint, risk, or implementation memory with evidence. |
| `moderate_spiking_cortical_trace` | Promotes, demotes, or prunes a governed trace by memory id. |
| `get_spiking_cortex_state` | Shows active governed sessions and typed cortical memory. |
| `profile_spiking_resources` | Shows topology footprint and optional quick-pruning benchmark. |
| `certify_spiking_runtime` | Emits native MLX/mlxsnn/provider/envelope certification evidence. |
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
| `.synapse_s2/capture_inbox` | Pending opt-in session payloads and client-session boundary notes for the sidecar. |
| `.synapse_s2/capture_processed` | Sidecar-processed payloads. |
| `.synapse_s2/capture-daemon.log` | Capture sidecar stderr/stdout log. |
| `.synapse_s2/*backup*.sqlite3` | Local backups. |
| `/Users/dan.driver/.local/bin/synapse-s2-mcp` | Launcher used by Codex, FastMCP, and inspector tools. |
