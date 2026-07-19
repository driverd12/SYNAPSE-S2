# SYNAPSE-S2 Proposal Compliance Matrix

This matrix maps the supplied proposal documents to the current implementation. It is intentionally strict: implemented items point to working files and tests; research-grade extensions are called out separately instead of being implied.

## Reviewed Sources

- `README.md`, seeded from `/Users/dan.driver/Downloads/SYNAPSE-S2-README.md`
- `docs/Neuromorphic-Attention-Plugin-Development-Plan.md`
- `docs/Neuromorphic-Attention-Plugin-Development-Plan.pdf`
- `docs/source-prompt-and-plan.txt`

## Implemented Acceptance Gates

| Proposal requirement | Status | Evidence |
| :--- | :--- | :--- |
| Apple Silicon local MCP server over JSON-RPC stdio | Implemented | `mcp_server.py`, `.mcp.json`, `/Users/dan.driver/.codex/config.toml` |
| FastMCP wrapper with stdout protected for JSON-RPC and logging routed to stderr | Implemented | `mcp_server.py` uses `logging.basicConfig(..., stream=sys.stderr, force=True)` and tests redirect stdout |
| `query_spiking_attention(prompt_embedding, context_id)` tool | Implemented | `mcp_server.py`, `tests/test_mcp_server.py` |
| `trigger_sleep_consolidation()` tool | Implemented | `mcp_server.py`, `tests/test_mcp_server.py` |
| Native `mlx.core` import and Apple Silicon MLX execution | Implemented | `mlx_backend.py`, `pyproject.toml` |
| Native `mlxsnn` import and Leaky LIF execution path | Implemented with hardened fallback | `mlx_backend.py` initializes `mlxsnn.Leaky`; explicit MLX LIF math remains as fallback |
| MLX immutable state updates | Implemented | `mlx_backend.py` assigns new `mem`, `spk`, `W_lateral`, and `active_traces` arrays rather than mutating in place |
| `mx.compile` accelerated LIF step | Implemented | `SpikingAttentionBackend._build_lif_step()` |
| MLX lazy graph realization with `mx.eval` | Implemented | `SpikingAttentionBackend._eval_if_available()` after recurrent and consolidation updates |
| Dimension-independent z-score top-k sensory coding | Implemented and tested | `encode_to_spikes_top_k()`, `tests/test_backend.py` |
| LIF dynamics `U[t+1] = beta * U[t] + X[t+1] - S[t] * V_thr` | Implemented and tested | `SpikingAttentionBackend._lif_update()` and explicit fallback in `_build_lif_step()` |
| Balanced excitatory/inhibitory synaptic matrices | Implemented | `_balanced_matrix()`, `_balanced_lateral_matrix()`, `_ei_sign_vector()` |
| Recurrent SNN execution loop | Implemented | `run_snn_cycle()` |
| Addition/subtraction STDP update with asymmetric temporal constants | Implemented | `_apply_stdp()` |
| Contextual focus gating | Implemented | global and per-context enable toggles in `set_enabled()` and MCP/CLI controls |
| Persistent associative memory substrate | Implemented | `memory_store.py` SQLite store, `remember_spiking_context`, `list_spiking_memory`, export, backup |
| Indexed spike-overlap recall | Implemented | `memory_spikes` durable inverted index in `memory_store.py`, migration/backfill, atomic upsert maintenance, and indexed recall tests |
| Indexed surface/facet text recall | Implemented | `memory_surface_terms` durable term index in `memory_store.py`, migration/backfill, atomic upsert maintenance, indexed query path in `mlx_backend.py`, and memory-store/backend tests |
| Local text-to-spike provider provenance | Implemented | `embedding_providers.py`, `metadata.embedding_provider`, CLI `--embedding-provider`, status/provider tests |
| Bayesian Surprise Event Segmenter for local text streams | Implemented as deterministic provider-backed semantic surprise with lexical fallback | `event_segmenter.py`, `ingest_spiking_memory_text`, `synapse_cli.py ingest-text`, `mlx_backend.py`, `tests/test_event_segmenter.py`, `tests/test_backend.py` |
| Dual graph memory protocol for episodic-semantic relationships | Implemented | `memory_relationships` table in `memory_store.py`, `list_spiking_memory_graph`, graph-expanded recall, deep-sleep relationship extraction |
| Agent/operator conversation capture into event memory | Implemented | `capture_spiking_conversation`, `synapse_cli.py capture-session`, `/api/capture-conversation`, GUI capture form |
| Always-on local session capture sidecar | Implemented as opt-in capture inbox | `capture_daemon.py`, `drop_spiking_capture_inbox`, confirmed `process_spiking_capture_inbox`, `synapse_cli.py capture-inbox-*`, `/api/capture-inbox`, dashboard capture preflight tokens, `scripts/install_capture_daemon.sh` |
| Local app attachment and transcript capture lane | Implemented | `transcript_capture.py`, CLI `app-list` / `app-connect` / `app-snapshot` / `capture-clipboard` / `transcript-source-*`, MCP App Connect and transcript tools, dashboard App Connect preflight-token panel, `scripts/capture_frontmost_selection.sh`, tests |
| App Connect preview receipts before memory writes | Implemented | `app-snapshot-preview`, dashboard `/api/app-snapshot-preview`, quality/capability badges, no-write blocked receipts, `tests/test_transcript_capture.py`, `tests/test_dashboard_server.py` |
| Saved memory namespace selector | Implemented | Dashboard Memory Context control lists `status.memory_contexts`, keeps `default` first, updates the URL/input/current memory URI when selected, preserves manual entry, and is covered by `tests/test_dashboard_server.py` |
| Current status report generator | Implemented | `scripts/synapse_status_report.py` writes `docs/CURRENT_STATUS.md` from live status/profile/Doctor/context-health/hygiene/Cortex state, with docs drift coverage in `tests/test_status_report.py` and `tests/test_documentation.py` |
| Operator graph pruning for bad or sensitive graph data | Implemented | `prune_spiking_memory`, `synapse_cli.py prune-memory --confirm`, `/api/prune-memory`, GUI graph prune controls |
| Hardened capture, pruning, and high-confidence memory safety envelope | Implemented | `redaction.py`, pre-write capture inbox redaction, private local file modes, symlink rejection, direct capture/context-bus response redaction, MCP `confirm=true` pruning and capture-inbox processing, CLI `--confirm`, dashboard confirmation/preflight tokens, Cortex prune confirmation, `test-validated` evidence enforcement, and tests |
| Loopback-only dashboard default | Implemented | `dashboard_server.py` refuses non-loopback binds unless `SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD=true`; static/API responses include browser security headers |
| Non-mutating readiness audit path | Implemented | `scripts/prep_tomorrow.sh --verify-only` runs tests, compile checks, status/profile/certification/preflight without installing agents, writing evidence, processing inboxes, launching MCP wrappers, dashboard smoke, maintenance, or backups |
| Shared state across Codex/Claude/direct CLI surfaces | Implemented | `.mcp.json`, `/Users/dan.driver/.codex/config.toml`, launcher, common `.synapse_s2/memory.sqlite3` |
| Codex, Claude Desktop, and Claude Code client registration | Implemented | `client_config.py`, `scripts/install_client_configs.py`, `tests/test_client_config.py` |
| Project-root state discovery through client environment | Implemented | `SYNAPSE_S2_*` envs, plus `CLAUDE_PROJECT_DIR` / `CODEX_PROJECT_DIR` fallback in `mlx_backend.py` |
| Durable context-bus deployment to connected local agents | Implemented as leased at-least-once delivery with explicit receipt acknowledgement and governed retry quarantine | `pull_spiking_context_deployments`, atomic-batch `ack_spiking_context_deployments`, confirmed `dead_letter_spiking_context_delivery`, `list_spiking_context_cursors`, CLI `pull-context` / `ack-context` / `dead-letter-context`, canonical targets, bounded attempts, attempt receipts, ACK tombstones, and durable-disposition cursors |
| Agent-ready context hydration after client restart | Implemented | `hydrate_spiking_agent_context`, `synapse_cli.py agent-brief`, backend `hydrate_agent_context`; hydration returns leases plus recall and graph summary and never acknowledges before the caller consumes them |
| Client-side startup/session-boundary bridge | Implemented | `mcp_client_wrapper.py`, `client_session_bridge.py`, launcher wrapper, per-client `SYNAPSE_S2_CLIENT_AGENT_ID`, automatic strict Cortex entry, sanitized boundary drops into capture inbox, and typed `follow_up` cortical trace commits |
| Recall does not fabricate historical tags when memory is empty | Implemented | no-memory queries return transparent raw activation summaries instead of synthetic `context::neuron-*` memory labels |
| Real-time agent cognitive governance loop | Implemented | Cortex Governor backend, scoped file/tool tick intent, CLI `enter-cortex` / `cortex-tick` / `commit-cortex` / `close-cortex` / `moderate-cortex` / `cortex-state`, MCP tools, dashboard panel with end-session plus promote/demote/prune controls, hydration state, and tests |
| Cross-process Cortex session closure persistence | Implemented | Runtime state persistence merges existing `cortex_sessions` before writing and terminal states win over stale active copies; covered by `tests/test_backend.py::test_cortex_close_survives_stale_backend_runtime_persist` |
| Operator-visible local control surface | Implemented | `dashboard_server.py`, `web/index.html`, `web/app.js`, `web/styles.css`, `scripts/smoke_dashboard.py`, `tests/test_dashboard_server.py` |
| Daily operator trust workflow | Implemented | Start Work, `agent-brief --mode morning`, Context Health, Doctor/Repair, Memory Hygiene, Goal Ledger, Wrap Session, operation receipts, dashboard recipes, CLI `start-work` / `context-health` / `doctor --repair-plan` / `memory-hygiene` / `goal.create` / `goal.update` / `goal.list` / `wrap-session`, MCP `create_spiking_goal` / `update_spiking_goal` / `list_spiking_goals`, and tests |
| Recall result promotion into operator-confirmed evidence | Implemented | Dashboard Recall Pin `/api/pin-memory`, Cortex `operator-confirmed` trace commits, receipt rendering, and dashboard tests |
| Quick-pruning mode every 5 minutes | Implemented and tested | `quick_pruning_interval_seconds=300.0`, auto-prune in `query()` / `register_trace()`, `tests/test_backend.py` |
| Quick-pruning completes under 60 ms budget as measured locally | Implemented as runtime check | `run_quick_pruning()` returns `within_60ms_budget`; unit test asserts the local path stays under budget |
| Quick-pruning is non-LLM GPU/array maintenance | Implemented | `run_quick_pruning()` decays MLX arrays and resets transient membrane state |
| Proposal resource envelope | Implemented as live topology estimate and readiness gate, with the current Mac-optimized default envelope set to 96-384 MB for the larger 8,192-neuron substrate | `resource_profile()`, `profile_spiking_resources`, `synapse_cli.py profile`, `synapse_cli.py preflight --require-resource-envelope`, `scripts/prep_tomorrow.sh` |
| Native MLX/mlxsnn certification evidence | Implemented | `certify_runtime()`, CLI `certify-runtime`, MCP `certify_spiking_runtime`, dashboard `/api/certify-runtime`, strict-native checks |
| Deep-sleep consolidation on idle | Implemented and tested | `run_idle_maintenance()`, `trigger_idle_maintenance()`, `synapse_cli.py idle-maintenance` |
| Hebbian Distillation into structured semantic hierarchy | Implemented | `run_deep_sleep_consolidation()` builds `semantic_hierarchy` from active traces, durable entries, and persisted relationship edges |
| Seven-phase consolidation lifecycle | Implemented and tested | `CONSOLIDATION_PHASES`, deep-sleep `phases`, `tests/test_backend.py` |
| MCP Inspector validation path | Implemented | `README.md`, `docs/TOMORROW_RUNBOOK.md`, `scripts/prep_tomorrow.sh` |
| Readiness preflight | Implemented | `synapse_cli.py preflight`, `scripts/prep_tomorrow.sh`, `tests/test_cli.py` |
| Single-pack operator readiness certification | Implemented | `scripts/operator_readiness_certify.py`, `docs/OPERATOR_READINESS_CERTIFICATION.md`, `tests/test_operator_readiness_certifier.py`; proves client config, MCP connect, native neural embedding, Doctor, Start Work, memory write, recall, App Connect no-write preview, Wrap Session persistence, and dashboard smoke in one evidence pack |

## Operator-Visible Controls

| Control | Surface |
| :--- | :--- |
| Enable/disable globally or per context | `set_spiking_attention_enabled`, `synapse_cli.py enable/disable` |
| Store real local memory | `remember_spiking_context`, `synapse_cli.py remember-text/remember-vector` |
| Segment long text into event memory graph | `ingest_spiking_memory_text`, `synapse_cli.py ingest-text` |
| Capture real session conversation notes | `capture_spiking_conversation`, `synapse_cli.py capture-session`, dashboard Conversation capture |
| Drop and process sidecar session payloads | `drop_spiking_capture_inbox`, `get_spiking_capture_inbox_status`, confirmed `process_spiking_capture_inbox`, `synapse_cli.py capture-inbox-*`, dashboard Magic Capture preflight |
| Attach a running local app and capture a redacted snapshot or selected text | `list_spiking_running_apps`, `connect_spiking_app`, `capture_spiking_app_snapshot`, `capture_spiking_clipboard`, CLI `app-list` / `app-connect` / `app-snapshot` / `capture-clipboard`, dashboard App Connect preflight, `scripts/capture_frontmost_selection.sh` |
| Preview App Connect capture quality before writing memory | CLI `app-snapshot-preview`, dashboard App Preview quality badge, no-write receipt, and selected-text fallback guidance |
| Choose an existing memory namespace from the dashboard | Dashboard saved Memory Context selector populated from live `memory_contexts`, plus manual namespace entry for new contexts |
| Regenerate the committed live status artifact | `scripts/synapse_status_report.py --context default --embedding-provider mlx-neural`, writing `docs/CURRENT_STATUS.md` |
| Register local transcript/log deltas | `register_spiking_transcript_source`, `list_spiking_transcript_sources`, `poll_spiking_transcript_sources`, CLI `transcript-source-*` |
| Query vector or text recall | `query_spiking_attention`, `query_spiking_attention_text`, CLI equivalents |
| Inspect status and dependency state | `get_spiking_attention_status`, `synapse_cli.py doctor/status/preflight` |
| Start the daily work loop | `synapse_cli.py start-work`, dashboard Start Work brief, health score, recipes, and receipt |
| Start an agent/operator morning brief | `synapse_cli.py agent-brief --mode morning`, including current objective, relevant memories, open risks, app/session traces, recommended next actions, source memory references, and goal ledger state |
| Inspect context health and memory quality | `synapse_cli.py context-health`, dashboard Context Health badge |
| Track active goals across days | `create_spiking_goal`, `update_spiking_goal`, `list_spiking_goals`, CLI `goal.create` / `goal.update` / `goal.list`, dashboard Goal Ledger |
| Run a repair-oriented doctor report | `synapse_cli.py doctor --repair-plan`, dashboard Doctor/Repair |
| Review memory hygiene work | `synapse_cli.py memory-hygiene`, dashboard Memory Hygiene queue and action receipts |
| Preview and commit a session handoff | `synapse_cli.py wrap-session --preview/--confirm`, dashboard Wrap Session preview/commit receipts |
| List/export/backup persisted memory | MCP and CLI memory commands |
| Inspect event relationships | `list_spiking_memory_graph`, `synapse_cli.py graph` |
| Hand-prune nodes, edges, deployment events, temporal edges, associative edges, or governed Cortex traces | `prune_spiking_memory`, `moderate_spiking_cortical_trace(confirm=true)`, `synapse_cli.py prune-memory --confirm`, `synapse_cli.py moderate-cortex --confirm`, dashboard Graph Prune and Cortex Governor controls |
| Pull and acknowledge context deployments | `pull_spiking_context_deployments`, `ack_spiking_context_deployments`, `list_spiking_context_cursors`, `synapse_cli.py pull-context/ack-context/list-context-cursors` |
| Hydrate a restarted agent from memory | `hydrate_spiking_agent_context`, `synapse_cli.py agent-brief`, `synapse_cli.py agent-brief --mode morning` |
| Run governed agent work sessions | `enter_spiking_cortex`, `tick_spiking_cortex` with intended file/tool scope, `commit_spiking_cortical_trace`, `close_spiking_cortex`, `moderate_spiking_cortical_trace`, `get_spiking_cortex_state`, CLI `enter-cortex` / `cortex-tick` / `commit-cortex` / `close-cortex` / `moderate-cortex` / `cortex-state`, dashboard Cortex Governor |
| Profile topology memory and pruning budget | `profile_spiking_resources`, `synapse_cli.py profile --benchmark-quick-prune` |
| Certify native runtime execution | `certify_spiking_runtime`, `synapse_cli.py certify-runtime --strict-native --benchmark-quick-prune --require-resource-envelope`, dashboard Native Certify |
| Use a local dashboard | `dashboard_server.py`, `scripts/smoke_dashboard.py` |
| Pin a recalled result as current-task evidence | dashboard Recall Pin `/api/pin-memory` with `operator-confirmed` receipt |
| Manual quick prune | `synapse_cli.py quick-prune` |
| Manual or forced idle deep sleep | `trigger_sleep_consolidation`, `trigger_idle_maintenance`, `synapse_cli.py sleep`, `synapse_cli.py idle-maintenance --force-deep-sleep` |

## Hardened Implementation Deviations

| Proposal language | Current implementation | Rationale |
| :--- | :--- | :--- |
| Raw `uv run mcp_server.py` in client config | Configs point to `/Users/dan.driver/.local/bin/synapse-s2-mcp` | The workspace path contains spaces and a colon. The launcher preserves the same synced `uv` environment while avoiding client command-splitting failures. |
| Capture raw client text into local memory | Capture paths redact common secret/token/private-key shapes before pending inbox disk writes, SQLite persistence, graph/context-bus deployment, and API/MCP responses | Local memory is useful only if operators can trust it will not casually preserve sensitive operational material. Redaction is a guardrail, not permission to capture secrets. |
| Any local HTTP dashboard bind | Dashboard defaults to loopback-only and refuses non-loopback bind attempts without an explicit override env var | The operator dashboard is a local control surface, not a LAN service by default. |
| Destructive prune tool calls | CLI, MCP, and dashboard destructive graph and Cortex trace pruning are confirmation-gated | Operators need fast surgical cleanup while preventing accidental node, edge, temporal, associative, or governed-trace deletion. |
| High-confidence `test-validated` memory | `test-validated` Cortex commits require concrete validation evidence; dashboard defaults to observed evidence | Prevents casual notes from becoming high-confidence agent guidance without a test, command, artifact, commit, output summary, or report. |
| Deep sleep invokes a localized language model reasoning engine | Deep sleep is deterministic local Hebbian Distillation over MLX state and SQLite memory | Keeps the tool offline, reproducible, and hardened for stdio MCP use tomorrow. No external model call is needed to produce the semantic hierarchy. |
| "Deploy to all connected agents" language | Deployment is durable targeted local pull with normalized routing, fenced leases, and per-attempt receipts | Local desktop clients do not expose a reliable push bus. Receipt-driven at-least-once pull is auditable, retryable, identity-scoped, and survives client restarts; legacy watermark cursors never authorize acknowledgement. |
| "Magic" passive capture | Implemented as a local always-on inbox, MCP startup/Cortex/session-boundary bridge, explicit transcript sources, selected-text capture, and confirmed App Connect snapshots | MCP clients hydrate automatically on server startup, enter Cortex, and drop sanitized boundary notes plus typed cortical lifecycle traces on exit. Manual inbox processing and dashboard App Connect writes require explicit confirmation/preflight tokens. Full chat capture still requires a local capture path, but operators can now attach running apps through a hardened local connector. |
| Text embeddings from arbitrary client text | Default installed client provider is `mlx-neural-v1` using `mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`; deterministic `semantic-hash-v1` and `python:/path.py:function` remain available | Real local neural embeddings now back text capture/recall while preserving an offline no-model fallback and explicit provenance on every text memory. |
| Proposal-scale multi-tier topology with very large neuron counts | Backend is configurable and defaults to a Mac-optimized 8,192-neuron recurrent substrate | A dense 150,000-neuron lateral matrix is not a practical default for a local tomorrow-ready tool. Neuron count can be raised further through `SYNAPSE_S2_NEURONS` or CLI args after profiling. |
| VRAM envelope language | Resource profile estimates resident MLX array footprint from live shapes and dtypes, with optional quick-prune benchmark and certification evidence payload | This is the right readiness signal for tomorrow. External Metal/Instruments counter capture can be added later for hardware certification. |

## Research Extensions Not Claimed Complete

These items are present in the architecture document as longer-horizon research directions, not as verified tomorrow acceptance gates in this prototype:

- PTsoftmax and Bit Shifting PowerNorm.
- Training-time MSLeaky/ALIF comparisons, chunked BPTT, state detachment, and STE gradient training.
- Online probabilistic Bayesian surprise over live token streams; current event segmentation is deterministic over configured local embedding-provider cosine distance, persists semantic and lexical boundary scores, and keeps lexical fallback for predictable MCP stdio behavior.
- External Metal counter / Instruments validation of peak GPU residency across multiple Apple Silicon SKUs; current certification evidence is MLX/topology/runtime based.
- Invisible capture of arbitrary already-running Codex/Claude chat transcript content without a local capture path; the MCP process boundary is captured, App Connect can attach visible local apps, and selected text/transcript files can be captured, but unsupported private transcript stores are not treated as a guaranteed interface.

## Current Verification Command

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Current result: run `scripts/prep_tomorrow.sh` before the presentation. The readiness script runs the full unit suite, compile check, CLI graph/profile/preflight gates, MCP smoke calls, consolidation lifecycle smoke, and a SQLite backup.
