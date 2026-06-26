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
| Local text-to-spike provider provenance | Implemented | `embedding_providers.py`, `metadata.embedding_provider`, CLI `--embedding-provider`, status/provider tests |
| Bayesian Surprise Event Segmenter for local text streams | Implemented as deterministic local surprise segmentation | `event_segmenter.py`, `ingest_spiking_memory_text`, `synapse_cli.py ingest-text`, `tests/test_event_segmenter.py` |
| Dual graph memory protocol for episodic-semantic relationships | Implemented | `memory_relationships` table in `memory_store.py`, `list_spiking_memory_graph`, graph-expanded recall, deep-sleep relationship extraction |
| Agent/operator conversation capture into event memory | Implemented | `capture_spiking_conversation`, `synapse_cli.py capture-session`, `/api/capture-conversation`, GUI capture form |
| Always-on local session capture sidecar | Implemented as opt-in capture inbox | `capture_daemon.py`, `drop_spiking_capture_inbox`, `process_spiking_capture_inbox`, `synapse_cli.py capture-inbox-*`, `/api/capture-inbox`, `scripts/install_capture_daemon.sh` |
| Operator safety pruning for bad or sensitive graph data | Implemented | `prune_spiking_memory`, `synapse_cli.py prune-memory --confirm`, `/api/prune-memory`, GUI safety prune controls |
| Shared state across Codex/Claude/direct CLI surfaces | Implemented | `.mcp.json`, `/Users/dan.driver/.codex/config.toml`, launcher, common `.synapse_s2/memory.sqlite3` |
| Codex, Claude Desktop, and Claude Code client registration | Implemented | `client_config.py`, `scripts/install_client_configs.py`, `tests/test_client_config.py` |
| Project-root state discovery through client environment | Implemented | `SYNAPSE_S2_*` envs, plus `CLAUDE_PROJECT_DIR` / `CODEX_PROJECT_DIR` fallback in `mlx_backend.py` |
| Durable context-bus deployment to connected local agents | Implemented as pull-plus-ack protocol | `pull_spiking_context_deployments`, `ack_spiking_context_deployments`, `list_spiking_context_cursors`, CLI `pull-context` / `ack-context`, `agent_context_cursors` table |
| Agent-ready context hydration after client restart | Implemented | `hydrate_spiking_agent_context`, `synapse_cli.py agent-brief`, backend `hydrate_agent_context`, cursor-backed ack plus recall and graph summary |
| Client-side startup/session-boundary bridge | Implemented | `mcp_client_wrapper.py`, `client_session_bridge.py`, launcher wrapper, per-client `SYNAPSE_S2_CLIENT_AGENT_ID`, sanitized boundary drops into capture inbox |
| Recall does not fabricate historical tags when memory is empty | Implemented | no-memory queries return transparent raw activation summaries instead of synthetic `context::neuron-*` memory labels |
| Operator-visible local control surface | Implemented | `dashboard_server.py`, `web/index.html`, `web/app.js`, `web/styles.css`, `scripts/smoke_dashboard.py`, `tests/test_dashboard_server.py` |
| Quick-pruning mode every 5 minutes | Implemented and tested | `quick_pruning_interval_seconds=300.0`, auto-prune in `query()` / `register_trace()`, `tests/test_backend.py` |
| Quick-pruning completes under 60 ms budget as measured locally | Implemented as runtime check | `run_quick_pruning()` returns `within_60ms_budget`; unit test asserts the local path stays under budget |
| Quick-pruning is non-LLM GPU/array maintenance | Implemented | `run_quick_pruning()` decays MLX arrays and resets transient membrane state |
| Proposal 61-138 MB resource envelope | Implemented as live topology estimate and readiness gate | `resource_profile()`, `profile_spiking_resources`, `synapse_cli.py profile`, `synapse_cli.py preflight --require-resource-envelope`, `scripts/prep_tomorrow.sh` |
| Native MLX/mlxsnn certification evidence | Implemented | `certify_runtime()`, CLI `certify-runtime`, MCP `certify_spiking_runtime`, dashboard `/api/certify-runtime`, strict-native checks |
| Deep-sleep consolidation on idle | Implemented and tested | `run_idle_maintenance()`, `trigger_idle_maintenance()`, `synapse_cli.py idle-maintenance` |
| Hebbian Distillation into structured semantic hierarchy | Implemented | `run_deep_sleep_consolidation()` builds `semantic_hierarchy` from active traces, durable entries, and persisted relationship edges |
| Seven-phase consolidation lifecycle | Implemented and tested | `CONSOLIDATION_PHASES`, deep-sleep `phases`, `tests/test_backend.py` |
| MCP Inspector validation path | Implemented | `README.md`, `docs/TOMORROW_RUNBOOK.md`, `scripts/prep_tomorrow.sh` |
| Readiness preflight | Implemented | `synapse_cli.py preflight`, `scripts/prep_tomorrow.sh`, `tests/test_cli.py` |

## Operator-Visible Controls

| Control | Surface |
| :--- | :--- |
| Enable/disable globally or per context | `set_spiking_attention_enabled`, `synapse_cli.py enable/disable` |
| Store real local memory | `remember_spiking_context`, `synapse_cli.py remember-text/remember-vector` |
| Segment long text into event memory graph | `ingest_spiking_memory_text`, `synapse_cli.py ingest-text` |
| Capture real session conversation notes | `capture_spiking_conversation`, `synapse_cli.py capture-session`, dashboard Conversation capture |
| Drop and process sidecar session payloads | `drop_spiking_capture_inbox`, `get_spiking_capture_inbox_status`, `process_spiking_capture_inbox`, `synapse_cli.py capture-inbox-*`, dashboard Magic Capture |
| Query vector or text recall | `query_spiking_attention`, `query_spiking_attention_text`, CLI equivalents |
| Inspect status and dependency state | `get_spiking_attention_status`, `synapse_cli.py doctor/status/preflight` |
| List/export/backup persisted memory | MCP and CLI memory commands |
| Inspect event relationships | `list_spiking_memory_graph`, `synapse_cli.py graph` |
| Hand-prune nodes, edges, deployment events, temporal edges, or associative edges | `prune_spiking_memory`, `synapse_cli.py prune-memory --confirm`, dashboard Safety Prune |
| Pull and acknowledge context deployments | `pull_spiking_context_deployments`, `ack_spiking_context_deployments`, `list_spiking_context_cursors`, `synapse_cli.py pull-context/ack-context/list-context-cursors` |
| Hydrate a restarted agent from memory | `hydrate_spiking_agent_context`, `synapse_cli.py agent-brief` |
| Profile topology memory and pruning budget | `profile_spiking_resources`, `synapse_cli.py profile --benchmark-quick-prune` |
| Certify native runtime execution | `certify_spiking_runtime`, `synapse_cli.py certify-runtime --strict-native --benchmark-quick-prune --require-resource-envelope`, dashboard Native Certify |
| Use a local dashboard | `dashboard_server.py`, `scripts/smoke_dashboard.py` |
| Manual quick prune | `synapse_cli.py quick-prune` |
| Manual or forced idle deep sleep | `trigger_sleep_consolidation`, `trigger_idle_maintenance`, `synapse_cli.py sleep`, `synapse_cli.py idle-maintenance --force-deep-sleep` |

## Hardened Implementation Deviations

| Proposal language | Current implementation | Rationale |
| :--- | :--- | :--- |
| Raw `uv run mcp_server.py` in client config | Configs point to `/Users/dan.driver/.local/bin/synapse-s2-mcp` | The workspace path contains spaces and a colon. The launcher preserves the same synced `uv` environment while avoiding client command-splitting failures. |
| Deep sleep invokes a localized language model reasoning engine | Deep sleep is deterministic local Hebbian Distillation over MLX state and SQLite memory | Keeps the tool offline, reproducible, and safe for stdio MCP use tomorrow. No external model call is needed to produce the semantic hierarchy. |
| "Deploy to all connected agents" language | Deployment is durable local pull with per-agent acknowledgement cursors | Local desktop clients do not expose a reliable push bus. Durable pull plus receipts is auditable and survives client restarts. |
| "Magic" passive capture | Implemented as a local always-on inbox plus MCP startup/session-boundary bridge, not unauthorized scraping of arbitrary app state | MCP clients hydrate automatically on server startup and drop sanitized boundary notes on exit. Full chat capture still requires clients, hooks, or operators to explicitly write payloads. |
| Text embeddings from arbitrary client text | Default installed client provider is `mlx-neural-v1` using `mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`; deterministic `semantic-hash-v1` and `python:/path.py:function` remain available | Real local neural embeddings now back text capture/recall while preserving an offline no-model fallback and explicit provenance on every text memory. |
| Proposal-scale multi-tier topology with very large neuron counts | Backend is configurable and defaults to a Mac-safe 5,000-neuron recurrent substrate | A dense 150,000-neuron lateral matrix is not a practical default for a local tomorrow-ready tool. Neuron count can be raised through `SYNAPSE_S2_NEURONS` or CLI args after profiling. |
| VRAM envelope language | Resource profile estimates resident MLX array footprint from live shapes and dtypes, with optional quick-prune benchmark and certification evidence payload | This is the right readiness signal for tomorrow. External Metal/Instruments counter capture can be added later for hardware certification. |

## Research Extensions Not Claimed Complete

These items are present in the architecture document as longer-horizon research directions, not as verified tomorrow acceptance gates in this prototype:

- PTsoftmax and Bit Shifting PowerNorm.
- Training-time MSLeaky/ALIF comparisons, chunked BPTT, state detachment, and STE gradient training.
- Probabilistic embedding-calibrated surprise over live token streams; embeddings can now be neural, but event segmentation thresholds remain deterministic and local for predictable MCP stdio behavior.
- External Metal counter / Instruments validation of peak GPU residency across multiple Apple Silicon SKUs; current certification evidence is MLX/topology/runtime based.
- Invisible capture of arbitrary already-running Codex/Claude chat transcript content without client cooperation; the MCP process boundary is captured, but full chat text still requires explicit client/tool/hook payloads.

## Current Verification Command

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Current result: run `scripts/prep_tomorrow.sh` before the presentation. The readiness script runs the full unit suite, compile check, CLI graph/profile/preflight gates, MCP smoke calls, consolidation lifecycle smoke, and a SQLite backup.
