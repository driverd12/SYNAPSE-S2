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
| Shared state across Codex/Claude/direct CLI surfaces | Implemented | `.mcp.json`, `/Users/dan.driver/.codex/config.toml`, launcher, common `.synapse_s2/memory.sqlite3` |
| Project-root state discovery through client environment | Implemented | `SYNAPSE_S2_*` envs, plus `CLAUDE_PROJECT_DIR` / `CODEX_PROJECT_DIR` fallback in `mlx_backend.py` |
| Quick-pruning mode every 5 minutes | Implemented and tested | `quick_pruning_interval_seconds=300.0`, auto-prune in `query()` / `register_trace()`, `tests/test_backend.py` |
| Quick-pruning completes under 60 ms budget as measured locally | Implemented as runtime check | `run_quick_pruning()` returns `within_60ms_budget`; unit test asserts the local path stays under budget |
| Quick-pruning is non-LLM GPU/array maintenance | Implemented | `run_quick_pruning()` decays MLX arrays and resets transient membrane state |
| Deep-sleep consolidation on idle | Implemented and tested | `run_idle_maintenance()`, `trigger_idle_maintenance()`, `synapse_cli.py idle-maintenance` |
| Hebbian Distillation into structured semantic hierarchy | Implemented | `run_deep_sleep_consolidation()` builds `semantic_hierarchy` from active traces and durable entries |
| Seven-phase consolidation lifecycle | Implemented and tested | `CONSOLIDATION_PHASES`, deep-sleep `phases`, `tests/test_backend.py` |
| MCP Inspector validation path | Implemented | `README.md`, `docs/TOMORROW_RUNBOOK.md`, `scripts/prep_tomorrow.sh` |
| Readiness preflight | Implemented | `synapse_cli.py preflight`, `scripts/prep_tomorrow.sh`, `tests/test_cli.py` |

## Operator-Visible Controls

| Control | Surface |
| :--- | :--- |
| Enable/disable globally or per context | `set_spiking_attention_enabled`, `synapse_cli.py enable/disable` |
| Store real local memory | `remember_spiking_context`, `synapse_cli.py remember-text/remember-vector` |
| Query vector or text recall | `query_spiking_attention`, `query_spiking_attention_text`, CLI equivalents |
| Inspect status and dependency state | `get_spiking_attention_status`, `synapse_cli.py doctor/status/preflight` |
| List/export/backup persisted memory | MCP and CLI memory commands |
| Manual quick prune | `synapse_cli.py quick-prune` |
| Manual or forced idle deep sleep | `trigger_sleep_consolidation`, `trigger_idle_maintenance`, `synapse_cli.py sleep`, `synapse_cli.py idle-maintenance --force-deep-sleep` |

## Hardened Implementation Deviations

| Proposal language | Current implementation | Rationale |
| :--- | :--- | :--- |
| Raw `uv run mcp_server.py` in client config | Configs point to `/Users/dan.driver/.local/bin/synapse-s2-mcp` | The workspace path contains spaces and a colon. The launcher preserves the same synced `uv` environment while avoiding client command-splitting failures. |
| Deep sleep invokes a localized language model reasoning engine | Deep sleep is deterministic local Hebbian Distillation over MLX state and SQLite memory | Keeps the tool offline, reproducible, and safe for stdio MCP use tomorrow. No external model call is needed to produce the semantic hierarchy. |
| Proposal-scale multi-tier topology with very large neuron counts | Backend is configurable and defaults to a Mac-safe 5,000-neuron recurrent substrate | A dense 150,000-neuron lateral matrix is not a practical default for a local tomorrow-ready tool. Neuron count can be raised through `SYNAPSE_S2_NEURONS` or CLI args after profiling. |

## Research Extensions Not Claimed Complete

These items are present in the architecture document as longer-horizon research directions, not as verified tomorrow acceptance gates in this prototype:

- PTsoftmax and Bit Shifting PowerNorm.
- Training-time MSLeaky/ALIF comparisons, chunked BPTT, state detachment, and STE gradient training.
- A full Bayesian Surprise Event Segmenter over streaming conversation transcripts.
- Measured 61 MB to 138 MB peak VRAM envelope across large topology profiles.
- Automatic Claude Desktop config installation through `fastmcp install`; the repo provides the command and working launcher, but does not mutate Claude Desktop config during tests.

## Current Verification Command

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Current result: 35 tests passing.
