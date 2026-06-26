# SYNAPSE-S2 Production Gap Audit

This file is intentionally blunt. It catalogs prototype-risk gaps, shorthand fixes, and current disposition so operators do not mistake demo scaffolding or research extensions for production guarantees.

## Closed In Latest Hardening Pass

| Gap | Risk | Shorthand solution | Disposition |
| :--- | :--- | :--- | :--- |
| No-memory recall fabricated `context::neuron-*` labels | Could look like historical memory when no memory existed | Return transparent raw activation summary instead of fake tags | Fixed in `mlx_backend.py`; covered by `tests/test_backend.py` |
| Context bus published events without consumption receipts | Could claim "deployed to agents" when no connected client had pulled anything | Add durable per-agent cursors with pull plus ack semantics | Fixed in `memory_store.py`, `mlx_backend.py`, `mcp_server.py`, `dashboard_server.py`, `web/app.js` |
| GUI published context events but did not acknowledge its own pulls | Operator could not tell whether the dashboard consumed the event it displayed | Dashboard calls `/api/context-ack` after pulling deployments | Fixed in `web/app.js`; covered by dashboard route tests |
| Canned demo-memory path remained available from ops surfaces | Polluted real memory with static content and could undermine trust in recall | Remove production CLI `seed-demo`; default prep to `default` context and factual preflight evidence | Fixed in `synapse_cli.py` and `scripts/prep_tomorrow.sh`; guarded by CLI and operational tests |
| CLI writes were not published to the context bus | CLI-captured thoughts would not appear in agent deployment pulls | Publish CLI remember/ingest writes and add CLI pull/ack cursor commands | Fixed in `synapse_cli.py`; covered by `tests/test_cli.py` |
| Agent/operator conversation notes had no first-class capture path | Future sessions would not naturally appear in the event relationship visualizer | Add `capture-session`, `capture_spiking_conversation`, `/api/capture-conversation`, and GUI capture form | Fixed in backend, MCP, CLI, dashboard, and GUI tests |
| Bad graph data could not be surgically removed | Sensitive, wrong, or partial-truth memory could keep influencing recall | Add confirmed pruning for memory nodes, event nodes, edges, context deployments, temporal edges, and associative edges | Fixed in `memory_store.py`, backend, MCP, CLI, dashboard, and GUI |
| README/runbook still taught `board-demo` and `seed-demo` | IT operators could accidentally present synthetic state | Rewrite examples around `default` and real operator captures | Fixed in `README.md` and `docs/TOMORROW_RUNBOOK.md` |
| Compliance matrix under-described client registration and delivery receipts | Proposal mapping lagged implementation | Add explicit rows for config installer and context cursors | Fixed in `docs/PROPOSAL_COMPLIANCE.md` |
| Capture required an active user-facing tool call | Useful session notes could be missed if the dashboard or agent forgot the synchronous capture form | Add a launchd-backed local capture inbox with CLI, MCP, dashboard status/process controls, redaction, processed/error queues, and tests | Fixed in `capture_daemon.py`, `synapse_cli.py`, `mcp_server.py`, `dashboard_server.py`, `web/app.js`, and `scripts/install_capture_daemon.sh` |
| Restarted agents had to manually compose raw pull, recall, graph, and ack calls | Codex/Claude could miss relevant memory or fail to acknowledge consumed deployments | Add one context-hydration command/tool that returns an agent-ready brief and updates the cursor | Fixed in `mlx_backend.py`, `synapse_cli.py`, `mcp_server.py`, `AGENTS.md`, and tests |
| Client startup and shutdown had no repeatable SYNAPSE-S2 habit | Clients could reconnect without hydrating or recording a useful session boundary | Wrap the local MCP launcher with startup hydration and sanitized exit capture; install per-client agent ids | Fixed in `client_session_bridge.py`, `mcp_client_wrapper.py`, `client_config.py`, launcher script, and tests |
| Text projection had no provider boundary or semantic provenance | Recall quality and claims were hard to audit because text embedding looked like fixed lexical hashing | Add local pluggable embedding providers, neural/hash/callable modes, and stored provider metadata | Fixed in `embedding_providers.py`, `mlx_backend.py`, CLI/MCP/dashboard surfaces, and tests |
| No bundled large neural embedding provider was wired into clients | "Semantic memory" could be dismissed as concept hashing instead of model-backed meaning | Add `mlx-neural-v1` using `mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`, local model cache, CLI/MCP provider benchmarks, and neural-native certification visibility | Fixed in `embedding_providers.py`, `client_config.py`, launcher/prep/capture scripts, `synapse_cli.py`, `mcp_server.py`, docs, and tests |
| Native execution could not produce a certification evidence payload | IT could challenge whether MLX/mlxsnn/envelope/prune-budget claims were currently true | Add `certify-runtime`, `certify_spiking_runtime`, dashboard certification endpoint/action, strict native checks, and evidence-pack writing | Fixed in backend, CLI, MCP, dashboard, `scripts/prep_tomorrow.sh`, and tests |

## Remaining Explicit Non-Claims

| Gap | Risk | Shorthand solution | Current disposition |
| :--- | :--- | :--- | :--- |
| No invisible interception of arbitrary already-running Codex/Claude transcript content | Running clients must still call a capture tool, CLI, or write a local inbox payload for full chat text to enter memory | Restart clients so the MCP startup/session-boundary bridge hydrates and records process boundaries; use explicit capture for full transcript notes | Documented limitation; bridge plus always-on inbox plus durable capture and pull/ack works now |
| Bayesian surprise is deterministic lexical approximation | Event boundaries are useful but not probabilistic token-stream inference | Add provider-backed or calibrated probabilistic surprise module | Research extension, not claimed complete |
| Resource envelope certification is MLX/topology evidence, not Instruments counters | Hardware-level memory certification is not yet captured from Apple Instruments traces | Add Instruments/Metal counter harness across target Apple Silicon SKUs | Research extension, not claimed complete |
| Dense lateral matrix limits very large neuron counts | Higher topology sizes can exceed local memory quickly | Add sparse/block lateral matrix backend | Research extension, not claimed complete |
| Strict native mode requires explicit enablement | Default developer mode still permits fallback so non-native hosts can run tests and local tooling | Set `SYNAPSE_S2_REQUIRE_NATIVE=1`, CLI `--require-native-backend`, preflight `--require-native`, or run certification with `strict_native=true` | Hard-fail and certification path implemented |

## Current Production Bar

The current bar for calling a local build presentable is:

1. `scripts/prep_tomorrow.sh` exits zero.
2. `get_spiking_attention_status` reports runtime ready, enabled, and shared `.synapse_s2` paths.
3. `pull_spiking_context_deployments` returns durable write events.
4. `ack_spiking_context_deployments` records a local client cursor.
5. No-memory recall returns a transparent raw activation summary, never a fake historical tag.
6. Conversation capture creates visible event nodes in the graph and a durable context-bus deployment.
7. Confirmed pruning can remove a single node, edge, deployment event, temporal edge set, or associative edge set.
8. The capture inbox sidecar is installed or `capture-inbox-process` proves pending drops become graph events with secret redaction.
9. The local MCP launcher enters through the startup/session-boundary bridge and client configs declare distinct agent ids.
10. Text memories show `embedding_provider` provenance from the active local provider, and `provider-benchmark`/`benchmark_spiking_embedding_provider` reports `mlx-neural-v1` plus `native_mlx: true` for installed client defaults.
11. `certify-runtime` or `certify_spiking_runtime` produces a native evidence payload and reports strict-native failures instead of silently downgrading.
12. The dashboard at `http://127.0.0.1:8765/?context_id=default` can write, capture conversations, process magic capture drops, ingest, recall, graph, prune, certify native runtime, sleep, back up, and show context-bus receipt state.
