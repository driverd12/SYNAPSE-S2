# SYNAPSE-S2 Proposal Compliance Matrix

This matrix maps the supplied proposal documents to the current implementation. It is intentionally strict: implemented items point to working files and tests; research-grade extensions are called out separately instead of being implied.

Implementation status is not deployment status. The live local production
service remains untouched on legacy v5; this worktree has not been cut over or
claimed published to either remote.

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
| `query_spiking_attention(prompt_embedding, context_id)` tool | Implemented as deprecated stateful proposal compatibility | `mcp_server.py`, `tests/test_mcp_server.py`; new read-only recall uses `retrieve_spiking_memory_v2` |
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
| Persistent associative memory substrate | Implemented | `memory_store.py` SQLite store, `remember_spiking_context`, `list_spiking_memory`, export, and segregated diagnostics |
| Atomic persistence and repair | Implemented | FULL-durability transactions, fsynced atomic runtime/export publication, no-overwrite verified backup, read-only revision-bound integrity audit, and confirmed repair in `memory_store.py` / `mlx_backend.py` |
| Governed legacy capture-ledger reconciliation | Implemented | Exact processed-payload/graph/deployment binding, projected canonical fingerprint, deployment-derived commit time, verified safety backup, revision-bound confirmed repair, no graph replay, and no synthetic transport receipt in `recovery_manager.py`, CLI/MCP/readiness surfaces, and `tests/test_capture_ledger_reconciliation.py` |
| Verified paired recovery and reversible retention | Implemented | Ed25519-signed SQLite plus exactly-once capture bundles, schema/provenance/replay reconciliation, independent pins for every foreign artifact present, bundle/dependent receipt identity binding through materialization, fully pinned foreign governed restore, isolated restore proof, repository locking, signed exact-inventory plans, atomic quarantine, crash journals, and idempotent restoration in `memory_store.py`, `recovery_manager.py`, CLI/MCP/dashboard/readiness surfaces, and `tests/test_backup_recovery.py` |
| Exactly-once capture | Implemented | Canonical request digests, unique capture-operation ledger, atomic graph mutation, private durable receipts, restart reconciliation, and concurrent duplicate fencing in `capture_daemon.py` and `memory_store.py` |
| Single authoritative runtime and writer | Implemented | One authenticated private Unix-socket core owns MLX, SQLite, runtime state, recovery, and embedded capture; durable schema-v6 authority epochs fence stale/forked writers; adapters use `CoreClient` with no local fallback |
| Governed core cutover and operational routing | Implemented | Fresh signed backup/verify/isolated-restore evidence, exact legacy-writer quiescence, private atomic LaunchAgent/config publication, stable identity/heartbeat health, lightweight dashboard/client plists, and v6 legacy-capture refusal are implemented in `scripts/core_*`, `scripts/install_core_agent.sh`, and the operational installers |
| Browser dashboard request integrity | Implemented | Owner-only rotating bootstrap, port-specific HttpOnly SameSite=Strict cookie, distinct `X-Synapse-Dashboard-Session` capability on every API GET/POST, exact Host/Origin on POST, port-scoped `sessionStorage` with fragment scrubbing, authenticated helper launch, and shared installer/smoke contract in `dashboard_server.py`, `web/app.js`, and `scripts/open_dashboard.py` |
| Deterministic delivery rejection journaling | Implemented | Proven no-effect ACK/release/dead-letter failures become terminal `failed` / `invalid_request`; credential-shaped delivery identities fail before journal admission; uncertain failures remain non-replayable `outcome_unknown`; terminal retention preserves finite total-row throughput in core/store/journal tests |
| Embedding and dense-topology admission | Implemented | Raw query/register vectors must exactly match the configured dimension before journal admission, and the exact steady float32 topology must fit 384 MiB before MLX load/materialization/resize. This is explicitly not peak-residency, target-hardware, or timing proof. |
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
| Governed capture-error resolution | Implemented | Terminal/historical/unsafe classification, content-free preflight, confirmed fenced archival, private crash-recoverable resolution manifests, CLI/MCP controls, and Doctor distinction between active failures and retained evidence |
| Compact MCP startup control plane | Implemented | Surface-only startup hydration and thread-safe control backend avoid dense MLX allocation during tool discovery/status; neural state materializes only for neural operations |
| Compact agent response contracts | Implemented | `synapse-s2.token-contract.v1` bounds authoritative Retrieval v2, memory list, graph, agent hydration, and Cortex state `structuredContent` after redaction; compact/full profiles, canonical serialization, exact byte accounting, counted omissions, provenance/completeness metadata, receipt/event one-to-one validation, lease release on projection failure, schema-closed secret-safe prevalidation of undeclared MCP arguments, installed-client 12,288-byte structured defaults, a separate 4,096-byte compact MCP safety-text contract, and explicit CLI legacy compatibility are implemented in `token_contracts.py`, `mcp_server.py`, `synapse_cli.py`, and `client_config.py` while dashboard rich APIs remain unchanged |
| Deterministic read-only Retrieval v2 | Implemented | `retrieve_text_v2`, MCP `retrieve_spiking_memory_v2`, CLI `retrieve-v2`, and the dashboard query route fuse durable spike/surface indexes with optional bounded same-context graph signals and bounded MMR diversity. The path does not run recurrent LIF, STDP, pruning, runtime-state writes, activity marking, or legacy query caching; responses expose stable identity, explicit scope/link/source provenance, completeness/work limits, and uncalibrated ranking semantics. |
| Authenticated snapshot pagination | Implemented | Compact/full memory list, graph, and Cortex reads return exact authoritative totals plus `authenticated-keyset-v2` continuations bound to contract version, response mode, namespace, scope, filters, unique ordering, content snapshot revision, expiry, and local origin. Cortex adds a frozen active-session runtime revision to the durable-memory revision; stale, tampered, expired, wrong-context/mode/filter/scope/order, and cross-origin cursors fail closed. |
| Retrieval v2 measurement harness | Implemented with synthetic-only acceptance scope | `scripts/measure_retrieval_v2.py`, `tests/fixtures/retrieval_v2/benchmark_v1.json`, and Retrieval v2 measurement tests check Recall@k, MRR, nDCG@k, namespace leakage, duplicates, score/provenance contracts, deterministic output across insertion/backend variations, and read purity in disposable stores. Passing is a regression gate for the fixed synthetic corpus, not proof of live-corpus relevance or production latency. |
| Compact-contract measurement acceptance | Verified | `docs/evidence/phase6-token-contract-acceptance.json` is bound to clean commit `519af91`, uses an isolated verified recovery restore, publishes aggregate-only evidence, and passes all 11 gates across four surfaces. Informational byte results are 96.818% installed-policy reduction and 78.03% same-source projection reduction; both output channels are verified independently, while token counts and transport framing are excluded. |
| Transactional LaunchAgent installation | Implemented | Per-label locks, private/fsynced plists and logs, bounded launchd transitions, authoritative functional probes, and exact prior-definition/policy rollback in both installers |
| Strict bounded loopback dashboard | Implemented | `dashboard_server.py` refuses non-loopback binds and limits the threaded adapter to eight active handlers/backlog 32, an absolute one-second pre-authentication header deadline, five-second post-header I/O, and bounded shutdown; API authorization uses the two-capability contract above |
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
| Proposal resource envelope | Implemented as exact steady float32 topology admission plus a live profile/readiness signal; the current Mac-optimized operating target is 96-384 MiB and authoritative admission hard-stops above 384 MiB before MLX loading/materialization | `core_service.py`, `mlx_backend.py`, `resource_profile()`, `profile_spiking_resources`, `synapse_cli.py profile`, preflight, and adversarial tests; no peak-residency/hardware/timing claim |
| Native MLX/mlxsnn certification evidence | Implemented | `certify_runtime()`, CLI `certify-runtime`, MCP `certify_spiking_runtime`, dashboard `/api/certify-runtime`, strict-native checks |
| Deep-sleep consolidation on idle | Implemented and tested | `run_idle_maintenance()`, `trigger_idle_maintenance()`, `synapse_cli.py idle-maintenance` |
| Hebbian Distillation into structured semantic hierarchy | Implemented | `run_deep_sleep_consolidation()` builds `semantic_hierarchy` from active traces, durable entries, and persisted relationship edges |
| Seven-phase consolidation lifecycle | Implemented and tested | `CONSOLIDATION_PHASES`, deep-sleep `phases`, `tests/test_backend.py` |
| MCP Inspector validation path | Implemented | `README.md`, `docs/TOMORROW_RUNBOOK.md`, `scripts/prep_tomorrow.sh` |
| Readiness preflight | Implemented | `synapse_cli.py preflight`, `scripts/prep_tomorrow.sh`, `tests/test_cli.py` |
| Single-pack operator readiness certification | Implemented | `scripts/operator_readiness_certify.py`, `docs/OPERATOR_READINESS_CERTIFICATION.md`, `tests/test_operator_readiness_certifier.py`; proves client config, MCP connect, native neural embedding, Doctor, Start Work, memory write, read-only Retrieval v2 recall, App Connect no-write preview, Wrap Session persistence, and dashboard smoke in one evidence pack |

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
| Read-only text recall | `retrieve_spiking_memory_v2`, `synapse_cli.py retrieve-v2`, and the dashboard query route. Legacy `query_spiking_attention*` / `query-*` surfaces remain deprecated stateful compatibility paths, not read-only recall. |
| Select bounded agent response detail | MCP `response_mode=compact|full` plus `max_response_bytes`; CLI `--response-mode compact|full` plus `--max-response-bytes`, with `legacy` reserved for known CLI compatibility consumers. For MCP, `structuredContent` is authoritative and the separately bounded safety `TextContent` is only a decision aid. |
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
| Use a local dashboard | Install/refresh with `scripts/install_dashboard_agent.sh`, open only with `.venv/bin/python scripts/open_dashboard.py`, and verify with `scripts/smoke_dashboard.py`; never launch a bare dashboard URL |
| Pin a recalled result as current-task evidence | dashboard Recall Pin `/api/pin-memory` with `operator-confirmed` receipt |
| Manual quick prune | `synapse_cli.py quick-prune` |
| Manual or forced idle deep sleep | `trigger_sleep_consolidation`, `trigger_idle_maintenance`, `synapse_cli.py sleep`, `synapse_cli.py idle-maintenance --force-deep-sleep` |

## Hardened Implementation Deviations

| Proposal language | Current implementation | Rationale |
| :--- | :--- | :--- |
| Raw `uv run mcp_server.py` in client config | Configs point to `/Users/dan.driver/.local/bin/synapse-s2-mcp` | The workspace path contains spaces and a colon. The launcher preserves the same synced `uv` environment while avoiding client command-splitting failures. |
| Capture raw client text into local memory | Capture paths redact common secret/token/private-key shapes before pending inbox disk writes, SQLite persistence, graph/context-bus deployment, and API/MCP responses | Local memory is useful only if operators can trust it will not casually preserve sensitive operational material. Redaction is a guardrail, not permission to capture secrets. |
| Any local HTTP dashboard bind or ambient browser cookie | Dashboard permits only loopback addresses and requires the port-specific cookie plus port-scoped header capability on every API call; POST additionally requires exact Host/Origin | The owner-only bootstrap and helper avoid bare URL launches, while the distinct header prevents another loopback port from reusing a host-scoped browser cookie. Remote access still requires a separately authenticated gateway. |
| Destructive prune tool calls | CLI, MCP, and dashboard destructive graph and Cortex trace pruning are confirmation-gated | Operators need fast surgical cleanup while preventing accidental node, edge, temporal, associative, or governed-trace deletion. |
| High-confidence `test-validated` memory | `test-validated` Cortex commits require concrete validation evidence; dashboard defaults to observed evidence | Prevents casual notes from becoming high-confidence agent guidance without a test, command, artifact, commit, output summary, or report. |
| Deep sleep invokes a localized language model reasoning engine | Deep sleep is deterministic local Hebbian Distillation over MLX state and SQLite memory | Keeps the tool offline, reproducible, and hardened for stdio MCP use tomorrow. No external model call is needed to produce the semantic hierarchy. |
| "Deploy to all connected agents" language | Deployment is durable targeted local pull with normalized routing, fenced leases, and per-attempt receipts | Local desktop clients do not expose a reliable push bus. Receipt-driven at-least-once pull is auditable, retryable, identity-scoped, and survives client restarts; legacy watermark cursors never authorize acknowledgement. |
| "Magic" passive capture | Implemented as a local always-on inbox, MCP startup/Cortex/session-boundary bridge, explicit transcript sources, selected-text capture, and confirmed App Connect snapshots | MCP clients hydrate automatically on server startup, enter Cortex, and drop sanitized boundary notes plus typed cortical lifecycle traces on exit. Manual inbox processing and dashboard App Connect writes require explicit confirmation/preflight tokens. Full chat capture still requires a local capture path, but operators can now attach running apps through a hardened local connector. |
| Return every rich memory field to every agent caller | Installed MCP clients and contracted CLI reads default to a versioned compact envelope with a byte ceiling; bounded `full` is explicit, CLI `legacy` is compatibility-only, and the loopback dashboard keeps its rich API | The compact envelope removes structural duplication while retaining trusted control fields, provenance, receipt identity, completeness, and counted omissions. Memory list/graph/Cortex pages preserve authenticated cursors and exact totals atomically. Critical/high, action-required, and protected contract warnings survive; noncritical warnings may be omitted only with a truthful count. Full mode remains recursively redacted and trust-labelled. |
| Text embeddings from arbitrary client text | Default installed client provider is `mlx-neural-v1` using `mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`; raw client vectors must exactly match the bound dimension before journaling | Real local neural embeddings back text capture/recall with explicit provenance, while strict dimension/topology admission prevents a client-controlled dense resize; the active provider remains binding-owned. |
| Proposal-scale multi-tier topology with very large neuron counts | Backend is configurable and defaults to a Mac-optimized 8,192-neuron recurrent substrate | A dense 150,000-neuron lateral matrix is not a practical default for a local tomorrow-ready tool. Neuron count can be raised further through `SYNAPSE_S2_NEURONS` or CLI args after profiling. |
| VRAM envelope language | Admission computes the exact steady float32 topology and rejects more than 384 MiB before MLX load; resource profile and quick-prune evidence remain separate runtime signals | This does not measure peak process/Metal residency, certify every hardware target, or prove execution time beyond the measured operation. External Instruments counters remain a future hardware-certification step. |

## Research Extensions Not Claimed Complete

These items are present in the architecture document as longer-horizon research directions, not as verified tomorrow acceptance gates in this prototype:

- PTsoftmax and Bit Shifting PowerNorm.
- Training-time MSLeaky/ALIF comparisons, chunked BPTT, state detachment, and STE gradient training.
- Online probabilistic Bayesian surprise over live token streams; current event segmentation is deterministic over configured local embedding-provider cosine distance, persists semantic and lexical boundary scores, and keeps lexical fallback for predictable MCP stdio behavior.
- External Metal counter / Instruments validation of peak GPU residency across multiple Apple Silicon SKUs; current certification evidence is MLX/topology/runtime based.
- Invisible capture of arbitrary already-running Codex/Claude chat transcript content without a local capture path; the MCP process boundary is captured, App Connect can attach visible local apps, and selected text/transcript files can be captured, but unsupported private transcript stores are not treated as a guaranteed interface.
- The proposal's citations to S2-Net, Spike Dice Attention (SDA), and Spiking Graph Transformer Networks (SGTN) as May-July 2026 publications were future-dated relative to the supplied design evidence and have not been independently verified as implementation evidence. SYNAPSE-S2 does not claim or implement an S2-Net phase-delay engine, SDA spike-train attention operator, or SGTN model; its namespace links and retrieval ranker are deterministic, operator-governed product mechanisms.
- Retrieval v2 relevance calibration on the live operator corpus. The fixed synthetic benchmark is an offline regression gate and does not establish live relevance quality, workload capacity, concurrency behavior, provider parity, or a service-level latency objective.

## Current Verification Command

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Current result: run `scripts/prep_tomorrow.sh` before the presentation. The readiness script runs the full unit suite, compile check, CLI graph/profile/preflight gates, MCP smoke calls, consolidation lifecycle smoke, an authoritative capture-ledger audit, and a signed paired recovery-point gate with reverification plus isolated restore proof. Operator certification additionally requires `mcp_contract_probe`, which independently validates the installed 12,288-byte authoritative structured response and separate 4,096-byte compact safety text; outer transport framing is excluded.
