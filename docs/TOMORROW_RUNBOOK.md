# SYNAPSE-S2 Tomorrow Runbook

This is the fast operator path for using SYNAPSE-S2 from this Mac tomorrow.

Rollout status remains separate from repository capability: live production is
still the untouched legacy-v5 service. None of the Phase 7 implementation,
tests, or runbook text below claims deployment or publication to either remote.

## Monday operator-trust certification

On an already bound installation, run this first when the question is "can we
trust SYNAPSE-S2 for real work right now?" For the first local-v5 cutover,
publish the candidate binding described below before running it.

```bash
cd "/Users/dan.driver/Documents/Playground/SYNAPSE-S2"
.venv/bin/python scripts/operator_readiness_certify.py \
  --context default \
  --agent-id codex-desktop \
  --expect-embedding-provider mlx-neural
```

The certifier derives the exact candidate configuration through the same
installer path used at cutover. The optional `--expect-*` arguments are
assertions against that candidate, not client-side configuration overrides. Its
manifest embeds the canonical `synapse-s2.core-config-evidence.v1` contract and
candidate configuration fingerprint. The certifier exits non-zero unless client
config, MCP connection, the required compact MCP contract probe, native neural
embedding, Doctor, Start Work, real memory write and read-only Retrieval v2 recall, App Connect
no-write preview, Wrap Session persistence, dashboard smoke, signed recovery,
and isolated restore are all ready.

The detailed certification runbook is `docs/OPERATOR_READINESS_CERTIFICATION.md`.
The installed-client response schema and byte-budget contract are documented in
`docs/TOKEN_CONTRACTS.md`.

## Authoritative-core status, cutover, and preflight

Every production surface uses one authority. Check it first:

```bash
scripts/install_core_agent.sh status
```

Installed clients read only the binding pointer from their configuration. The
canonical owner-only binding is
`~/.config/synapse-s2/core-binding.json`. It pins one complete reviewed layout,
the core label, private canonical CoreConfig path and digest, exact
configuration fingerprint, embedding-space identity, and
one of two modes: `candidate-local-v5` before first adoption or
`authoritative-core-v6` after stable activation.

For a first cutover, publish the candidate binding before certification, then
install the launcher and client configs that consume it:

```bash
scripts/install_core_agent.sh publish-binding
scripts/install_local_launcher.sh
.venv/bin/python scripts/install_client_configs.py
.venv/bin/python scripts/operator_readiness_certify.py \
  --context default \
  --agent-id codex-desktop \
  --expect-embedding-provider mlx-neural
```

`publish-binding` refuses a database already governed by schema v6. For a v6
replacement, require the existing status response to report
`client_binding.ready: true`; never downgrade it to candidate mode. A reviewed
noncanonical layout must pass the same `--noncanonical-layout-manifest` to
`publish-binding`, the readiness certifier, and `install`.

After the certifier's last accepted write, stop the exact legacy
dashboard/capture/MCP writer processes and follow
`docs/AUTHORITATIVE_CORE_OPERATIONS.md`. The only prep command allowed to claim
the store requires the fresh evidence path explicitly:

```bash
scripts/prep_tomorrow.sh --apply \
  --install-core /absolute/path/to/manifest.json
```

The apply path does not trust a coarse backup timestamp or row-count match. It
recomputes the live logical memory digest, capture manifest, runtime-state
canonical digest, and authoritative-v6 request-journal digest, compares them
to the signed bundle and isolated restore, then publishes the private signed
`core/cutover-attestation.json`. That receipt is bound to the exact build,
config, clean HEAD, and evidence pack and expires within ten minutes. A missing,
drifted, near-expiry, or signer-mismatched binding stops before installation.
After stable authenticated health and an embedded-capture heartbeat, the
installer atomically replaces the candidate document with an
`authoritative-core-v6` binding. Every CoreClient request carries its expected
configuration fingerprint, so stale or cross-layout clients fail before
journal acceptance or dispatch. Confirm the transition:

```bash
scripts/install_core_agent.sh status
# Require healthy=true, capture_ready=true, and client_binding.ready=true.
```

The prep command is certification-only by default:

```bash
cd "/Users/dan.driver/Documents/Playground/SYNAPSE-S2"
scripts/prep_tomorrow.sh --verify-only
```

Before any production directory, installer, client configuration, LaunchAgent,
or memory state is changed, the prep script requires an existing environment,
a clean and stable worktree, fresh clean-HEAD evidence when applying, the full
unit suite, an in-memory source compile pass, and a valid deterministic build
identity. It never runs `uv sync` on the operator's behalf. It never starts the
legacy standalone capture daemon.

For an audit pass that avoids installs, memory writes, inbox processing, MCP wrapper launches, dashboard smoke, maintenance, and backup writes:

```bash
scripts/prep_tomorrow.sh --verify-only
```

Only the explicit `--apply --install-core <manifest>` stage may install the
core, launcher, and all client configs, then write factual preflight evidence,
exercise graph/capture/context-bus/dashboard/maintenance flows, and create the
signed paired recovery point. All immutable gates rerun in the same invocation
before that apply marker, so an earlier verification run cannot be substituted
for current source or evidence.

To refresh local client registration directly:

```bash
scripts/install_local_launcher.sh
scripts/install_client_configs.py
scripts/install_dashboard_agent.sh
```

`scripts/install_capture_daemon.sh` is retained only for deliberate pre-cutover
v5 maintenance. It fails closed before any launchd or filesystem mutation when
the v6 authority marker or core LaunchAgent is present.

Restart Codex, Claude Desktop, and Claude Code after the client-config installer reports changes. Existing sessions usually do not hot-reload newly added MCP server definitions. New SYNAPSE-S2 MCP server processes perform observation-only startup hydration, enter a strict Cortex Governor session, and drop a sanitized session-boundary note into `.synapse_s2/capture_inbox` when the process exits. Startup never leases or acknowledges unseen events. A client leases events only through an explicit hydrate/pull call and acknowledges the returned receipt ids only after successful use. The exit path also commits a typed `follow_up` cortical trace so the lifecycle is visible in Cortex state.

## Hardened local contract

- Dashboard HTTP is strictly local. Binding to `0.0.0.0` or any non-loopback interface fails; remote access requires a separately authenticated and reviewed gateway.
- Dashboard API GET and POST calls require both a port-specific HttpOnly, SameSite=Strict cookie and the distinct `X-Synapse-Dashboard-Session` capability obtained through the rotating owner-only bootstrap. POST also requires the exact configured Host and same-origin Origin. The auth file is `0600` inside a `0700` directory and contains no cookie secret; the browser keeps the header capability only in port-scoped `sessionStorage` and scrubs it from the bootstrap fragment.
- Schema v6 is service-owned. If the core socket is unavailable, adapters return service unavailable/outcome unknown; they do not construct a local backend or replay an ambiguous mutation.
- Client layout is binding-owned. Direct socket, database, state, capture, export, or neural settings that conflict with the owner-only binding fail closed; a candidate binding cannot operate a governed v6 database and an authoritative binding cannot operate an ungoverned v5 database.
- The core is the only capture worker. The separate legacy capture LaunchAgent must remain absent after cutover.
- Capture inbox payloads are redacted before the pending file is written. Pending, processed, error, export, backup, runtime, and SQLite paths are created private to the local user where the filesystem permits it.
- Capture processing refuses symlinks and oversized payloads. It does not follow arbitrary filesystem targets from the inbox.
- Direct `capture-session`, MCP `capture_spiking_conversation`, context-bus deployments, graph metadata, and returned API payloads all share the same redaction layer.
- Manual capture inbox processing is confirmation-gated: CLI requires `--confirm`, MCP requires `confirm=true`, and the dashboard Magic Capture flow requires a short-lived preflight token tied to the pending file list.
- Dashboard App Connect attach and snapshot actions require short-lived preflight tokens bound to the selected app or connection before they can write to memory.
- Destructive memory and Cortex pruning are confirmation-gated: CLI requires `--confirm`, MCP requires `confirm=true`, and the dashboard requires an explicit confirmation action before deleting graph data or governed traces.
- `test-validated` Cortex memory requires concrete validation evidence such as a test command, test list, output summary, artifact path, commit, or verification report. Use `observed` or `operator-confirmed` for ordinary notes.
- Retrieval v2 is backed by durable SQLite indexes for sparse spikes and surface terms, with optional bounded same-context graph expansion and deterministic MMR diversity selection. Existing databases are backfilled automatically, and `memory_store.stats()` exposes the populated index counts. Ranking scores are uncalibrated relevance signals, not probabilities or truth confidence.
- Client config installation refuses malformed existing JSON instead of silently replacing it.
- Installed MCP clients default to `synapse-s2.token-contract.v1` compact responses with a 12,288-byte post-redaction UTF-8 ceiling for authoritative `structuredContent` on Retrieval v2, memory list, graph, agent hydration, and Cortex state calls. MCP also emits one separate compact safety `TextContent` item bounded to 4,096 bytes; full-mode safety text is bounded separately to 131,072 bytes. Outer JSON-RPC framing is excluded from all three ceilings. `response_mode="full"` is an explicit bounded diagnostic choice, never an automatic fallback.
- CLI `retrieve-v2`, `agent-brief`, `list-memory`, `graph`, and `cortex-state` use the same compact envelope by default. Use `--response-mode full --max-response-bytes <4096..131072>` for bounded diagnostics or `--response-mode legacy` only for a known compatibility consumer.
- Compact/full memory-list, memory-graph, and Cortex-state reads expose exact authoritative totals and authenticated keyset continuation. A cursor is bound to contract version, response mode, context, scope, filters, ordering, snapshot revision, expiry, and origin node. Cortex cursors additionally bind the frozen live active-session view. A stale, expired, altered, wrong-context, wrong-mode, wrong-filter, or cross-origin cursor fails closed instead of restarting at page one.
- Compact hydration preserves a one-to-one mapping from every leased `receipt_id` to a visible deployment event. Projection failure releases acquired leases; only a later exact-receipt acknowledgement advances durable delivery state.
- A deterministic no-effect ACK, release, or dead-letter request becomes a terminal `failed` / `invalid_request` journal row; a genuinely uncertain commit remains `outcome_unknown` and is never replayed. Credential-shaped delivery identifiers fail before journal admission. Terminal rows retain dedup evidence until age-based pruning, so total retained-row throughput remains finite even though deterministic rejects do not consume accepted-row capacity.
- Raw `register_trace` and `query` vectors must match the configured dimension before journal admission. The exact steady float32 dense topology must fit 384 MiB before MLX loading, materialization, or resize; this is not peak-residency, target-hardware, or execution-time proof.
- Critical/high, action-required, and protected contract warnings survive compact projection. Noncritical warnings may be omitted only as complete items with a truthful omission count. MCP consumers must treat `structuredContent` as authoritative; safety text is a bounded decision aid.
- The loopback dashboard stays on its rich local API. The MCP compact profile does not reduce Namespace Galaxy, ganglion, neuron, or graph inspection payloads in the browser.

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
| `mcp_contract_probe` | The installed launcher did not return the exact compact schema/budget, independently verified canonical size, or the separate bounded safety summary. | Reinstall the launcher and client configs, restart the MCP client, then rerun certification. Inspect `docs/TOKEN_CONTRACTS.md` before changing a ceiling. |
| `memory_minimum_met` | The selected context has fewer persisted memories than requested. | Capture a real trace with `synapse_cli.py --json remember-text --context default --tag <tag> --text <text>`. |
| `relationship_minimum_met` | The selected context has too few persisted event relationships for the requested gate. | Run the event graph ingestion command below. |
| `resource_envelope_met` | The steady float32 topology exceeds the configured operating target or 384 MiB admission ceiling. | Inspect `synapse_cli.py --json profile --benchmark-quick-prune`, then review the bound topology; do not claim peak-residency or hardware proof from this calculation. |
| `native_certification_ready` | Strict MLX/mlxsnn certification failed. | Run `synapse_cli.py --json certify-runtime --strict-native --benchmark-quick-prune --require-resource-envelope` and inspect `failed_checks`. |
| `effective_enabled` | The selected context is disabled. | Run `synapse_cli.py --json enable --context default`. |
| `query_returned_context` | Recall did not return a registered context. | Seed or remember a matching trace, then query again. |

## Daily Operator Trust Loop

Use this flow at the beginning and end of each real working block. It is the same loop exposed in the dashboard's Daily Operator Trust Loop panel.

Start Work:

```bash
.venv/bin/python synapse_cli.py --json start-work \
  --context default \
  --agent-id codex-desktop \
  --prompt "Prepare SYNAPSE-S2 for today's operator work."
```

`start-work` is an observation-only operator overview and never leases a
deployment. When the local agent is ready to consume durable events, run the
receipt-bearing alternative and ACK only after consumption:

```bash
.venv/bin/python synapse_cli.py --json agent-brief \
  --mode morning \
  --context default \
  --agent-id codex-desktop \
  --prompt "Prepare SYNAPSE-S2 for today's operator work." \
  --response-mode compact \
  --max-response-bytes 12288
.venv/bin/python synapse_cli.py --json ack-context \
  --context default \
  --agent-id codex-desktop \
  --receipt-id '<receipt_id from agent-brief>'
```

This returns a morning brief, current objective, relevant memories, open risks, recent app/session traces, recommended next actions, source memory references, current health score, memory quality score, recommended recipes, goal ledger state, and an operation receipt. If the health score is degraded or blocked, run the next two commands before trusting recall.

Goal Ledger:

```bash
.venv/bin/python synapse_cli.py --json goal.create \
  --context default \
  --agent-id codex-desktop \
  --title "Prepare SYNAPSE-S2 for Monday operator use" \
  --owner operator \
  --goal-state in_progress \
  --next-action "Run Start Work, Doctor, App Preview, Recall Pin, and Wrap Session."
.venv/bin/python synapse_cli.py --json goal.update \
  --context default \
  --agent-id codex-desktop \
  --goal-id "<memory-id-from-goal-create>" \
  --goal-state blocked \
  --evidence "Waiting on an external prerequisite." \
  --next-action "Clear the prerequisite, then rerun Start Work."
.venv/bin/python synapse_cli.py --json goal.list --context default
```

Goals are governed `goal` traces. The dashboard Goal Ledger, `agent-brief --mode morning`, MCP hydration, and `get_spiking_cortex_state` all read the same owner/state/evidence/next-action ledger.

Doctor and repair report:

```bash
.venv/bin/python synapse_cli.py --json doctor \
  --context default \
  --include-apps \
  --repair-plan
```

Memory Hygiene queue:

```bash
.venv/bin/python synapse_cli.py --json memory-hygiene \
  --context default \
  --limit 25
```

Context Health:

```bash
.venv/bin/python synapse_cli.py --json context-health --context default
```

Wrap Session preview, then commit only if the receipt is accurate:

```bash
.venv/bin/python synapse_cli.py --json wrap-session \
  --context default \
  --agent-id codex-desktop \
  --source-tag codex-session \
  --text "Summarize factual decisions, implementation details, validation evidence, blockers, and follow-up constraints here." \
  --preview
.venv/bin/python synapse_cli.py --json wrap-session \
  --context default \
  --agent-id codex-desktop \
  --source-tag codex-session \
  --text "Same final factual summary after preview review." \
  --confirm
```

The dashboard adds the same receipts visually: Start Work shows what to do next, Goal Ledger shows current owner/state/evidence/next action, Doctor explains what is healthy or blocked, Memory Hygiene queues stale/duplicate/low-confidence work, App Preview proves capture quality before writing memory, Recall Pin turns a recalled item into operator-confirmed evidence, and Wrap Session captures a clean handoff.

## Operator commands

Status:

```bash
.venv/bin/python synapse_cli.py --json status --context default
```

Compact memory list:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 10 \
  --response-mode compact --max-response-bytes 12288
```

Full vector details, only when needed:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 2 \
  --include-vectors --response-mode full --max-response-bytes 131072
```

Recall smoke:

```bash
.venv/bin/python synapse_cli.py --json retrieve-v2 \
  --context default \
  --prompt "durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients" \
  --scope local --result-limit 8 --candidate-limit 64 \
  --response-mode compact --max-response-bytes 12288
```

Require `operation: "memory-retrieval"`, `data.raw_input_stored: false`, explicit
`data.scope.contexts`, and item-level `scope_provenance`, `source_provenance`,
and `confidence.signal: "uncalibrated-ranking-score"`. `has_more: true` on this
ranked response reports a bounded candidate/result limit; it is not a page
cursor. Use a larger bounded request or a new snapshot when more ranked results
are needed. Do not fall back to the deprecated stateful `query-text` command.

Event graph ingestion:

```bash
.venv/bin/python synapse_cli.py --json ingest-text \
  --context default \
  --tag production-preflight-brief \
  --text "The SYNAPSE-S2 backend imports mlx.core and mlxsnn on Apple Silicon. The recurrent LIF backend uses z-score top-k spike coding, immutable MLX state updates, STDP relationship updates, quick-pruning maintenance, and deep-sleep consolidation. The context bus stores durable deployment events that connected local clients pull with fenced receipts, acknowledge exactly after consumption, and track through derived delivery cursors." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1
.venv/bin/python synapse_cli.py --json graph --context default --limit 5 \
  --response-mode full --max-response-bytes 131072
```

The graph output should show event tags like `production-preflight-brief-event-001` and at least one `temporal_next` relationship. Event memory metadata should also include `surprise_model`, `surprise_mode`, `semantic_surprise_score`, and `lexical_surprise_score`. `surprise_mode: embedding` means the boundary was cut from the configured local provider's cosine-distance signal; `surprise_mode: lexical` means SYNAPSE-S2 used the hardened token-overlap fallback.

Agent context hydration:

```bash
.venv/bin/python synapse_cli.py --json agent-brief \
  --context default \
  --agent-id codex-desktop \
  --prompt "Prepare SYNAPSE-S2 for the next live operator session." \
  --response-mode compact \
  --max-response-bytes 12288
```

This CLI command and installed MCP `hydrate_spiking_agent_context` calls default to the bounded `synapse-s2.token-contract.v1` compact envelope. Every compact receipt has a matching visible deployment, and the envelope reports `ack_required`, `has_more`, retry/dead-letter blockers, provenance, completeness, and counted omissions. CLI callers use `--response-mode full --max-response-bytes <4096..131072>` for bounded diagnostics; MCP callers pass the corresponding `response_mode` and `max_response_bytes` arguments. CLI `--response-mode legacy` is reserved for known local compatibility consumers. Neither compact nor full mode acknowledges a lease. The client wrapper performs a separate observation-only hydration at MCP startup; this command remains useful for manual diagnostics. Use receipt-driven delivery directly when validating the protocol:

Follow `continuation.strategy` literally. `claim-events-to-observe-delivery`
means the observation-only call cannot establish queue completeness;
`hydrate-when-context-expected` is the observed idle state; receipt-bearing
responses require consume-then-ACK (or release) before another hydration; an
`active-lease` strategy requires waiting for its expiry without touching another
consumer's receipt; and a `retry-exhausted` strategy requires governed
dead-letter review. A response can contain both receipts and a blocker, in which
case finish the receipt instruction first and then the blocker instruction. The
complete strategy matrix is in `docs/TOKEN_CONTRACTS.md`.

```bash
.venv/bin/python synapse_cli.py --json pull-context \
  --context default \
  --agent-id cli-operator \
  --consumer-instance-id cli-operator-manual \
  --limit 10
# After the output has been consumed successfully, repeat --receipt-id for each returned receipt.
.venv/bin/python synapse_cli.py --json ack-context \
  --context default \
  --agent-id cli-operator \
  --receipt-id 'ctxrcpt_...'
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

This creates event nodes in the relationship visualizer and publishes a durable context-bus event for connected clients to pull. Conversation capture also auto-builds a context namespace: `Thread:`, `Feature:`, `Topic:`, `Goal:`, `Objective:`, and `Event:` prefixes become typed namespace/topic/goal/objective/event nodes, and the original session events are linked back with `namespace_contains` edges so new topics and feature efforts visibly grow in the graph. Do not capture secrets, credentials, raw tokens, private keys, or speculative claims.

Always-on capture inbox:

```bash
scripts/install_capture_daemon.sh
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "Capture a concise factual session boundary note here."
.venv/bin/python synapse_cli.py --json capture-inbox-status
.venv/bin/python synapse_cli.py --json capture-inbox-process --confirm
```

The sidecar watches `.synapse_s2/capture_inbox`, redacts common secret patterns, ingests pending payloads into real temporal event memories, then moves files to `.synapse_s2/capture_processed`. This is the production-hardened "magic" layer: clients and hooks still opt in by writing payloads, but no running dashboard or terminal session has to stay open for ingestion. Manual one-shot processing remains explicit: the CLI uses `--confirm`, MCP uses `confirm=true`, and the dashboard preflights the exact pending files before committing.

App Connect:

```bash
.venv/bin/python synapse_cli.py --json app-list
.venv/bin/python synapse_cli.py --json app-connect \
  --context default \
  --app-name "Google Chrome" \
  --tag chrome-live \
  --speaker operator \
  --confirm
.venv/bin/python synapse_cli.py --json app-connections
.venv/bin/python synapse_cli.py --json app-snapshot-preview \
  --connection-id "<connection-id-from-app-connections>"
.venv/bin/python synapse_cli.py --json app-snapshot \
  --connection-id "<connection-id-from-app-connections>" \
  --confirm
scripts/capture_frontmost_selection.sh default frontmost-selection operator
```

Use App Connect when an already-running local app needs to contribute context. `app-list` detects attachable local apps through a fast filtered process-list scan, `app-connect` records an explicit local attachment, `app-snapshot-preview` reports capability/quality badges and a no-write receipt, `app-snapshot` captures a confirmed redacted Accessibility snapshot into memory, and the frontmost-selection helper captures intentionally selected text once while restoring the prior clipboard. If the preview is blocked or low-signal, select the relevant app text and use `scripts/capture_frontmost_selection.sh`. If macOS asks for Accessibility permission, approve Terminal/Codex for this local capture workflow and rerun the command.

Transcript file deltas:

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

Use transcript sources for local tools that already write session logs. SYNAPSE-S2 stores the file path hash, tails only new bytes after registration by default, caps each poll, redacts common secret shapes, and writes captured deltas as real event graph memory.

Hand pruning:

```bash
.venv/bin/python synapse_cli.py --json graph --context default --limit 30 \
  --response-mode compact --max-response-bytes 12288
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

The default topology should report `within_target_envelope: true` for the 96-384 MiB Mac-optimized target and a quick-pruning result with `within_60ms_budget: true`. Independently, core admission requires the exact steady float32 topology to fit the 384 MiB ceiling before MLX load or array materialization/resize, and raw query/register vectors must match the configured dimension before journaling. Certification additionally checks MLX availability, `mx.compile`, `mlxsnn`, active `mlxsnn.Leaky` execution path, local embedding provider provenance, and any requested GPU/envelope gates. These are steady-array and implementation-level runtime signals, not an external Instruments measurement of peak residency, a guarantee for every target Mac, or timing proof beyond the measured quick-prune run.

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
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 5 \
  --response-mode full --max-response-bytes 131072
```

The benchmark should report `embedding_provider.provider: mlx-neural-v1`, `model_id: mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`, and `native_mlx: true`. First run may include model download or cache load cost; warm in-process runs should show the steady-state embedding latency. The memory entry metadata should carry the same neural provider provenance. For deterministic no-model fallback, set `--embedding-provider semantic-hash`; for an IT-managed local encoder, set `--embedding-provider python:/absolute/path/encoder.py:embed` or `SYNAPSE_S2_EMBEDDING_PROVIDER` to the same value.

Audit capture-ledger authority before backup:

```bash
.venv/bin/python synapse_cli.py --json capture-ledger-integrity
```

Proceed only when the result is `ready`, `verification_passed` is true, and the
missing, mismatch, and blocked counts are zero. If the audit reports a bounded
legacy cohort with `repairable: true`, review the samples and exact revision,
then run the separately confirmed repair and repeat the read-only audit:

```bash
.venv/bin/python synapse_cli.py --json capture-ledger-integrity \
  --repair --confirm \
  --expected-revision '<audit_revision>'
.venv/bin/python synapse_cli.py --json capture-ledger-integrity
```

This repair does not replay capture text or graph effects and does not synthesize
a capture receipt or context-delivery acknowledgement. It projects the canonical
request fingerprint from the surviving redacted payload, uses the durable
conversation-capture deployment timestamp for historical completion, and writes
only missing compact ledger rows plus one content-free maintenance receipt after
a verified safety backup. Any stale revision or ambiguous/modern-v2 loss fails
closed.

Create the recovery point only after that gate is ready:

```bash
.venv/bin/python synapse_cli.py --json backup-recovery \
  --purpose manual \
  --pinned
```

The authoritative core chooses the capture root and retention directory from
its reviewed binding. Do not pass `--capture-root`,
`--allow-noncanonical-capture-root`, or retention `--directory` on the core
lane; they are retained only for explicitly offline local-v5 maintenance.
Omitting `--output` selects a unique server-owned destination. Client-selected
bundle, receipt, and isolated-restore paths must be absolute and remain confined
to the configured backup or recovery roots.

Recovery destinations are exclusive: existing files are never replaced. A
successful result binds and verifies four artifacts—the SQLite snapshot, its
signed receipt, the exactly-once capture archive, and the signed bundle receipt.
`cutover_ready: true` means the signed reconciliation found no replay-required
transport debt and independent verification reproduced the processed-request
ledger binding. Review `capture_ledger_binding.verified`,
`verified_capture_count`, and `revision`; matching IDs/counts without that proof
do not qualify. `backup-memory` remains a database-only diagnostic and is not a
complete recovery point.

Before relying on a recovery point, run both read-only verification and an
isolated restore drill:

```bash
.venv/bin/python synapse_cli.py --json verify-recovery \
  --receipt "/absolute/path/returned/by/backup-recovery.bundle.receipt.json"
.venv/bin/python synapse_cli.py --json restore-recovery-proof \
  --receipt "/absolute/path/returned/by/backup-recovery.bundle.receipt.json" \
  --output-root "$PWD/.synapse_s2/recovery/manual-proof-$(date +%Y%m%d-%H%M%S)" \
  --confirm
```

The restore proof must reproduce the same content-free
`capture_ledger_binding` count/revision returned by `verify-recovery`; raw
request fingerprints, metadata, and archive paths are never exposed in it.

When the bundle came from another Mac or signer, independently review and pass
the digest for every included artifact. In addition to
`--expected-database-sha256` and `--expected-capture-sha256`, governed bundles
require `--expected-request-journal-sha256`, and any bundle carrying runtime
state requires `--expected-runtime-state-sha256`. A foreign-signed bundle with
even one missing pin is not verification- or restore-eligible. Verification
binds the exact bundle receipt plus its dependent database, capture,
journal-binding, and runtime receipt identities through materialization; a
receipt or artifact swap fails before the output root is created. A fully
pinned foreign governed bundle is supported and must reverify its restored
journal binding and runtime state.

To retire old verified bundles, first persist a signed exact-inventory plan,
review every protected/retiring disposition, and then apply that same plan with
confirmation:

```bash
.venv/bin/python synapse_cli.py --json recovery-retention-plan \
  --keep-latest 7 --max-age-days 30
.venv/bin/python synapse_cli.py --json recovery-retention-apply \
  --plan-token "<plan_token>" \
  --cutoff-created-at "<cutoff_created_at>" \
  --keep-latest 7 --max-age-days 30 --confirm
```

Apply only moves complete bundles into private same-filesystem quarantine. It
never deletes them, so it does not reclaim disk space. Reverse a committed plan
with `recovery-retention-restore --plan-token <plan_token> --confirm`. Isolated
restore proof never overwrites live state; do not improvise a live cutover while
independent writers are running.

Proposal lifecycle smoke:

```bash
.venv/bin/python synapse_cli.py --json quick-prune
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep
```

The deep-sleep response should include `phase_count: 7` and phase names for connection weight decay, synaptic clustering, semantic merging, threshold rescoring, trace promotion, relationship extraction, and neurogenesis.

## Local Dashboard

Install or refresh the loopback adapter, then launch it through the authenticated
helper:

```bash
scripts/install_dashboard_agent.sh
.venv/bin/python scripts/open_dashboard.py
```

Never open the bare loopback URL. `open_dashboard.py` validates the owner-only
`dashboard-auth.json` (`0600` inside a `0700` directory), consumes its rotating
bootstrap without putting it in argv, and opens the browser. The bootstrap sets
the port-specific HttpOnly, SameSite=Strict cookie and carries the distinct
`X-Synapse-Dashboard-Session` capability in a redirect fragment. The browser
stores the latter only in port-scoped `sessionStorage`, scrubs the fragment, and
sends both on every API GET/POST; POST additionally needs exact Host and Origin.
The auth file has the header capability but no cookie secret.

The server admits eight active handlers behind backlog 32, applies an absolute
one-second deadline for complete request headers, uses five-second post-header
I/O timeouts, and bounds shutdown. The dashboard shows runtime status, context
enablement, topology resource envelope, durable trace capture, conversation
capture, App Connect local app detection/attachment/snapshot capture, event
ingestion, Cortex Governor enter/tick/commit/close plus promote/demote/prune
controls, memory graph edges, context deployments, guarded graph pruning,
recall results, quick-pruning, deep-sleep, and backup controls. Its loopback HTTP
API intentionally keeps the rich graph and visualization payloads; installed
MCP compact budgets do not reduce browser data. The installer health check and
the fixed-port-free smoke below authenticate through the same cookie-plus-header
contract:

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
  --intended-file mlx_backend.py \
  --intended-file web/app.js \
  --intended-tool "python -m unittest discover -s tests -v" \
  --mutation-intent \
  --confidence 0.65
.venv/bin/python synapse_cli.py --json commit-cortex \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --type validation \
  --truth-posture test-validated \
  --text "The governed session path entered, ticked, and committed a typed validation trace." \
  --evidence '{"tests":["runbook cortex path"],"test_command":"synapse_cli.py enter-cortex && cortex-tick && commit-cortex && close-cortex"}'
.venv/bin/python synapse_cli.py --json close-cortex \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --reason "runbook-smoke-complete"
.venv/bin/python synapse_cli.py --json cortex-state --context default \
  --agent-id codex-desktop \
  --response-mode compact --max-response-bytes 12288
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
| `retrieve_spiking_memory_v2` | Deterministically recalls bounded memory through the configured local provider without recurrent/STDP/pruning/runtime-state mutation; returns explicit scope/link provenance, completeness, and uncalibrated ranking semantics. |
| `query_spiking_attention_text` | Deprecated stateful compatibility query; it may mutate recurrent runtime state and must not be used as read-only recall. |
| `ingest_spiking_memory_text` | Segments a long briefing into event memories and relationship edges. |
| `capture_spiking_conversation` | Captures real operator/agent session notes into event memory. |
| `drop_spiking_capture_inbox` | Drops opt-in session notes for the always-on local sidecar. |
| `get_spiking_capture_inbox_status` | Shows pending and processed capture inbox counts. |
| `process_spiking_capture_inbox` | Manually processes pending capture inbox files; requires `confirm=true`. |
| `preflight_spiking_capture_error_resolution` | Returns content-free terminal, historical, unsafe, and unresolved error counts plus a revision-bound confirmation token. |
| `resolve_spiking_capture_errors` | Archives only the reviewed terminal/historical artifacts; requires the matching token, reason, scope, and `confirm=true`. |
| `list_spiking_memory` | Lists persisted records through the compact response contract by default; compact mode rejects vector/index arrays and `full` is explicit. |
| `list_spiking_memory_graph` | Lists compact nodes and graph relationships with endpoint, provenance, completeness, and omission metadata. |
| `prune_spiking_memory` | Removes a node, relationship edge, deployment event, or relationship mode. |
| `pull_spiking_context_deployments` | Pulls context-bus events published by GUI and MCP write actions. |
| `ack_spiking_context_deployments` | Atomically acknowledges exact receipt ids after their deployments were consumed. |
| `dead_letter_spiking_context_delivery` | Quarantines a retry-exhausted delivery with explicit confirmation, reason, and audit receipt. |
| `list_spiking_context_cursors` | Lists per-agent delivery cursors and pending deployment counts. |
| `hydrate_spiking_agent_context` | Leases a bounded compact deployment contract with one visible event per receipt, prompt recall, and graph highlights; acknowledgement is a separate exact-receipt call. |
| `enter_spiking_cortex` | Starts a governed agent session with recall and policy. |
| `tick_spiking_cortex` | Checks the current observation, proposed action, intended files, intended tools, mutation, confidence, and sensitive-data scope before acting. |
| `close_spiking_cortex` | Ends an active governed session after validation or handoff and publishes a lifecycle event. |
| `commit_spiking_cortical_trace` | Persists typed validation, decision, constraint, risk, or implementation memory with evidence. |
| `moderate_spiking_cortical_trace` | Promotes, demotes, or prunes a governed trace by memory id. |
| `get_spiking_cortex_state` | Shows active governed sessions and typed cortical memory through the compact response contract by default. |
| `profile_spiking_resources` | Shows topology footprint and optional quick-pruning benchmark. |
| `certify_spiking_runtime` | Emits native MLX/mlxsnn/provider/envelope certification evidence. |
| `backup_spiking_memory` | Writes a segregated SQLite-only diagnostic snapshot; not a complete recovery point. |
| `audit_capture_ledger_integrity` | Audits processed capture.v2 evidence against authoritative SQLite ledger bindings without mutation. |
| `repair_capture_ledger_integrity` | Applies only a reviewed, revision-bound legacy ledger projection; never replays graph effects or synthesizes transport receipts. |
| `backup_spiking_recovery` | Creates and verifies a signed paired SQLite plus exactly-once capture recovery point. |
| `verify_spiking_recovery` | Reverifies all four bound artifacts and the signed reconciliation. |
| `restore_spiking_recovery_proof` | Materializes an isolated restore proof without touching live state. |
| `plan_spiking_recovery_retention` | Persists a signed, expiring, exact-inventory retention plan. |
| `apply_spiking_recovery_retention` | Reversibly quarantines the exact planned stale bundles after confirmation. |
| `restore_retired_spiking_recovery` | Restores a quarantined plan and reverifies every bundle. |
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
| `.synapse_s2/capture_error_archive` | Private governed archive of reviewed terminal or sanitized historical error evidence. |
| `.synapse_s2/capture_error_resolutions` | Private crash-recoverable manifests for capture-error archival operations. |
| `.synapse_s2/capture-daemon.log` | Capture sidecar stderr/stdout log. |
| `.synapse_s2/backups/verified` | Signed paired recovery bundles eligible for verification and isolated restore proof. |
| `.synapse_s2/backups/database-only` | SQLite-only diagnostic snapshots; never substitute these for paired recovery. |
| `.synapse_s2/backups/retired` | Reversible per-plan quarantine; no automatic purge or disk reclamation. |
| `.synapse_s2/backups/retention-plans` | Signed expiring exact-inventory retention plans. |
| `.synapse_s2/backups/retirement-journals` | Signed prepared/completed/recovered/restore receipts for crash recovery and idempotency. |
| `/Users/dan.driver/.local/bin/synapse-s2-mcp` | Launcher used by Codex, FastMCP, and inspector tools. |
