# **SYNAPSE-S2: Spiking STDP Transformer MCP Server**

SYNAPSE-S2 (Synaptic Plasticity & Spiking Encoding via S2) is an Apple Silicon-optimized Model Context Protocol (MCP) server. It provides local large language models (LLMs) with high-efficiency, associative memory capabilities using a persistent, biologically grounded Spiking Neural Network (SNN) substrate.

Traditional transformer self-attention forms a dense token-token score matrix for every layer and attention head, so the attention logits and probabilities scale as `O(N^2)` in sequence length `N`. SYNAPSE-S2 does not materialize that per-request all-pairs attention matrix during recall. It projects local embeddings into sparse spike sets, runs bounded recurrent Leaky Integrate-and-Fire (LIF) dynamics, and stores learned co-activation structure in durable sparse spike, surface-term, relationship, and synaptic indexes. The practical scaling shift is from dense request-time self-attention memory to sparse spike propagation plus indexed local memory lookup. SYNAPSE-S2 still has a configurable topology resource envelope, so the precise claim is that it avoids the transformer attention-matrix memory wall rather than making every internal structure sub-quadratic in every parameter.

### Math Note: What Replaces the `O(N^2)` Attention Wall

In standard scaled dot-product self-attention, an input sequence `X` with shape `N x d` is projected into query, key, and value matrices:

```math
Q = XW_Q,\quad K = XW_K,\quad V = XW_V
```

Each token compares against every other token:

```math
S = \frac{QK^\top}{\sqrt{d_k}},\quad A = \mathrm{softmax}(S),\quad Y = AV
```

Because `S` and `A` are both `N x N`, their memory footprint is `Theta(N^2)` per head before counting values, activations, caches, or batching. Doubling the usable context length roughly quadruples the attention-matrix storage. That is the self-attention memory wall.

SYNAPSE-S2 uses a different runtime object. Text is embedded locally, converted to sparse sensory spikes, and propagated through a recurrent substrate:

```math
z = \mathrm{embed}(\text{text}),\quad s_0 = \mathrm{TopK}(\mathrm{zscore}(z), k)
```

```math
x_t = s_{\text{in}}W_{\text{syn}}\gamma_{\text{syn}} + s_tW_{\text{lat}}\gamma_{\text{lat}}
```

```math
\tilde{u}_{t+1} = \beta u_t + x_t,\quad
s_{t+1} = H(\tilde{u}_{t+1} - V_{\text{thr}}),\quad
u_{t+1} = \tilde{u}_{t+1} - s_{t+1}V_{\text{thr}}
```

Temporal co-activation changes durable relationship strength through STDP:

```math
\Delta W_{\text{lat}} =
A_+e^{-1/\tau_+}s_t s_{t+1}^{\top}
-
A_-e^{-1/\tau_-}s_{t+1}s_t^{\top}
```

```math
W_{\text{lat}} \leftarrow \mathrm{clip}(W_{\text{lat}} + \Delta W_{\text{lat}}, -c, c)
```

At inference time, active spike operations are dominated by additions, threshold comparisons, decay, and sparse/indexed retrieval rather than dense query-key matrix multiplication over all token pairs. The implementation still uses MLX arrays and scalar multiplications for decay, weighting, and setup where appropriate; "multiplication-free" should be read as the neuromorphic recall path avoiding dense per-token dot-product attention, not as a claim that no numeric multiplication exists anywhere in the codebase. The STDP equation above is the implemented one-step discrete update: previous spikes potentiate current spikes, current spikes depress the reverse direction, and lateral weights are clipped to a configured envelope.

## **Operational Quickstart**

This repository now includes one authoritative local core, a SQLite-backed persistent memory store, runtime toggle controls, and lightweight CLI, MCP, dashboard, and capture adapters. The core alone owns the neural arrays, runtime state, durable writes, recovery lane, and embedded capture worker. Installed MCP client definitions carry only the path to an owner-only core binding and never fall back to a second local backend after schema v6 is claimed. That binding pins the reviewed layout, private canonical CoreConfig path and digest, exact candidate configuration fingerprint, embedding-space identity, authority mode, and private socket path. Candidate publication writes and rereads the `0600` canonical config before atomically publishing the binding; a missing, malformed, or drifted config makes every bound client fail closed.
Text recall inside the core is routed through a pluggable local embedding provider. The production provider is `mlx-neural-v1`, backed by the local MLX model `mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ` at immutable revision `6c3ae70858513f1a78e9cdca3cae330d9075cd2a`; it runs on the Apple GPU through `mlx-lm`, stores weights under `.synapse_s2/models`, requires the pinned snapshot to be available locally, and emits provider provenance on every text memory. The authoritative-core installer publishes that closed neural contract by default. `semantic-hash-v1` remains available only through an explicit provider override for offline v5 maintenance and tests.

### 1. Install Runtime Dependencies

```bash
brew install uv
uv sync
scripts/install_core_agent.sh status
```

First cutover is deliberately separate from everyday setup. While the database
is still local-v5, publish the reviewed candidate binding and install the
lightweight launcher/client configs:

```bash
scripts/install_core_agent.sh publish-binding
scripts/install_local_launcher.sh
.venv/bin/python scripts/install_client_configs.py
```

Before producing final evidence, process and reconcile capture debt, gracefully
close every persistent MCP wrapper and wait for its `finish()` writes, pause the
exact automations or LaunchAgents that can relaunch those wrappers, let the
capture worker drain, stop the exact legacy writer labels/PIDs, and prove the
zero-writer inventory. Keep all respawners paused through accepted core health;
if any client returns, drain again and discard the old evidence. Then certify
that exact candidate:

```bash
.venv/bin/python synapse_cli.py --json capture-inbox-status
.venv/bin/python synapse_cli.py --json capture-inbox-process --confirm
.venv/bin/python synapse_cli.py --json capture-inbox-status
scripts/core_cutover_preflight.sh --inventory-only --require-quiescent
.venv/bin/python scripts/operator_readiness_certify.py \
  --json \
  --context default \
  --agent-id codex-desktop \
  --expect-embedding-provider mlx-neural
```

The certifier runs every live functional probe first, performs a bounded inbox
drain, then acquires exclusive core authority and the existing global capture
lock. Backup, signed verification, isolated restore, and the final
process/LaunchAgent inventory occur in-process under that one guard. The guard,
temporary restore, store, and lease must unwind cleanly before the optional ZIP
is built and `manifest.json` is atomically published last. The shared 21-proof
contract rejects missing, duplicate, optional-shadow, or non-ready proof rows.
The shared quiescence policy also requires
`com.master-mold.imprint.inboxworker` to be both absent and positively disabled;
a temporarily empty process list is insufficient. No recovery CLI child may
reopen local authority during the guarded phase, and child probes receive only
a minimal credential-free environment.

Deployment status is never inferred from repository implementation, tests, or
documentation. Run `scripts/install_core_agent.sh status` and require
`healthy`, `runtime_healthy`, `production_ready`, `capture_ready`, and
`client_binding.ready` to be true, `provisional` to be false, and
`deployment_mode` to be `authoritative`. Use the explicit backup, quiescence,
attestation, install, and stabilized-health procedure below for every cutover.

The evidence manifest embeds `synapse-s2.core-config-evidence.v1`, including the
same configuration fingerprint the installer will require. Treat it as
immediately perishable and proceed directly through the final quiescence gate
and install. The installer publishes the `authoritative-core-v6` binding only after
stable authenticated health and capture readiness; confirm
`client_binding.ready: true` in `scripts/install_core_agent.sh status`. A v6
replacement keeps the existing authoritative binding—`publish-binding` is only
for a pre-adoption v5 store. The full procedure and failure semantics are in
`docs/AUTHORITATIVE_CORE_OPERATIONS.md`.

The launcher installs `$HOME/.local/bin/synapse-s2-mcp`. It exists because a checked-out workspace path may contain spaces or punctuation that can break tools which split command strings or PATH entries. The launcher executes the synced virtual environment directly:

```bash
"$HOME/.local/bin/synapse-s2-mcp"
```

The launcher enters through `mcp_client_wrapper.py`, which hydrates recall and graph state at MCP process startup without claiming or acknowledging context-bus events that the host has not seen, enters a strict Cortex Governor session for that client, and drops a sanitized session-boundary note into `.synapse_s2/capture_inbox` when the client disconnects. The same exit path also commits a typed `follow_up` cortical trace so the client lifecycle is visible in governed memory, not only the inbox. If a host kills the wrapper before that exit path runs, the authoritative core's post-authority embedded-capture loop observes the exact process-ownership tuple after capture work. It marks only an active `mcp-client` Cortex session orphaned after at least two consecutive definite-missing probes and a 15-second confirmation window; a live or indeterminate owner, ownership change, terminal session, or non-MCP session is left untouched. A late valid wrapper finish still supersedes an orphan transition. Content-free health counters expose successful reaps and maintenance errors without returning session identifiers. `scripts/install_client_configs.py` stamps distinct delivery identities for Codex, Claude Desktop, Claude Code, and the project `.mcp.json` manifest so one client cannot consume another client's exact-target deployments. Project `.mcp.json` is intentionally generated per host and ignored by Git; `.mcp.json.example` is the tracked, path-free instruction document. Certification proves the generated definition is converged through the installer dry-run instead of binding a source commit to one user's home directory.

When `synapse_cli.py` is executed directly without `--memory-db` or `--state`,
it auto-discovers the installed owner-only core binding before considering a
host application's project directory or the shell working directory. This
keeps hydration and capture on the authoritative store even when the command
is launched from another repository. Explicit `--memory-db` or `--state`
remains the reviewed offline/local-store lane.

### 2. Verify the Local Engine

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python synapse_cli.py --json doctor --context default
.venv/bin/python synapse_cli.py --json \
  --embedding-provider mlx-neural \
  provider-benchmark \
  --text "SYNAPSE-S2 neural embedding benchmark" \
  --runs 3
.venv/bin/python synapse_cli.py --json certify-runtime \
  --strict-native \
  --benchmark-quick-prune \
  --require-resource-envelope
```

For the Monday operator-trust certification path, run:

```bash
.venv/bin/python scripts/operator_readiness_certify.py \
  --context default \
  --agent-id codex-desktop \
  --expect-embedding-provider mlx-neural
```

This writes a single evidence pack under `.synapse_s2/evidence_packs/` proving client config, MCP launcher connection, the installed compact MCP contract and its two independently bounded output channels, native MLX neural embeddings, Doctor, Start Work, real memory write and recall, App Connect no-write preview, Wrap Session persistence, and dashboard render smoke. The command exits non-zero unless every required proof is ready.

For the full verification path after the core is already healthy, run:

```bash
scripts/prep_tomorrow.sh
```

To explicitly install the core, supply the fresh evidence manifest; the prep
script never claims a production store implicitly:

```bash
scripts/prep_tomorrow.sh --apply \
  --install-core /absolute/path/to/manifest.json
```

For a no-install/no-ingest audit pass first:

```bash
scripts/prep_tomorrow.sh --verify-only
```

The detailed operator runbook is in `docs/TOMORROW_RUNBOOK.md`.
The single-pack readiness certification runbook is in `docs/OPERATOR_READINESS_CERTIFICATION.md`.
The strict proposal coverage matrix is in `docs/PROPOSAL_COMPLIANCE.md`.
The production gap audit is in `docs/PRODUCTION_GAP_AUDIT.md`.
The point-in-time live status report is in `docs/CURRENT_STATUS.md`.
The bounded source-backed primary-abstraction and cue-anchor contract is in
`docs/HARMONIC_MEMORY.md`.
The durable idempotency, crash-recovery, and rollout contract for capture
producers is in `docs/EXACTLY_ONCE_CAPTURE.md`.
The bounded installed-client response profiles, receipt-safety invariants, and
the reproducible measurement acceptance gate are in `docs/TOKEN_CONTRACTS.md`.
The Retrieval v2 ranker, authenticated continuation, scope/provenance, and
synthetic validation contract is in `docs/RETRIEVAL_V2_VALIDATION.md`. Its
sanitized acceptance artifact is
`docs/evidence/phase8-retrieval-v2-acceptance.json`, bound to clean commit
`738cfce`; it records Recall@k 1.0, MRR 1.0, nDCG@k 0.99951846, zero namespace
leakage, deterministic output, and unchanged measured read state. This remains
a fixed synthetic regression gate, not a live-corpus relevance or latency SLO.
The proposal/review/CAS lifecycle, actor binding, expiry and revocation rules,
audit non-repair semantics, namespace catalog, and safe operator procedure for
connected recall are in `docs/BRIDGE_GOVERNANCE.md`.
The authoritative-core-only, offline multi-Mac checkpoint protocol, anti-TOFU
pairing flow, private replication inbox, isolated restore proof, and signed ACK
procedure are in `docs/MULTI_MAC_REPLICATION.md`.
The sanitized Phase 6 acceptance artifact is
`docs/evidence/phase6-token-contract-acceptance.json`: it passed all 11
correctness gates against a verified isolated recovery restore, with an
informational 96.818% installed-policy byte reduction and 78.03% same-source
projection reduction. Those two measurements are deliberately separate and do
not replace the correctness gates.
Regenerate `docs/CURRENT_STATUS.md` before demos, handoffs, or readiness claims:

```bash
.venv/bin/python scripts/synapse_status_report.py \
  --context default \
  --agent-id codex-desktop
```

### Daily Operator Trust Loop

The loopback dashboard now has a single operator workflow for first-use and handoff confidence: the saved memory namespace selector, Start Work, Context Health, Doctor/Repair, Memory Hygiene, Goal Ledger, App Preview receipts, Recall Pin, Recipes, and Wrap Session. The same loop is available from the CLI:

```bash
.venv/bin/python synapse_cli.py --json start-work \
  --context default \
  --agent-id codex-desktop \
  --prompt "Prepare SYNAPSE-S2 for today's operator work."
# start-work is observation-only. To claim durable deployments for use:
.venv/bin/python synapse_cli.py --json agent-brief \
  --mode morning \
  --context default \
  --agent-id codex-desktop \
  --prompt "Prepare SYNAPSE-S2 for today's operator work." \
  --response-mode compact \
  --max-response-bytes 12288
# After consuming every rendered deployment, ACK its exact receipt (repeat as needed):
.venv/bin/python synapse_cli.py --json ack-context \
  --context default \
  --agent-id codex-desktop \
  --receipt-id '<receipt_id from agent-brief>'
.venv/bin/python synapse_cli.py --json goal.create \
  --context default \
  --agent-id codex-desktop \
  --title "Prepare SYNAPSE-S2 for Monday operator use" \
  --owner operator \
  --goal-state in_progress \
  --next-action "Run Start Work, Doctor, App Preview, Recall Pin, and Wrap Session."
.venv/bin/python synapse_cli.py --json goal.list --context default
.venv/bin/python synapse_cli.py --json context-health --context default
.venv/bin/python synapse_cli.py --json memory-hygiene --context default --limit 25
.venv/bin/python synapse_cli.py --json doctor --context default --include-apps --repair-plan
.venv/bin/python synapse_cli.py --json wrap-session \
  --context default \
  --agent-id codex-desktop \
  --source-tag codex-session \
  --text "Session decisions, validation evidence, and follow-up constraints." \
  --preview
```

Use `wrap-session --confirm` only after the preview receipt matches the facts you intend to preserve.

### Hardened Local Operating Contract

- Dashboard HTTP is a strictly loopback-only operator API. Non-loopback binds are refused; use an authenticated, separately reviewed gateway if remote access is ever required.
- Capture inbox drops are redacted before they are written to disk; inbox, processed, error, backup, export, and SQLite files are kept private to the local user where the filesystem permits it.
- Redaction is recursive across nested metadata and response payloads. Credential-shaped CLI/API identifiers are rejected without reflection, raw-content digest fields are removed before persistence, and public errors expose only sanitized categories.
- Capture processing rejects symlink payloads and over-large payloads instead of following arbitrary files.
- Capture commits are exactly-once by `capture_id`: the memory/event/relationship write and capture-operation ledger commit in one transaction, while durable receipt files make post-commit cleanup crash-recoverable.
- Terminal discard evidence and sanitized historical capture errors remain visible until an operator reviews a content-free preflight and confirms archival. Use `capture-error-preflight` and `capture-error-resolve --confirm`; unsafe or raw-retaining artifacts are never auto-archived.
- Direct conversation capture, context-bus deployments, graph metadata, and returned API/MCP payloads use the same redaction path, so sanitized storage does not mask a raw response leak.
- Versioned startup hygiene re-runs stronger detection rules against legacy durable content. Secret-derived memory nodes and their retrieval artifacts are pruned; repairable event/metadata fields are transactionally sanitized; only count-only maintenance receipts are retained.
- MCP memory and Cortex pruning require explicit `confirm=true`; CLI memory and Cortex pruning require `--confirm`; the dashboard requires a confirmation control before destructive graph operations and governed-trace deletion.
- `test-validated` Cortex traces require concrete validation evidence such as a test command, test list, output summary, artifact path, commit, or verification report. Dashboard typed-memory defaults stay at `observed` evidence.
- Spike recall and surface-text recall both use durable SQLite indexes (`memory_spikes` and `memory_surface_terms`) maintained on every memory write, so recall does not need to scan the full memory table as the graph grows.
- Client config installation refuses malformed existing JSON instead of silently overwriting it.
- Existing client configs receive private, exclusive, collision-proof backups before atomic replacement. The local MCP bridge starts in a compact control-plane mode and defers dense neural state until a neural tool is actually requested.
- Installed MCP clients default to the versioned `compact` response profile with an exact 12,288-byte post-redaction UTF-8 ceiling for authoritative `structuredContent` on memory lists, memory graphs, agent hydration, and Cortex state. MCP emits one separate safety `TextContent` item bounded to 4,096 bytes in compact mode; full-mode safety text is separately bounded to 131,072 bytes. Outer JSON-RPC framing is excluded. Each envelope reports provenance, completeness, pagination support, serialized bytes, and counted omissions; `response_mode="full"` is an explicit bounded diagnostic escape hatch.
- CLI `agent-brief`, `list-memory`, `graph`, and `cortex-state` use the same compact contract by default. They accept `--response-mode full --max-response-bytes <4096..131072>` for bounded diagnostics and `--response-mode legacy` only for known local compatibility consumers.
- Compact projection never drops a leased receipt or its matching visible event. If a hydration projection cannot be delivered safely, its leases are released and acknowledgement remains a separate exact-receipt operation.
- Critical/high, action-required, and protected contract warnings survive compact projection. Noncritical warnings may be omitted only as complete items with a truthful omission count. MCP consumers must treat `structuredContent` as authoritative; the bounded text item is only a safety decision aid.
- The reproducible Phase 6 acceptance artifact passed all 11 gates on the four surfaces contracted at that phase. It records 1,200,724 legacy installed-policy bytes versus 38,205 compact structured bytes (96.818% reduction), and 106,735 identical-source legacy bytes versus 23,450 compact structured bytes (78.03% reduction). These are informational byte measurements from a verified isolated restore; token counts and transport framing are excluded. The later `memory-retrieval` surface has its own synthetic-only validation method and is not retroactively included in those percentages.
- The loopback dashboard keeps its rich browser API and Namespace Galaxy payloads; the installed MCP token ceiling does not reduce the operator visualization.
- Dashboard API reads and writes require two independent browser capabilities: a port-specific HttpOnly, SameSite=Strict cookie and `X-Synapse-Dashboard-Session`. The owner-only rotating bootstrap issues both without storing the cookie secret in its `0600` auth file; the browser keeps the header capability only in port-scoped `sessionStorage` and removes it from the redirect fragment before normal navigation. POST additionally requires the exact configured `Host` and same-origin `Origin`.
- LaunchAgent installers fence concurrent installs, publish private/fsynced plists, wait for launchd unload/start transitions, probe the authoritative service, and restore the prior definition and policy when a health gate fails. The core plist carries the non-secret build identity plus the exact closed `CoreConfig.mlx_device` as `MLX_DEVICE`, so a reviewed CPU/GPU/default selection survives launchd startup.
- A governed v6 process remains writable only while its exact owner-only `authority.lock` inode, database inode, durable authority epoch, and full closed authority marker still match the claim it made at startup. On macOS, durable lock identity v2 uses inode plus filesystem birth time instead of the reboot-volatile mount device number; held-versus-visible fencing still compares the live device and inode on every check. A legacy v1 marker can advance to v2 only during a signed build-replacement admission that binds both generations, the same inode and birth time, fresh paired recovery, isolated restore, delivery state, and the unchanged root/store/journal/runtime identities. Any arbitrary lock replacement or v2 drift fails closed. The marker also binds configuration, build/protocol, root generation, store and request-journal identities, embedding space, restored-target lineage, and timestamps; replacement or mutation poisons the service and closes its listener instead of permitting fallback.
- Governed `runtime_state.json` is version 3 and binds the exact canonical durable-marker digest, epoch number, and lock generation. Version 2 remains accepted only as pre-governed v5 input and recovery compatibility; it is not accepted as the live state for an already governed v6 store. The SQLite claim carries a bound pending publication receipt; after exact JSON publication, the receipt becomes complete. A crash in between is recoverable only by an unbound successor on the same lock generation with every marker/config/build/protocol/path identity unchanged. This remains two separately durable commits—not a cross-filesystem atomic transaction.
- A failed first adoption may archive a request journal only when the memory store is exactly ungoverned v5 and unchanged, the journal has the exact current schema/store binding, and it contains zero request rows. Canonical main/WAL evidence is sealed and verified through an isolated copy before same-directory archival. Rollback/unknown transients, nonempty rows, malformed schema, identity drift, or orphan residue fail closed; pending/complete/retiring receipts make renames and bounded eight-set retention crash-resumable. Installer preflight and direct service startup use the same repair primitive and exact pre/post store inspection.
- The private socket admits at most 32 active request workers behind a backlog of 64 and gives a connection one second to present its peer identity, authenticated request, and complete bounded frame; authenticated socket I/O then has a five-second timeout. The dashboard separately admits at most eight active handlers behind backlog 32, enforces an absolute one-second deadline for complete request headers, switches to five-second post-header I/O, and bounds shutdown. Both services close admission before bounded drains.
- Neural embedding, retrieval, trace, capture, Cortex, and consolidation operations share a 120-second client/service deadline floor derived from measured native execution, while ordinary control-plane RPCs retain the 30-second stall fence. Core worker and capture threads enter an MLX thread-local stream context before touching arrays. Dashboard Memory Hygiene reads stable 50-entry cursor pages without serializing relationship edges, scans at most the latest 250 entries per request, and reports exact scan coverage instead of implying a complete-store audit.
- Deterministic acknowledgement, release, or dead-letter requests that provably commit no delivery change finish as terminal journal rows with `invalid_request`; credential-shaped delivery identifiers are rejected before journal admission. Failures whose commit state is genuinely uncertain remain `outcome_unknown` and are never replayed. Terminal rows age out, so accepted-row capacity is not consumed by deterministic rejects, but the total retained-row ceiling still makes sustained throughput finite until retention pruning runs.
- Raw `register_trace` and `query` embeddings must have exactly the configured dimension before journal admission. The exact steady float32 dense topology—sensory matrix, lateral matrix, membrane, spike, and active-trace arrays—must fit 384 MiB before MLX model loading, array materialization, or sensory resize. This is an admission calculation, not proof of peak process residency, target hardware behavior, or execution time.

### 3. Write and Query Persistent Memory

```bash
.venv/bin/python synapse_cli.py --json remember-text \
  --context default \
  --tag production-memory-contract \
  --text "SYNAPSE-S2 stores durable local memory in the shared .synapse_s2 SQLite substrate. Codex, Claude Desktop, Claude Code, the CLI, the dashboard, and direct FastMCP launches use the same local launcher and memory database."
.venv/bin/python synapse_cli.py --json ingest-text \
  --context default \
  --tag production-preflight-brief \
  --text "The SYNAPSE-S2 backend imports mlx.core and mlxsnn on Apple Silicon. The recurrent LIF backend uses z-score top-k spike coding, immutable MLX state updates, STDP relationship updates, quick-pruning maintenance, and deep-sleep consolidation. The context bus stores durable deployment events that connected local clients pull with fenced receipts, acknowledge exactly after consumption, and track through derived delivery cursors." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1
.venv/bin/python synapse_cli.py --json retrieve-v2 \
  --context default \
  --prompt "Which clients share the SYNAPSE-S2 memory database and launcher?" \
  --scope local --result-limit 10 --candidate-limit 64 \
  --response-mode compact --max-response-bytes 12288
.venv/bin/python synapse_cli.py --json graph --context default --limit 10 \
  --response-mode compact --max-response-bytes 12288
```

Expected Retrieval v2 output is a `synapse-s2.token-contract.v1` `memory-retrieval` envelope containing ranked registered traces such as `production-memory-contract` and linked event traces from `production-preflight-brief`. The read does not run the recurrent network, apply STDP or pruning, update runtime state, mark activity, or populate the legacy query cache. It fingerprints the redacted prompt without storing or returning the raw prompt.
Event ingestion additionally creates segmented memories such as `production-preflight-brief-event-001` and relationship edges such as `temporal_next` and `semantic_overlap`. Event boundaries are driven by the configured local embedding provider's cosine-distance surprise when available, while retaining lexical surprise as an auditable fallback.

The dashboard also recognizes typed reference neurons. Store a concise, non-secret
description or locator and set `metadata.context_memory_type` to `image`, `audio`,
or `file`; Namespace Galaxy and Memory Graph render those types with distinct
colors and shapes, alongside context, app, temporal, ordinary-memory, and unknown
neurons. This deliberately stores a searchable reference, not the binary payload:

```bash
.venv/bin/python synapse_cli.py --json remember-text \
  --context default --tag media-reference \
  --text "Image reference: rack elevation showing switch and patch-panel labels." \
  --metadata '{"context_memory_type":"image","display_label":"Rack elevation"}'
.venv/bin/python synapse_cli.py --json remember-text \
  --context default --tag media-reference \
  --text "Audio reference: operator intercom check recorded for commissioning review." \
  --metadata '{"context_memory_type":"audio","display_label":"Intercom check"}'
.venv/bin/python synapse_cli.py --json remember-text \
  --context default --tag file-reference \
  --text "File reference: approved commissioning checklist in the project workspace." \
  --metadata '{"context_memory_type":"file","display_label":"Commissioning checklist"}'
```

Do not place credentials, private keys, or sensitive file contents in these
descriptions. The graph legend is always visible, so color is never the only type
indicator.

For a real local image, use the dashboard Image memory picker or the bound CLI:

```bash
.venv/bin/python synapse_cli.py --json capture-image \
  --context default \
  --path /absolute/path/to/rack-elevation.jpg \
  --label "Rack elevation" \
  --description "Approved rack elevation showing switch and patch-panel placement." \
  --confirm
.venv/bin/python synapse_cli.py --json image-cache-audit
```

Apple Vision enrichment is optional and off by default. Feature prints support
image-to-image similarity only; they are not captions or text-to-image search.
OCR may be inaccurate and may expose text visible in the image, so selecting OCR
is explicit consent to store its redacted output as a searchable cue:

```bash
.venv/bin/python synapse_cli.py --json capture-image \
  --context default \
  --path /absolute/path/to/rack-elevation.jpg \
  --label "Rack elevation" \
  --description "Approved rack elevation." \
  --vision-enrichment all \
  --require-vision-enrichment \
  --confirm
```

Omit `--require-vision-enrichment` to let an unavailable local helper produce a
visible optional/unavailable receipt while the baseline image capture succeeds.
The short-lived native helper analyzes a derivative with a maximum edge of 2048
pixels. Learned feature-print bytes remain owner-only in the node-local media
cache; durable memory stores only the versioned provider/revision/type/count
reference plus redacted OCR when requested. Neither thumbnail nor feature-print
bytes is currently included in paired recovery or multi-Mac replication.

The original file is decoded transiently, remains untouched at its source path,
and is never copied into SYNAPSE-S2 or SQLite. CLI capture accepts an absolute
owner-readable PNG, JPEG, or HEIC path up to 20 MB; the dashboard accepts PNG or
JPEG and downsamples in the browser. The verified binding data root receives only an owner-only JPEG thumbnail
with a maximum edge of 320 pixels and a private integrity manifest; the durable
typed memory receives the searchable
description plus a bounded numeric RGB tensor, color histogram, edge histogram,
and difference bits. Visual descriptors are kept separate from the deployed text
embedding space. The thumbnail cache is local and non-authoritative: it is not yet
included in paired recovery or multi-Mac replication, while the description and
descriptor metadata are durable memory. Browser thumbnail reads require the same
dual dashboard authorization as every other `/api/*` read.

Real memory is stored locally in `.synapse_s2/memory.sqlite3`, and governed runtime toggles and session state live in the version-3 `.synapse_s2/runtime_state.json`. Installed MCP definitions and `$HOME/.codex/config.toml` carry only `SYNAPSE_S2_CORE_BINDING`; the owner-only binding loads and verifies the exact canonical core config before a candidate-v5 maintenance process starts or an authoritative-v6 client connects. It does not grant adapters an independent database, state, export, backup, capture, replication, or neural configuration. Authoritative exports, recovery paths, and the private replication inbox are published explicitly by the binding and constrained by the reviewed server layout; explicit local paths remain available only on the pre-governed offline maintenance lane.
Each text memory stores `metadata.embedding_provider` provenance including provider id, provider type, model id, local-only status, semantic flag, dimensions, vector hash, and neural runtime fields when applicable (`native_mlx`, `pooling`, `source_dimensions`). Set `--embedding-provider semantic-hash` for the deterministic no-model fallback, `--embedding-provider lexical-hash` for exact legacy behavior, or `--embedding-provider python:/absolute/path/encoder.py:embed` to use a local callable that returns a vector or `{ "vector": [...], "model_id": "...", "semantic": true }`.
Each event memory also stores `metadata.surprise_model`, `metadata.surprise_mode`, `metadata.semantic_surprise_score`, and `metadata.lexical_surprise_score`, so operators can tell whether a boundary was cut by semantic embedding distance or by lexical fallback.
SQLite maintains a durable sparse spike index and a durable surface-term index for prompt recall. The surface index is built from tags, display labels, display summaries, semantic facets, detail badges, keywords, and bounded source text, and existing memory databases are backfilled automatically on startup.
Compound entry/index/event writes use explicit SQLite transactions with `FULL` synchronous durability by default. Set `SYNAPSE_S2_SQLITE_DURABILITY=balanced` only when measured throughput is more important than retaining the latest committed transaction through sudden power loss.

Inspect and export the memory store:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context default --limit 20 \
  --response-mode compact --max-response-bytes 12288
.venv/bin/python synapse_cli.py --json export-memory \
  --context default \
  --output .synapse_s2/default-memory-export.json
```

Exports publish through a private same-directory temporary file and atomic
rename. Paired recovery points are integrity-checked, fsynced, Ed25519-signed,
and published without overwriting existing paths. They bind SQLite to the
exactly-once capture transport and expose signed replay reconciliation plus a
separate `cutover_ready` decision. Verification re-canonicalizes every archived
processed v2 request against the snapshot ledger and returns a content-free
`capture_ledger_binding` count/revision proof; an isolated restore derives the
same proof again from the restored files and database. `backup-memory` is retained as a segregated
database-only diagnostic; it is not sufficient for recovery.

Before creating a paired recovery point, prove that every processed
`capture.v2` record is bound to the authoritative SQLite capture ledger:

```bash
.venv/bin/python synapse_cli.py --json capture-ledger-integrity
```

`status: "ready"`, `verification_passed: true`, and zero missing, blocked, or
mismatched records are required. A paired backup runs this authority gate again
before publishing any bundle artifacts. If a read-only audit reports a bounded
historical cutover cohort as `repairable`, review its finding samples and retain
the exact `audit_revision`, then make the separate confirmed repair and re-audit:

```bash
.venv/bin/python synapse_cli.py --json capture-ledger-integrity \
  --repair --confirm \
  --expected-revision '<audit_revision>'
.venv/bin/python synapse_cli.py --json capture-ledger-integrity
```

After the fresh audit is ready, create the complete recovery point:

```bash
.venv/bin/python synapse_cli.py --json backup-recovery \
  --purpose operator \
  --pinned
```

Paired backup, verification, isolated restore, capture-ledger recovery, signed
retention, and replication checkpoint create/stage use a closed authenticated
recovery-maintenance lane with a one-hour deadline. Ordinary memory and bridge
operations retain the five-minute protocol ceiling. While this lane is active,
authenticated health reports `operational_state: "maintenance"`,
`accepting_ordinary_operations: false`, a fixed `backend_lane.owner`, and
`deadline_remaining_ms`; let the operation finish. A lost mutation response is
still `outcome_unknown`: preserve its caller/request ID, reconcile it with
`request-status`, and never blind-retry. The longer execution budget does not
extend recovery-evidence freshness, signed retention-plan expiry, bridge
proposal expiry, or any cutover/admission ticket.

On the authoritative lane, the service injects the capture root and retention
directory from the reviewed binding. Public recovery calls therefore reject
`--capture-root`, `--allow-noncanonical-capture-root`, and retention
`--directory`; those flags remain only for explicitly offline local-v5
maintenance. Omitting `--output` selects a unique server-owned destination.
Caller-selected backup, receipt, and isolated-restore paths must be absolute and
are still constrained to the configured backup or recovery roots.

A bundle signed by a different SYNAPSE-S2 installation is never trusted merely
because its internal signature is self-consistent. Cross-machine verification
requires independently reviewed SHA-256 values for every artifact present:
database, capture archive, request journal when governed, and runtime state when
included. Pass the runtime pin with `--expected-runtime-state-sha256`; omitting
any required pin fails before restore materialization, so enablement and context
policy cannot be substituted behind otherwise reviewed database/capture bytes.
For a foreign governed bundle, the database restore sink accepts its
cryptographically valid paired journal binding only when the independently
reviewed request-journal digest also matches that binding. The exact verified
bundle receipt and every dependent database, journal-binding, capture, and
runtime receipt identity remain bound through materialization; a receipt swap
or artifact change fails before output creation. A foreign governed restore is
supported only when all four present artifacts are independently pinned and
those bound identities reverify.

This governed legacy reconciliation does not replay a processed capture, create
memory/relationship/deployment graph effects, or synthesize a capture transport
receipt or context-delivery acknowledgement. It projects the canonical request
fingerprint from the surviving redacted processed payload and uses the already
durable conversation-capture deployment timestamp as the historical commit
time. Only the missing compact ledger rows and one content-free maintenance
receipt are written, after a verified safety backup. Stale revisions, modern-v2
ledger loss, ambiguous deployment ownership, changed evidence, or incomplete
graph bindings fail closed and require evidence repair or a verified restore.
`cutover_ready: true` additionally requires a verified capture-ledger binding
proof; matching capture IDs or reconciliation counts alone are not sufficient.

Retention is a signed two-step contract. Planning is read-only and binds the
exact identity of every protected and retiring artifact; applying requires the
same policy, the unexpired plan token, and explicit confirmation. Apply moves
whole verified bundles by atomic rename into a private same-filesystem
quarantine. It never deletes them, and the matching restore command is
idempotent:

```bash
.venv/bin/python synapse_cli.py --json recovery-retention-plan \
  --keep-latest 7 --max-age-days 30
.venv/bin/python synapse_cli.py --json recovery-retention-apply \
  --plan-token "<plan_token>" \
  --cutoff-created-at "<cutoff_created_at>" \
  --keep-latest 7 --max-age-days 30 --confirm
.venv/bin/python synapse_cli.py --json recovery-retention-restore \
  --plan-token "<plan_token>" --confirm
```

Quarantine is deliberately reversible and does not reclaim disk space. There is
no purge command. Restore proof is isolated and never overwrites the live store;
a live cutover must be performed later through a separately quiesced,
authoritative service workflow.

Audit derived recall indexes before relying on Doctor or after any interrupted,
disk-full, or legacy write. Audit mode opens the existing database read-only,
does not apply schema migrations, and returns a content-bound `audit_revision`:

```bash
.venv/bin/python synapse_cli.py --json memory-integrity --context default
```

If the report is `degraded` and `repairable` is true, review its mismatch
samples and pass that exact revision into the confirmed repair:

```bash
.venv/bin/python synapse_cli.py --json memory-integrity \
  --context default \
  --repair \
  --confirm \
  --expected-revision '<audit_revision>'
```

Repair refuses stale plans and malformed canonical source data. Before changing
an index it drains cooperating dashboard, capture, MCP, and CLI writers; verifies
enough free-space headroom; creates a private, SHA-256 recorded SQLite safety
snapshot; and verifies `quick_check` and foreign keys. It then repairs only
affected rows (including missing derived-index schema) in one bounded writer
transaction, bumps the durable semantic-index generation so every process cache
invalidates, writes a target-digested maintenance receipt, and performs a full
post-repair audit. If planning, backup, or commit fails, the transaction rolls
back and the unused attempt backup is removed.

Dashboard Quick Doctor completes ordinary readiness checks without implicitly
starting the global semantic-index scan. The separate Deep integrity scan
button starts that all-namespace audit in a background worker; Quick Doctor then
reports its bounded pending or age-stamped cached state. A lock-free health
pulse keeps the header and last good Namespace Galaxy responsive while the
governed maintenance lane is occupied. The CLI Doctor waits for a current
authoritative audit.

Connected MCP processes hydrate recall and graph state on startup, but deliberately leave context events unclaimed until an agent-facing pull or hydrate response can carry the receipt. To lease the current FIFO briefing manually:

```bash
.venv/bin/python synapse_cli.py --json agent-brief \
  --context default \
  --agent-id codex-desktop \
  --prompt "Summarize the current SYNAPSE-S2 work and next implementation gap." \
  --response-mode compact \
  --max-response-bytes 12288
```

`agent-brief` composes a leased FIFO event batch, text recall, and graph summary into one agent-ready briefing. It never acknowledges before stdout or transport delivery: after the briefing is successfully consumed, acknowledge each returned `receipt_id`. `agent-brief --mode morning` returns the operator Start Work structure; the dashboard acknowledges its receipts only after rendering succeeds. Delivery is target-isolated and at-least-once, with a stable `delivery_id` for consumer deduplication and a new fenced receipt on each expired retry. An ACK, release, or dead-letter request that deterministically changed nothing is recorded as terminal `failed` / `invalid_request`; only an uncertain commit remains `outcome_unknown`, and neither is automatically replayed. Credential-shaped delivery identities fail before request-journal admission. Use the lower-level commands when diagnosing delivery state directly:

The CLI command above and installed MCP `hydrate_spiking_agent_context` calls
return `synapse-s2.token-contract.v1` in `compact` mode by default. Compact
hydration preserves one visible deployment for every leased receipt and reports
`ack_required`, `has_more`, retry/dead-letter blockers, provenance, and any
projection omissions. MCP callers can pass `response_mode="full"` and
`max_response_bytes`; CLI callers use `--response-mode full` and
`--max-response-bytes`. CLI `--response-mode legacy` exists only for known local
compatibility consumers. See `docs/TOKEN_CONTRACTS.md` for the exact contract.

```bash
.venv/bin/python synapse_cli.py --json observe-context --context default --since-event-id 0 --order asc --limit 10
.venv/bin/python synapse_cli.py --json pull-context --context default --agent-id codex-desktop --consumer-instance-id terminal-review --limit 10
.venv/bin/python synapse_cli.py --json ack-context --context default --agent-id codex-desktop --receipt-id '<receipt_id>'
.venv/bin/python synapse_cli.py --json release-context --context default --agent-id codex-desktop --consumer-instance-id terminal-review --receipt-id '<receipt_id>'
.venv/bin/python synapse_cli.py --json list-context-cursors --context default
```

The raw `observe-context` ledger is read-only and FIFO by default. It cannot create a receipt or advance a cursor. Legacy high-watermark acknowledgements are rejected; only an opaque receipt belonging to the configured context and agent can advance the receipt-verified contiguous cursor. Existing pre-v2 cursor rows remain explicitly unverified and are not imported as proof of consumption, so retained events replay safely instead of preserving a potentially skipped backlog.

Run a governed agent session when you want SYNAPSE-S2 to act as a live cognitive control plane instead of passive recall only:

```bash
SESSION_ID=$(.venv/bin/python synapse_cli.py --json enter-cortex \
  --context default \
  --agent-id codex-desktop \
  --task "Implement the next SYNAPSE-S2 change with verification before mutation." \
  --mode strict | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
.venv/bin/python synapse_cli.py --json cortex-tick \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --observation "About to edit backend and dashboard files." \
  --proposed-action "Patch code, run focused tests, then run full validation." \
  --intended-file mlx_backend.py \
  --intended-file web/app.js \
  --intended-tool "python -m unittest discover -s tests -v" \
  --mutation-intent \
  --confidence 0.62
.venv/bin/python synapse_cli.py --json commit-cortex \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --type validation \
  --truth-posture test-validated \
  --text "Focused and full validation passed for the governed change." \
  --evidence '{"tests":["unittest discover"],"surface":"cli"}'
.venv/bin/python synapse_cli.py --json close-cortex \
  --context default \
  --agent-id codex-desktop \
  --session-id "$SESSION_ID" \
  --reason "validated-and-wrapped"
.venv/bin/python synapse_cli.py --json cortex-state --context default \
  --agent-id codex-desktop \
  --response-mode compact --max-response-bytes 12288
```

The Cortex Governor state is also included in `agent-brief`, MCP hydration, and the dashboard snapshot. It is intentionally typed: `goal`, `objective`, `decision`, `constraint`, `implementation`, `validation`, `risk`, `correction`, and `follow_up` traces carry truth posture, confidence, evidence, agent id, and session id. Each governor tick can also declare intended files and tools; SYNAPSE-S2 persists that scope, warns on undeclared mutations, sensitive paths, and high-impact tool use, and surfaces active goals, assumptions, contradictions, suggested next move, and capture queue in Cortex state. Use `goal.create`, `goal.update`, and `goal.list` to track lightweight operational goals with owner, state, evidence, and next action; MCP clients use `create_spiking_goal`, `update_spiking_goal`, and `list_spiking_goals` for the same ledger. Close the session after verified traces or Wrap Session handoff are captured so the dashboard returns to an explicit idle state instead of leaving stale active sessions. Runtime state persistence now merges cross-process Cortex session closures, so a long-running dashboard or capture daemon cannot resurrect a session that a fresh CLI/MCP process already closed.

Capture real operator/Codex conversation notes into the event graph:

```bash
.venv/bin/python synapse_cli.py --json capture-session \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "User asked for future conversation details to appear in the event relationship graph. Codex added durable session capture plus surgical memory pruning. Operators can remove sensitive, wrong, or partial-truth graph data by node, edge, deployment event, or relationship mode."
```

Conversation capture automatically builds a local context namespace for the active topic or feature. Prefixes such as `Thread:`, `Feature:`, `Topic:`, `Goal:`, `Objective:`, and `Event:` become typed graph nodes, while the original conversation events receive the same `context_namespace` metadata and are linked back to the namespace anchor with `namespace_contains` edges. This is what makes new topics, current features, objectives, and temporal session details visibly grow in the relationship visualizer.

For the always-on "magic" capture lane, run the launchd sidecar and drop session payloads into the local inbox. This is still opt-in and local: clients, hooks, or operators write a payload, then the sidecar redacts common secret shapes and ingests it into the same real graph used by MCP, CLI, and the dashboard.

```bash
scripts/install_capture_daemon.sh
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "Capture a concise factual session note here."
.venv/bin/python synapse_cli.py --json capture-inbox-status
.venv/bin/python synapse_cli.py --json capture-inbox-process --confirm
.venv/bin/python synapse_cli.py --json graph --context default --limit 30 \
  --response-mode compact --max-response-bytes 12288
```

Manual inbox processing is confirmation-gated. The launchd sidecar can process its own local queue continuously, but CLI and MCP one-shot processing require `--confirm` / `confirm=true`, and the dashboard Magic Capture button performs a preflight with a short-lived confirmation token before committing pending files.

Every new producer should use capture protocol `capture.v2`: create one
`s2cap_<32 lowercase hex>` ID before its first attempt and reuse that ID only
when retrying the exact same redacted request. The SQLite capture ledger is the
source of truth; filenames, paths, timestamps, and raw-input hashes are never
capture identity. See `docs/EXACTLY_ONCE_CAPTURE.md` before deploying or rolling
back capture producers and the sidecar.

App Connect gives operators a local attach path for already-running apps. It detects attachable local apps through a fast filtered process-list scan, records a confirmed attachment, and can capture either intentionally selected text or a redacted Accessibility snapshot into the same temporal event graph and context bus. Dashboard app attach and snapshot actions use preflight confirmation tokens bound to the selected app/connection so a stale click cannot silently retarget capture. This is a hardened local connector, not a remote control plane.

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

Preview before snapshot is the trust step: it reports a quality badge, signal character count, line count, redaction count, and recommended next action without writing memory. If the badge is blocked or low-signal, select the relevant visible text in that app and run the frontmost-selection helper. The helper copies the selection once, calls `capture-clipboard`, restores the prior clipboard, and exits.

Local transcript files can also be registered as bounded delta sources for clients or tools that write their own logs:

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

Hand-prune bad or sensitive memory from the same durable store:

```bash
.venv/bin/python synapse_cli.py --json graph --context default --limit 30 \
  --response-mode compact --max-response-bytes 12288
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

For a known disposable namespace, first create a pinned signed recovery point,
then use the authoritative-only batch helper. Preview is read-only and returns a
revision; commit re-inventories the same targets and refuses if that revision,
delivery leases, pending proposals, or active bridges changed:

```bash
.venv/bin/python synapse_cli.py --json backup-recovery \
  --purpose operator-namespace-cleanup --pinned
.venv/bin/python scripts/purge_namespaces.py preview \
  --context demo --context codex-ui-validation
.venv/bin/python scripts/purge_namespaces.py commit \
  --context demo --context codex-ui-validation \
  --reason "Remove reviewed disposable UI validation namespaces." \
  --expected-revision "<revision-from-preview>" \
  --confirm
```

The helper refuses `default`, `global`, cataloged namespaces, active bridges,
pending proposals, and delivery leases. Mutations always pass through the
authoritative core; an owner-bound read-only metadata probe detects catalog rows
because this release cannot archive them. The helper suppresses per-target audit
events that would recreate an emptied namespace, writes a sanitized start audit
in `default` before deletion, verifies disappearance, then writes a completion
audit. Because the supported prune primitives are per item, the batch reports
that it is not atomic; if transport returns `outcome_unknown`, reconcile the
supplied request ID before any retry.

### 4. Toggle Runtime Behavior

```bash
.venv/bin/python synapse_cli.py --json disable --context default
.venv/bin/python synapse_cli.py --json status --context default
.venv/bin/python synapse_cli.py --json enable --context default
.venv/bin/python synapse_cli.py --json retrieve-v2 --context default \
  --prompt "anything" --scope local --response-mode compact
```

The enable switch governs the stateful recurrent/spiking execution path. Use status to verify the toggle and Retrieval v2 for ordinary recall. Retrieval v2 is deliberately read-only; it does not use a recall request as an opportunity to mutate the recurrent substrate.

### 5. MCP Tool Surface

The MCP server exposes these tools:

| Tool | Purpose |
| :--- | :--- |
| `retrieve_spiking_memory_v2` | Deterministic, structured, read-only text retrieval through the configured local provider, with explicit namespace scope, provenance, completeness, and uncalibrated score semantics. This is the recall tool for new integrations. |
| `query_spiking_attention` | Deprecated stateful dense-vector query. It may update recurrent runtime state; do not use it for read-only recall. |
| `query_spiking_attention_text` | Deprecated stateful text query. It may update recurrent runtime state; use `retrieve_spiking_memory_v2` instead. |
| `remember_spiking_context` | Persist a named context trace from text and/or an embedding. |
| `set_spiking_attention_enabled` | Enable or disable SYNAPSE-S2 globally or per context id. |
| `get_spiking_attention_status` | Report health, dependency state, memory counts, and toggle state. |
| `list_spiking_memory` | List persisted SQLite memory through the compact contract by default; `full` is explicit and compact mode rejects vector/index arrays. |
| `ingest_spiking_memory_text` | Segment long text into event memories and persist graph relationships. |
| `capture_spiking_conversation` | Capture real operator/agent conversation notes as temporal event memories. |
| `drop_spiking_capture_inbox` | Drop opt-in session text into the local capture inbox sidecar. |
| `get_spiking_capture_inbox_status` | Show pending, processed, and failed inbox file counts. |
| `process_spiking_capture_inbox` | Process pending inbox drops into the real memory graph; requires `confirm=true`. |
| `register_spiking_transcript_source` | Register a confirmed local transcript/log file for bounded delta capture. |
| `list_spiking_transcript_sources` | List registered local transcript sources. |
| `poll_spiking_transcript_sources` | Poll registered transcript deltas into temporal event memory. |
| `capture_spiking_clipboard` | Capture intentionally selected/copied text as a one-shot redacted memory payload. |
| `list_spiking_running_apps` | Detect locally visible foreground apps for App Connect. |
| `connect_spiking_app` | Attach a confirmed local app connection for snapshot/selection capture. |
| `list_spiking_app_connections` | List App Connect attachments. |
| `capture_spiking_app_snapshot` | Capture a confirmed redacted local app Accessibility snapshot into memory. |
| `list_spiking_memory_graph` | List compact memory nodes and relationship edges with endpoint resolution, provenance, completeness, and omission metadata. |
| `list_spiking_namespace_map` | List the bounded namespace catalog, active governed links, pending proposals, and read-only bridge suggestions for the Neural Galaxy. |
| `propose_spiking_namespace_link` | Create an isolated pending bridge proposal with evidence and expiry; it does not expand recall. |
| `reject_spiking_namespace_link` | CAS-reject the exact pending proposal revision; the MCP surface cannot approve a bridge or expand recall. |
| `list_spiking_namespace_link_history` | Inspect bounded append-only bridge-governance history by proposal or durable link id. |
| `audit_spiking_namespace_link_governance` | Read-only integrity audit across governance projections, receipts, and durable link rows. |
| `get_spiking_replication_identity` | Read this authoritative core's signed offline-replication identity; it cannot pair a peer or mutate state. |
| `get_spiking_replication_status` | Read bounded peer/checkpoint/ACK status; all replication mutations remain operator-CLI only. |
| `prune_spiking_memory` | Remove one memory node, relationship edge, context deployment event, or relationship mode. |
| `pull_spiking_context_deployments` | Pull durable context-bus events published by GUI and MCP write actions. |
| `ack_spiking_context_deployments` | Atomically acknowledge exact receipt ids after their deployments were consumed. |
| `dead_letter_spiking_context_delivery` | Quarantine a retry-exhausted delivery with a reason, explicit confirmation, and durable governance audit. |
| `list_spiking_context_cursors` | List per-agent delivery cursors and pending deployment counts. |
| `hydrate_spiking_agent_context` | Lease a bounded agent-ready contract with one visible event per receipt, prompt recall, and graph highlights; acknowledge returned receipts separately after use. |
| `enter_spiking_cortex` | Start a governed agent session with policy, recall, and a context-bus deployment. |
| `tick_spiking_cortex` | Evaluate the current observation, proposed action, intended files, and intended tools against governed memory before proceeding. |
| `close_spiking_cortex` | End an active governed session after validation or handoff and publish a `cortex-closed` lifecycle event. |
| `commit_spiking_cortical_trace` | Persist a typed governed trace with truth posture, confidence, and evidence. |
| `moderate_spiking_cortical_trace` | Promote, demote, or prune a governed trace from MCP clients by memory id. |
| `get_spiking_cortex_state` | Inspect active governed sessions and typed cortical memory through the compact contract by default. |
| `create_spiking_goal` | Create an auditable goal-ledger trace with owner, state, evidence, and next action. |
| `update_spiking_goal` | Append a state update to an existing goal-ledger trace. |
| `list_spiking_goals` | List current goal-ledger state for a context. |
| `benchmark_spiking_embedding_provider` | Benchmark the configured local embedding provider and return latency plus provenance. |
| `profile_spiking_resources` | Report actual topology array memory estimates and optional quick-pruning timing. |
| `certify_spiking_runtime` | Emit native runtime certification evidence for MLX, mlxsnn, envelope, provider, and quick-prune checks. |
| `export_spiking_memory` | Export persisted memory entries as JSON, optionally to a local file. |
| `backup_spiking_memory` | Create a segregated SQLite-only diagnostic snapshot. |
| `audit_capture_ledger_integrity` | Read-only audit of processed capture.v2 evidence against authoritative SQLite ledger bindings. |
| `repair_capture_ledger_integrity` | Apply a reviewed, revision-bound legacy ledger reconciliation without replaying graph effects or synthesizing transport receipts. |
| `backup_spiking_recovery` | Create and immediately verify a signed paired database plus capture recovery point. |
| `verify_spiking_recovery` | Reverify all four bound recovery artifacts and signed replay reconciliation. |
| `restore_spiking_recovery_proof` | Materialize an isolated paired restore proof without touching live state. |
| `plan_spiking_recovery_retention` | Produce and persist a signed, expiring, exact-inventory retention plan. |
| `apply_spiking_recovery_retention` | Atomically quarantine only the exact planned stale bundles; requires confirmation. |
| `restore_retired_spiking_recovery` | Reversibly restore quarantined bundle sets and reverify them; requires confirmation. |
| `trigger_sleep_consolidation` | Run deep-sleep consolidation and semantic hierarchy extraction. |
| `trigger_idle_maintenance` | Run due maintenance or force idle deep-sleep consolidation. |

FastMCP smoke check:

```bash
.venv/bin/fastmcp list --command "$HOME/.local/bin/synapse-s2-mcp" --json --timeout 15
.venv/bin/fastmcp call --command "$HOME/.local/bin/synapse-s2-mcp" \
  --target get_spiking_attention_status \
  --input-json '{"context_id":"default"}' \
  --json --timeout 15
```

Project `.mcp.json`, `$HOME/.codex/config.toml`, Claude Desktop, and Claude Code can be refreshed with:

```bash
scripts/install_client_configs.py
```

The installer preserves existing client settings, writes timestamped backups before mutating existing JSON/TOML files, and points every bound client at `$HOME/.local/bin/synapse-s2-mcp` with only the owner-only `SYNAPSE_S2_CORE_BINDING` route. The generated project `.mcp.json` remains untracked and is still covered by the transactional publication journal plus the certification dry-run. The installer also assigns per-client `SYNAPSE_S2_CLIENT_AGENT_ID` values: `codex-desktop`, `claude-desktop`, `claude-code`, and `project-mcp`, and stamps `SYNAPSE_S2_CLIENT_CORTEX=1` with `SYNAPSE_S2_CLIENT_CORTEX_MODE=strict`. Restart Codex, Claude Desktop, and Claude Code after running it so each client reloads its MCP server registry and starts using the startup/Cortex/session-boundary bridge.

### 6. Maintenance Lifecycle

Quick-pruning is configured for the proposal's five-minute interval (`300` seconds) and automatically runs from the live query/register path when due. It is also available as an explicit operator command:

```bash
.venv/bin/python synapse_cli.py --json quick-prune
```

Resource profiling reports the steady float32 topology footprint represented by `W_syn`, `W_lateral`, membrane state, spike state, and active traces. Before the authoritative core loads MLX or materializes/resizes those arrays, it requires that exact calculation to fit the 384 MiB ceiling; raw `register_trace` and `query` vectors must also match the configured dimension before journal admission. With the default 1,024 x 8,192 topology the calculation is near 288 MiB. This is a deterministic steady-array admission bound, not an Instruments measurement of peak process residency, proof for every Apple Silicon SKU, or an execution-time guarantee.

```bash
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune
.venv/bin/python synapse_cli.py --json preflight --require-resource-envelope
.venv/bin/python synapse_cli.py --json certify-runtime \
  --strict-native \
  --benchmark-quick-prune \
  --require-resource-envelope \
  --output .synapse_s2/native-certification.json
```

Idle deep-sleep consolidation is available from MCP and CLI:

```bash
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep
.venv/bin/python synapse_cli.py --json sleep
```

Deep sleep returns all seven proposal lifecycle phases: connection weight decay, synaptic clustering, semantic merging, threshold rescoring, trace promotion, relationship extraction, and neurogenesis.

### 7. Local Control Dashboard

The dashboard is a loopback-only, bounded threaded adapter for the same authoritative core used by MCP and the CLI. It admits at most eight active handlers behind backlog 32, requires complete request headers inside an absolute one-second pre-authentication deadline, uses five-second post-header I/O timeouts, and performs bounded shutdown. It exposes live status, a saved memory namespace selector populated from live contexts, one core enable switch, the Daily Operator Trust Loop, Start Work briefs, Context Health, Memory Quality, Goal Ledger, Doctor/Repair reports, Memory Hygiene actions, operation receipts, Wrap Session preview/commit, Recipes, resource envelope profiling, native certification, durable trace capture, conversation and image capture, App Connect capability badges plus tokenized preview/snapshot capture, tokenized magic capture inbox processing, event ingestion, Cortex Governor enter/tick/commit/close plus promote/demote/prune controls, Recall evidence actions and Recall Pin, graph memory inspection, surgical graph pruning, recall, quick-pruning, deep-sleep, and signed paired recovery points. A hidden far-right Impact control opens content-free recall/yield/bridge/graph/latency/resource analytics plus an editable `$0`-to-upper-bound cost what-if; it is explicitly not provider billing or proven savings. Current coverage is one all-namespace local aggregate of dashboard `/api/query` only—not MCP, CLI, or agent hydration—and approximate tokens are response UTF-8 bytes divided by four. Reported recall latency covers backend retrieval, not full HTTP delivery. Its rich local HTTP payloads are intentionally separate from the installed MCP compact-response projector, so the 12,288-byte agent budget does not remove graph or drill-down evidence from the browser.

### Connected namespace recall and neural galaxy

The namespace selector remains the precise control surface, while the Neural Galaxy provides a navigable overview of every live namespace. Namespace bodies scale with stored memory volume; approved typed links form durable bridges; and suggested bridges stay visually distinct until an operator explicitly approves them. A click on a namespace body loads that namespace through the same saved-context path as the sidebar selector and enters its read-only internal cortex.

The internal view uses semantic level of detail rather than decorative particles. The outer cortex shows deterministic ganglia derived from stored typed namespaces and relationships; zooming or selecting a ganglion reveals its bounded memory neurons and real relationship edges. Breadcrumbs, browser history, Back/Escape, keyboard controls, and an equivalent DOM list move between `all namespaces -> cortex -> ganglion -> neuron inspection`. The server re-redacts legacy display text, emits only bounded allowlisted summaries and provenance, strictly scopes every row to the selected context, and reports sampling/truncation whenever the complete graph is larger than the response limit. This drill-down never writes, copies, links, or mutates memory.

The dashboard reads that projection from `GET /api/namespace-detail` with `context_id`, `level=cortex|ganglion|neurons`, optional `cluster_id`, and a bounded `limit`. Stable IDs and ordering make an unchanged namespace render consistently across refreshes.

Recall always declares one of three scopes:

- `local` (default) reads the selected namespace plus memories explicitly stored in the inherited `global` context.
- `connected` adds directly connected, enabled namespaces to the local/global set and retains source/link provenance on every recalled trace.
- `all` deliberately searches all namespaces plus global memory. It is never selected implicitly.

Retrieval v2 fuses the durable spike-overlap index, durable surface/facet index, and an optional bounded set of same-context graph neighbors with versioned weights, then applies bounded MMR/Jaccard diversity selection. Every result carries stable memory identity, source provenance, scope provenance, and—when it crossed a namespace boundary—the exact approved one-hop link that authorized it. Scores are deterministic ranking signals, not confidence estimates, truth probabilities, or biological firing rates. The response reports candidate, scope, term, and result truncation independently; ranked retrieval itself is one bounded snapshot read and does not advertise a continuation cursor.

The full validation contract, cursor behavior, benchmark method, and non-claims are documented in [`docs/RETRIEVAL_V2_VALIDATION.md`](docs/RETRIEVAL_V2_VALIDATION.md).
The production bridge lifecycle, authenticated actor semantics, supported
surfaces, audit behavior, and containment runbook are documented in
[`docs/BRIDGE_GOVERNANCE.md`](docs/BRIDGE_GOVERNANCE.md).

Connected recall is a bounded read operation. Similarity suggestions combine density-normalized Dice with a conservative multi-overlap sparse-to-dense containment lift so a focused namespace is not drowned out by a much larger one. Suggestions never copy or write durable memories into another namespace, and links require explicit confirmation. Phase-delay values are presentation metadata used only for bridge styling and inspection in the galaxy, not a claim that the SQLite memory store runs a validated biological synchronization model.

The supplied proposal cited S2-Net, Spike Dice Attention (SDA), and Spiking Graph Transformer Networks (SGTN) as May-July 2026 publications. Those citations were future-dated relative to the design evidence supplied to this repository and have not been independently verified as implementation evidence for SYNAPSE-S2. No S2-Net phase-delay engine, SDA spike-train attention operator, or SGTN training/inference model is implemented or validated here. The galaxy and bridge suggestions are operator-governed product features built from durable indexes, typed links, deterministic scoring, and explicit provenance—not a claim of experimentally established biological synchronization.

Install or refresh the local adapter, then open it only through the authenticated
helper:

```bash
scripts/install_dashboard_agent.sh
.venv/bin/python scripts/open_dashboard.py
```

This opens the authenticated dashboard as a Chrome app window by default. Use
`--browser-tab` only when a conventional authenticated browser tab is preferred.

Do not open a bare loopback URL. The helper reads the rotating bootstrap from
the owner-only `dashboard-auth.json` (`0600` inside a `0700` directory) without
placing it in argv. Bootstrap sets the port-specific HttpOnly,
SameSite=Strict cookie and redirects with a distinct
`X-Synapse-Dashboard-Session` capability in the fragment. The browser stores
that header capability only in port-scoped `sessionStorage`, scrubs the
fragment, and sends both capabilities on every API GET and POST; POST also
requires the exact `Host` and same-origin `Origin`. The auth file never contains
the cookie secret. Installer and smoke probes authenticate through this same
contract.

For non-interactive readiness checks:

```bash
.venv/bin/python scripts/smoke_dashboard.py default
```

For a complete operator-trust evidence pack:

```bash
.venv/bin/python scripts/operator_readiness_certify.py \
  --context default \
  --agent-id codex-desktop \
  --expect-embedding-provider mlx-neural
```

## **System Architecture**

Lightweight adapters communicate with local editor interfaces and LLM desktop
wrappers over JSON-RPC 2.0 stdio, then route all governed state and neural work
to the single authenticated authoritative core over its owner-only Unix socket.

```mermaid
flowchart TB
  Client["LLM client<br/>Codex + Claude"]
  MCP["MCP bridge<br/>stdio JSON-RPC"]
  Core["Authoritative core<br/>authenticated Unix socket"]
  Embedding["Embedding<br/>MLX / hash"]
  Cortex["Cortex<br/>policy gate"]
  Memory["Spiking core<br/>LIF + STDP"]
  Store["Memory DB<br/>SQLite indexes"]
  Dashboard["Dashboard<br/>operator loop"]

  Client -->|"tools"| MCP
  MCP -->|"bounded request"| Core
  Core -->|"embed"| Embedding
  Embedding -->|"spikes"| Memory
  Core -->|"govern"| Cortex
  Cortex -->|"traces"| Store
  Memory -->|"evidence"| Store
  Dashboard -->|"bounded action"| Core
  Core -->|"receipts"| Store
```

The diagram labels are intentionally compact so hosted Mermaid renderers do not clip them. The full path is: local clients call the lightweight FastMCP bridge over stdio; the bridge authenticates to the sole authoritative core; text is embedded through the binding-selected local provider; the spiking core runs recurrent LIF/STDP; confirmed operator actions and receipts are surfaced through the loopback dashboard; durable memory lands in SQLite entries, spike indexes, surface terms, and relationships. An installed adapter never opens an independent governed backend.

## **Hierarchical Neural Network Topology**

The SNN is organized into a multi-tiered hierarchical network designed to route, associate, and gate conceptual activations dynamically.

```mermaid
flowchart TB
  Input["Input<br/>text / app / session"]
  Embed["Embedding<br/>z vector"]
  TopK["Layer 1<br/>Top-k spikes"]
  LIF["Layer 2<br/>Recurrent LIF"]
  STDP["STDP<br/>weight update"]
  Graph["Layer 3<br/>memory graph"]
  Recall["Recall<br/>context injection"]

  Input --> Embed --> TopK --> LIF --> STDP --> Graph --> Recall
  Graph -. "index" .-> LIF
```

Layer 1 computes z-score top-`k` sensory spikes. Layer 2 projects those spikes through `W_syn`, adds lateral current from `W_lateral`, emits thresholded spikes, and subtracts `V_thr` after firing. STDP updates the lateral matrix from previous/current spike co-activation, while durable recall also uses `memory_spikes`, `memory_surface_terms`, and relationship rows in SQLite.

## **Core Mathematical Formulation**

### **1. Dimension-Independent Population Coding**

Dense embeddings `E` are mapped into binary spike states `S_i in {0, 1}` using coordinate-wise standardized z-scores. This keeps the sensory coding stable even when the upstream embedding provider changes dimensionality:

```math
Z_i = \frac{E_i - \mu_E}{\sigma_E}
```

```math
S_i =
\begin{cases}
1 & \text{if } i \in \mathrm{argTopK}(Z,k) \\
0 & \text{otherwise}
\end{cases}
```

### **2. Leaky Integrate-and-Fire (LIF) Dynamics**

The recurrent cycle first builds total current from the sensory projection plus lateral recurrence:

```math
X_t = S_{\text{in}}W_{\text{syn}}\gamma_{\text{syn}} + S_tW_{\text{lat}}\gamma_{\text{lat}}
```

Individual neuron potentials are then processed with bounded discrete-time updates:

```math
\tilde{U}_{t+1} = \beta U_t + X_t,\quad
S_{t+1}=H(\tilde{U}_{t+1}-V_{\text{thr}}),\quad
U_{t+1}=\tilde{U}_{t+1}-S_{t+1}V_{\text{thr}}
```

Here `U` is membrane potential, `X` is total synaptic input current, `beta in (0,1)` is decay, and `V_thr` is the spike threshold. Updates are written as new MLX arrays so the recurrent step can compile cleanly on Apple Silicon.

### **3. Asymmetric Temporal STDP**

Rather than storing dense request-time attention matrices, temporal correlation is consolidated into synaptic and graph weights. SYNAPSE-S2 implements a one-cycle discrete form of asymmetric STDP:

```math
\Delta W_{ij} =
A_+e^{-1/\tau_+}S_i[t]S_j[t+1]
-
A_-e^{-1/\tau_-}S_i[t+1]S_j[t]
```

```math
W_{ij} \leftarrow \mathrm{clip}(W_{ij}+\Delta W_{ij}, -c, c)
```

This is the fixed-step implementation of the usual exponential STDP rule: pre-before-post spike pairs potentiate the forward direction, while post-before-pre pairs depress it. The runtime also skips STDP when the active set exceeds the configured guardrail and clips updated weights into a bounded envelope. Vector search compares a query vector against stored vectors at query time; STDP turns repeated temporal co-activation into durable structure, so future recall can follow learned activation paths instead of recomputing every pairwise token-token relation.

## **Memory Consolidation and Pruning Lifecycle**

The SNN maintains long-term structural efficiency and manages Apple Silicon VRAM limitations by executing a scheduled multi-phase pruning pipeline.

| Phase | System Process | Core Mathematical Operation | Downstream Cognitive Function |
| :---- | :---- | :---- | :---- |
| Phase 1 | Connection Weight Decay | `W_ij <- gamma_decay W_ij`, where `0 < gamma_decay < 1` | Lowers weight values for weak connections |
| Phase 2 | Synaptic Clustering | `C_m = {i | density(i) >= tau_c}` | Identifies overlapping spiking patterns |
| Phase 3 | Semantic Merging | Merge `m_i,m_j` when `sim(m_i,m_j) >= tau_merge` | Consolidates redundant memory paths |
| Phase 4 | Threshold Rescoring | `V_thr <- V_thr + alpha(r_observed - r_target)` | Keeps firing rates in healthy, balanced ranges |
| Phase 5 | Trace Promotion | `p_i <- p_i + 1[activation(i) >= tau_promote]` | Moves active traces to persistent storage |
| Phase 6 | Relationship Extraction | `edge(i,j) <- HebbianEvidence(i,j) + STDPEvidence(i,j)` | Builds structured semantic connection graphs |
| Phase 7 | Neurogenesis | Reset inactive state: `u_i,s_i <- 0` for recycled nodes | Frees up inactive nodes for new memory traces |

## **Hardware Integration Optimization**

By executing directly inside Apple's Unified Memory Architecture via mlx-snn, SYNAPSE-S2 resolves the physical memory limitations that plague CUDA-emulated systems :

* **Metal JIT Acceleration**: Synaptic weight updates are compiled natively into GPU kernels using mx.compile to prevent execution overhead on the CPU.  
* **No-Copy Memory Sharing**: The host CPU pre-processes input embeddings, while the integrated M-series GPU computes the spiking networks inside the same physical RAM, completely avoiding costly PCIe bus data copies.  
* **Footprint Control**: Before MLX load or array materialization/resizing, the authoritative core requires the exact steady float32 dense topology to fit 384 MiB; the default 8,192-neuron substrate calculates to about 288 MiB. Profiling can additionally report the 96-384 MiB operating target, but neither calculation is an Instruments measurement of peak residency, a hardware-wide certification, or a timing guarantee.

## **Verification and Diagnostics**

To verify the transport layer, launch the interactive MCP Inspector interface with the launcher:

```
npx @anthropic-ai/mcp-inspector "$HOME/.local/bin/synapse-s2-mcp"
```

This verifies the stdio JSON-RPC endpoints and ensures structural tool definitions are fully accessible before registering the server to your primary client environments.
