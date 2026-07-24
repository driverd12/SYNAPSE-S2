# SYNAPSE-S2 Operator Readiness Certification

This runbook is the Monday trust gate. It is not a demo seeder and it does not use example datasets. It derives the exact candidate core configuration through the same installer path used for cutover, runs real local SYNAPSE-S2 commands against the selected context, verifies the installed compact MCP contract through both output channels, writes and recalls one factual readiness trace, previews a real running app, wraps the session, proves processed capture authority, creates and re-verifies a signed paired recovery point, proves an isolated restore, and packages the evidence into one local artifact.

Certification is evidence, not deployment. Determine live status only through
the authoritative installer status contract; this document makes no
internal-remote or public-GitHub publication claim.

## Binding prerequisite

For a first cutover while the database is still local-v5, publish the reviewed
candidate binding and install the clients that consume it before certification:

```bash
scripts/install_core_agent.sh publish-binding
scripts/install_local_launcher.sh
.venv/bin/python scripts/install_client_configs.py
```

The canonical `~/.config/synapse-s2/core-binding.json` is owner-only and records
the complete layout, private canonical CoreConfig path and digest,
configuration fingerprint, embedding-space identity, and
`candidate-local-v5` authority mode. `publish-binding` refuses an already
governed v6 database. For a v6 replacement, keep the current
`authoritative-core-v6` binding and require
`scripts/install_core_agent.sh status` to report `client_binding.ready: true`.
For a reviewed noncanonical layout, pass the same
`--noncanonical-layout-manifest` to `publish-binding`, this certifier, and the
eventual install.

`scripts/install_client_configs.py` intentionally keeps persisted client JSON
free of `PYTHONPATH`. The installed launcher resolves its own real checkout
root and prepends that path at runtime. Project-scoped `.mcp.json` is generated
per host and ignored by Git; `.mcp.json.example` is the tracked path-free
instruction document. The certifier requires the generated definition to be
fully converged while the source checkout remains clean, including reviewed
noncanonical layouts.

## Run

```bash
cd "/absolute/path/to/SYNAPSE-S2"
.venv/bin/python scripts/operator_readiness_certify.py \
  --context default \
  --agent-id codex-desktop \
  --expect-embedding-provider mlx-neural
```

`--expect-*` options are fail-closed assertions against the installer-derived
candidate; they do not configure a client or substitute a different neural
backend. Omitting them accepts the candidate defaults. The manifest embeds the
canonical `synapse-s2.core-config-evidence.v1` document, and cutover must match
its exact `config_fingerprint`.

The command writes:

- `.synapse_s2/evidence_packs/<run-id>/manifest.json`
- `.synapse_s2/evidence_packs/<run-id>/summary.md`
- `.synapse_s2/evidence_packs/<run-id>/runbook.md`
- `.synapse_s2/evidence_packs/<run-id>/artifacts/`
- `.synapse_s2/evidence_packs/<run-id>.zip`

Exit code `0` means every required proof returned `ready`. Any `degraded` or `blocked` required proof returns a non-zero exit code and must be treated as not ready until rerun cleanly.

The certifier checks the source checkout before live probes. A non-empty
`git status --short` produces a blocked diagnostic pack immediately; it must not
be treated as operator-ready or used for cutover.

## What It Proves

| Required proof | What must be true |
| :--- | :--- |
| Candidate core contract | The manifest contains the complete validated candidate configuration and exact fingerprint produced by the same resolver/builder the installer uses. Every supplied `--expect-*` assertion matches it. |
| Local launcher | `$HOME/.local/bin/synapse-s2-mcp` exists and is executable. |
| Client config | `scripts/install_client_configs.py --dry-run` has no pending changes and the installed definitions carry only the reviewed core-binding pointer. |
| MCP connect | FastMCP lists SYNAPSE-S2 tools through the installed launcher; its status payload exactly matches the bound topology, maintenance intervals, MLX device, provider identity, configuration fingerprint, and embedding-space identity. |
| MCP compact contract probe | An installed-launcher `list_spiking_memory` call returns exactly one authoritative `synapse-s2.token-contract.v1` compact `structuredContent` envelope at or below 12,288 bytes, with independently verified canonical byte accounting, exact authoritative totals, and authenticated-keyset snapshot/continuation metadata, plus exactly one `synapse-s2.mcp-safety-summary.v1` `TextContent` item at or below its separate 4,096-byte ceiling. The safety item must declare `structuredContent_required: true`. Outer JSON-RPC framing is excluded. |
| Neural embedding | The requested provider returns a non-empty vector; `mlx-neural` must report native MLX. The bound dimension and exact steady float32 topology must pass pre-materialization admission at or below 384 MiB. |
| Doctor | Doctor is clean, or the evidence pack clearly reports a repair plan. |
| Start Work | Start Work returns real operator sections from the selected context. |
| Memory write | A unique readiness trace is written into the local SQLite memory DB. |
| Recall | Read-only `retrieve-v2` returns the same unique readiness trace by run id, tag, or memory id inside a bounded `memory-retrieval` contract. It must report `raw_input_stored: false`, local scope, authoritative Retrieval v2 provenance, and uncalibrated score semantics. |
| App Connect preview | A real running app is attached and previewed without writing memory. Quality and capability badges must be present even if Accessibility is blocked. |
| Wrap Session | A factual handoff is persisted as durable session memory. |
| Capture ledger audit | Every processed `capture.v2` record has an exact authoritative SQLite ledger binding; missing, ambiguous, or mismatched evidence blocks backup. |
| Paired recovery backup | SQLite and exactly-once capture transport are bound by signed receipts with no replay debt. |
| Recovery verification | The database, schema contract, capture archive, provenance, reconciliation, and canonical processed-request ledger-binding proof reverify from durable artifacts. |
| Isolated recovery drill | A paired restore materializes outside live state and independently reproduces the same content-free capture-ledger binding count and revision. |
| Dashboard smoke | Page/assets and the protected snapshot API load through the same rotating bootstrap, port-specific cookie, and `X-Synapse-Dashboard-Session` contract used by the installer; no bare URL or unauthenticated API success qualifies. |

## Interpreting Results

Open `summary.md` first. The top section shows:

- `Overall status`
- `Operator trustworthy`
- Required checks ready out of total checks
- The exact git commit and embedding provider
- A required-proof table
- A repair plan

Only `Operator trustworthy: true` is acceptable for "ready to use with coworkers." A degraded pack is still useful as a repair report, but it is not a success certificate.

The compact contract probe does not add its two channels together into one
budget. `response_contract.serialized_bytes` measures only authoritative
`structuredContent`; the safety `TextContent` is verified independently, and
transport framing belongs to neither measurement. Full-mode diagnostics use a
separate safety-text ceiling of 131,072 bytes and are not the installed compact
readiness gate.

The 384 MiB topology check is the exact steady float32 array calculation for the
sensory matrix, lateral matrix, membrane, spikes, and active traces. It occurs
before MLX loading/materialization, and raw query/register vectors must match the
configured dimension before request-journal admission. It is not an Instruments
measurement of peak process residency, proof for every Mac, or a timing claim.

Request-journal reconciliation also distinguishes proof from uncertainty. A
delivery ACK, release, or dead-letter operation that deterministically changed
nothing is terminal `failed` / `invalid_request`; credential-shaped delivery
identifiers are rejected before admission. A genuinely uncertain commit remains
non-replayable `outcome_unknown`. Terminal rows age out without consuming the
accepted-row ceiling, but the total retained-row ceiling keeps throughput finite
until pruning.

Cross-machine recovery has a separate trust gate. For a foreign signer, the
operator must independently pin every artifact present: database, capture,
request journal when governed, and runtime state when included. Verification
binds the exact bundle and dependent receipt identities through materialization;
receipt/artifact substitution fails before output creation. A fully pinned
foreign governed bundle may complete the isolated restore with its journal and
runtime bindings intact.

For an installed dashboard, `dashboard-auth.json` is `0600` inside an owner-only
`0700` directory and contains the rotating bootstrap plus header capability, not
the cookie secret. `scripts/open_dashboard.py` consumes it without exposing the
bootstrap in argv. The browser keeps the header only in port-scoped
`sessionStorage`, scrubs the redirect fragment, and sends it with the
port-specific HttpOnly SameSite=Strict cookie on all API calls; POST also
requires exact Host/Origin. The bounded adapter admits eight handlers behind
backlog 32, enforces an absolute one-second header deadline and five-second
post-header I/O, and uses bounded shutdown.

## Common Repairs

| Failed proof | Operator action |
| :--- | :--- |
| Candidate configuration or binding | On local-v5, rerun `scripts/install_core_agent.sh publish-binding`, then reinstall launcher/client configs. On v6, do not publish a candidate; inspect `scripts/install_core_agent.sh status` and repair the authoritative core/binding. Reuse the same reviewed noncanonical layout manifest everywhere. |
| `local_launcher` | Run `scripts/install_local_launcher.sh`. |
| `client_config` | Run `scripts/install_client_configs.py`, then restart Codex, Claude Desktop, and Claude Code. |
| `mcp_connect` or `mcp_status_call` | Run `uv sync`, reinstall the launcher, then rerun FastMCP list/call. |
| `mcp_contract_probe` | Run `scripts/install_local_launcher.sh` and `scripts/install_client_configs.py`, restart the MCP client, and rerun certification. Inspect the probe artifact for schema/profile/budget mismatch, falsified canonical size, multiple or missing structured payloads, or an invalid/oversized safety summary; do not raise a ceiling to hide a contract failure. |
| `neural_embedding` | Verify `.synapse_s2/models` contains the configured model snapshot, `SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY=1`, and the provider benchmark passes with `--embedding-provider mlx-neural`. |
| `doctor` | Follow the repair plan inside `summary.md`; rerun Doctor before rerunning certification. |
| `memory_write` | Check authoritative-core health and the binding-owned memory store; do not inject a competing database path into a bound client. |
| `recall` | Verify the readiness memory id exists in `list-memory`; then rerun `retrieve-v2` with the same embedding provider. Do not substitute deprecated `query-text`, which is a stateful compatibility path. |
| `app_preview` | Open a visible app, grant macOS Accessibility/Automation where appropriate, or use selected-text capture when preview reports low signal. |
| `wrap_session` | Run `wrap-session --preview`, confirm text is non-empty, then rerun certification. |
| `capture_ledger_audit` | Review `finding_samples` and `audit_revision`. Only when `repairable: true`, run `capture-ledger-integrity --repair --confirm --expected-revision '<audit_revision>'`, then rerun the read-only audit and certification. Never replay captures or synthesize receipts. |
| `recovery_backup` | Resolve disk space, SQLite integrity, capture errors, signing-key permissions, or replay-required transport files. On the authoritative lane, omit capture-root and noncanonical-root overrides; the service owns those paths. |
| `recovery_verify` | Inspect the four bundle artifacts and signed receipt; never substitute a database-only copy. |
| `recovery_restore` | Inspect the isolated restore proof and capture-ledger reconciliation before any cutover planning. |
| `dashboard` | Run `.venv/bin/python scripts/smoke_dashboard.py default`. For operator review, install/refresh with `scripts/install_dashboard_agent.sh` and use `.venv/bin/python scripts/open_dashboard.py`; never open a bare loopback URL. Verify the auth file is `0600` inside its `0700` directory. |

## Why This Exists

`scripts/prep_tomorrow.sh` is still the broad install and preflight path. Its apply stage requires this fresh manifest and does not choose a candidate configuration independently. After the installer reaches stable authenticated health and capture readiness, it publishes the `authoritative-core-v6` binding; clients send that binding's expected configuration fingerprint on every request. The broad path then refreshes launchers, client configs, tests, maintenance, MCP smoke checks, dashboard smoke, and backups.

`scripts/operator_readiness_certify.py` is narrower and stricter. It answers one operator question: can SYNAPSE-S2 be trusted right now for real work? It fails closed when required evidence is missing, writes the proof into one pack, and preserves the raw stdout/stderr needed to debug failures without guessing. It never auto-repairs a capture-ledger gap: the operator must separately review the bounded findings, explicitly confirm the exact revision, and rerun the audit before the certifier will write a paired recovery bundle.

The authoritative recovery lane accepts no public `capture_root`,
noncanonical-capture permission, or retention-directory override. Those options
are for explicit offline local-v5 maintenance only; the core injects its reviewed
capture and backup roots. Receipt and isolated-restore outputs are still bounded
to the configured backup/recovery trees.
