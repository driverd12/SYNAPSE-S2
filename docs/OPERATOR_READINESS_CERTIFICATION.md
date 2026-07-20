# SYNAPSE-S2 Operator Readiness Certification

This runbook is the Monday trust gate. It is not a demo seeder and it does not use example datasets. It runs real local SYNAPSE-S2 commands against the selected context, verifies the installed compact MCP contract through both output channels, writes and recalls one factual readiness trace, previews a real running app, wraps the session, proves processed capture authority, creates and re-verifies a signed paired recovery point, proves an isolated restore, and packages the evidence into one local artifact.

## Run

```bash
cd "/Users/dan.driver/Documents/Playground/SYNAPSE-S2"
.venv/bin/python scripts/operator_readiness_certify.py \
  --context default \
  --agent-id codex-desktop \
  --embedding-provider mlx-neural
```

The command writes:

- `.synapse_s2/evidence_packs/<run-id>/manifest.json`
- `.synapse_s2/evidence_packs/<run-id>/summary.md`
- `.synapse_s2/evidence_packs/<run-id>/runbook.md`
- `.synapse_s2/evidence_packs/<run-id>/artifacts/`
- `.synapse_s2/evidence_packs/<run-id>.zip`

Exit code `0` means every required proof returned `ready`. Any `degraded` or `blocked` required proof returns a non-zero exit code and must be treated as not ready until rerun cleanly.

## What It Proves

| Required proof | What must be true |
| :--- | :--- |
| Local launcher | `/Users/dan.driver/.local/bin/synapse-s2-mcp` exists and is executable. |
| Client config | `scripts/install_client_configs.py --dry-run` has no pending changes. |
| MCP connect | FastMCP lists SYNAPSE-S2 tools through the installed launcher and can call status. |
| MCP compact contract probe | An installed-launcher `list_spiking_memory` call returns exactly one authoritative `synapse-s2.token-contract.v1` compact `structuredContent` envelope at or below 12,288 bytes, with independently verified canonical byte accounting, plus exactly one `synapse-s2.mcp-safety-summary.v1` `TextContent` item at or below its separate 4,096-byte ceiling. The safety item must declare `structuredContent_required: true`. Outer JSON-RPC framing is excluded. |
| Neural embedding | The requested provider returns a non-empty vector; `mlx-neural` must report native MLX. |
| Doctor | Doctor is clean, or the evidence pack clearly reports a repair plan. |
| Start Work | Start Work returns real operator sections from the selected context. |
| Memory write | A unique readiness trace is written into the local SQLite memory DB. |
| Recall | `query-text` returns the same unique readiness trace by run id, tag, or memory id. |
| App Connect preview | A real running app is attached and previewed without writing memory. Quality and capability badges must be present even if Accessibility is blocked. |
| Wrap Session | A factual handoff is persisted as durable session memory. |
| Capture ledger audit | Every processed `capture.v2` record has an exact authoritative SQLite ledger binding; missing, ambiguous, or mismatched evidence blocks backup. |
| Paired recovery backup | SQLite and exactly-once capture transport are bound by signed receipts with no replay debt. |
| Recovery verification | The database, schema contract, capture archive, provenance, reconciliation, and canonical processed-request ledger-binding proof reverify from durable artifacts. |
| Isolated recovery drill | A paired restore materializes outside live state and independently reproduces the same content-free capture-ledger binding count and revision. |
| Dashboard smoke | The loopback dashboard page, `app.js`, `styles.css`, and snapshot API load without known warning/error text. |

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

## Common Repairs

| Failed proof | Operator action |
| :--- | :--- |
| `local_launcher` | Run `scripts/install_local_launcher.sh`. |
| `client_config` | Run `scripts/install_client_configs.py`, then restart Codex, Claude Desktop, and Claude Code. |
| `mcp_connect` or `mcp_status_call` | Run `uv sync`, reinstall the launcher, then rerun FastMCP list/call. |
| `mcp_contract_probe` | Run `scripts/install_local_launcher.sh` and `scripts/install_client_configs.py`, restart the MCP client, and rerun certification. Inspect the probe artifact for schema/profile/budget mismatch, falsified canonical size, multiple or missing structured payloads, or an invalid/oversized safety summary; do not raise a ceiling to hide a contract failure. |
| `neural_embedding` | Verify `.synapse_s2/models` contains the configured model snapshot, `SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY=1`, and the provider benchmark passes with `--embedding-provider mlx-neural`. |
| `doctor` | Follow the repair plan inside `summary.md`; rerun Doctor before rerunning certification. |
| `memory_write` | Check memory DB writeability and `SYNAPSE_S2_MEMORY_DB`. |
| `recall` | Verify the readiness memory id exists in `list-memory`; then rerun with the same embedding provider. |
| `app_preview` | Open a visible app, grant macOS Accessibility/Automation where appropriate, or use selected-text capture when preview reports low signal. |
| `wrap_session` | Run `wrap-session --preview`, confirm text is non-empty, then rerun certification. |
| `capture_ledger_audit` | Review `finding_samples` and `audit_revision`. Only when `repairable: true`, run `capture-ledger-integrity --repair --confirm --expected-revision '<audit_revision>'`, then rerun the read-only audit and certification. Never replay captures or synthesize receipts. |
| `recovery_backup` | Resolve disk space, SQLite integrity, capture errors, signing-key permissions, or replay-required transport files. |
| `recovery_verify` | Inspect the four bundle artifacts and signed receipt; never substitute a database-only copy. |
| `recovery_restore` | Inspect the isolated restore proof and capture-ledger reconciliation before any cutover planning. |
| `dashboard` | Run `.venv/bin/python scripts/smoke_dashboard.py default` and fix static asset/API warnings. |

## Why This Exists

`scripts/prep_tomorrow.sh` is still the broad install and preflight path. It refreshes launchers, client configs, sidecars, tests, maintenance, MCP smoke checks, dashboard smoke, and backups.

`scripts/operator_readiness_certify.py` is narrower and stricter. It answers one operator question: can SYNAPSE-S2 be trusted right now for real work? It fails closed when required evidence is missing, writes the proof into one pack, and preserves the raw stdout/stderr needed to debug failures without guessing. It never auto-repairs a capture-ledger gap: the operator must separately review the bounded findings, explicitly confirm the exact revision, and rerun the audit before the certifier will write a paired recovery bundle.
