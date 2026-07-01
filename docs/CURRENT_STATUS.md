# SYNAPSE-S2 Current Status

Generated: `2026-07-01T09:17:45-06:00`
Context: `default`
Agent: `codex-desktop`

## Runtime Snapshot

| Field | Current value |
| :--- | :--- |
| Runtime | `ready` |
| Core enabled | `yes` |
| Embedding provider | `mlx-neural-v1 / mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ / native MLX / semantic` |
| Neurons | `8,192` |
| Dimension / top-k | `1,024` / `256` |
| Memory entries / relationships | `1,533` / `2,500` |
| Latest context-bus event | `2,307` |
| Topology footprint | `288.1 MB` |
| Target envelope | `96-384 MB`, within target: `yes` |
| Quick prune | `9.7 ms` of `60 ms`, within budget: `yes` |
| Doctor | `ready` |
| Context health | `degraded` / score `78` |
| Memory hygiene backlog | `70` / quality `40` |
| Cortex active sessions / goals | `0` / `1` |
| Source checkout at generation | branch `main`, head `214b6ba`, uncommitted changes `yes` |

## Saved Memory Contexts

| Namespace | Entries |
| :--- | ---: |
| default | 1,533 |
| board-demo | 9 |
| demo | 3 |
| proposal | 1 |
| qa-relationship-modes | 3 |
| servus-gui-hydrated-handoff-20260630 | 249 |
| servus-hydrated-handoff-20260630 | 252 |
| servus-servus-gui-sanitized-handoff-20260630 | 399 |
| x | 2 |

## Feature Inventory

| Feature | Real current behavior |
| :--- | :--- |
| Saved namespace menu | Dashboard sidebar lists live `memory_contexts`, keeps `default` first, and preserves manual namespace entry. |
| Start Work | Dashboard and CLI morning brief for current objective, risks, recent traces, next actions, source memories, and goals. |
| Wrap Session | Preview and confirmed handoff capture for decisions, validation evidence, blockers, and next actions. |
| Cortex Governor | Enter, tick, commit typed traces, moderate working memory, close sessions, and expose guardrails. |
| Cross-process Cortex closure | Closed, finished, or orphaned Cortex sessions survive stale dashboard and capture-daemon runtime-state writers. |
| App Connect preview | Detect apps, attach with confirmation, preview capture quality, and write only after operator confirmation. |
| Selected-text fallback | Exact-content capture path for apps that expose only chrome or metadata through Accessibility. |
| Memory Hygiene | Queue low-confidence, duplicate, stale, sensitive-looking, or follow-up memory for operator action. |
| Doctor / Repair | Runtime, config, LaunchAgent, embedding, memory DB, App Connect, and repair-plan diagnostics. |
| Recall with evidence | Recall cards expose score, source, provenance, why-matched detail, moderation, and pin-to-session action. |
| Goal Ledger | Durable goal create/update/list state surfaced in Start Work and Cortex state. |
| Context bus | Durable pull/ack deployments for MCP clients, local IDE adapters, and dashboard writes. |
| Operator readiness pack | Single evidence pack proving client connect, memory write, recall, app preview, wrap, Doctor, and dashboard smoke. |

## Known Non-Claims And Do-Not-Do Rules

- App Connect is not guaranteed internal app scraping; it captures locally exposed Accessibility text or exact selected text.
- SYNAPSE-S2 does not invisibly intercept arbitrary private transcript stores; clients must expose text through MCP, inbox drops, transcript sources, selected text, or App Connect.
- Do not capture credentials, tokens, private keys, or unnecessary personal data; redaction is a guardrail, not permission.
- Do not call `test-validated` truth unless concrete command, artifact, output, commit, or report evidence exists.
- Do not treat dashboard detection of an app as proof that the app exposed useful internal content.
- Do not assume the default CLI provider equals the installed client/dashboard provider; pass `--embedding-provider mlx-neural` when validating the neural path.
- Do not claim Apple Instruments or external Metal counter certification; current certification is MLX/topology/runtime evidence.
- Do not push or prune memory without explicit confirmation and a focused target.

## Current Gaps To Watch

- Memory Hygiene currently reports `70` review items; top categories: assumption_or_follow_up=69, duplicate_candidate=68.
- Doctor repair plan: No repair required. Run Start Work and capture a Wrap Session at handoff.
- Cortex has no active sessions in this report.

## Regeneration

```bash
.venv/bin/python scripts/synapse_status_report.py --context default --embedding-provider mlx-neural
```

Use this report as a point-in-time status artifact. Re-run it before demos, handoffs, and readiness claims. The source-checkout row records the repository state at generation time; after committing this file, use `git log -1 --oneline` and `git status -sb` for the final commit position.
