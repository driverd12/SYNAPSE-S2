# SYNAPSE-S2 Current Status

> **Freshness notice (2026-08-24):** the runtime measurements, namespace
> counts, health scores, and checkout state below are a preserved historical
> snapshot from 2026-07-01. They are not current Dans-MBP evidence and must not
> be used for a handoff, readiness claim, or recovery decision. This
> documentation refresh did not query or mutate the live core. The source
> capability inventory immediately below was audited against implementation
> baseline `910d9a7a46b1d79b6887f6c0714df1816be2e9e4`; documentation-only commits
> after that baseline do not imply a runtime deployment.

## Source Capability Inventory

| Area | Implemented source behavior at the audited baseline | Boundary |
| :--- | :--- | :--- |
| Authority | One authenticated, owner-only authoritative core owns neural state, SQLite writes, capture, recovery, and replication. Adapters fail closed rather than opening a fallback backend. | Repository state, tests, and documentation do not prove that a particular host is running this build. |
| Durable knowledge | Persistent text, event, image, namespace, Cortex, Goal Ledger, temporal, associative, spike-index, and surface-term records are available through CLI, MCP, and the loopback dashboard. | Only information actually captured is present; SYNAPSE-S2 is not an invisible transcript or filesystem scraper. |
| Retrieval | Retrieval v2 provides deterministic, bounded, read-only hybrid recall with source/scope/link provenance and uncalibrated ranking scores. | Legacy attention queries remain stateful. Synthetic acceptance is not a live-corpus relevance or latency SLO. |
| Retrieval associations | Source-backed harmonic cues and separately governed Memora cue bindings can contribute bounded retrieval evidence. The dashboard labels these contributions **Retrieval associations**. | An association is explanatory retrieval evidence, not an operator action, approval, instruction, or truth claim. Memora shadow planning alone never affects recall. |
| Local image memory and media similarity | Typed image memories, owner-only thumbnails, deterministic descriptors, optional Apple Vision feature prints/OCR, stored-image similarity, and transient image similarity are implemented. Referenced derivatives participate in recovery and capability-negotiated replication. | Full-resolution originals are not copied. Feature-print scores are uncalibrated and not cross-device semantic guarantees. Whole-memory deletion and derivative cleanup are not one SQLite-plus-filesystem atomic transaction. |
| Capture and recovery | Capture v2 commits memory, event, relationship, and ledger effects exactly once by `capture_id`; signed paired recovery seals the database, capture state, runtime/journal bindings, and media when referenced. Isolated restore proof and governed restored-target adoption exist. | A raw SQLite copy is not a complete recovery point. Recovery material is signed, not encrypted. |
| Multi-Mac handoff | Offline checkpoints are signed, paired, target-bound, staged into an isolated restore, and acknowledged through durable evidence. | No live synchronization, database merge, federated recall, automatic promotion, or conflict resolution is claimed. |
| Operator surfaces | The CLI, 70 MCP tools, and authenticated loopback dashboard expose memory, graph, capture, governance, recovery, and diagnostics. The **Impact** drawer reports content-free local dashboard recall/resource telemetry. | Impact is not billing or proven savings and currently does not cover MCP, CLI, or agent-hydration traffic. |
| Release safety substrate | The repository contains closed source inventory/update planning, preservation inspection, Ed25519 provenance, exact-build compatibility profile 4, owner-only inactive source staging, installed-layout modeling, an activation journal/state-machine contract, and partial environment/static-evidence producers. | These pieces do not form an authorized updater. They do not build an environment, select or activate a release, migrate/downgrade data, execute rollback/equivalence, publish a package, or modify the live service. The environment chain remains on compatibility profile 3 and its native-file/dynamic evidence is incomplete. |

For the release-state diagram and exact primitive-by-primitive nonclaims, see
[PRODUCTION_GAP_AUDIT.md](PRODUCTION_GAP_AUDIT.md). For live truth, run the
regeneration command at the end of this document and separately verify the
installed core and deployment evidence.

## Historical Runtime Snapshot — 2026-07-01

Generated: `2026-07-01T09:17:45-06:00`
Context: `default`
Agent: `codex-desktop`

| Field | Recorded value |
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

## Historical Saved Memory Contexts

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

## Historical Feature Inventory

| Feature | Behavior recorded in this historical snapshot |
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

## Historical Gaps Recorded At Generation

- Memory Hygiene reported `70` review items; top categories: assumption_or_follow_up=69, duplicate_candidate=68.
- Doctor repair plan: No repair required. Run Start Work and capture a Wrap Session at handoff.
- Cortex has no active sessions in this report.

## Regeneration

```bash
.venv/bin/python scripts/synapse_status_report.py --context default --embedding-provider mlx-neural
```

Use this report as a point-in-time status artifact. Re-run it before demos, handoffs, and readiness claims. The source-checkout row records the repository state at generation time; after committing this file, use `git log -1 --oneline` and `git status -sb` for the final commit position.
