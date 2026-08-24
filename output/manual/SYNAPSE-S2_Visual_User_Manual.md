# SYNAPSE-S2 Visual Operator Manual

Human-readable field guide for the current local memory system, its governed operator surfaces, recovery model, and honest release posture.

Source baseline 910d9a7 | Generated 2026-08-24.

Companion artifacts:

- [Annotated visual manual (PDF)](../pdf/SYNAPSE-S2_Visual_User_Manual.pdf)
- [One-page operator reference (PDF)](../pdf/SYNAPSE-S2_Quick_Reference.pdf)
- [One-page operator reference (PNG)](SYNAPSE-S2_Quick_Reference.png)
- `plates/` contains one presentation-ready PNG for each manual page.

## The one-sentence model

SYNAPSE-S2 is a durable local memory substrate: one authoritative core stores explicitly captured knowledge, retrieves bounded evidence, governs agent work, and preserves verifiable recovery state without claiming unseen information or unsupported authority.

## 1. The operating model

Durable local memory with explicit authority boundaries.

> SYNAPSE-S2 stores what was deliberately captured. It never claims unseen thoughts, files, or app state.

### Memory anatomy

- Galaxy: every observed namespace and reviewed connection.
- Cortex: one namespace and its governed work state.
- Ganglion: a derived semantic or type cluster, not a stored object.
- Neuron: one durable memory entry with provenance and relationships.

### Authoritative core

- One authenticated local core owns SQLite writes, neural state, capture, recovery, and replication.
- CLI, MCP, and dashboard clients use that authority instead of fallback databases.
- The loopback dashboard is an operator surface, not a second source of truth.

### What persists

- Text, events, typed relationships, namespace catalog state, goals, and governed traces.
- Private image derivatives and their exact database references when image memory is used.
- Delivery, capture, recovery, replication, and governance receipts needed for audit.

### What stays transient

- Graph layouts, open drawers, browser navigation, and other presentation state.
- Quick Prune and Deep Sleep maintain bounded runtime state; neither silently deletes durable memory.
- Unreviewed suggestions never become execution authority.

Operator note: Inspect first; mutate only through the smallest named governed operation.

## 2. The Daily Operator Trust Loop

Establish current truth before relying on memory or starting risky work.

> Choose context -> Start Work -> Health and Doctor -> Enter Cortex -> Capture or Recall -> Wrap and protect.

### Start Work

- Loads a bounded morning brief for the selected namespace.
- Shows recent evidence, active goals, risks, next actions, and leased delivery receipts.
- Acknowledgement happens only after content is successfully rendered or consumed.

### Trust checks

- Context Health explains memory quality and recommendations.
- Doctor checks runtime, SQLite, embeddings, capture, delivery, and App Connect.
- Readiness evidence is stronger than a green dashboard badge alone.

### Governed work

- Enter Cortex with agent, mode, and task before substantial mutation.
- Tick before risky actions and declare intended files, tools, mutation intent, and confidence.
- Commit verified traces, then close instead of leaving stale active work.

### Clean handoff

- Wrap Session records decisions, validation, blockers, and next action.
- Create a recovery point before broad repair, pruning, or transfer.
- Keep commit, publication, installation, and live readiness as separate claims.

Operator note: Prove which context, core, and evidence are active at the start of each session.

## 3. Durable memory and capture

Explicit creation paths with exactly-once processing and provenance.

> Capture is deliberate: bounded source text receives identity, is committed once, and remains attributable.

### Creation paths

- Remember stores one trace; ingest segments structured events and relationships.
- Conversation capture enters through the exactly-once capture ledger.
- App Connect previews locally exposed text before confirmed snapshot capture.

### Exactly-once posture

- Stable request identity and journals fail closed around uncertain outcomes.
- The inbox defers work while the core is unavailable, then resumes bounded batches.
- Credential-shaped material is rejected or redacted before durable ingestion.

### Typed context

- Goal, Decision, Risk, Validation, and Follow-up prefixes create typed context where appropriate.
- The active dashboard or CLI context determines the durable namespace target.
- Provenance remains available for recall, correction, and recovery checks.

### Correction

- Capture a replacement, then prune only the bad node or relationship.
- Arbitrary stored text is not edited in place.
- Broad relationship-class deletion is reserved for an entirely bad class.

Operator note: Secret redaction is a guardrail, never permission to capture credentials or private keys.

## 4. Recall and Retrieval associations

Deterministic retrieval with visible evidence and bounded graph assistance.

> Retrieval associations are relevance cues, not user actions, approvals, tasks, or execution instructions.

### Recall scopes

- Local searches the active namespace plus explicit global memory.
- Connected adds approved, enabled, one-hop namespace bridges.
- All explicitly searches every saved namespace for that read-only request.

### Retrieval v2

- Local neural embeddings and deterministic ranking return bounded evidence.
- Typed and graph-neighbor evidence can improve relevance without mutating memory.
- Recall cards expose provenance and why-matched detail for review.

### Associations

- Derived terms can route a query toward related durable evidence.
- They stay subordinate to source memories and can be audited or revoked through Memora.
- Association output must never be described as operator intent.

### Bounded nonclaims

- A non-empty result does not prove relevance, truth, completeness, or success.
- Visible degree describes only the returned relationship sample.
- Benchmarks do not prove every real workload or every target Mac.

Operator note: Recall locally first; expand scope only when the question needs broader evidence.

## 5. Namespace Galaxy and bridges

Read-only navigation plus reviewed cross-namespace recall.

> Galaxy -> Cortex -> Ganglion -> Neuron is semantic drill-down. Focus never edits, copies, or reconnects memory.

### Navigate

- Enter namespace changes the active operating scope.
- Scroll changes semantic depth; focus loads bounded neuron detail.
- The accessible list mirrors canvas navigation.

### Visual meaning

- Galaxy area combines memory volume, indexed density, and enabled approved bridge weight.
- Ganglion and neuron size summarize bounded structure, not truth or importance.
- Suggestions and phase-delay values are presentation evidence only.

### Bridge lifecycle

- Suggestion -> pending proposal -> exact review -> approved enabled bridge.
- Disable, revoke, and expiry close recall authority without copying memory.
- Changed evidence invalidates stale review material.

### Isolation

- Connected recall follows approved one-hop paths and remains read-only.
- Suggestions never expand recall scope or affect durable state.
- The namespace catalog is not an ACL or ownership registry.

Operator note: Changing scope does not move, duplicate, synchronize, or merge stored memory.

## 6. Private image and media memory

Locally derived visual evidence with explicit capture and recovery boundaries.

> Image memory is opt-in and local: thumbnail, description, and bounded descriptors support inspection and similarity.

### Capture

- The operator chooses an image and target namespace before creation.
- Transient source handling produces bounded private derivatives, not a hidden cloud upload.
- Explicit descriptions remain source-backed and inspectable.

### Apple Vision lane

- Local feature prints support image-to-image similarity.
- Consent-gated OCR contributes imperfect searchable cues.
- Neither lane is a VLM or calibrated text-to-image semantic search.

### Similarity

- Find Similar resolves candidates from authoritative references.
- Distance is uncalibrated and carries truncation or exclusion notices.
- Feature bytes, raw OCR, and witness internals stay out of responses.

### Preservation

- Recovery and replication seal derivatives referenced by the immutable snapshot.
- Missing or corrupt referenced derivatives block publication.
- Valid orphan files are excluded and reported.

Operator note: Visual recall is evidence with provenance, not an identity or semantic-certainty claim.

## 7. Memora governance

Compact abstractions and cues remain reviewable, attributable, and reversible.

> Memora improves relevance routing while source-backed durable memory remains authoritative.

### Shadow planning

- A read-only plan proposes abstractions and cue anchors for one namespace.
- Planning never changes retrieval or writes an effective binding.
- Raw source text, vectors, supporting IDs, and witness internals stay hidden.

### Governed lifecycle

- Proposal records one isolated candidate for exact review.
- Promotion requires separated proposer and reviewer roles.
- Reject and revoke preserve append-only receipts and remove authority.

### Integrity

- Bindings, sources, provider identity, and receipts are cross-checked.
- Recovery and replication carry a content-free aggregate that recomputes exactly.
- Invalid source memories cannot stay effective through a stale cue.

### Authority boundary

- Cues influence retrieval relevance only.
- They do not create goals, tasks, approvals, follow-ups, bridges, or writes.
- Source memories remain independently inspectable and deletable.

Operator note: Call them Retrieval associations: useful routing, never autonomous intent.

## 8. Impact and evaluation

Observed behavior stays separate from illustrative estimates.

> Impact never claims provider billing, savings, relevance, correctness, or avoided work.

### Observed scorecard

- Counts non-empty dashboard recalls and bridge or graph-neighbor routing.
- Reports backend p50/p95 latency, response-byte token estimates, and warm coverage.
- Delivery ACK ratio is reliability evidence, not a quality score.

### Cost what-if

- The operator supplies a token rate and tokens-per-assist assumption.
- The dollar result is illustrative equivalence only.
- Coverage excludes MCP, CLI, and agent hydration traffic.

### LongMem evaluation

- Bounded artifacts cover factual, temporal, update, abstention, and visual dimensions.
- The official adapter lane stays isolated from live operator memory.
- A benchmark gate supports comparison, not universal certification.

### Interpretation

- Non-empty recall is yield, not proven relevance.
- Latency covers backend retrieval, not complete client experience.
- Resource evidence is not external Instruments or Metal certification.

Operator note: Prefer a small defensible claim with visible coverage over an unclear impressive number.

## 9. Cortex Governor and Goal Ledger

Typed work state preserves intent, evidence, risk, and next action.

> The governor disciplines work; it never replaces operator approval or turns relevance into authority.

### Session lifecycle

- Enter with agent, mode, and task.
- Tick with observation, proposed action, files, tools, mutation intent, and confidence.
- Commit typed evidence and close or wrap when the task ends.

### Typed traces

- Goal, decision, constraint, implementation, validation, risk, correction, and follow-up stay distinct.
- Truth posture, confidence, evidence, agent, and session identity remain attached.
- Promote and Demote apply to governed traces, not arbitrary memories.

### Goal Ledger

- Goals carry owner, state, evidence, and next action.
- Active goals appear in Start Work and Cortex across CLI, MCP, and dashboard.
- A goal records coordination state; it does not authorize unrelated mutation.

### Guardrails

- Undeclared mutations, sensitive paths, and high-impact tools produce warnings.
- Cross-process closure prevents resurrection of ended sessions.
- An idle Cortex is normal before work begins.

Operator note: Store verified outcomes and concrete follow-ups, not speculation that could look factual later.

## 10. Delivery and operational integrity

Bounded leases and exact receipts protect agent context.

> Delivery is at-least-once with stable identity; consumers deduplicate and acknowledge exact receipts.

### Hydration

- Agent Brief combines leased events, recall, graph, Cortex state, and goals.
- Startup hydration does not acknowledge unseen events.
- Compact output retains visible receipts or releases the lease.

### Receipt lifecycle

- A receipt is acknowledged only after successful delivery.
- Expired work gets a new fenced receipt with stable delivery identity.
- Release and dead-letter remain explicit operations.

### Failure semantics

- Deterministic invalid requests finish terminally and are not replayed.
- Genuinely uncertain commit state stays outcome-unknown and is never auto-replayed.
- Only pre-connect failure may retry the same signed request once.

### Capacity

- Response channels and scans are bounded to protect core and client context.
- Terminal rows age out; sustained throughput remains finite until pruning.
- Rich dashboard views stay separate from compact MCP projections.

Operator note: A response without matching receipt and delivery identity is incomplete delivery evidence.

## 11. Evidence, recovery, and multi-Mac

Preserve database, capture, media, and authority as one verified story.

> Use paired signed recovery or target-bound replication, never an ad hoc live SQLite copy.

### Recovery point

- A verified pair seals the immutable database snapshot and capture state.
- Referenced media derivatives are included by exact reference and digest.
- Isolated restore proof runs before the artifact is trusted.

### Evidence pack

- A readiness report and pinned recovery bundle preserve one run's proof.
- Certification checks core, embeddings, write, recall, App Preview, wrap, and dashboard smoke.
- Evidence is time-bound and must be refreshed for a new handoff.

### Offline replication

- Checkpoints are signed, paired, capability-negotiated, and target-bound.
- The receiver proves an isolated restore before signed acknowledgement.
- Any future live adoption requires a separately governed procedure; promotion is not supported here.

### Handoff rule

- Quiesce the writer before final checkpoint creation.
- Current replication stops at isolated stage and signed ACK with promotion_supported false.
- Any later live use or return transfer needs separate governance; never improvise a two-way merge.

Operator note: Signing protects authenticity, not confidentiality; transfer through encryption.

## 12. Safe release lane

Strong primitives exist; a conventional executable product does not yet.

> Production-ready local runtime and downloadable executable product are separate milestones.

### Working today

- A verified checkout runs the core, dashboard, CLI, MCP, capture, recovery, and offline replication.
- Source inspection, preservation, compatibility, and inactive staging exist.
- Readiness and replacement gates prove the installed checkout before launch.

### Dormant substrate

- Provenance, layout, environment evidence, staging, and activation journals fail closed.
- They verify authority but do not compose one unattended cutover executor.
- Current evidence profiles do not form complete activation authority.

### Not yet claimed

- No signed and notarized macOS app or package is published.
- No offline installer, automatic migration, or executable rollback exists.
- No CI-backed multi-host canary proves unattended adoption.

### Safe order

- Verify provenance and compatibility; preserve state; stage immutably.
- Journal cutover, prove environment and equivalence, then commit the floor.
- Reconcile or roll back through evidence, never manual file replacement.

Operator note: Dormant release primitives are safety foundations, not an executable updater.

## 13. Capability boundaries and checklist

Treat unsupported capabilities as unavailable, never implied.

> SYNAPSE-S2 is production-usable local memory, not yet an unattended downloadable multi-host product.

### Memory boundaries

- No in-place text or ganglion editor and no neuron reassignment.
- No namespace rename, archive, or delete lifecycle.
- No freeform relationship topology or weight editor.

### Intelligence boundaries

- Associations and Memora cues route relevance only.
- Vision features are not a VLM or identity system.
- Impact and benchmarks do not prove truth or savings.

### Before host handoff

- Drain capture and establish one active writer.
- Create a signed target-bound checkpoint and use encryption.
- Prove isolated restore before ACK; treat live adoption as unsupported until separately governed.

### Before release claims

- Verify the exact commit independently on every remote.
- Separate publication, installation, launch, and live readiness.
- Name missing installer, migration, rollback, and canary work plainly.

Operator note: If evidence is stale, refresh it. If state may diverge, stop one writer before creating another.

## Source anchors

- [README](../../README.md) - active CLI, MCP, dashboard, capture, retrieval, media, governance, and recovery behavior.
- [Authoritative Core Operations](../../docs/AUTHORITATIVE_CORE_OPERATIONS.md) - authority, readiness, replacement, and recovery procedures.
- [Bridge Governance](../../docs/BRIDGE_GOVERNANCE.md) - namespace isolation and reviewed one-hop recall.
- [Memora Shadow](../../docs/MEMORA_SHADOW.md) - Retrieval association planning and cue governance.
- [Frontier Enhancements](../../docs/FRONTIER_ENHANCEMENTS.md) - image, evaluation, Impact, and future boundaries.
- [Production Gap Audit](../../docs/PRODUCTION_GAP_AUDIT.md) - implemented controls and productization nonclaims.
- [Multi-Mac Replication](../../docs/MULTI_MAC_REPLICATION.md) - signed target-bound offline handoff.

## Regeneration

Use a disposable documentation environment; do not add these rendering tools to the SYNAPSE-S2 runtime environment. The checked-in images were rendered with ReportLab 4.4.9, Python 3.12, and Poppler 26.05.0.

```bash
PDFTOPPM="$(command -v pdftoppm || true)"
test -x "$PDFTOPPM" || { printf '%s\n' 'Poppler pdftoppm is required' >&2; exit 1; }
"$PDFTOPPM" -v 2>&1 | grep -F '26.05.0' >/dev/null || { printf '%s\n' 'Poppler 26.05.0 is required for byte-stable regeneration' >&2; exit 1; }
uv run --isolated --no-project --python 3.12 --with 'reportlab==4.4.9' \
  python scripts/synapse_status_report.py --visual-docs \
  --visual-revision "$(git rev-parse --short=7 HEAD)" \
  --visual-source-date "$(date +%F)" \
  --visual-pdftoppm "$PDFTOPPM"
```

`uv run --isolated --no-project` keeps ReportLab out of the project `.venv`; Poppler remains a separately provisioned executable. Neither tool is a SYNAPSE-S2 runtime dependency.
