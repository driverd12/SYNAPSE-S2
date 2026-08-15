# Memora Shadow and governed cue bindings

Memora Shadow remains a bounded, deterministic proposal planner inspired by
the Memora paper's abstraction/cue/consolidation ideas. Its plan is read-only,
but reviewed learned proposals now have a separate governed lifecycle:
propose, independently review and promote, audit, revoke, or supersede. A
valid promoted binding contributes bounded cue routing to Retrieval v2 without
rewriting its source memories. Planner schema: `synapse-s2.memora-shadow.v1`.

## What it is, honestly

- **Pretrained embedding inference, nothing else.** When the pinned local
  neural provider (`mlx-neural`) is active, `learned: true` means the plan
  used pretrained embedding *inference*. It is **not** fine-tuning, **not**
  LLM content merging, **not** GRPO or any reinforcement learning, and
  **not** automatic promotion. With the deterministic `semantic-hash`
  fallback provider the plan reports `learned: false` and its clusters are
  hash projections, not learned semantics.
- **A plan never applies itself.** Every planner response carries `mode: "shadow"`,
  `applied: false`, and `retrieval_effect: false`, and the token-contract
  projector refuses to serialize a payload that claims otherwise. Running a
  plan alone persists nothing and changes no retrieval result. Only a distinct
  governed proposal followed by an explicit, confirmed promotion can affect
  routing.
- **Source rows stay immutable and independently deletable.** The planner
  only reads existing rows; it never rewrites, merges, or links them.
  Deleting any source memory simply removes it from future snapshots.

## Scope and bounds

- Exactly **one namespace** per plan (`context_id`), never the implicit
  `global` namespace and never connected/bridged scope.
- At most **64 entries**, **65,536 embedded input bytes** (1,024 per
  entry), **16 clusters**, and **8 proposed cues per cluster**.
- Snapshot stability mirrors Retrieval v2: the namespace revision is read
  before and after the bounded read, one retry is allowed, and a second
  moving snapshot fails closed.

## What gets embedded

Only already-redacted durable source text plus an explicit whitelist of
structured fields: `tag`, `display_label`, `display_summary`,
`semantic_facets`, `keywords`, and `detail_badges`. Everything else is
structurally excluded: arbitrary metadata, filesystem paths, spike/neuron
indices, media/feature bytes, embedding provenance, harmonic scaffolds, and
Cortex evidence. Every fragment is re-redacted before embedding, and
redaction always runs on the full stored value **before** any truncation —
truncating raw text first could cut a credential at a length boundary into
an unrecognizable tail. Only already-redacted text is collapsed and
truncated; oversized raw fragments are dropped outright rather than
truncated. Whitelist fragments that trip redaction are dropped entirely
(fail closed), and the plan reports drop/rewrite counts. Raw embeddings
never appear in any response, and `raw_input_stored` is always `false`.

## Determinism and provenance

For a fixed snapshot and provider the plan is byte-identical across repeats
and independent of row insertion order: entries are processed in ascending
`memory_id` order, greedy leader clustering uses stable lexicographic
tie-breaks, floats are rounded, and every collection is sorted. Entries
whose stored embedding provenance conflicts with the active pinned
provider/model/revision are excluded as `provider-mismatch` rather than
mixed into an incompatible vector space. Each plan reports the snapshot
`source_revision`, the provider identity (provider, type, model, revision),
every excluded entry with a reason, and for each cluster the medoid, member
memory ids, cosine similarity statistics, and all contributing source ids
(the content-addressed `s2_…` stable memory ids).

## Planner surfaces (all read-only)

- Core operation `memora_shadow_plan` (`retry_safe`, non-mutating, never
  journaled) plus `CoreClient.memora_shadow_plan(...)`.
- MCP tool `plan_spiking_memora_shadow` (readOnlyHint) through the compact
  token contract (`memora-shadow` surface, 16 KiB default budget).
- CLI `synapse_cli.py memora-shadow --context <id>`; it requires the
  reviewed core binding or an explicit `--memory-db` path and refuses to
  create an implicit repo-local database.
- Dashboard `GET /api/memora-shadow` and the small footer "Shadow" drawer,
  which render proposals with the same never-applied caveat.

## Governed lifecycle

`memora-propose` recomputes the reviewed plan server-side and persists only a
bounded projection: source lifecycle witnesses and short redacted cue terms
marked `untrusted-derived-routing-evidence`. It stores no source text, vectors,
content digest, signature, or public equality oracle. Promotion requires an
exact binding revision, `--confirm`, an independently named reviewer, and the
same ready pinned local neural provider identity. There is no automatic
promotion.

```bash
.venv/bin/python synapse_cli.py --json memora-propose \
  --context default \
  --plan-digest '<reviewed plan_digest>' \
  --cluster-ordinal 0 \
  --reason 'reviewed cue proposal'

.venv/bin/python synapse_cli.py --json memora-promote \
  --binding-id '<binding_id>' \
  --expected-revision '<revision>' \
  --reviewed-by '<independent reviewer>' \
  --reason 'approved bounded routing cue' \
  --confirm
```

List/get/history/audit surfaces are bounded and integrity-checked. Reject,
revoke, and supersede use exact revision compare-and-swap. Every lifecycle
transition is written with its catalog projection and append-only governance
receipt in one SQLite transaction. Retrieval revalidates the catalog,
projection, last receipt, provider identity, and every source witness; any
drift makes the binding ineffective without deleting its sources.

## Recovery, replication, and readiness

Recovery bundle v3 signs a content-free `memora_integrity` aggregate covering
every catalog, binding projection, and governance-event receipt. It records
only revisions and counts, including effective/promoted/provider-drift/source-
drift totals; raw cue terms, source text, and vectors are explicitly absent.
The aggregate is recomputed from the immutable backup, the isolated restore,
and each replication-stage replay. Any omission, tamper, broken chain, provider
drift, or source drift blocks recovery readiness. Legacy v1/v2 bundles remain
inspectable and restorable, but are cutover-ready only when immutable inspection
proves they contain zero Memora catalogs, projections, and receipts.

Operator readiness, cutover attestation v3, and replacement admission v5 bind
the exact same aggregate. Neural replacement staging performs a bounded local
provider readiness check from the closed CoreConfig before it can publish a
recovery point. The staged replica remains isolated; this proof does not grant
replication permission to overwrite live memory.
