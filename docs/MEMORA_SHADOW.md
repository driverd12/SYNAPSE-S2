# Memora Shadow v1

Memora Shadow is a bounded, deterministic, **shadow-only** consolidation
planner inspired by the Memora paper's abstraction/cue/consolidation ideas.
It proposes clusters of related durable memories and candidate cue bindings
for **manual review only**. Schema: `synapse-s2.memora-shadow.v1`.

## What it is, honestly

- **Pretrained embedding inference, nothing else.** When the pinned local
  neural provider (`mlx-neural`) is active, `learned: true` means the plan
  used pretrained embedding *inference*. It is **not** fine-tuning, **not**
  LLM content merging, **not** GRPO or any reinforcement learning, and
  **not** automatic promotion. With the deterministic `semantic-hash`
  fallback provider the plan reports `learned: false` and its clusters are
  hash projections, not learned semantics.
- **Nothing is applied.** Every response carries `mode: "shadow"`,
  `applied: false`, and `retrieval_effect: false`, and the token-contract
  projector refuses to serialize a payload that claims otherwise. No plan
  output is persisted anywhere; retrieval results are byte-identical with
  or without a shadow plan having run.
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

## Surfaces (all read-only)

- Core operation `memora_shadow_plan` (`retry_safe`, non-mutating, never
  journaled) plus `CoreClient.memora_shadow_plan(...)`.
- MCP tool `plan_spiking_memora_shadow` (readOnlyHint) through the compact
  token contract (`memora-shadow` surface, 16 KiB default budget).
- CLI `synapse_cli.py memora-shadow --context <id>`; it requires the
  reviewed core binding or an explicit `--memory-db` path and refuses to
  create an implicit repo-local database.
- Dashboard `GET /api/memora-shadow` and the small footer "Shadow" drawer,
  which render proposals with the same never-applied caveat.

## Promotion path

There is none, deliberately. A human reads the proposals and, if convinced,
acts through the existing governed write surfaces. Nothing in Memora Shadow
can apply, persist, or schedule its own output.
