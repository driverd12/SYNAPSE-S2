# Harmonic memory scaffolding

Status: bounded production baseline, 2026-08-13

SYNAPSE-S2 implements a conservative subset of the representation described by
[Memora](https://arxiv.org/abs/2602.03315v2). The paper separates a stable
primary abstraction from concrete memory values and adds multiple cue anchors
so one value can be reached through different vocabulary. This implementation
adopts that separation without importing Memora's LLM extraction, content
merging, learned retrieval policy, or benchmark claims.

## What is implemented

Each newly captured source event has, by default, one co-located metadata object with schema
`synapse-s2.harmonic-scaffold.v1`:

- one stable, context-scoped primary-abstraction ID and label;
- at most eight context-scoped cue-anchor IDs, labels, aspects, and derivation
  bases;
- explicit `untrusted-memory-evidence` trust posture;
- provenance back to the same authoritative `memory_entries` source row;
- lifecycle and retrieval declarations that state the scaffold is regenerable,
  navigation-only, non-learned, and not independent evidence.

The source value remains unchanged in `memory_entries.source_text`. The
scaffold never replaces it and never becomes a second authoritative memory.
Primary and cue labels are merged into `semantic_facets` without removing
caller-provided facets or keywords. Labels and stable IDs are also indexed in
the existing `memory_surface_terms` table, providing a many-to-many implicit
index with no schema migration or free-standing cue nodes.

The generator prefers reviewed operator metadata:

```bash
.venv/bin/python synapse_cli.py --json capture-session \
  --context camera-ops \
  --tag stage-camera \
  --speaker operator \
  --metadata '{"primary_abstraction":"PTZ camera imaging","cue_anchors":["iris control","low-light exposure"]}' \
  --text 'The automatic exposure circuit was tuned for the dark stage camera.'
```

When those fields are absent, the bounded deterministic fallback uses existing
typed context labels, namespace title, display label, semantic facets,
keywords, and structured technical identifiers from the already-redacted
source. It does not call a model or invent synonyms. Set
`"harmonic_scaffold_enabled": false` in capture metadata for a controlled
baseline or rollback comparison.

## Why this helps

The operator can add vocabulary that is not present in the source value. For
example, a source that says `automatic exposure circuit` can be found with the
reviewed cue `iris control`. The cue participates in the existing deterministic
surface-plus-spike fusion rather than starting a separate retrieval engine.
This improves alternate-vocabulary access while keeping the exact source text
available for downstream reasoning and review.

The included fixture proves a real bounded benefit: before adding `iris
control`, the source has only its spike score for that query; after adding the
cue, the enhanced row gains a non-zero surface-index signal and outranks the
otherwise identical baseline. Scores remain relevance signals, not confidence
or truth probabilities.

## Safety and deletion semantics

- IDs are hashes of redacted, normalized navigation labels plus context, not
  hashes of raw source content and not public content digests.
- A cue never crosses a namespace automatically. Context remains part of every
  stable navigation ID and normal bridge governance still controls connected
  recall.
- Metadata, surface terms, and stable IDs are stored on or derived for the same
  source row. Deleting that row cascades its surface-index terms, so one-row
  prune leaves no derivative cue residue for that row.
- Standard JSON export, SQLite backup, and restore preserve the nested metadata
  because no sidecar or new schema object is involved.
- Cue count and text lengths are bounded. Duplicate and generic noisy cues are
  removed deterministically.

## Deliberate limits

This is not full Memora. It does not consolidate updates into a mutable shared
memory value, because that would weaken independent source provenance and
deletion. It does not traverse shared cues beyond the current query, generate
LLM synonyms, refine queries, choose `Expand`/`Stop` actions, or train a GRPO
retrieval policy. The scaffold declares `max_expansion_hops: 0` so those absent
behaviors cannot be mistaken for shipped capability.

Promotion beyond this baseline requires evaluation evidence showing that
bounded cue expansion improves multi-hop tasks without retrieval noise,
namespace leakage, deletion residue, unacceptable latency, or memory pressure.
