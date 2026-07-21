# SYNAPSE-S2 Retrieval v2 Validation Contract

This document defines what Retrieval v2 does, how to validate it, and what it
does **not** prove. Implementation status is separate from deployment status:
the hardening worktree contains these surfaces, while the live local service
remains on legacy v5 until an independently reviewed authoritative-core cutover.
Nothing here claims an internal-remote or public-GitHub publication.

## Supported recall surfaces

New integrations use one of these equivalent read-only entry points:

```bash
.venv/bin/python synapse_cli.py --json retrieve-v2 \
  --context default \
  --prompt "current task constraints and validated decisions" \
  --scope local \
  --result-limit 8 \
  --candidate-limit 64 \
  --response-mode compact \
  --max-response-bytes 12288
```

```text
MCP tool: retrieve_spiking_memory_v2
```

The authoritative core method is `retrieve_text_v2`; the dashboard query route
and internal agent/Cortex briefing recall use the same domain response. Legacy
CLI `query-text` / `query-vector` and MCP `query_spiking_attention_text` /
`query_spiking_attention` remain available only as deprecated stateful
compatibility surfaces. They are not substitutes for a read-only recall proof.

## Read-purity boundary

One Retrieval v2 request may read durable indexes, relationships, namespace
links, and embedding-provider state needed to encode the query. It does not:

- run the recurrent LIF cycle;
- apply STDP;
- run quick pruning or deep-sleep consolidation;
- write SQLite memory, relationship, link, delivery, or capture rows;
- write runtime state or mark a context active; or
- populate the legacy query-result cache.

The prompt is bounded to 16,384 UTF-8 bytes, redacted before ranking, and
represented in the response by a SHA-256 fingerprint plus redaction count.
`raw_input_stored` is always `false`; the raw prompt is not returned in the
contract or persisted as a side effect of retrieval.

The domain read is an optimistic snapshot. Retrieval records the entry, scope,
and relevant graph revisions before and after candidate collection. It retries
once if the snapshot moves and then fails closed rather than returning a mixed
view.

## Deterministic hybrid ranker

Ranker identity is `synapse-hybrid-mmr` version `2.0.0`.

| Signal | Weight | Meaning |
| :--- | ---: | :--- |
| `spike_index` | 0.55 | Overlap with the durable sparse spike index. |
| `surface_index` | 0.40 | Match against durable bounded tags, labels, summaries, facets, keywords, and source terms. |
| `same_context_graph` | 0.05 | Optional bounded evidence from relationships whose endpoints stay in one namespace. |

The weighted relevance pool is deduplicated and selected with bounded
MMR/Jaccard diversity (`lambda = 0.82`). Ordering ends in stable identity
tie-breakers, and every item identifies the ranker/version that produced it.

Scores are **not calibrated**. `score`, `score_breakdown.relevance_score`, and
`confidence.score` are ranking signals, not a probability that the memory is
true, current, or applicable. Consumers must preserve:

```text
confidence.calibrated = false
confidence.probability = null
confidence.signal = "uncalibrated-ranking-score"
```

Stored `metadata.confidence`, when present, remains source provenance; it does
not convert the retrieval score into a probability.

## Namespace scope and provenance

Every request selects exactly one scope:

- `local`: the selected namespace and its inherited `global` namespace;
- `connected`: local/global plus enabled, approved one-hop namespace links; or
- `all`: an explicit bounded search across every namespace plus global memory.

`all` is never inferred. Connected traversal is one hop only. Every resolved
scope record names its origin and provenance. A connected result additionally
names the exact enabled context-link id, relation type, direction, endpoints,
confidence, approval state, approving identity, and approval/update times that
authorized the crossing.
If that provenance is absent, disabled, directionally invalid, or beyond the
scope ceiling, the result cannot be represented as an authorized connected hit.

Each item also carries stable memory identity, source provenance, optional graph
provenance, match reasons, output-redaction count, and
`raw_source_included: false`.

## Ranked-result completeness

Ranked Retrieval v2 is one bounded snapshot read, not a page stream. It reports
separate flags for:

- namespace/link scope truncation;
- query-term truncation;
- candidate-source/pool truncation; and
- result-limit truncation.

The `memory-retrieval` contract therefore sets `pagination.supported: false`
and `next_cursor: null`. `completeness.has_more: true` means at least one bounded
stage may have more evidence; it does **not** mean a continuation cursor exists.
A caller may deliberately issue a larger request within the documented bounds
or start a new snapshot. It must not splice that new result into the old
snapshot and call the union complete.

Compact output can reduce the effective result limit to fit the selected byte
budget. `pagination.requested_limit` and `pagination.effective_limit` expose
that distinction even though ranked pagination is unsupported.

## Authenticated keyset pages

The memory-list, memory-graph, and Cortex-state read surfaces do support stable
continuation in compact and full modes. Their opaque `s2rc2` cursor binds:

- token-contract schema/version and read surface;
- response mode;
- namespace, recall scope, and all filters;
- complete ordering and unique keyset position;
- content snapshot revision;
- issue and expiry time; and
- local origin node.

The cursor is HMAC-authenticated with a domain-separated owner-local 32-byte
key. The key's parent must be an owner-controlled `0700` directory and the key
must be a regular, owner-only `0600` file; symlinks, hard links, wrong owners,
wrong sizes, or broader modes fail closed. The default cursor lifetime is 900
seconds and the implementation ceiling is 3,600 seconds. A cursor conveys no
write authority.

| Surface | Stable page ordering | Snapshot contents |
| :--- | :--- | :--- |
| Memory list | `updated_at DESC, memory_id DESC` | Exact selected durable memory rows and bound namespace scope. |
| Memory graph | Independent entry and relationship streams, each ordered by update time then unique id | Exact primary nodes, relationships, and hydrated relationship endpoints. Endpoint-only nodes do not inflate the primary-node total. |
| Cortex state | `updated_at DESC, memory_id DESC` | Exact durable Cortex memories plus the frozen live active-session view for the requested context/agent. |

Cortex uses a composite revision. The durable page revision and live active
session revision are both authenticated, and the response is rendered from the
frozen session copy. An enter, update, close, or removal between pages makes the
old cursor stale, preventing a page sequence from mixing two live governor
states.

Malformed, tampered, expired, stale, wrong-contract, wrong-surface,
wrong-context, wrong-mode, wrong-scope, wrong-filter, wrong-ordering, or
cross-origin cursors fail explicitly. No failure silently restarts at page one.

## Offline acceptance benchmark

Run all Retrieval v2 tests:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_retrieval*.py' -v
```

Run the deterministic offline acceptance fixture:

```bash
.venv/bin/python scripts/measure_retrieval_v2.py --latency-samples 20
```

The versioned fixture is
`tests/fixtures/retrieval_v2/benchmark_v1.json`. It spans local, approved
connected, unrelated, sparse, dense, duplicate, near-duplicate, and exact-tie
cases. Acceptance checks:

- macro and per-query Recall@k, MRR, and nDCG@k;
- zero namespace leakage;
- zero exact duplicate rate and a bounded near-duplicate collision rate;
- positive coverage from spike, surface, and same-context graph signals;
- stable score, confidence, scope, link, graph, and source provenance;
- canonical equality across repeated reads, a fresh backend, and seeded
  randomized insertion order; and
- unchanged neural arrays, runtime fields/file, SQLite database/logical rows,
  and SQLite WAL/SHM/journal state before and after reads, with forbidden
  mutators tripwired.

Latency samples are informational and excluded from acceptance. When a durable
evidence artifact is needed, write the canonical report to a new reviewed path
with `--output`; do not overwrite or reinterpret an older report.

The reviewed Phase 8 artifact is
`docs/evidence/phase8-retrieval-v2-acceptance.json`. It is bound to clean code
commit `738cfceb21aa878aad70cdb219ec370c86a833bc`, has owner-only mode `0600`,
and records a passing synthetic acceptance verdict. The evidence commit that
adds this immutable report is intentionally separate from the implementation
commit it measures.

## Exact current limitations

- The acceptance corpus is fixed and synthetic. A pass does not prove relevance
  quality on live SYNAPSE-S2 memory, operator satisfaction, production capacity,
  concurrency behavior, or a service-level latency objective.
- The fixture uses `semantic-hash`; it does not establish parity across every
  deployable embedding provider or model revision.
- Ranked Retrieval v2 has no continuation cursor. Increasing limits starts a
  new bounded snapshot.
- Exact list/graph/Cortex snapshot revisions hash transaction-coupled,
  per-namespace memory, relationship, and Cortex generations together with
  exact counts and the semantic-index generation. Governed maintenance writes
  and derived spike/surface-index mutations rotate the same relevant namespace
  generation. This removes per-page full-content hashing. The fence depends on
  the authoritative-core rule that
  all writers use governed store connections; unsupported raw SQLite writers
  can bypass the connection-local triggers and must not be introduced.
- Cross-origin cursor rejection is intentional. Multi-Mac replication must
  define its own signed replication/checkpoint protocol; copying a cursor to
  another Mac is not replication.
- Scores are uncalibrated ranking signals and cannot establish truth, freshness,
  causality, safety, or permission to act.
- Compact output may lower the effective hit count to preserve mandatory
  provenance and safety fields within the byte budget.

## Research non-claim

The supplied design material cited S2-Net, Spike Dice Attention (SDA), and
Spiking Graph Transformer Networks (SGTN) as May-July 2026 publications. Those
references were future-dated relative to the supplied design evidence and have
not been independently verified as implementation evidence for this system.
SYNAPSE-S2 does not implement or validate an S2-Net phase-delay engine, an SDA
spike-train attention operator, or an SGTN model. Retrieval v2 and the Namespace
Galaxy are deterministic, operator-governed product mechanisms built from
durable indexes, typed links, bounded graph evidence, and explicit provenance.
