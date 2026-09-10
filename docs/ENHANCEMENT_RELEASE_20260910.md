# September 2026 recall and operator-trust enhancement

This release improves read latency and dashboard reliability while preserving
the governed writer, namespace boundaries, recovery admission, and uncertain
request history. Source capability and a host's accepted runtime remain
separate: a checkout alone does not activate these changes.

## Included changes

- Retrieval v2 records content-free phase timings for queue wait, embedding,
  namespace/revision lookup, candidate lookup, graph expansion, ranking, and
  serialization. Timings are excluded from semantic result identities.
- Candidate lookup ranks the same bounded rows with the same score and tie
  order, then decodes and redacts only the selected records. No cross-request
  retrieval cache or new scoring weights are introduced.
- Jaccard similarity uses the exact integer identity
  `|Q union T| = |Q| + |T| - |Q intersection T|`, avoiding an unnecessary union
  allocation. The store still derives the denominator from the actual trace
  intersection, preserving prior behavior when a derived index disagrees.
- Dashboard availability derives from fresh authority, backend-lane, and
  capture evidence. Initial labels are unverified; stale or unauthenticated
  observations cannot turn indicators green. Actual process memory is labeled
  separately from the topology estimate.
- Runtime, graph, namespace map, and gallery retain separate freshness and
  recovery state. Context switches and failed requests cannot publish obsolete
  responses or start overlapping retries.
- The gallery uses a bounded authoritative image listing, projecting only
  display metadata from typed image records. Older images remain discoverable
  even when more than 200 newer text records exist. It does not transmit full
  text, vectors, or arbitrary metadata.
- Ordinary namespace-map requests default to lightweight data. Explicit
  enrichment has one bounded worker, revision-aware caching, a calculated-at
  time, and cheap status reads. Revision observation covers database commits,
  store replacement, and bridge expiry; unknown or old evidence becomes stale.
- Hygiene scans advance one bounded page per request and bind their cursor to
  one exact namespace and revision. Reports expose coverage, configured
  category counts, and provisional duplicate-to-survivor mappings. Partial
  scans cannot establish absence of findings across a namespace. A hygiene
  review backlog does not mean the core is unavailable.
- Manual capture processing through a governed CoreClient is rejected before
  transport changes or capture-lock acquisition. Certification polls the
  embedded worker. Uncertain capture responses retain validated reconciliation
  handles when they are available.

## Mathematical research decisions

The accepted optimization changes when records are decoded, not the candidate
set or ranking equation. The copied-corpus comparison checks the entire
semantic response, including scores and provenance, after removing only timing
observations. Randomized and boundary checks establish the integer Jaccard
identity independently of its implementation.

Several additional ideas were evaluated with Claude Fable and the existing
NotebookLM Memora and Agent Quality notebooks, then checked against source and
primary research. They remain experiments rather than enabled optimizations:

| Idea | Evidence and release decision |
|---|---|
| Reciprocal Rank Fusion | `score(d) = sum_r 1 / (k + rank_r(d))` combines rankings without assuming comparable score scales. The original paper uses `k=60`. This would change SYNAPSE ranking, so it needs held-out relevance judgments and non-regression in Recall@k, MRR and nDCG before adoption. [Cormack et al., SIGIR 2009](https://cormack.uwaterloo.ca/cormacksigir09-rrf.pdf) |
| Upper-bound pruning | WAND's two-level evaluation is relevant to skipping candidates that cannot beat the current threshold. Applying it here requires sound bounds for every score contribution and the tie rule, including graph and prior terms. Those bounds have not been established. [Broder et al., CIKM 2003](https://research.ibm.com/publications/efficient-query-evaluation-using-a-two-level-retrieval-process) |
| Memora abstraction and cue anchors | The paper separates primary abstractions, concrete memory values and cue anchors, then uses policy-guided retrieval. Its results motivate bounded experiments with this repository's existing Memora surfaces; they do not prove that a new local policy or abstraction rewrite preserves current memories or retrieval quality. [Xia et al., 2026](https://arxiv.org/abs/2602.03315) |
| Cosine/normalization simplification | Dot product equals cosine mathematically for unit vectors. Removing normalization or changing top-k preprocessing can change floating-point ties and selected spikes. Neither is included without exact parity evidence. |
| Cross-request embedding or result caches | Potential benefit must exceed invalidation complexity. Model/build identity, namespace scope, deletion, restore, revision and deterministic inference all need coverage. The measured latency target is reached on the copied corpus without such a cache. |

NotebookLM suggestions and model reviews are research input, not proof. In
particular, analogies to Apple Vision/OCR settings do not establish exact
pruning bounds or normalized embedding behavior in this system.

## Validation and host activation

The portable benchmark is deliberately read-only and content-free:

```bash
.venv/bin/python scripts/benchmark_recall.py \
  --repo "$PWD" --host-label '<verified host label>' \
  --output '/absolute/private/evidence/recall.json' --execute
```

Run it against an accepted production core. It records its fixed Retrieval v2
request, pinned model/configuration, authority identity, corpus revisions,
result identities and wall times. It excludes one warm-up from three measured
samples. Compare only matching request and corpus conditions; certification
writes may change a live corpus, so copied-corpus parity and live readiness
are independent evidence.

Run the Python unit suite and `node --test tests/test_dashboard_refresh_behavior.cjs`.
Retain the retrieval quality/semantic parity measurement, host identity,
source commit and build, namespace counts, signed recovery/isolated restore
proof, and benchmark JSON in the host's acceptance record.

Use [the authoritative-core replacement procedure](AUTHORITATIVE_CORE_OPERATIONS.md)
for activation. Preserve existing work before updating a checkout. Keep
writers and respawners quiescent through signed staging, certification and
final admission; restore their prior policies only after fresh accepted core
and capture health. Do not bypass failed admission with a direct launch or
unreviewed database rollback.

For a second Mac, transfer the reviewed source commit or Git bundle and repeat
its own tests, quiescence, recovery, certification, admission and benchmark.
Do not copy the first Mac's database, binding, private recovery key, runtime
state, client configuration, or authority evidence.

## Evidence boundaries

A dashboard hygiene scan reads at most 50 entries per request and 20,000 per
session. Four sessions, a 30-minute refreshed idle lifetime, 200 returned
candidate mappings, and an 8 MiB estimated retained-payload budget bound its
work and bookkeeping. The estimate is not a process RSS cap. Full-source
records must also fit the configured core response frame (normally 1 MiB);
an oversized page fails closed rather than silently truncating source text.
Current paging does not automatically reduce a page on a frame-size failure.

Enrichment's duration bound controls whether a result is accepted; it does not
forcibly cancel an ongoing backend operation. A late result is discarded, and
the single worker remains occupied until that operation returns.

A complete hygiene scan establishes only its configured checks at its recorded
revision. It is not a cleanup-preservation certificate. Deletion requires its
own reviewed candidate/survivor mapping, must-retain probes and explanation of
removed edges; this release performs no automatic cleanup.

Historical requests with unknown outcomes remain unresolved until exact
authoritative evidence supports a disposition. Owners and intended follow-up
can be recorded without replaying a mutation or fabricating completion.
Receipt consumption, delivery backlog, bridge-expiry materialization and
recovery readiness are distinct obligations; none is inferred from a green
dashboard or a passing source test suite.
