# Memory confidence gate

The memory confidence gate is a compact, deterministic regression test for the
behaviors SYNAPSE-S2 must preserve as long-horizon memory features evolve. It
adapts the evaluation *dimensions* described by
[LongMemEval](https://arxiv.org/abs/2410.10813) and
[LongMemEval-V2](https://arxiv.org/abs/2605.12493), then adds SYNAPSE-specific
namespace, image, and deletion safety cases.

It is not a run of either official benchmark. It does not claim their scores,
their scale, live-corpus relevance, or downstream answer accuracy.

## What it proves

Every run creates a private disposable repository and SQLite store, uses the
offline deterministic `semantic-hash` provider, and performs no LLM or network
call. It never discovers or opens the installed authoritative database.

The gate requires all of these cases to pass:

| Dimension | Deterministic proof |
|---|---|
| Static state | A stable environment fact is returned by identity. |
| Dynamic tracking | An update to the same tag keeps one stable memory identity and exposes revision 2. |
| Workflow knowledge | A multi-step recovery runbook is recalled by its fixture marker. |
| Environment gotcha | A secure-launcher/bookmarked-loopback failure mode is recalled. |
| Premise awareness | A query whose unique premise marker is absent returns no evidence containing that marker. Unrelated low-score results do not count as support. |
| Factual recall | A precise access-window fact is returned by identity. |
| Update/supersession | The current marker is retrievable while the retired marker no longer occurs in application-visible retrieval or stored metadata. |
| Temporal order | Both event nodes are recalled and a stored `temporal_next` edge points from the earlier event to the later one. |
| Abstention | A never-seen marker has zero qualified evidence. This is evidence-level abstention, not an answer-model test. |
| Bridge isolation | Local recall cannot see the approved neighbor; connected recall can see that neighbor but cannot see an unbridged decoy namespace. |
| Image-description recall | An image-typed memory is recalled from its explicit description while the original is not retained. |
| Deletion residue | Confirmed memory prune plus revision-guarded media prune leaves zero rows in application tables, zero retrievable marker hits, and zero node-local cache objects. |

Deletion fidelity is deliberately scoped: the result proves logical
application-visible deletion in the disposable SQLite store and the node-local
derivative cache. It does not prove forensic free-space erasure or deletion
from replicas and historical backups.

## Run it

```bash
.venv/bin/python scripts/measure_memory_confidence.py \
  --latency-samples 3 \
  --code-commit "$(git rev-parse HEAD)" \
  > /tmp/synapse-s2-memory-confidence.json
```

The command emits one machine-readable JSON report to standard output and
returns `0` only when every gate passes. It deliberately has no file-output
option, so it cannot overwrite or follow an operator-provided output path.
Redirect only to a reviewed path if a durable report is needed.

Warm p50/p95 query latency is recorded for trend inspection but excluded from
acceptance; synthetic timing is not a service-level objective. Acceptance
thresholds are exact and fail closed if removed or weakened.

Run the harness tests with:

```bash
.venv/bin/python -m unittest tests.test_memory_confidence_measurement -v
```

## How it complements Retrieval v2 acceptance

`scripts/measure_retrieval_v2.py` remains the broader ranking harness: it
measures Recall@k, MRR, nDCG, duplicate control, score/provenance contracts,
namespace leakage, deterministic insertion order, and read purity. The memory
confidence gate imports its canonical JSON, percentile, and identity helpers,
then tests state evolution and governed deletion. Keeping the gates separate
makes the claims legible:

- Retrieval v2 acceptance asks, “Does this ranked retrieval implementation
  remain relevant, deterministic, scoped, and read-only on its fixed corpus?”
- Memory confidence asks, “Does the end-to-end memory substrate preserve the
  minimum long-horizon behaviors and remove its derived image state when
  explicitly pruned?”

Neither synthetic gate replaces periodic live-corpus sampling, official
LongMemEval/LongMemEval-V2 evaluation, target-Mac certification, or operator
review of sensitive and stale memory.
