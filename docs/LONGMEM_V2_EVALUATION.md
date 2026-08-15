# LongMemEval-V2 Evaluation Lane

`longmem_eval.py` + `scripts/measure_longmem_v2.py` implement an offline,
deterministic evaluation lane that is **compatible with the LongMemEval-V2
interaction contract** — trajectories are inserted sequentially and questions
are answered with compact text/image evidence — while staying honest about
what it does and does not prove.

## Pinned official-harness runner

`scripts/run_longmem_v2_official.py` is a separate frontier lane that imports
the official harness without editing its pristine pinned checkout, then adds a
small wrapper-only SYNAPSE lifecycle shim. It never installs dependencies or
downloads data. First run
the content-free registry/preflight check:

```sh
LONGMEM_V2_OFFICIAL_ROOT=/absolute/path/to/pinned/longmemeval-v2 \
LONGMEM_V2_OFFICIAL_DEPS=/absolute/path/to/operator-staged/dependencies \
.venv/bin/python scripts/run_longmem_v2_official.py --verify-only
```

For a full run, the questions, haystack, and trajectories JSON files are
streamed into bounded owner-private copies. The trajectories tree must contain
only regular files/directories; prepare screenshot data in official copy mode,
not symlink mode. The output parent must already exist and the final output
name must not exist—the wrapper stages under its private run root, validates
the result tree, and publishes it once with an atomic no-clobber rename.

Only the pinned harness's reader/evaluator tuning flags are accepted after
`--`; wrapper-owned flags cannot be repeated or overridden. API-key files are
copied into the private run root and removed at completion. Per-question
SYNAPSE memories are closed in a `finally` guard (including failed queries),
while shared memories remain available for the full question stream and are
closed before teardown.

Loading a saved memory requires independent operator provenance:

```sh
.venv/bin/python scripts/run_longmem_v2_official.py \
  --domain web \
  --questions-path /absolute/path/questions.json \
  --haystack-path /absolute/path/haystack.json \
  --trajectories-path /absolute/path/trajectories.json \
  --output-dir /absolute/new/output-name \
  --memory-config-path /absolute/path/synapse-config.json \
  --load-memory-dir /absolute/path/memory_state \
  --expected-artifact-manifest-sha256 <out-of-band-sha256>
```

The expected manifest digest is supplied out of band, never trusted from the
artifact, and is runtime-only—it is not written into a saved memory config.
Verification and wrapper completion records always carry
`official_score_claimed: false`; only a separately reviewed complete official
reader/evaluator run can support a benchmark-score claim.

## This is not the official benchmark

- **No official score is ever claimed.** Every report carries
  `official_score_claimed: false` plus an explicit claim notice, and the
  acceptance gate itself fails if that honesty flag is tampered with.
- The official LongMemEval-V2 setup uses the released corpus (100/500
  trajectory tiers, 451 questions), a Qwen reader, and a GPT judge. This lane
  never downloads anything and never runs a reader or judge model; grading is
  deterministic against fixture judgments.
- The runner records the official contract in each report
  (`official_contract`) so the boundary is visible in the artifact itself.

## Modes

### `synapse-derived` (default)

Runs the version-controlled synthetic multimodal fixture
`tests/fixtures/longmem_v2/benchmark_v1.json`:

```sh
python scripts/measure_longmem_v2.py --code-commit <sha>
```

The fixture covers all five LongMemEval-V2 abilities (`static_state`,
`dynamic_state`, `workflow`, `environment_gotchas`, `premise_awareness`) and
all three horizons, with: state supersession and late-arriving temporal
updates, a false-premise probe, an abstention probe, image memories (one
alive, one deleted), exact duplicates, near duplicates, an over-tie ordering
group, a governed cross-namespace bridge, and an unbridged leak-trap
namespace.

### `official-adapter`

Runs an **operator-prepared local dataset** (schema
`synapse-s2.longmem-v2-prepared.v1`) through the same adapter contract. The
dataset is never downloaded; all four integrity pins are mandatory:

```sh
python scripts/measure_longmem_v2.py \
  --mode official-adapter \
  --dataset-path /local/prepared.json \
  --dataset-sha256 <sha256 of the file bytes> \
  --dataset-version <bounded label> \
  --adapter-sha256 <sha256 of longmem_eval.py>
```

The `--dataset-sha256` pin is verified against the exact bytes that are then
parsed (one bounded read serves both), and `--dataset-version` must equal the
prepared dataset's own `dataset_version` metadata field exactly — a pin that
does not match the dataset's self-declared version is rejected.

A prepared dataset that claims `official_reader_parity: true` is rejected
outright — this harness cannot verify that claim, so it refuses to carry it.
Even a valid official-adapter run reports `official_score_claimed: false`
because the official reader/judge never execute here.

Official-adapter mode always uses the built-in audited adapter
(`longmem_eval.LongMemInsertQueryAdapter`); passing an injected
`adapter_factory` in this mode is rejected. Injected adapters exist only as a
test/ablation seam in `synapse-derived` mode (see below).

## Safety and I/O posture

- Every run builds a disposable temporary store under `/private/tmp` and
  never opens the operator's live database, cache, or services.
- No network access, no LLM calls, offline `semantic-hash` embeddings only.
- Fixed resource bounds (`longmem_eval.RESOURCE_BOUNDS`) are enforced by the
  loaders **before any backend is constructed**: dataset file bytes, backend
  dimension/neurons/top-k/recall counts, namespace/trajectory/turn/question
  counts, per-turn and total text bytes, and per-question
  `result_limit`/`candidate_limit`.
- Output is one canonical JSON report on **stdout only**. There is
  deliberately no output-path option, so the tool can never overwrite a file.
- Exit codes: `0` pass, `1` gate failure, `2` measurement error (error JSON
  still goes to stdout with `official_score_claimed: false`).

## What a passing run proves

| Area | Evidence |
| --- | --- |
| Retrieval quality (fixture-relative) | graded macro Recall@k ≥ 0.75, nDCG@k ≥ 0.7, MRR ≥ 0.7, per-question recall floor ≥ 0.5, sliced per ability and horizon; only `items[:result_limit]` are graded, so over-returning can never inflate scores |
| Query result contract | at most `result_limit` items with unique, ordered, 1-based ranks; violations are counted and hard-gated at zero |
| Namespace isolation | zero leakage outside each question's allowed contexts; scope provenance must authorize every returned item |
| Answer decision (evidence-level) | every applicable question carries an explicit deterministic decision (`qualified` or `abstain`) with its supporting memory IDs; graded questions must decide `qualified` on judged-relevant support within `result_limit`, false-premise/absent-topic probes must decide `abstain` with zero marker-bearing support. This grades the evidence decision only — no reader model runs, so it is **not** a reader-level premise-awareness ability claim |
| Premise/absent-topic evidence hygiene | zero marker-bearing items surface for a false-premise or absent-topic probe (a contamination/leak tripwire, demoted from any awareness claim) |
| Dynamic state | current revision text returned, retired marker invisible, stable memory identity and revision metadata across supersession |
| Temporal-evidence retrieval | governed `temporal_next` relationship present and both evidence turns returned with consistently ordered stored `event_time`s, including a late-arriving earlier event; this grades evidence retrieval, not an ordered final answer |
| Image evidence | expected image memory returned with its `media_id`, raw original never stored |
| Deletion fidelity | deleted memories never returned; zero logical rows, zero surface terms, zero media artifacts (audit + orphan prune); recovery/replication root probes must be clean **when the roots exist** — a never-created root is an unexercised informational probe, not a zero-residue pass |
| Duplicates | exact duplicates collapse (observed source deduplication), duplicate content rate 0; near-duplicate collisions reported informationally |
| Determinism | repeated queries, a fresh backend over the same store, and a fresh store populated in seeded-shuffled trajectory order all produce byte-identical envelopes and equal canonical digests |
| Read purity | full runtime digests (neural arrays, state file, logical DB, physical files) unchanged across every query phase, with mutation tripwires armed |
| Honesty | complete source/provider/scope provenance, uncalibrated confidence contract, `official_score_claimed: false`, scope disclosure present |

Latency (p50/p95), result/evidence bytes with `ceil(bytes/4)` token
estimates, and tracemalloc peak memory are reported **informationally** and
are excluded from acceptance.

## Fixed hard gates

`longmem_eval.SAFE_THRESHOLDS` is the only accepted threshold set. Both the
fixture/dataset loaders and `acceptance_verdict` compare for exact equality
and fail closed (`acceptance-thresholds-weakened`), so the gates cannot be
removed or weakened through data or configuration.

## Known limitations

- The synapse-derived corpus is small and synthetic; passing does not prove
  retrieval quality on live data and is not an official LongMemEval-V2 score.
- Deletion evidence is logical and node-local: SQL rows, surface terms, media
  artifacts, and this run's disposable recovery/replication roots. The
  recovery/replication residue probes are net-new filesystem probes
  introduced by this lane, not audits of any production pipeline; when a
  probe root was never created the probe is reported as unexercised and
  informational.
- Premise-awareness and abstention gates grade the deterministic evidence
  decision (abstain with zero marker-bearing support within `result_limit`).
  No reader model runs, so they demonstrate evidence hygiene and decision
  consistency — they do not measure reader-level premise awareness, and
  awareness is never inferred from unrelated retrieval.
- `embedding_prompt` pins the offline semantic-hash spike channel; it is a
  fixture device, not a claim about production embedding behavior.

## Ablation seam

`run_measurement(..., adapter_factory=...)` (library-level only, never CLI)
accepts a factory returning any object implementing the
`longmem-insert-query-v1` protocol defined by
`longmem_eval.LongMemInsertQueryAdapter`. This allows a future baseline vs
Memora Shadow comparison without importing an unmerged branch, with strict
boundaries:

- Injected adapters are permitted **only** in `synapse-derived` mode;
  official-adapter (pinned) runs always use the built-in audited adapter.
- Every injected adapter's identity is bound explicitly: it must declare the
  `longmem-insert-query-v1` protocol and a bounded public label, and the
  report records its `module.qualname` identity with
  `injected_ablation_adapter: true` and `source_sha256: null` (the adapter
  source hash is claimed only for the built-in adapter).
- A run with an injected adapter never claims offline/live-database/network/
  LLM execution provenance: those fields are `null` with an explicit
  "unverified: injected test adapter" provenance note, because the harness
  cannot attest what arbitrary injected code did.

## Tests

```sh
python -m unittest tests.test_longmem_eval tests.test_longmem_v2_measurement -v
```

covering: fail-closed corpus/fixture/prepared-dataset validation, threshold
tamper rejection, population contract (stable identity, supersession
metadata, fixed-time groups, raw-original refusal), full-report shape and
claims, determinism/purity, residue zeros, per-gate closure mutations,
dataset pin verification, official-adapter + ablation-adapter runs, and
stdout/exit-code behavior including rejection of any `--output` flag.

## Relation to the other gates

This lane complements — and does not replace — the retrieval contract gate
(`scripts/measure_retrieval_v2.py`, `docs/RETRIEVAL_V2_VALIDATION.md`) and
the 12-dimension memory confidence gate
(`scripts/measure_memory_confidence.py`, `docs/MEMORY_CONFIDENCE_GATE.md`).
Those remain unchanged and authoritative for their scopes.
