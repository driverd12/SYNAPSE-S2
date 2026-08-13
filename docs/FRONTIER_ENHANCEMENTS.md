# Frontier enhancement roadmap

Last reviewed: 2026-08-13

This roadmap translates recent primary research into bounded SYNAPSE-S2 work. It does not treat paper benchmarks as guarantees for this implementation. Every retrieval, compression, or representation change must earn promotion through local accuracy, latency, resource, privacy, and deletion-fidelity tests.

## Ranked opportunities

1. **Local multimodal image memory.** Start with transient source handling, a low-resolution thumbnail, an explicit searchable description, and bounded deterministic pixel descriptors. Apple Vision provides local [image feature prints](https://developer.apple.com/documentation/vision/vngenerateimagefeatureprintrequest) and [text recognition](https://developer.apple.com/documentation/vision/vnrecognizetextrequest) for a later versioned enrichment lane. Feature prints support image similarity, not text-to-image semantic search. [SigLIP 2](https://arxiv.org/abs/2502.14786) and Apple [FastVLM](https://github.com/apple/ml-fastvlm) are later options, not baseline dependencies.
2. **Proof and impact telemetry.** Adapt a small deterministic fixture set from the evaluation dimensions in [LongMemEval](https://arxiv.org/abs/2410.10813) and multimodal [LongMemEval-V2](https://arxiv.org/abs/2605.12493): factual recall, updates, temporal reasoning, workflows, environment gotchas, premise awareness, abstention, image evidence, bridge isolation, and deletion. Report accuracy or recall, bounded-context bytes/tokens, p50/p95 latency, cache hits, deduplication, and deletion residue. Dollar output is only an equivalent estimate based on a user-configured input-token rate; it is not a bill or proven counterfactual saving.
3. **Compact abstractions and cue anchors.** Borrow the separation in [Memora](https://arxiv.org/abs/2602.03315): preserve a source-backed memory value while indexing a compact primary abstraction and multiple cue anchors. Future image OCR, learned features, and visual identifiers can become cues linked to the typed image-memory record. Generated cues must remain versioned, attributable, reviewable, and regenerable.
4. **Type-aware evidence retrieval.** Make neuron types affect retrieval budgets, not only presentation. Route and fuse bounded evidence from facts/text, temporal transitions, procedures/gotchas, files, and images. LongMemEval-V2's structured pools are evidence that typed observations, events, and strategy notes are worth testing; they do not prove that its reported gains transfer to SYNAPSE-S2.
5. **Bi-temporal validity and supersession.** Evaluate `valid_from`, `valid_to`, `recorded_at`, `supersedes`, and source-event provenance, following the temporal context-graph direction in [Zep/Graphiti](https://arxiv.org/abs/2501.13956). Current-fact recall and historical recall must be explicit modes, with deterministic late-arrival and contradiction tests.
6. **Bounded graph activation.** Test a HippoRAG 2-inspired Personalized PageRank reranker seeded by existing spike, semantic, and surface matches. [HippoRAG 2](https://arxiv.org/abs/2502.14802) reports stronger associative retrieval in its own setting. SYNAPSE-S2 must cap hops, honor approved bridge scope, preserve direct-retrieval fallback, and prove that graph propagation does not leak or over-amplify weak links.
7. **Salience-guided memory hygiene.** Explore novelty, correction value, task impact, verification, and observed reuse as review signals, informed by surprise-driven memory in [Titans](https://arxiv.org/abs/2501.00663) and evolving structured notes in [A-MEM](https://arxiv.org/abs/2502.12110). These signals may prioritize or propose archival; they must not silently delete durable memory.
8. **Compact embeddings and prompt packing.** The deployed Qwen3 embedding family supports custom Matryoshka dimensions ([official repository](https://github.com/QwenLM/Qwen3-Embedding)). A smaller shortlist plus full-vector rerank may be worth benchmarking. [RaBitQ](https://arxiv.org/abs/2405.12497) is a later high-scale ANN option, while [LLMLingua-2](https://arxiv.org/abs/2403.12968) is an optional post-retrieval compressor. Embedding changes require governed reindexing; prompt compression must be tested for lost negation, qualifiers, provenance, and instructions.

## Implementation boundary

### Shipped foundation

- Local image capture now leaves the operator's source untouched and does not copy or retain it. The dashboard downsamples in browser memory; the CLI validates and holds the source while deriving an owner-only JPEG thumbnail beneath the verified binding data root. Both commit an explicit searchable description plus a bounded `16 x 16 x 3` byte tensor, RGB histogram, edge histogram, and difference bits as typed `image` memory metadata. Thumbnails are served only through the authenticated dashboard capability. This baseline deliberately does not claim OCR, learned visual semantics, source retention, or backup/replication coverage for the thumbnail cache.
- The hidden far-right footer Impact drawer records one content-free, all-namespace aggregate of dashboard recall counters, non-empty yield, bridge/graph evidence assists, bounded recent backend-retrieval p50/p95 latency, response-byte token estimates, trace-cache occupancy, delivery acknowledgements, and topology headroom. It does not yet cover MCP, CLI, or agent hydration. Its editable dollar figure is a `$0`-to-upper-bound what-if range; it is not billing or proven savings.
- Image-cache integrity has a content-free audit, owner-only layout checks, atomic publication, deterministic retry binding, and revision-guarded orphan pruning at the module boundary. Whole-memory deletion parity, authoritative media-reference enumeration, recovery inclusion, and a governed operator prune surface remain prerequisites before promising complete derivative deletion.

### Next, after the baseline passes

- Add versioned Apple Vision OCR and feature-print enrichment behind an optional, local, resource-bounded lane. Keep those features separate from the deployed text embedding space.
- Add an authoritative media-reference index plus atomic memory-and-derivative prune, backup/restore treatment, and deletion-residue tests before treating thumbnails as durable artifacts.
- Add a compact deterministic proof harness covering recall quality, stale updates, abstention, bridge scope, image lookup, resource bounds, and derivative deletion. The [Forgetting Residue Score study](https://arxiv.org/abs/2606.10062) is a useful warning that raw-only deletion can leave derived memory recoverable, not independent proof about SYNAPSE-S2.
- Add versioned cue anchors and primary abstractions without replacing source-backed memory.
- Add deterministic type-aware retrieval budgets and fusion, then compare them with the current retrieval path.
- Add bi-temporal validity and supersession only with late-arrival, conflict, historical-query, migration, backup, and restore coverage.

### Defer until benchmarked

- Personalized PageRank or other graph propagation across memory and approved bridges.
- Persistent VLM loading, automatic captioning, or SigLIP-style cross-modal indexing. Any optional visual model must be on-demand, resource-gated, unloadable, and locally measured before promotion.
- Embedding-space migration, Matryoshka shortlists, binary/vector quantization, or broad prompt compression.
- Automatic salience deletion or self-modifying memory summaries.

Raw image bytes are not themselves a semantic representation: a decoder and feature extractor must convert them into numeric features, OCR, or descriptors. In the shipped foundation, ordinary text recall uses the operator description while deterministic pixel descriptors remain machine-readable metadata for inspection and future visual retrieval; the descriptor is not mixed into the deployed text embedding space.
