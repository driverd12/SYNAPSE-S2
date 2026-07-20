# SYNAPSE-S2 Compact Response Contracts

SYNAPSE-S2 has two different response audiences:

- local agents consuming installed MCP output or the four contracted CLI read
  commands, where every repeated field consumes context-window tokens; and
- the loopback dashboard, where the browser needs the richer graph and
  inspection payloads used to render the operator UI.

Phase 6 keeps those boundaries separate. Installed agent clients default to a
bounded `compact` response. An operator can explicitly request `full` output
for diagnostics. The dashboard continues to use the rich local backend and HTTP
API; the agent contract does not silently reduce the dashboard's graph or
Namespace Galaxy data.

## Installed-client default

`scripts/install_client_configs.py` writes these values into each installed
SYNAPSE-S2 MCP definition:

```text
SYNAPSE_S2_DEFAULT_RESPONSE_MODE=compact
SYNAPSE_S2_MAX_RESPONSE_BYTES=12288
```

The byte value is an exact post-redaction UTF-8 budget for the authoritative
contract JSON document returned as MCP `structuredContent`, excluding outer
JSON-RPC transport framing. MCP also returns one deliberately redundant safety
`TextContent` item: compact responses bound that item independently to 4,096
UTF-8 bytes, while full responses bound it independently to 131,072 bytes.
Neither safety-channel ceiling is included in
`response_contract.serialized_bytes`. These are byte contracts, not claims
about one model's tokenizer. Tokenization varies by model, while UTF-8 byte
length is deterministic across Codex, Claude, the CLI, and regression tests. A
client must be restarted after configuration installation before a new MCP
process inherits these defaults.

The installed 12,288-byte ceiling overrides the projector's standalone default
for MCP calls unless the caller explicitly supplies another valid ceiling. The
contract accepts budgets from 4,096 through 131,072 bytes. Its per-surface
standalone defaults are:

| Contract surface | Default ceiling |
| :--- | ---: |
| `agent-hydration` | 16,384 bytes |
| `memory-list` | 32,768 bytes |
| `memory-graph` | 49,152 bytes |
| `cortex-state` | 16,384 bytes |

Only these four agent-facing surfaces use
`synapse-s2.token-contract.v1`: MCP `hydrate_spiking_agent_context`,
`list_spiking_memory`, `list_spiking_memory_graph`, and
`get_spiking_cortex_state`, plus their CLI `agent-brief`, `list-memory`, `graph`,
and `cortex-state` counterparts. Receipt acknowledgement, release, dead-letter,
repair, backup, morning Start Work, and other fixed-purpose operations keep
their established schemas; they are not passed through a generic lossy
projector.

## Modes

### `compact`

`compact` is the installed-client default. It returns the smallest useful,
provenance-bearing representation of memory, graph, Cortex, and delivery state.
It removes repeated renderings and diagnostic bulk, including full vector/index
arrays, repeated endpoint summaries, redundant Markdown plus JSON copies,
absolute local paths, and repeated provider-detail objects.

Compact mode may omit optional evidence, but it must never become
safety-ambiguous. For every returned delivery or record it preserves the
identity and state needed for the next safe operation, including exact receipt,
delivery, and event ids, acknowledgement requirements, retry/dead-letter
blockers, warning severity, provenance, and truncation/completeness state.

### `full`

`full` is an explicit diagnostic escape hatch. It exposes the established rich
domain payload when an operator or test genuinely needs the omitted metadata,
vectors/indexes, raw redacted event payload, or expanded graph evidence. Full
mode must never be selected automatically because a compact projection is
difficult or because a client supplied an unknown mode. Unknown modes fail
closed.

Full output can be substantially larger than an agent-oriented response. Use a
small item limit, save it to a local file when appropriate, and do not paste it
back into an agent context unless the additional fields are actually needed.
The rich payload is wrapped at `data.payload` inside the same versioned envelope.
It is still recursively redacted, masks local paths, strips untrusted raw-content
digest fields, labels the payload as mixed control and untrusted evidence, and is
bounded: the operation fails when the full serialization exceeds the selected
ceiling. A caller that genuinely needs a larger diagnostic response must
explicitly select a ceiling no larger than 131,072 bytes. Full MCP mode uses its
own independently bounded safety `TextContent` ceiling of 131,072 bytes. The
full-mode escape hatch does not weaken redaction, context isolation, receipt
fencing, confirmation requirements, or any other security boundary.

### `legacy` (CLI only)

The four contracted CLI commands accept `--response-mode legacy` for internal
operator scripts and reports that still consume the established unwrapped
domain payload. It is a deliberate compatibility path, not an installed MCP
profile, and it is never selected as a fallback after a contract error. MCP
accepts only `compact` or `full`. New agent integrations should consume the
versioned compact envelope instead of depending on legacy output.

## Versioned envelope

Every compact or full response contains exactly these top-level fields:

```text
schema, version, operation, ok, data, provenance, warnings,
pagination, completeness, continuation, response_contract
```

`schema` is `synapse-s2.token-contract.v1` and `version` is `1`.
`response_contract` contains `profile`, `max_output_bytes`,
`serialized_bytes`, `estimated_tokens`, `truncated`, and `omissions`.
`estimated_tokens` is only a byte-derived planning estimate; it is never a
budget or correctness signal. `omissions` is an allowlisted section-to-count
map describing optional evidence removed by the bounded projector.

For MCP, this envelope in `structuredContent` is authoritative. The accompanying
single `TextContent` item is a bounded `synapse-s2.mcp-safety-summary.v1` decision
aid and explicitly says `structuredContent_required: true`; it is not a second
complete response. Consumers must validate and use the structured contract for
data, exact receipts, completeness, and omission accounting. The compact
structured document, compact safety text, full safety text, and outer JSON-RPC
framing are four separate byte-accounting domains.

## Response and budget invariants

The compact contract is evaluated after recursive redaction and before a result
is exposed through MCP or emitted by a contracted CLI command.

1. The serialized result is valid canonical JSON: UTF-8, deterministic key
   ordering, compact separators, finite JSON values, and no arbitrary `repr`
   fallback.
2. `response_contract.serialized_bytes` covers the complete contract JSON
   document. It must not exceed the effective `max_output_bytes`; outer MCP
   JSON-RPC framing is not included.
3. JSON bytes are never sliced. The projector shortens an allowlisted text value
   or omits a complete optional section before serialization.
4. Stable identifiers, receipt ids, and contract-defined revisions or cursors
   supplied by a supported surface are atomic. They are either present intact
   or the operation fails; they are never prefix-truncated. Untrusted raw-content
   digest fields are removed rather than promoted into trusted contract data;
   this is not a promise to preserve every producer-supplied field named
   `digest`, `hash`, or `revision`.
5. Every bounded collection reports its returned count. If the authoritative
   producer does not expose an exact total or cursor, `completeness.complete`
   is `null`, its reason says so, and pagination is explicitly marked
   `retrieval-v2-required`; compact output never invents an available count.
6. A projection-truncated response says so explicitly through
   `response_contract.truncated`, the omission count map, and an
   `output-truncated` warning. Source completeness remains a separate
   `completeness` claim and is never inferred from a short array.
7. Safety fields are mandatory. Errors, required actions, `ack_required`,
   `has_more`, blocking delivery state, retry/dead-letter state, exact
   receipt/deployment/event identity, and provenance cannot be dropped to
   satisfy the byte budget. Critical or high-severity warnings, warnings marked
   `action_required`, and protected contract warnings survive projection.
   The protected codes are `ack-required`, `delivery-retry-exhausted`,
   `output-truncated`, and `request-failed`.
   Noncritical warnings may be omitted only as complete items, with the omission
   count recorded under `response_contract.omissions.noncritical_warnings`.
8. Untrusted memory metadata stays under an evidence/provenance field. A stored
   key named `status`, `warning`, or `next_action` cannot impersonate a trusted
   contract field.
9. If the minimum safety envelope cannot fit, projection fails with a bounded
   contract error (`response-budget-invalid` at the public boundary). It does not
   emit malformed JSON, silently switch to full mode, or pretend the result is
   complete.
10. A malformed requested budget cannot expand its own error response. MCP and
    CLI errors retain the valid installed/configured ceiling; if that local
    configuration is itself invalid, they fall back only to the documented
    standalone ceiling for that surface.
11. Contracted MCP calls reject undeclared arguments at the server boundary,
    before FastMCP/Pydantic validation can render an attacker-controlled key or
    value in an exception or warning log. The rejection never reflects the
    rejected material, still returns a bounded structured contract error, and
    applies across the real MCP transport, middleware-bypassed `call_tool`, and
    direct registered-tool `run`/`_run` paths. Transport debug logging is
    content-free. Published tool schemas remain closed with
    `additionalProperties: false`.

The response-contract version is separate from domain protocol versions such as
the context-delivery protocol. Changing projection fields does not rewrite or
reinterpret durable receipt semantics.

## Delivery and acknowledgement invariants

Compaction must not turn at-least-once delivery into an ambiguous acknowledgement
flow.

- Each leased `receipt_id` maps one-to-one to a visible deployment event in the
  same response.
- A receipt is never returned without enough event identity and summary for the
  caller to decide whether it was consumed.
- Compact projection does not acknowledge a receipt or advance a delivery
  cursor.
- The caller acknowledges the exact receipt only after successful use. If the
  result reports more work, it acknowledges or releases the current page before
  requesting the continuation.
- An undersized budget is rejected before leasing. If projection fails after a
  lease was acquired, the acquired receipts are released before the error is
  returned.
- Retry exhaustion, a blocking delivery, and governed dead-letter requirements
  survive every compact projection.

Do not acknowledge a compact deployment until its visible event summary has
actually been incorporated into the caller's work. If that evidence is
insufficient, release the receipt and explicitly request a bounded full
diagnostic hydration; do not acknowledge merely to clear the queue.

## Provenance invariants

Compact memory and graph records retain stable identity and origin even when
bulk metadata is omitted:

- context and memory identity;
- source surface or stored source tag;
- relationship type, direction, weight, and endpoint identity where relevant;
- recall scope and approved-link provenance for connected recall;
- update/order fields currently available from the producer; and
- explicit trust posture identifying stored memory text as untrusted evidence.

Compact graph responses apply that posture to both node text and relationship
text. A stored relationship type is evidence, not an instruction: standalone
memory graphs expose `edge_text_trust`, and hydrated graph summaries expose
`relationship_text_trust`, both as `untrusted-memory-evidence`.

Repeated provider-detail objects, raw vectors, and duplicate node metadata are
not emitted in compact mode. Graph edges refer to stable endpoint ids instead of
repeating each node's labels, summaries, facets, and metadata on every edge.

## Current continuation behavior

Agent hydration uses the durable context-delivery protocol rather than an
invented page cursor. The continuation is a state machine, not one universal
instruction:

| Observed delivery state | Continuation strategy | Required caller behavior |
| :--- | :--- | :--- |
| Hydration ran with claiming disabled | `claim-events-to-observe-delivery` | Claim in a later hydration before concluding the queue is complete. Observation-only output has unknown queue completeness and does not report leased receipts. |
| Claiming enabled, no receipts, no blocker | `hydrate-when-context-expected` | The observed page is idle; hydrate again when new context is expected. |
| One or more receipts, no blocker | `ack-all-receipts-then-hydrate-again` | Consume each visible event, acknowledge its exact receipt only after use, release anything unconsumed, and hydrate again when `has_more` is true. |
| Active lease blocker, no receipts in this page | `wait-for-active-lease-expiry` | Wait until `blocking.lease_expires_at`; never acknowledge another consumer's receipt. |
| Receipts plus an active lease blocker | `ack-receipts-then-wait-for-active-lease-expiry` | Resolve this page's receipts after use, then wait for the other lease to expire before hydrating again. |
| Retry-exhausted blocker, no receipts in this page | `governed-dead-letter-required` | Complete governed dead-letter review before later delivery can advance. |
| Receipts plus a retry-exhausted blocker | `ack-receipts-then-governed-dead-letter` | Resolve this page's receipts after use, then complete governed dead-letter review for the blocker. |

Claiming hydrations use `receipt-fenced-fifo`; observation-only hydration uses
`not-observed`. A receipt and blocker can coexist in one response, so callers
must follow both halves of the combined continuation instruction instead of
assuming the visible receipt page is the whole queue.

Compact memory-list, memory-graph, and Cortex-state responses do not yet claim
cursor pagination. They return `pagination.supported: false`, strategy
`retrieval-v2-required`, `next_cursor: null`, and unknown authoritative
completeness. An operator can request bounded full mode for diagnosis; full mode
does not turn that absence into a cursor.

## Retrieval v2 continuation requirements

Retrieval v2 must use keyset continuation rather than an offset that can silently
skip or duplicate changing data. A continuation must bind the response contract
version, mode, namespace, recall scope and filters, ordering, unique tie-breaker,
snapshot revision, expiry, and origin node. It must be authenticated with a
domain-separated local key.

Tampered, expired, stale-revision, wrong-context, wrong-mode, wrong-filter, or
cross-host Retrieval v2 continuations must fail closed. They must never restart
from page one without telling the caller. Stable ordering must always end in a
unique id tie-breaker.

## Dashboard boundary

The dashboard's loopback-only rich API is intentionally unchanged by the agent
response mode. Browser views may request expanded graph nodes, evidence,
ganglia, neuron provenance, and visual sizing data needed for interactive
rendering. Existing dashboard limits, redaction, context isolation, truncation
signals, and no-write Namespace Galaxy behavior still apply.

Do not pass a dashboard response through the MCP compact projector and do not
change dashboard semantics merely to satisfy an agent token budget. If a rich
HTTP route later needs a smaller network response, version that route
independently.

## Measurement method and acceptance gate

The normative Phase 6 gate is contract correctness, not a target percentage
reduction. The sanitized acceptance snapshot is published at
[`evidence/phase6-token-contract-acceptance.json`](evidence/phase6-token-contract-acceptance.json).
It is bound to source commit `519af911d64a6bf169f55956510969c56205f786`,
used a verified Phase 5 recovery bundle through an isolated disposable restore,
and made no benchmark writes to live state.

The artifact passed all 11 gates across memory list, memory graph, Cortex state,
and agent hydration. Its informational byte measurements are:

- installed policy: 1,200,724 legacy-requested-source bytes versus 38,205
  compact structured bytes, a 96.818% reduction; and
- same source: 106,735 legacy-identical-source bytes versus 23,450 compact
  structured bytes, a 78.03% projection reduction.

Token counts and transport framing are excluded. The measurements are not
interchangeable: installed policy includes compact source caps plus projection,
while same-source holds producer rows and limits constant.

`scripts/measure_token_contracts.py` implements that gate. It verifies the
signed Phase 5 receipt, restores the paired database and capture root into a
private temporary directory, performs benchmark writes only in that disposable
restore, injects synthetic secret and local-path canaries into a rendered field
on every contracted surface, and removes the restore afterward. A run with
`--output` additionally refuses a dirty worktree, binds the report to the same
clean Git revision observed before and after measurement, attests that the
loaded contract modules came from that repository without changing after
import, publishes only aggregate fields, and creates a new evidence file without
following symlinked parents or replacing an existing/racing artifact.

Use an explicit private receipt and its authoritative live database only for
local recovery-identity verification:

```bash
.venv/bin/python scripts/measure_token_contracts.py \
  --receipt "$PHASE5_RECEIPT" \
  --memory-db .synapse_s2/memory.sqlite3 \
  --context default
```

To refresh the snapshot, start from a clean implementation commit and add
`--output` with a new, previously unused repository path under `docs/evidence/`.
The publisher will not overwrite this artifact. Percentage reductions remain
informational observations; they never substitute for the correctness gates
below.

That acceptance run must record, for each compact surface:

- serialized UTF-8 bytes and configured maximum;
- returned item counts and any authoritative total the producer actually
  supplies;
- source-completeness and projection-truncation state as separate fields;
- omission section/count pairs;
- receipt/event one-to-one counts for leased results; and
- deterministic equality evidence from two repeated reads of an unchanged
  fixture, without publishing raw memory text, namespace identifiers, local
  paths, signing material, or source-artifact digests.

Record `before_bytes` from the exact installed-policy legacy request and
`after_bytes` from `response_contract.serialized_bytes`; independently
canonicalize the compact envelope and require the two after values to match.
Installed-policy reduction includes both the compact source cap and projection,
so it must be labeled separately from a same-source projection comparison that
uses identical producer rows and limits. Neither may be presented as the other.
If whitespace-only savings are isolated, record a separate
canonicalized-legacy value instead of replacing the wire baseline. An exact,
locally available named tokenizer revision may be used for an informational
token delta, but tokenizer output is not an acceptance signal. The benchmark
row also records requested and effective limits, profile, omissions,
completeness reason, and code revision so later runs cannot compare different
scopes accidentally.

Installed-client compact responses pass only when authoritative
`structuredContent` is at or below 12,288 bytes without losing a mandatory
safety or provenance field, the separate MCP safety `TextContent` is at or below
4,096 bytes, and independent canonicalization agrees with the declared size.
Transport framing is excluded. Full-mode payloads and their separate 131,072
byte safety channel may be measured for visibility but are not compared to the
compact installed-client budget. The published acceptance artifact verifies
these boundaries independently for every contracted surface.

## Operator checks

After refreshing client configuration, verify the installed values and restart
the client. The operator certifier's required `mcp_contract_probe` calls
`list_spiking_memory` through the installed launcher with compact mode and the
12,288-byte structured ceiling. It fails closed unless the authoritative
`structuredContent` independently canonicalizes to its declared size and the
single safety `TextContent` parses, declares structured content required, and
fits its separate 4,096-byte ceiling. Transport framing is not part of either
measurement.

Compare compact and explicitly requested full output only against a disposable
context or verified isolated restore; do not create benchmark memories in a
production namespace. Confirm that compact JSON parses, reports its contract and
budget metadata, preserves exact receipt ids, and states every omission. Confirm
that full mode remains redacted, trust-labelled, and context-scoped.

CLI examples:

```bash
.venv/bin/python synapse_cli.py --json list-memory \
  --context default --limit 50 \
  --response-mode compact --max-response-bytes 12288
.venv/bin/python synapse_cli.py --json graph \
  --context default --limit 5 --response-mode full \
  --max-response-bytes 131072
.venv/bin/python synapse_cli.py --json cortex-state \
  --context default --response-mode legacy
```

Use the legacy form only for a known local consumer that has not yet migrated
to the versioned envelope. A full response may still fail if its complete
serialization does not fit the explicit ceiling.
