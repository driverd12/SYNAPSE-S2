# Exactly-Once Capture Contract

SYNAPSE-S2 capture protocol `capture.v2` applies one durable graph mutation for
one explicit logical capture ID. The guarantee covers memory entries, spike and
surface indexes, memory events, relationships, the context-bus deployment, and
the committed result receipt.

## Identity rules

- A capture ID is `s2cap_` followed by exactly 32 lowercase hexadecimal
  characters.
- A producer creates the ID before its first attempt and reuses it only when
  retrying the same logical operation.
- The post-redaction canonical request fingerprint detects misuse; it is not the
  deduplication identity.
- Same ID and same canonical request returns the original committed result with
  `idempotent_replay: true` and performs no graph writes.
- Same ID with different text, context, source, speaker, segmentation settings,
  or safe metadata is an idempotency conflict and performs no writes.
- Different IDs containing identical text are distinct temporal occurrences.
  Stable namespace and entity anchors may still merge by their documented graph
  identity.
- Filename, path, inode, modification time, raw-content hash, and redaction
  count never define capture identity.

The capture ledger is committed-only and intentionally has no cascading foreign
key to graph rows. Its receipt is a bounded, content-free effect manifest: it
retains producer identity, counts, timestamps, and a compact deployment header,
but never captured text, segments, namespace titles, relationship evidence, or
deployment payloads. If an operator later prunes the captured graph or
deployment, replaying its capture ID returns that compact receipt and does not
resurrect the pruned data. Startup transactionally scrubs the older full v2
receipt shape before accepting capture traffic.

## Transaction boundary

The backend computes a redacted, JSON-safe capture plan before opening a SQLite
writer transaction. A single `BEGIN IMMEDIATE` then:

1. checks the capture ledger for replay or conflict;
2. applies all planned entries and their spike, surface, and memory-event rows;
3. applies every planned relationship;
4. publishes the context event and normalized delivery targets;
5. inserts the immutable committed capture receipt; and
6. commits the transaction.

An exception or process death before commit rolls back every row family. Runtime
JSON and in-memory caches are refreshed only after commit and are never the
source of capture truth.

## Producer behavior

- Direct CLI and MCP callers may supply `capture_id`; generated IDs are returned
  in receipts so callers can safely retry a lost response.
- The dashboard generates an ID before sending a capture and retains the exact
  request body in memory until a successful response. A repeated click after a
  network failure therefore reaches the same ledger row.
- Inbox v2 files persist their ID before they become visible in
  `capture_inbox`. Legacy v1 JSON, JSONL, and text files remain readable during
  migration and receive stable IDs in their atomic processing claim.
- Registered transcript sources derive IDs from logical source ID, stream
  generation, and byte range. Their cursor advances only after a committed or
  idempotently replayed capture. File rotation advances the stream generation.
- App snapshots, selected text, clipboard capture, Wrap Session, and client
  session-boundary drops all propagate the same explicit ID contract.

## Inbox ownership and recovery

Workers atomically rename a pending file into a private processing claim before
parsing it. Only the rename winner may process the file. A per-capture lock is a
transport-level guard; the SQLite ledger remains authoritative across processes
and crash windows.

Processed/error moves and transport receipts occur after the database commit.
Failure to archive a committed file is cleanup-only: the claim is retried and
the ledger returns the original result without duplicating graph effects.
Abandoned processing claims are recoverable. Historical error files are not
automatically retried because old JSONL prefixes may have been partially applied
before `capture.v2` existed.

### Incomplete write artifacts

Files that still have a recognized inbox temporary name are transport debris,
not capture payloads. This includes legacy `<name>.json.tmp`,
`<name>.jsonl.tmp`, and `<name>.txt.tmp` files as well as the current hidden
atomic-write form `.<name>.<suffix>.<32-hex>.tmp`. The daemon never parses,
redacts, fingerprints from content, or submits these files to the capture
backend.

Every status and processing receipt reports the total, fresh, stale, and ignored
inbox-temp counts plus the configured stale threshold. A regular, non-symlink
temp remains untouched for five minutes after its newest modification or inode
change, protecting an active or recently interrupted producer. Once stale, the
daemon revalidates the same device, inode, size, modification time, and change
time immediately before atomically moving it to `capture_errors`. The adjacent
`.evidence.json` records only file-system metadata and a metadata-derived
transport token; it explicitly records that content was neither inspected nor
digested.

Symlinks and other non-regular temp artifacts are never followed or moved
automatically. They remain visible in the ignored count for manual operator
review. Quarantined temp artifacts are evidence only and are never
automatically retried. If a producer must recover one, first establish whether
the write completed, create a valid final-suffix capture file with an explicit
capture ID, and submit that repaired file as a deliberate new inbox action.

### JSON and JSONL batch boundary

Exactly-once atomicity is **per capture record**, not per inbox file. Before the
first record is applied, the daemon parses and normalizes the complete JSON or
JSONL file, persists all missing legacy IDs, and rejects duplicate IDs within
the batch. It then submits records in file order. Each submitted record has its
own atomic SQLite transaction and immutable ledger receipt. If record 2 fails
after record 1 committed, record 1 remains durably committed; the file is not a
single cross-record database transaction.

For any partial batch failure, the adjacent `capture_errors/*.error.json`
sidecar is the repair authority. It records:

- `batch_atomicity: "per-record"`, the total known record count, and the
  zero-based failed record index and capture ID;
- every already-committed capture ID in order;
- committed event and relationship totals; and
- per-record `idempotent_replay` and `receipt_replay` flags plus aggregate replay
  counts.

To repair a v2 batch, inspect that sidecar, correct the failed or unapplied
record without changing any logical capture IDs, then deliberately move the
quarantined file back to `capture_inbox`. Requeuing the full file is safe: the
SQLite ledger replays the committed prefix without graph writes, while the
previously failed suffix can commit. Never assign new IDs to records listed as
committed merely to bypass a conflict. Legacy pre-v2 error files remain manual
review items and are never auto-requeued.

## Governed historical ledger reconciliation

A bounded hot-runtime cutover can leave a narrow legacy state: the old daemon
may have archived a processed record and committed its memory graph plus
conversation-capture deployment after the new ledger schema was installed, but
before the ledger-aware process took over. Treat that state as missing authority,
not as permission to replay the capture.

Run the read-only audit first:

```bash
.venv/bin/python synapse_cli.py --json capture-ledger-integrity \
  --capture-root .synapse_s2
```

The audit binds processed payload identity, the normalized redacted request,
namespace entries, relationship identities and endpoints, the unique durable
deployment, deployment target records, and existing ledger-backed fingerprints.
Its public findings contain bounded IDs, reason codes, and effect counts; raw
content, internal file digests, paths, and request fingerprints remain private.

Only a fully evidenced historical cohort reports `repairable: true`. Review the
finding samples and preserve the exact `audit_revision`. The repair is an
explicit second action:

```bash
.venv/bin/python synapse_cli.py --json capture-ledger-integrity \
  --capture-root .synapse_s2 \
  --repair --confirm \
  --expected-revision '<audit_revision>'
.venv/bin/python synapse_cli.py --json capture-ledger-integrity \
  --capture-root .synapse_s2
```

The revision binds both missing-row evidence and every processed ledger-backed
record, so any intervening capture or evidence change makes the plan stale. The
repair re-reads and re-hashes each source under the global capture lock, creates
a verified SQLite safety backup, and commits all missing rows plus one
content-free maintenance receipt in one transaction. For each historical row,
the request fingerprint is a deterministic projection from the current
canonical redacted payload; it is not represented as a recovered historical
transport fingerprint. `committed_at` and deployment publication time come from
the already durable conversation-capture deployment timestamp.

The repair never replays capture text, inserts memory nodes or relationships,
publishes another deployment, recreates a capture receipt file, or synthesizes a
context-delivery ACK. A modern canonical v2 ledger loss, duplicate capture ID,
changed payload, ambiguous deployment, incomplete graph binding, or conflicting
deployment ownership is blocked and must be resolved from authoritative evidence
or a verified paired restore. After repair, require a fresh audit with
`status: "ready"` before backup or deployment.

Paired-bundle verification does not trust archive membership alone. It
re-canonicalizes every processed v2 payload against the signed SQLite
snapshot's protocol, request fingerprint, context, source, and speaker, then
returns only a content-free binding count and revision. The isolated restore
derives that proof again from the restored database and files and must match it
before publishing recovery proof. `cutover_ready` is false without this binding
proof even when capture IDs and replay-debt counts appear consistent.

## Safe deployment and rollback

Deploy in this order:

1. require a ready `capture-ledger-integrity` audit, create a signed
   `backup-recovery` bundle, then prove `verify-recovery` and an isolated
   `restore-recovery-proof`; require `cutover_ready: true`;
2. stop the capture LaunchAgent and verify its process exited;
3. migrate the store and deploy the ledger-aware daemon while v1 compatibility
   remains enabled;
4. verify replay, conflict, crash rollback, claim recovery, and transcript
   cursor tests against a disposable store;
5. restart the daemon and verify health;
6. only then deploy producers that emit v2 IDs.

Do not roll the daemon binary back by itself after v2 files exist. Old code can
ignore the new fields and replay them without consulting the ledger. Safe
rollback restores the exact signed pre-deployment database and capture archive as
one governed pair, or
rolls forward with capture projection disabled until repair completes.

## Privacy boundary

Canonical fingerprints are computed after redaction. Capture v2 does not persist
or return a digest of the unredacted input. The ledger stores only a bounded,
content-free effect receipt needed for deterministic acknowledgement;
secret-bearing raw input and redacted capture content are never part of that
receipt.
