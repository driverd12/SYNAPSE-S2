# Governed multi-Mac replication

SYNAPSE-S2 replication is an offline, operator-mediated recovery-checkpoint
protocol. It is not live database synchronization. One authoritative core
creates a signed, target-bound checkpoint; the paired receiver verifies it,
materializes an isolated restore proof, and signs an acknowledgement. No step
overwrites either Mac's live memory database.

## Safety boundary

- Only the authoritative core may pair or revoke peers, create checkpoints,
  stage received checkpoints, or record acknowledgements.
- MCP and dashboard surfaces expose signed identity and bounded status only.
- There is no SSH client, network listener, peer discovery, live cutover, or
  multi-writer merge path in this protocol.
- Imported descriptors, checkpoint directories, and acknowledgements must be
  copied by the operator into the server-owned, client-binding-published
  `<data-root>/replication/inbox` tree. Every directory must be mode `0700`
  and every file mode `0600`; symlinks, hard links, public modes, and paths
  outside that tree fail closed.
- Pairing requires both `--confirm` and the independently verified signed
  descriptor `receipt_digest`. Confirmation alone is not trust-on-first-use.
- Normal staging accepts authoritative governed checkpoints only. Legacy-v5
  material is migration input, not a replication checkpoint and must never
  produce a normal receiver ACK.

## Explicit two-Mac pairing

Run commands with `--json` if machine-readable output is desired. Before
redirecting identity documents, use `umask 077` so the resulting file is
private.

On each Mac, read its identity:

```bash
.venv/bin/python synapse_cli.py --json replication-identity
```

Independently compare the displayed `node_id`, `auth_key_id`, and
`receipt_digest` through a trusted channel. Copy each complete descriptor into
the other Mac's `<data-root>/replication/inbox` directory. Generate one lineage
identifier and use that exact value on both Macs:

```bash
.venv/bin/python synapse_cli.py --json replication-lineage-new
```

On the sending Mac, pin the receiver for `send`; on the receiver, pin the
sender for `receive`:

```bash
.venv/bin/python synapse_cli.py --json replication-peer-add \
  --descriptor receiver-node.json \
  --expected-descriptor-digest '<independently verified 64-hex digest>' \
  --lineage-id 's2lineage_<32 hex>' \
  --direction send \
  --confirm

.venv/bin/python synapse_cli.py --json replication-peer-add \
  --descriptor sender-node.json \
  --expected-descriptor-digest '<independently verified 64-hex digest>' \
  --lineage-id 's2lineage_<same 32 hex>' \
  --direction receive \
  --confirm
```

Inspect or revoke pins with:

```bash
.venv/bin/python synapse_cli.py --json replication-peer-list
.venv/bin/python synapse_cli.py --json replication-peer-revoke \
  --peer-id 's2node_<32 hex>' --reason '<operator reason>' --confirm
```

### Activate media replication on an existing pair

Peers created before `media-artifact-v1` remain valid for database-only
checkpoints, but referenced-media checkpoints fail closed until capability
evidence is active in both directions. Upgrade the receiver first, then the
sender, and do not create a referenced-media checkpoint until both status
reports are ready.

On each Mac, save the current local `descriptor_digest` and the other Mac's
pinned peer `descriptor_digest` from these read-only commands:

```bash
.venv/bin/python synapse_cli.py --json replication-status
.venv/bin/python synapse_cli.py --json replication-peer-list
```

Then upgrade each Mac's active node descriptor with the exact reviewed local
digest. Use `umask 077` because the resulting descriptor will be copied to the
other Mac:

```bash
umask 077
.venv/bin/python synapse_cli.py --json replication-node-upgrade \
  --expected-current-digest '<that Mac current descriptor_digest>' \
  --confirm > upgraded-node.json
```

Independently compare each upgraded descriptor's `node_id`, `auth_key_id`,
`receipt_digest`, and `capabilities` through the same trusted channel used for
initial pairing. The capability list must contain `media-artifact-v1`. Copy
each complete upgraded descriptor into the other Mac's core-owned replication
inbox, then replace each existing pin with an exact compare-and-swap:

```bash
# On the sender, upgrade its pinned receiver descriptor.
.venv/bin/python synapse_cli.py --json replication-peer-upgrade \
  --descriptor receiver-upgraded-node.json \
  --expected-descriptor-digest '<verified receiver upgraded receipt_digest>' \
  --expected-previous-descriptor-digest '<sender previously pinned receiver digest>' \
  --confirm

# On the receiver, upgrade its pinned sender descriptor.
.venv/bin/python synapse_cli.py --json replication-peer-upgrade \
  --descriptor sender-upgraded-node.json \
  --expected-descriptor-digest '<verified sender upgraded receipt_digest>' \
  --expected-previous-descriptor-digest '<receiver previously pinned sender digest>' \
  --confirm
```

Re-run `replication-status` on both Macs. Continue only when each report has
`integrity.state: ready`, `media_artifact_capable: true`, and the relevant peer
has `media_ready: true`, `evidence_problem: null`, and a capability list that
contains `media-artifact-v1`. A stale digest, missing transition receipt,
one-sided upgrade, or tampered descriptor blocks media checkpoint creation or
staging without changing the replication ledger.

## Checkpoint and acknowledgement flow

Create a target-bound checkpoint on the sender:

```bash
.venv/bin/python synapse_cli.py --json replication-checkpoint-create \
  --peer-id 's2node_<receiver id>'
```

A checkpoint packs the verified paired recovery bundle: the memory database,
its backup receipt, the capture archive, the sealed media archive (thumbnails,
private Apple Vision feature prints, and per-object manifests for every image
memory referenced by the bundled database; `synapse-s2.recovery-bundle.v3`),
optional request-journal and runtime-state artifacts, and the signed bundle
receipt. Full-resolution originals are never copied, and media bytes travel
only inside the digest-bound sealed archive. Older media-absent v2/v1 bundle
receipts stay verifiable; their staging proofs report
`media_recovery_complete: false` whenever the bundled database still
references image memories, so incompleteness is visible rather than silent.

Copy the entire returned `checkpoint_directory`, without changing its internal
names or modes, into the receiver's replication inbox. Then stage its manifest:

```bash
.venv/bin/python synapse_cli.py --json replication-stage \
  --manifest '<copied-checkpoint>/checkpoint.manifest.json'
```

Successful staging returns an isolated `restore_root` plus a receiver-signed
`ack_path`. Checkpoint creation and staging both report the deliberately narrow
readiness contract:

- `memory_recovery_cutover_ready: true` means the recovery artifact and its
  isolated proof are ready for a separately governed memory-recovery decision.
- `replication_promotion_ready: false` and `promotion_supported: false` mean
  this replication protocol cannot promote the staged copy to the live store.
- `live_overwrite_performed: false` confirms that the operation did not modify
  the receiver's live memory database.

The receiver-signed ACK carries `memory_recovery_cutover_ready`, not a generic
promotion or cutover assertion. Copy that ACK file into the sender's
replication inbox and record it:

```bash
.venv/bin/python synapse_cli.py --json replication-ack \
  --acknowledgement '<copied receiver ACK>.json'
```

Read bounded state at any time:

```bash
.venv/bin/python synapse_cli.py --json replication-status
```

Global status deliberately keeps `memory_recovery_cutover_ready: false` even
when ledger integrity is ready. Readiness is an assertion about the exact
checkpoint or staged proof returned by its artifact-specific operation, never
about an empty or merely healthy replication ledger. Status exposes checkpoint
state and integrity separately so an operator can choose and re-verify the
specific artifact involved in a later governed recovery decision.

The equivalent read-only HTTP endpoints are
`GET /api/replication/identity` and `GET /api/replication/status`.

## Encryption and local-account boundary

Replication descriptors, checkpoint artifacts, manifests, and ACKs are signed
for authenticity and integrity, but they are **plaintext**. A signature is not
encryption. Keep FileVault enabled on both Macs and move checkpoint directories
only through an encrypted channel or encrypted removable volume controlled by
the operator. Do not place replication material in email, chat attachments,
unencrypted removable media, or a cloud-synchronized folder.

The `0700`/`0600` checks isolate files from other local accounts; they do not
protect against another process already running as the same macOS UID. Treat
the SYNAPSE-S2 account as the replication trust boundary, keep untrusted tools
out of that account, and revoke a peer if the account or signing material may
have been compromised.

After the receiving side has verified and staged an artifact, and after the
sender has recorded the signed ACK, remove temporary transfer and inbox copies
from both Macs and the transfer device. APFS flash storage cannot provide a
reliable per-file overwrite guarantee, so “secure delete” must come from
full-volume encryption and destruction/rotation of the transfer-volume key,
not repeated overwrite commands. Retain only the core-managed checkpoint,
staged proof, ledger, and ACK records required by policy, and verify that
temporary copies were not swept into backups or cloud sync before cleanup.

## Operational behavior

Checkpoint creation and staging are exclusive maintenance operations that
create, hash, verify, and—for staging—restore a complete paired recovery point.
They belong to the authenticated closed recovery allowlist and receive a
bounded one-hour synchronous deadline. Ordinary operations, pairing, peer
revocation, signed ACK recording, and bridge governance retain the five-minute
protocol ceiling. Waiting to acquire the serialized maintenance lane is also
capped at five minutes, so queued callers cannot consume the one-hour execution
budget before admission. There is no unbounded or hidden server claim and no
asynchronous job contract. If the caller loses the response, the result is
`outcome_unknown`: preserve its caller and request ID, use the normal
`request-status` reconciliation path, and do not blindly submit a new logical
operation:

```bash
.venv/bin/python synapse_cli.py --json request-status \
  --caller '<caller from outcome_unknown>' \
  --request-id '<request ID from outcome_unknown>'
```

`request-status` deliberately returns only bounded reconciliation metadata,
not checkpoint, restore, or ACK paths. If and only if it reports `completed`,
rerun the exact same logical replication command with unchanged peer,
fingerprint, lineage, manifest, or ACK inputs to retrieve the manager's
idempotent result. Do not blind-retry a request reported as `accepted`,
`ambiguous`, `failed`, or `not_found`; preserve the artifacts and investigate
or reconcile first.

Health and request-status remain available while the lane is active. Health
reports `operational_state` as `maintenance`, marks the backend lane
`degraded`, sets `accepting_ordinary_operations: false`, identifies the fixed
lane owner, and reports `deadline_remaining_ms`; ordinary memory RPCs may wait
or time out until maintenance ends. The one-hour execution budget does not
extend recovery-evidence freshness, retention-plan expiry, bridge proposal
expiry, or cutover/admission tickets.

## Ledger witness operations and residual limits

Normal status verifies the current signed anchor, its current history receipt,
the signed external high-water witness, and the neutral high-water revision in
the authoritative memory database. It intentionally does not scan the entire
anchor history on every request. Schedule a core-exclusive
`ReplicationLedger.audit_anchor_history(maximum=...)` maintenance audit after
each replication transfer window and at least weekly. Treat any failure as a
stop condition. This release does not install that scheduler or expose a
public audit command, so the deployment runbook must own the schedule until an
authoritative-core wrapper exists.

Every ledger mutation performs a streamed digest and bounded integrity work
over the existing ledger, so mutation cost remains O(n) as the ledger grows.
The implementation fails closed at 256 MiB, 10,000 peers/checkpoints/ACKs,
100,000 audit rows, or 100,000 anchor revisions; it does not rotate
automatically. Plan and test an authoritative, signed archival/rotation
procedure well before the first applicable cap. Never delete rows or anchor
receipts by hand to recover capacity.

The neutral high-water revision is intentionally stored in the authoritative
main memory database while its signed witness lives outside the replication
tree. Any future promotion or database rebase must atomically reconcile that
neutral revision with the destination node's ledger metadata, current anchor,
anchor history, and signed external witness. Restoring or copying the database
alone is not a valid rebase; a mismatch must remain degraded. No such rebase or
promotion procedure is implemented in this release.

The hybrid witnesses detect a replication-tree rollback while the independent
state remains current. They do not defend against a same-UID attacker or backup
system that can coherently roll back the whole SYNAPSE-S2 data root, including
the main database, replication tree, signed external witness, and signing key.
Use independently retained, immutable/off-host evidence if that threat is in
scope.

This design intentionally favors confidence and recoverability over immediate
propagation. Async replication jobs, resumable chunk transport, scheduled RPO
monitoring, and an explicit human-governed cutover procedure are future layers;
none are implied by a successful ACK.
