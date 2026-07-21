# Authoritative Core Operations

SYNAPSE-S2 schema v6 is service-owned. Once the durable authority marker is
published, local backend fallback is intentionally unavailable. The supported
writer is one macOS LaunchAgent running:

```text
.venv/bin/python core_service.py serve --config .synapse_s2/core/service.json
```

The plist contains no token, database path, capture path, model selector, or
topology settings. Its environment contains only the deterministic, non-secret
source-manifest build ID used by the health identity gate and `MLX_DEVICE` copied
from the exact closed `CoreConfig`. This keeps a reviewed `cpu`, `gpu`, or
`default` device selection identical under launchd instead of inheriting a shell
or silently falling back. All other runtime settings live in the owner-only
config created by `write_core_config`.
Authentication remains in the owner-only socket token sidecar and is never put
in argv, launchd environment, logs, or JSON output.

Rollout status is separate from repository capability: the live local
production instance has not yet been cut over to this authoritative-core lane.
It remains on the legacy v5 runtime until the fresh backup, quiescence,
attestation, install, and stabilized-health gates below are deliberately run.
Nothing in this document by itself proves that cutover or remote publication
has happened.

## Adapter and browser boundary

The MCP launcher and installed MCP client definitions route through the
owner-only document named by `SYNAPSE_S2_CORE_BINDING`. Those client definitions
contain that one binding path, not an independent socket, database,
runtime-state, capture, export, MLX, model, or topology selection. CLI,
selected-text, readiness, and status processes use the same backend router when
the binding is present. After v6 authority is published, a missing or
conflicting binding fails closed. Before first adoption only, absence of a
binding preserves the canonical repository-local v5 compatibility lane; it
cannot select a noncanonical layout and it cannot override a v6 marker.
Mutations are never automatically replayed when their outcome is unknown. The
dashboard LaunchAgent is a separately hardened local adapter, but its installed
environment carries the same single owner-only binding path plus bounded
dashboard response fields—not an independent socket, database, runtime-state,
capture, export, or neural selection. All mutable work remains inside the core.

The binding has two closed modes. `candidate-local-v5` lets the pre-cutover
launcher and certifier exercise the exact installer-derived candidate while the
database is still ungoverned. `authoritative-core-v6` routes every surface to
the private socket and places the exact expected configuration fingerprint in
every authenticated request. A candidate binding is rejected after v6 adoption;
an authoritative binding is rejected against an ungoverned v5 database; and a
service-side fingerprint mismatch is rejected before path authorization,
journal acceptance, or dispatch.

Both modes bind `core/service.json` by its canonical byte digest, closed
configuration fingerprint, and embedding-space identity. A client loads and
verifies that owner-only `0600` config before any backend import. Candidate-v5
then hydrates every topology, maintenance, MLX, native-runtime, and pinned
provider setting from that config; inherited or explicit conflicting values are
rejected. `SYNAPSE_S2_NEURAL_MODEL` is the canonical model selector;
`SYNAPSE_S2_NEURAL_MODEL_ID` is accepted only as a non-conflicting publication
alias and is never exported into a bound client.

Capture polling is embedded in the core and becomes ready only after its live
heartbeat. The old capture installer is a pre-cutover v5 maintenance tool: an
installed core plist or a v6 service marker makes it exit before creating a
log, directory, plist, or launchd definition.

The dashboard remains loopback-only, but loopback alone is not authorization.
Every API GET and POST requires both the port-specific HttpOnly,
SameSite=Strict cookie and a distinct `X-Synapse-Dashboard-Session` capability.
The rotating owner-only bootstrap issues them; POST additionally requires the
exact configured `Host` and same-origin `Origin`, with no interchangeable host
aliases. Use `.venv/bin/python scripts/open_dashboard.py`, never a bare
dashboard URL. The helper reads `dashboard-auth.json` only when it is `0600`
inside an owner-only `0700` directory and does not expose its bootstrap in argv.
That file contains the bootstrap URL and header capability, never the cookie
secret. After bootstrap, the browser stores the header capability only in the
port-scoped `sessionStorage`, scrubs it from the redirect fragment, and sends
both capabilities on API calls. Installer health and `scripts/smoke_dashboard.py`
exercise this same contract. This is a browser request-integrity boundary, not
remote authentication.

HTTP framing is deliberately narrow: POST requires exactly one canonical
decimal `Content-Length`, request bodies are bounded, incomplete or timed-out
bodies close the connection, `Transfer-Encoding` is refused, and GET cannot
carry a body. Benchmarking, Monday readiness, repair, and other stateful work
use POST-only capabilities; a green GET is an observation, never a hidden
maintenance trigger. The bounded threaded server admits eight active handlers
behind backlog 32. Complete request headers have an absolute one-second
pre-authentication deadline; post-header I/O has a five-second timeout, and
shutdown is bounded.

## Files and ownership

The default installation is repository-relative:

| Purpose | Path | Mode |
| --- | --- | --- |
| Installed client binding | `~/.config/synapse-s2/core-binding.json` | `0600` |
| Service configuration | `.synapse_s2/core/service.json` | `0600` |
| Authority lease | `.synapse_s2/core/authority.lock` | `0600` |
| Root-generation sentinel | `.synapse_s2/core/store-generation.json` | `0600` |
| Unix socket | `.synapse_s2/core/service.sock` | `0600` |
| Authentication sidecar | `.synapse_s2/core/service.sock.token` | `0600` |
| Mutation request journal | `.synapse_s2/core/requests.sqlite3` | `0600` |
| Request-journal lock | `.synapse_s2/core/requests.sqlite3.lock` | `0600` |
| Cutover attestation | `.synapse_s2/core/cutover-attestation.json` | `0600` |
| Runtime state | `.synapse_s2/runtime_state.json` | `0600` |
| Core log | `.synapse_s2/core/service.log` | `0600` |
| Durable memory | `.synapse_s2/memory.sqlite3` | `0600` |
| Capture transport root | `.synapse_s2/` | `0700` |
| Core runtime directory | `.synapse_s2/core/` | `0700` |

The installer refuses symlinks, non-regular config/log/token/database targets,
foreign owners, hard-linked private files, and non-private modes. Publication
of the config and plist uses same-directory temporary files, file `fsync`,
atomic rename, and parent-directory `fsync`.

The authority lease is bound to the stable device/inode generation of the
owner-only `authority.lock` regular file. The durable SQLite marker records
that lock generation together with its exact schema/service flag, epoch,
instance, configuration, build, protocol, store, request-journal, root
generation, embedding-space, restored-target lineage, and timestamps. The core
caches a canonical digest of the complete closed marker after claim. Every live
authority check revalidates the held lock and visible lock path, the exact
database inode, the durable schema/migration pair, the lease epoch, and that
full marker digest. A missing field, added field, malformed value, marker edit,
database replacement, or lock-path replacement poisons the process and closes
new admission.

An ordinary restart or reviewed build/config replacement must reuse the same
`authority.lock` and root-generation files. Replacing the lock path creates a
new generation and is not an ordinary rollover: a durable marker may adopt it
only through the explicit signed restored-target flow, with the verified
restored request-journal binding. Replacement while a service is live fails
closed immediately. Operators must not delete or recreate `authority.lock` as
a lock-recovery shortcut.

## Failed-first-adoption journal recovery

A failed first v5-to-v6 adoption can leave `requests.sqlite3` even though the
memory database never committed a v6 authority marker. The only automatic
cleanup is deliberately narrow: both direct service startup and installer
preflight acquire the same exact unbound core authority lease, construct the
memory store through its full schema validator, and require an unchanged
pre-governed v5 inspection before and after repair. A v6 store, a malformed v5
store, a different store identity, any authority marker, or a bound authority
epoch makes this path fail closed.

The candidate journal must have the exact current application ID, user version,
canonical `sqlite_schema` SQL, table/index metadata, and the three-field
`journal_id`/`store_identity` binding. It must contain zero request rows. One row
is enough to refuse recovery because it may be the only durable evidence that a
mutation ran. The journal main file and lock, plus any WAL/SHM sidecars, are read
through owner-only no-follow descriptors and sealed by device, inode, size, and
SHA-256. A rollback journal, SHM without WAL, unknown SQLite transient, missing
or nonempty lock, changed artifact, extra schema object/column/index, or binding
mismatch is never normalized or discarded.

SQLite is not allowed to open the canonical journal during this decision. The
sealed main file and WAL are copied into a private bounded scratch directory;
WAL replay/checkpoint, exact schema checks, integrity checks, binding checks,
and the zero-row proof run only on that disposable copy. The canonical sources
are then reread and must retain the exact sealed bytes and inodes before a
private pending receipt can authorize same-directory archival.

The repair receipt progresses through `pending`, `complete`, and `retiring`
states with monotonic timestamps and immutable evidence. Interrupted receipt
publication, partial artifact renames, and partial retention deletion resume
only after the exact receipt, archives, lock, v5 store, and authority lease are
revalidated. Orphan archives and unverifiable temporary/scratch residue fail
closed. At most eight completed repair sets are retained; creating another
retires the oldest verified set through the same crash-resumable receipt state
instead of deleting unbound files. This is recovery for a proven-empty
first-adoption journal only, not a general journal reset or v6 repair command.

Before a durable authority claim, backend startup only observes an absent or
already-canonical runtime-state document. It does not create a runtime lock,
quarantine or rewrite malformed state, migrate retired embedded traces, reap
orphaned Cortex sessions, or change memory rows. Legacy or noncanonical state
must be repaired through the local pre-cutover maintenance path before the core
can claim authority. Existing wrong-mode, symlinked, hard-linked, foreign-owner,
or replaced runtime, transcript, capture, config, and journal locks fail closed;
only a lock leaf created by the current operation may have its mode normalized.

Runtime-state version 3 is the governed format. Its closed
`authority_binding` contains the canonical digest of the complete durable
marker, the exact authority epoch number, and the exact lock generation. On a
v6 restart, the existing version-3 file must match the preceding durable marker
before a successor epoch can be considered; after the SQLite claim, the core
atomically replaces and rereads the file with the new exact binding before it
reports startup complete. Version 2 remains valid only as canonical
pre-governed v5 input and as recovery compatibility evidence. It is not a
valid live runtime document for an already governed v6 store.

The v6 marker, migration row, SQLite user version, and a `pending` runtime-
publication receipt commit together in one SQLite transaction. That receipt
binds the exact marker digest, epoch, lock generation, instance, configuration,
build, protocol, and canonical runtime-state path. Runtime-state publication is
a separate same-directory temporary-file, `fsync`, rename, reread, and
directory-`fsync` operation; only after it succeeds does the core transactionally
mark the receipt `complete`. SYNAPSE-S2 does not claim one atomic transaction
spanning SQLite and the filesystem.

If a process dies inside that one publication window, a successor may repair it
only while holding an unbound core lease on the same visible lock generation
and only when the durable receipt is still `pending` and every bound identity is
unchanged. It first publishes the exact version-3 state for the interrupted
marker so the ordinary successor epoch claim can proceed. That claim replaces
the old pending intent with its own exact pending receipt, publishes the
successor state, and completes the successor receipt before readiness. A
replaced lock/root, changed configuration/build/protocol or embedding space,
malformed receipt, or stale state paired with an already `complete` receipt is
not auto-repaired. Thus crash recovery is narrow and same-generation; unrelated
mismatches still stop startup and health.

That repository-relative layout is mandatory by default. A different data root
requires `--noncanonical-layout-manifest /absolute/private/manifest.json`. The
owner-only manifest must use schema
`synapse-s2.noncanonical-core-layout.v1`, set `reviewed=true`, name a
`reviewed_by` operator, and enumerate every exact internal path. Individual
socket, database, capture, state, config, or log paths cannot be scattered.
Installers walk existing path components without following application-owned
symlinks, reject foreign or hard-linked targets, and never repair safety by
changing permissions on an existing caller-owned directory.

## First cutover or replacement

1. For a first cutover from local-v5, publish the exact installer-derived
   candidate binding before running readiness:

   ```bash
   scripts/install_core_agent.sh publish-binding
   scripts/install_local_launcher.sh
   .venv/bin/python scripts/install_client_configs.py
   ```

   This first atomically writes and rereads the canonical owner-only
   `core/service.json`, then atomically publishes its digest-bound binding with
   mode `candidate-local-v5`. A failure between those writes leaves the prior
   binding/config pair mismatched, so new clients fail closed. It refuses a
   store that already carries v6 governance.
   For a v6 replacement, do not run `publish-binding`; require
   `scripts/install_core_agent.sh status` to report the existing
   `authoritative-core-v6` binding as ready. For a reviewed noncanonical layout,
   pass the same `--noncanonical-layout-manifest /absolute/private/manifest.json`
   to `publish-binding`, readiness, and install. If the standalone preflight is
   also run, pass the exact memory and capture paths enumerated by that reviewed
   manifest through its `--memory-db` and `--capture-root` inventory arguments.
2. Produce a fresh, clean-HEAD operator-readiness evidence pack through the
   binding-backed launcher:

   ```bash
   .venv/bin/python scripts/operator_readiness_certify.py \
     --context default \
     --agent-id codex-desktop \
     --expect-embedding-provider mlx-neural
   ```

   The certifier loads the digest-bound candidate through the same installer
   contract used by cutover. Its installed-launcher status call must match the
   observed effective configuration fingerprint and embedding-space identity,
   and its manifest must contain the canonical
   `synapse-s2.core-config-evidence.v1` contract and exact configuration
   fingerprint. `--expect-*` flags are assertions only; they cannot select a
   different backend. Recovery backup, signed verification, isolated restore,
   and every required proof must be ready and replay-free.
3. After the certifier's last accepted write, stop the legacy capture and
   dashboard LaunchAgents, the exact prior core
   label, and every reported `mcp_client_wrapper.py` process through its owning
   client. Review exact PIDs; never use `pkill`, `killall`, or a broad command
   match.
4. Run the read-only inventory and recovery binding gate:

   ```bash
   scripts/core_cutover_preflight.sh \
     --evidence-manifest /absolute/path/to/evidence-pack/manifest.json \
     --require-quiescent
   ```

   The gate checks a clean v5 local store or a correctly marked v6 store,
   SQLite integrity, absence of a nonempty WAL/rollback journal, current clean
   Git HEAD, evidence freshness, trusted signatures, stable artifact hashes,
   live snapshot equality, capture-ledger binding, zero replay debt, and the
   signed isolated-restore proof. A failed exact `launchctl print` is not
   interpreted as absence: a successful user-domain inventory must positively
   prove that the label is absent. The gate also acquires the existing
   owner-only authority lock exclusively and nonblocking for the full database
   and recovery comparison. Process output is limited to PID and a fixed
   category; command text is never returned.
5. Install only with that explicit evidence manifest:

   ```bash
   scripts/install_core_agent.sh install \
     --evidence-manifest /absolute/path/to/evidence-pack/manifest.json
   ```

   Immediately before any install mutation, the installer publishes a signed
   `synapse-s2.core-cutover-attestation.v1` at the canonical core path. The
   owner-only receipt binds the current clean Git HEAD, deterministic source
   build ID, config fingerprint, evidence-manifest digest, governance
   generation, exact logical database digest, exact capture-manifest digest,
   runtime-state presence and canonical digest, and (for v6) the exact request-
   journal logical digest and source binding receipt. It also binds the signed
   recovery-bundle and isolated-restore receipt digests. The receipt is valid
   for at most ten minutes and publication requires at least two minutes of
   remaining evidence validity; expired, future-dated, near-expiry, partially
   populated, or signer-mismatched receipts fail closed.

   When the production data root is itself a promoted authoritative-v6
   recovery target, add `--restored-target`. That explicit closed flag requires
   the live `core/requests.sqlite3.binding.receipt.json`, verifies its exact
   memory/journal/runtime targets and source-binding chain, and adds its
   distinct receipt digest to the cutover attestation. Do not use the flag for
   an ordinary live v6 store, and do not infer restored-target status merely
   because an optional file happens to exist.

The installer unloads only `aero.boom.synapse-s2.core`, disables it during the
replacement window, reruns the full proof against the quiescent database,
publishes the private config and plist, then uses exact `launchctl enable`,
`bootstrap`, and `kickstart` targets. Success requires one stable launchd PID,
an authenticated health response, matching config/build/store/schema identity,
the exact `sqlite-53324442-v6` application/schema identity, a numeric
`epoch-<positive integer>` authority epoch, private socket/token, and a live
embedded capture heartbeat.

Only after that stabilized health gate succeeds does the installer atomically
publish `authority_mode: authoritative-core-v6` to the owner-only client
binding. The activation result and later `status` calls must report
`client_binding.ready: true`; otherwise clients are not published as ready. A
failed activation unloads and disables the new core and does not publish an
active binding. Reinstalling an already healthy exact build repairs the active
binding idempotently.

Before authority claim/startup, the core-side verifier rereads the canonical
private attestation, requires a clean matching Git HEAD plus exact build,
config, and evidence-manifest digests, validates freshness and signature, then
recomputes the WAL-aware live database logical digest, capture manifest,
runtime canonical state, and v6 journal/source binding. A signed restored-
target flag additionally revalidates the distinct live restore binding. The
verifier returns only a closed set of verified identities and performs no
repair, acknowledgement, publication, or authority-lock acquisition.

The dashboard and legacy-capture installers share the same regular-file
`flock` and no-follow path validator. Their lock files may remain after a run;
the kernel lock, not a stale directory, is the concurrency authority. Client
configuration is published as one four-target transaction. A private durable
journal and per-target backups allow the next invocation to roll back an
interrupted Codex/Claude/project publication before making new changes.

## Recovery path authority

The public authoritative-core recovery contract never accepts a client-selected
capture root, noncanonical-capture permission, or retention directory. The
service injects the configured capture root and backup/retention root after
validating its binding and path capabilities. Therefore, omit
`--capture-root`, `--allow-noncanonical-capture-root`, and retention
`--directory` from normal CLI, MCP, dashboard, and readiness calls. Those flags
exist only for deliberately offline local-v5 maintenance and are rejected when
the operation routes through `CoreClient`.

Omitting the optional bundle output selects a unique server-owned destination.
Bundle output, bundle receipt, and isolated-restore output remain explicit where
the operation needs them, but every caller-selected path must be absolute and
the core constrains it to the configured backup or recovery tree. A caller path
cannot widen the reviewed layout.

A bundle signed by another installation is eligible only after the operator
supplies an independent SHA-256 for every artifact present: database and capture
archive, plus request journal for governed bundles and runtime state whenever it
is included. The exact verified bundle-receipt identity and its dependent
database, capture, journal-binding, and runtime receipt identities remain bound
through isolated materialization. A changed receipt or artifact fails before
the output root is created. With all required pins supplied, a foreign governed
bundle can complete isolated restore and reverify its bound journal and runtime;
partial pinning is not accepted.

Path authorization currently pins the reviewed root, parent, and target with
no-follow descriptors, validates ownership/link count/mode and containment, and
revalidates identity immediately before dispatch. The existing store, recovery,
and capture implementations then reopen the authorized pathname for their
operation. This is not an end-to-end descriptor-relative guarantee against a
malicious process running as the same macOS user with comparable write access
to the reviewed directories. The production trust boundary therefore treats
the owner account as trusted. Supporting mutually untrusted same-UID clients
would require fd-relative APIs throughout SQLite, archive, retention, and
capture consumers; the current implementation does not claim that property.

## Embedding and topology admission

Raw `register_trace` and `query` embeddings must contain exactly the configured
number of coordinates. This is validated before request-journal admission, so a
client cannot resize the sensory projection by supplying a larger vector. The
service and backend also compute the exact steady float32 dense topology—the
sensory matrix, lateral matrix, membrane state, spike state, and active-trace
vector—and require it to fit 384 MiB before MLX model loading, array
materialization, or resize. The admission proof covers those steady arrays
only. It does not claim peak process/Metal residency, target-hardware counters,
or execution-time performance.

## Safe lifecycle commands

```bash
scripts/install_core_agent.sh status
scripts/install_core_agent.sh stop
scripts/install_core_agent.sh uninstall
```

`status` is read-only. `stop` disables and boots out only the exact core label.
`uninstall` additionally removes only its exact owner-controlled plist. Neither
command deletes the database, captures, config, token, state, evidence, or log.
Repeated stop/uninstall calls are safe.

New socket admission is bounded before dispatch. The Unix listener backlog is
64, at most 32 connection workers may be active, and each accepted connection
has one second to prove the local peer UID, present an authenticated request,
and complete its bounded pre-authentication frame. Authentication does not turn
the socket into an unbounded session: subsequent socket I/O carries a five-
second timeout and request deadlines still govern dispatch. The production
model trusts the owner account, and the socket must not be exposed to mutually
untrusted clients that run under the same UID.

Shutdown first closes the listener, then gives the serialized backend lane and
ordered backend (or store), journal, and lease teardown one shared two-second
grace window. Capture/request-worker draining receives a separate shared
two-second window. If an active operation does not quiesce, a close hook hangs,
or an earlier authority-bearing teardown step fails, the service poisons itself
and retains the backend, journal, and authority lease references. It does not
report a clean teardown or deliberately release the lock for a potentially
overlapping writer; the process supervisor must terminate that process so the
operating system closes retained descriptors before a successor starts.

## Failure semantics

Every mutation that passes protocol, credential, dimension, and topology
admission is accepted into the private request journal before backend dispatch.
The journal stores only content-free identity and state metadata: caller,
request ID, operation, request fingerprint, authority epoch, state, result
kind, safe error code, and timestamps. Arguments, responses, byte counts, and
response digests are not durable journal content. `accepted` and `ambiguous`
rows are never replayable; a completed row without the process-local response
cache is also `outcome_unknown`. Reconcile with `request_status` using the
exact caller and request ID. A `not_found` result remains non-replayable because
retention expiry cannot prove that the mutation never ran.

Delivery ACK, release, and dead-letter operations have one narrower terminal
case. When the backend reports that its transaction made no delivery change (or
rolled back before returning), the request is finalized as `failed` with safe
error `invalid_request`. This preserves durable deduplication without consuming
the accepted/ambiguous ceiling. Credential-shaped delivery identifiers are
rejected at protocol validation before journal admission and therefore return
no journal status row. Any exception that cannot prove the commit state remains
`outcome_unknown`; it is never reclassified merely to free capacity.

Journal capacity never evicts live dedup evidence. Completed and terminal
failed rows are pruned only after the retention horizon; accepted and ambiguous
rows are not removed to make space. Consequently deterministic rejects do not
exhaust accepted-row capacity, but the total retained-row ceiling still places
a finite bound on sustained invalid-request throughput and can backpressure new
mutations until terminal rows age out. When either configured ceiling is
reached, new mutations fail closed. A v6 restart requires the existing nonempty
`requests.sqlite3`; only a first v5 adoption or genuinely new store may create
one. Foreign recovery verification and isolated restore require every artifact
pin: database, capture archive, request journal when governed, and runtime state
when included. Cutover recomputes the
live logical database, capture manifest, runtime canonical state, and request-
journal logical state under their established locks and compares every value
to the signed bundle, parsed verifier result, and signed isolated restore. A
coarse row-count or high-water match is never a substitute for exact logical
state. The journal binding receipt is required for an authoritative-v6 cutover
proof; a pre-governed v5 store may instead carry a signed runtime-state absence.

The cutover receipt currently reuses the same audited local Ed25519 authority
as recovery receipts. Before exposing this as a cross-process public protocol,
promote those signing and verification calls to a typed public recovery API;
do not duplicate key access or create a second cutover key.

Pure `resource_profile` and `get_cortex_state` calls are retry-safe. Quick-prune
benchmarking and orphan-session reaping are separate journaled mutations.
Capture status and transcript source listing are observation-only; transport
creation and legacy-state repair are explicit maintenance operations.

If activation or its stabilized health gate fails, the new agent is booted out
and disabled. The plist, config, token, state, database, captures, and logs are
preserved for diagnosis. There is no automatic return to a local backend after
schema v6 is claimed: that would permit two authorities or stale writes. Repair
the core and rerun the verified install, or follow a separately reviewed,
verified recovery procedure.
