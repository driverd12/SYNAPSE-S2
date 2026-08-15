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

The canonical installer default is the production Apple-Silicon contract:
`mlx-neural-v1`, model
`mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`, immutable revision
`6c3ae70858513f1a78e9cdca3cae330d9075cd2a`, cache
`.synapse_s2/models`, local-files-only loading, and `MLX_DEVICE=gpu`. An
operator may deliberately publish another closed CPU/GPU/provider contract
through the documented environment overrides, but absence of overrides never
silently selects the semantic-hash maintenance provider.

Rollout status is separate from repository capability. Nothing in this document
by itself proves live cutover or remote publication. Verify the installed state
with `install_core_agent.sh status` and require `healthy`, `runtime_healthy`,
`production_ready`, `capture_ready`, and `client_binding.ready` to be true,
`provisional` to be false, and `deployment_mode` to be `authoritative`.

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

The default durable installation is repository-relative; launchd process output
uses the user's canonical Logs directory so current macOS protected-folder
admission cannot stop the daemon before Python starts:

| Purpose | Path | Mode |
| --- | --- | --- |
| Installed client binding | `~/.config/synapse-s2/core-binding.json` | `0600` |
| Service configuration | `.synapse_s2/core/service.json` | `0600` |
| Authority lease | `.synapse_s2/core/authority.lock` | `0600` |
| Root-generation sentinel | `.synapse_s2/core/store-generation.json` | `0600` |
| Unix socket | `.synapse_s2/core/service.sock` when it fits Darwin's socket bound; otherwise `~/.config/synapse-s2/run/<data-root-digest>/service.sock` | `0600` |
| Authentication sidecar | Beside the selected Unix socket as `service.sock.token` | `0600` |
| Mutation request journal | `.synapse_s2/core/requests.sqlite3` | `0600` |
| Request-journal lock | `.synapse_s2/core/requests.sqlite3.lock` | `0600` |
| Cutover attestation | `.synapse_s2/core/cutover-attestation.json` | `0600` |
| Runtime state | `.synapse_s2/runtime_state.json` | `0600` |
| Core log | `~/Library/Logs/SYNAPSE-S2/core-service.log` | `0600` |
| Dashboard log | `~/Library/Logs/SYNAPSE-S2/dashboard.log` | `0600` |
| Durable memory | `.synapse_s2/memory.sqlite3` | `0600` |
| Capture transport root | `.synapse_s2/` | `0700` |
| Core runtime directory | `.synapse_s2/core/` | `0700` |

Only the socket and authentication sidecar may use the short transport
directory. The authority lease, generation sentinel, journal, repair receipts,
cutover attestation, runtime state, database, backups, and captures remain in
their durable repository-relative layout.

The installer refuses symlinks, non-regular config/log/token/database targets,
foreign owners, hard-linked private files, and non-private modes. Publication
of the config and plist uses same-directory temporary files, file `fsync`,
atomic rename, and parent-directory `fsync`.

The authority lease is bound to one filesystem generation of the owner-only
`authority.lock` regular file. On macOS, `lockfs-v2` derives the durable
generation from inode plus rounded filesystem birth time, avoiding the
mount-assigned `st_dev` value that can change across reboot. Platforms without
birth time retain `lockfs-v1` device/inode identity. In either case, each live
held-versus-visible check still compares the current device and inode, owner,
mode, link count, and pathname identity. The durable SQLite marker records the
generation together with its exact schema/service flag, epoch, instance,
configuration, build, protocol, store, request-journal, root generation,
embedding-space, restored-target lineage, and timestamps. The core caches a
canonical digest of the complete closed marker after claim. Every live
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

One compatibility ceremony is narrower than restored-target adoption. A
reviewed build replacement may migrate an existing `lockfs-v1` marker to
`lockfs-v2` only when the held and visible private zero-byte lock still have the
same inode encoded by v1, its birth time predates the durable claim, and the
signed replacement-admission v5 binds the exact predecessor, candidate,
transition mode, birth time, explicit media-recovery completeness, and the
content-free Memora integrity/effective-binding aggregate.
The admission also requires a fresh paired recovery bundle, verified isolated
restore, clean repository, ready delivery audit, unchanged
configuration/root/store/journal/runtime/embedding identities, and a distinct
successor build. The v2 marker and runtime publication advance
in the normal authority-claim transaction and publication sequence. This lane
does not admit v2-to-v2 drift, a changed inode, a newly created lock, or
`recover-existing`.

If that signed migration commits the v2 marker but crashes before the runtime
publication receipt becomes complete, the next exact-build startup performs
only the already-bound recovery: it republishes the runtime binding, atomically
changes the matching receipt from `pending` to `complete`, and stops without
advancing the epoch or consulting the old transition admission. Operators must
then rerun replacement staging so fresh recovery evidence produces a v2/`none`
admission. The legacy v1-to-v2 receipt is never replayed or inferred as
authorization for the resumed claim.

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

That repository-relative durable-data layout and the separate fixed
`~/Library/Logs/SYNAPSE-S2/core-service.log` path are mandatory by default. A
different data root requires
`--noncanonical-layout-manifest /absolute/private/manifest.json`. The owner-only
manifest must use schema
`synapse-s2.noncanonical-core-layout.v1`, set `reviewed=true`, name a
`reviewed_by` operator, and enumerate every exact internal path. Individual
socket, database, capture, state, or config paths cannot be scattered, and the
log cannot be redirected away from its canonical Logs path.
Installers walk existing path components without following application-owned
symlinks, reject foreign or hard-linked targets, and never repair safety by
changing permissions on an existing caller-owned directory.

## First cutover or replacement

1. For a first cutover from local-v5, publish the exact installer-derived
   candidate binding before running readiness:

   ```bash
   scripts/install_core_agent.sh publish-binding
   scripts/install_local_launcher.sh
   .venv/bin/python scripts/install_client_configs.py \
     --codex-disabled-for-certification
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
2. Resolve capture/replay debt, then quiesce every persistent writer before
   producing final evidence. First inspect and drain the governed inbox while
   the legacy capture worker is still available:

   ```bash
   .venv/bin/python synapse_cli.py --json capture-inbox-status
   .venv/bin/python synapse_cli.py --json capture-inbox-process --confirm
   .venv/bin/python synapse_cli.py --json capture-inbox-status
   ```

   Reconcile every reported capture error, ambiguous request, or
   replay-required artifact; never delete or replay it to make the count zero.
   Gracefully close each exact persistent MCP client first and wait for its
   `mcp_client_wrapper.py` process to exit. Its `finish()` path writes the final
   session-boundary capture and Cortex trace, so killing it after certification
   would invalidate the evidence. Pause or disable every exact automation or
   LaunchAgent that can relaunch those clients, record how it will be restored,
   and keep it paused until the authoritative core has reached stable accepted
   health. A momentarily empty process list is not durable quiescence when a
   respawner remains active. Let the capture worker drain the final writes,
   check the inbox again, then stop the exact legacy capture, dashboard, and
   prior core LaunchAgents. Review exact PIDs and labels; never use `pkill`,
   `killall`, or a broad command match.

   Keep the reviewed Codex MCP definition present but set to `enabled=false`
   for the entire certification window. This bounded activation profile
   preserves the exact command, environment, and binding contract while
   preventing an already-running Codex host from respawning a wrapper during
   the long recovery proof. Publish it transactionally and prove it is
   idempotent before process inventory:

   ```bash
   .venv/bin/python scripts/install_client_configs.py \
     --codex-disabled-for-certification
   .venv/bin/python scripts/install_client_configs.py \
     --codex-disabled-for-certification \
     --dry-run
   ```

   The dry-run must report schema `synapse-s2.client-config-plan.v1`, profile
   `certification-quiescence`, `codex_mcp_enabled: false`, all four expected
   clients, `publication_recovery_required: false`, no pending change, and
   `restart_required: false`. Its repository, launcher, binding path and digest,
   configuration fingerprint, embedding-space identity, and authority mode
   must match the reviewed candidate exactly. Continue to close and disable
   every other persistent client or exact respawner independently; the Codex
   profile is not a blanket quiescence bypass. A surviving config-publication
   journal blocks dry-run certification until a real non-dry-run invocation
   safely completes or rolls back that transaction.

   Run a separate read-only inventory before certification:

   ```bash
   scripts/core_cutover_preflight.sh --inventory-only --require-quiescent
   ```

   Continue only when its JSON reports `ready: true`, an empty
   `process_findings` array, `process_findings_truncated: false`, an empty
   `quiescence_loaded_categories` array, and an empty
   `quiescence_policy_blockers` array. The reviewed policy requires the exact
   `com.master-mold.imprint.inboxworker` respawner to be positively disabled as
   well as unloaded. A capped or unavailable inventory is not proof of absence.
   Do not reopen a persistent MCP client or legacy worker after this gate, and
   treat any automatically relaunched client as an invalidation that requires
   another inbox drain and a completely new evidence run.

   If an earlier first-adoption start failed while the database remained exact
   unclaimed v5 and left `core/requests.sqlite3`, do not rerun installation or
   use `recover-existing`. With the exact core LaunchAgent positively disabled
   and unloaded, reconcile that residue before producing any new recovery or
   readiness evidence:

   ```bash
   scripts/install_core_agent.sh repair-preclaim-residue --confirm
   ```

   This guarded lane accepts only the exact supported pre-governed v5 store and
   a verified zero-row preclaim journal. Under the exclusive authority lease it
   preserves the journal and lock as authenticated private archives, publishes
   a complete repair receipt, revalidates all prior repair evidence, and proves
   the full logical database snapshot is unchanged. A nonempty journal,
   malformed or unexpected sidecar, active/loaded core, v6 marker, schema
   mismatch, authority contention, or changed prior archive fails without
   replay or cleanup. Review the content-free result, require
   `status: complete`, `request_row_count: 0`, and the same logical snapshot
   digest, then start again with a fresh paired bundle and the complete
   certification sequence below. The command does not make older evidence
   reusable.

3. Produce a fresh, clean-HEAD operator-readiness evidence pack through the
   binding-backed launcher only after the preceding zero-writer proof:

   ```bash
   .venv/bin/python scripts/operator_readiness_certify.py \
     --json \
     --context default \
     --agent-id codex-desktop \
     --expect-embedding-provider mlx-neural \
     --codex-disabled-for-certification
   ```

   The certifier loads the digest-bound candidate through the same installer
   contract used by cutover. Its installed-launcher status call must match the
   observed effective configuration fingerprint and embedding-space identity,
   and its manifest must contain the canonical
   `synapse-s2.core-config-evidence.v1` contract and exact configuration
   fingerprint. `--expect-*` flags are assertions only; they cannot select a
   different backend. Before any functional probe, the required runtime-build
   proof compares the service health build ID and configuration fingerprint to
   the deterministic build of the current clean source tree; a mismatch ends
   the run as a diagnostic-only blocked pack. Recovery backup, signed
   verification, isolated restore,
   and every required proof must be ready and replay-free. The certifier's own
   bounded client processes complete their `finish()` writes before its later
   bounded capture drain. It then acquires exclusive core authority and the
   existing global capture lock, rechecks process and LaunchAgent inventory,
   and performs backup, verification, isolated restore, and final evidence
   capture in-process. The final postflight completes while both locks are
   held. The recovery manager, temporary restore, store, and authority lease
   must then unwind successfully; only afterward is the optional ZIP built from
   the staged manifest and `manifest.json` atomically published last. The
   versioned 21-proof contract rejects missing, duplicate, optional-shadow, or
   non-ready rows, and the manifest binds the exact versioned quiescence policy
   digest. Probe children receive only a minimal allowlisted environment, not
   ambient GitHub, OpenAI, Hugging Face, Python, or DYLD credentials/settings.
   Its Retrieval v2 proof writes one fresh, run-derived alphabetic marker, uses
   the exact write text as the local-scope query with graph-neighbor expansion
   disabled, and accepts only one returned item carrying the exact memory ID,
   tag, and marker together. This keeps historical certification traces from
   crowding or accidentally satisfying the proof without weakening the normal
   production ranker.
   The entire guarded recovery transaction also runs under the installer's
   canonical 600-second backup-inspection policy. Ambient shell values cannot
   shorten or enlarge that reviewed bound, and the prior environment is
   restored after the transaction unwinds. On Dans-MBP, SQLite recorded the
   certifier inspection as `interrupted` about 121 seconds after the publication
   journal completed while this environment value was absent, directly matching
   the prior 120-second default; the four downstream recovery-proof skips were
   then mechanical consequences. That exact certifier failure is time-causally
   attributable to the policy mismatch, but it is not evidence that the earlier
   candidate's generic cutover-attestation rejection had the same sole cause.
   Those transient Phase-A processes do not authorize reopening an external
   persistent wrapper. Treat the returned manifest as immediately perishable
   and proceed directly to the next two commands.

   For an ordinary v6 replacement whose exact bound core is already healthy,
   add `--handoff-running-core`. The certifier performs every live Phase-A
   proof first and only then disables and unloads the exact bound core label
   before taking the exclusive authority guard. If any required Phase-A proof
   is not ready, it leaves launchd untouched and the evidence pack is blocked.
   `--repair-delivery-publication-after-handoff` may be added only with that
   handoff flag and the canonical core label. The certifier first records the
   content-free audit, then delegates its exact revision to
   `install_core_agent.sh context-delivery-integrity` for any required repair.
   That subprocess takes the same installer lock and enforces the same
   disabled/unloaded label gate as the manual procedure below; the certifier is
   not a second SQLite write lane. Its evidence is ready only when the installer
   returns a verified maintenance receipt, complete checkpoint, `quick_check`,
   zero foreign-key errors, verified backup, and a final `ready` audit. Neither
   flag is a way to make an unhealthy Phase-A probe pass.

   If the incumbent v6 build is too old to satisfy the current live contract,
   do not restart it and do not reuse an older evidence pack. After the exact
   core label is disabled and unloaded, first run the content-free delivery
   audit and review its exact revision. Then use the one-shot replacement
   certification lane:

   ```bash
   scripts/install_core_agent.sh stage-replacement \
     --confirm \
     --expected-revision '<exact ready audit revision>'
   .venv/bin/python scripts/operator_readiness_certify.py \
     --json \
     --context default \
     --agent-id codex-desktop \
     --expect-embedding-provider mlx-neural \
     --handoff-running-core \
     --codex-disabled-for-certification
   ```

   Replacement staging admits one configured capture batch by default. If an
   extended outage left a larger but otherwise clean queue, first resolve every
   error, temporary, malformed-claim, reconciliation, and receipt-backed item;
   keep all writers and respawners quiescent; then compute the smallest whole
   number of configured batches covering the observed pending-plus-processing
   count. A reviewed recovery may pass that explicit bound (maximum 32 batches
   and 1,000 signed files) and a longer bounded activation wait:

   ```bash
   scripts/install_core_agent.sh stage-replacement \
     --confirm \
     --expected-revision '<exact ready audit revision>' \
     --replacement-capture-batches '<reviewed batch count>' \
     --wait-seconds 600
   ```

   The selected batch count does not alter the production CoreConfig or weaken
   transport classification. The exact queued set is still signed into the
   recovery evidence, every file must drain exactly once, and any unexpected,
   ambiguous, unsafe, or remaining item triggers verified candidate cleanup.

   `stage-replacement` accepts only a build-only successor with unchanged
   configuration, protocol, root generation, lock inode, embedding space,
   store, and request journal. Under one exclusive authority and capture lock
   scope it creates and verifies a fresh signed backup plus isolated restore,
   binds the ready delivery audit and clean current Git build into a private,
   dynamically budgeted admission (ten minutes by default and at most thirty
   minutes for the longest bounded activation wait), and starts the candidate
   from a separate non-`KeepAlive` plist. Publisher proof and launchd startup
   both pin `SYNAPSE_S2_BACKUP_INSPECTION_TIMEOUT_SECONDS=600`; shell values do
   not override it. The same finite value is present in the temporary candidate
   and persistent production plists because each process independently
   reverifies its signed recovery binding before claiming authority. This
   prevents either launch from silently falling back to the library's
   120-second default after the installer completed a valid large-store proof.
   The SQLite VM-step and maximum-value limits remain independently bounded and
   unchanged. Health reports
   `deployment_mode: replacement-certification`; the process self-fences when
   that admission expires. Its durable authority marker remains explicitly
   provisional, so a crash or manual restart without fresh final cutover
   evidence fails closed. It publishes neither a persistent LaunchAgent nor a
   client binding. The certifier must prove that exact runtime build, disable
   and unload it, and publish a completely fresh 21-proof pack. Only the normal
   `install --evidence-manifest ...` command below may then create the
   persistent production service. On candidate activation failure the installer
   attempts exact-label cleanup and verifies both the loaded/running snapshot
   and disabled policy before saying the label is safe. If either readback or
   cleanup fails, cutover stops with an unverified-cleanup error and the signed
   candidate self-fences at admission expiry; never fall back to the predecessor
   build or continue promotion from that state.

   Final wrapper shutdown may leave a bounded set of durable session-boundary
   drops after every old writer is already disabled. An interrupted provisional
   core may also leave valid payloads inside its atomic processing claims.
   Staging permits one configured capture batch by default, or the explicit
   reviewed multi-batch bound above, across the inbox and well-formed processing
   claims only when every temporary, malformed-claim, error, and reconciliation
   class is zero; that exact queued set is included in the signed recovery
   bundle. Before taking that recovery point, the
   installer publishes an owner-only, time-bounded capture freeze under the
   same global capture lock used by every producer. Session-boundary records
   that arrive during proof or activation are atomically written to a private
   deferred spool instead of changing the signed queue. The provisional core
   must drain the admitted batch through its governed exactly-once worker, and
   staging verifies a completely zero-debt main transport after stabilized
   health. The bounded drain permits only the admitted files to move through a
   canonical processing claim and requires the processed-archive and receipt
   totals to rise by that exact count. The installer then atomically thaws the
   deferred spool into the empty inbox and drains those late arrivals before
   returning staged health. A partial batch, malformed drop, error, unexpected
   file in the signed main queue, or remaining pending file triggers the same
   verified exact-label cleanup and blocks certification.
   A queued capture that already has a matching transport receipt is also
   rejected before launch: its drain accounting is ambiguous until a governed
   reconciliation contract can prove the receipt, payload, and ledger together.
   An interrupted freeze also fails recoverably: its bounded lease expires,
   and the next producer moves every validated deferred payload back into the
   normal inbox under the global lock before accepting the new drop. Unsafe
   deferred files or directories fail closed and require operator repair; they
   are never silently skipped or deleted.
   Candidate activation first proves the authority, socket, journal, and backend
   while allowing the admitted capture worker to report `ready: false` only
   during its first in-flight iteration. The installer then lets the drain use
   the unused portion of the two signed activation waits and requires a second
   stabilized health proof with the capture worker fully ready. It never
   extends the admission TTL or consumes the reserved certification window.
   One daemon iteration coalesces repairable MLX
   trace/cache/runtime refreshes across the admitted files, so a durable batch
   pays that refresh cost once without weakening per-capture SQLite atomicity,
   receipts, or archive moves. Drain observation uses nonblocking lock probes so
   the installer deadline remains enforceable while the worker owns the capture
   maintenance lock.

   Semantic-index audit and repair are likewise explicit bounded maintenance
   lanes rather than ordinary 30-second RPCs. Both the authoritative client
   and service allow up to 120 seconds for these full-store operations, so a
   healthy audit that outlives a short caller timeout cannot be misclassified
   as a stalled writer and poison the core. Health remains authenticated and
   reports maintenance while either lane is active.

   Native neural operations use a separate 120-second bounded floor on both
   the authoritative client and serialized backend lane. This covers embedding,
   Retrieval v2, SNN query, trace registration, conversation/event capture,
   Cortex recall and trace commits, goal writes, certification benchmarks, and
   consolidation. A caller cannot shorten that floor and turn a healthy native
   mutation into an avoidable `outcome_unknown`; longer valid deadlines remain
   valid up to the protocol maximum. Ordinary non-replication status and graph
   control-plane reads retain the 30-second lane fence. Every core RPC and
   capture worker also enters the backend's MLX thread-local stream context
   before array execution, so serialized work remains valid even though
   accepted requests run on different OS threads.

   Paired backup, verification, isolated restore, capture-ledger recovery,
   signed retention, replication checkpoint create/stage, and the replication
   status read's full staged-checkpoint semantic audit use a separate closed
   authenticated recovery/replication-maintenance class. Those eleven operations
   have a one-hour client, protocol, and backend-lane budget because a verified
   large-store copy or staged semantic audit can legitimately outlive five
   minutes. All ordinary, bridge-governance, pairing, revocation, and ACK
   operations retain their existing shorter bounds. Health remains authenticated
   during recovery and reports the fixed lane owner plus `deadline_remaining_ms`;
   a lost mutation response still requires exact `request-status`
   reconciliation and is never replayed automatically. Waiting to acquire the
   serialized lane remains
   capped at five minutes, preventing the longer execution budget from becoming
   an hour-long worker queue. This execution budget does not modify evidence
   freshness or any signed plan, proposal, admission, or final-cutover expiry.

   Start Work and Context Health share one Memory Hygiene result. Hygiene reads
   `memory-list` compact cursor pages of at most 50 entries, holds one snapshot
   revision across the bounded scan, rejects repeated or malformed cursors, and
   never serializes unrelated graph endpoints or relationship bodies. The
   response states the exact total, scanned count, 250-entry scan ceiling, and
   whether that bounded assessment covered the whole namespace.

   The existing authoritative client binding is deliberately retained so the
   certifier can exercise the staged service. It also means another already
   configured same-user MCP client could connect during this window. Close all
   persistent wrappers, disable their exact respawners, and keep them closed
   from the reviewed audit through final installation. Any unexpected client
   invalidates the certification run. During staging,
   `install_core_agent.sh status` reports `runtime_healthy: true`,
   `provisional: true`, `deployment_mode: replacement-certification`, and
   `production_ready: false`; do not interpret the retained binding as a live
   promotion. Staging also requires at least five minutes of signed admission
   life to remain after stabilized health so certification and final promotion
   cannot begin inside an unsafe expiry window.

   If a provisional candidate crashes, expires, or is interrupted before the
   final evidence pack exists, its durable marker intentionally prevents an
   ordinary restart. Stop the exact label so it is disabled and unloaded, run
   `context-delivery-integrity` again, review the new ready audit revision, and
   rerun `stage-replacement --confirm --expected-revision ...`. A fresh signed
   recovery point may resume the same build only when the predecessor marker
   is already explicitly provisional; an ordinary same-build marker remains
   ineligible. Never reuse the expired admission or a partial evidence pack.
4. Run the read-only inventory and recovery binding gate immediately after the
   certifier. This is also the post-backup quiescence proof: it must still show
   no writer process or loaded legacy category, and the exact recovery binding
   must still match the live database and runtime state.

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
   category; command text is never returned. After the potentially long
   recovery comparison, it revalidates the exact disabled client profile and
   repeats process plus LaunchAgent inventory immediately before attestation or
   a ready result. A wrapper or respawner that appears during verification
   therefore invalidates the cutover instead of slipping through the earlier
   snapshot.
5. Install only with that explicit evidence manifest:

   ```bash
   scripts/install_core_agent.sh install \
     --evidence-manifest /absolute/path/to/evidence-pack/manifest.json
   ```

   Immediately before any install mutation, the installer publishes a signed
   `synapse-s2.core-cutover-attestation.v3` at the canonical core path. The
   owner-only receipt binds the current clean Git HEAD, deterministic source
   build ID, config fingerprint, evidence-manifest digest, governance
   generation, exact logical database digest, exact capture-manifest digest,
   recovery media schema/completeness, media archive and manifest digests, and
   media object/reference counts, the exact bounded Memora catalog/projection/
   governance-receipt revision and effectiveness/drift counts (never cue text,
   source text, or vectors),
   runtime-state presence and canonical digest, and (for v6) the exact request-
   journal logical digest and source binding receipt. It also binds the signed
   recovery-bundle and isolated-restore receipt digests. The receipt is valid
   for at most ten minutes and publication requires at least 180 seconds of
   remaining evidence validity, covering the bounded full-store preclaim digest,
   commit margin, and launch scheduling headroom. Before replacing an older
   canonical attestation, the
   installer preserves its exact bytes in a private digest-named archive with a
   signed inode- and digest-bound receipt. Expired, future-dated, near-expiry,
   partially populated, or signer-mismatched receipts fail closed.

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

After `install` and a fresh `status` both report stable authenticated health,
`production_ready: true`, embedded capture readiness, and
`client_binding.ready: true`, restore the normal Codex activation profile and
prove the publication is already converged:

```bash
scripts/install_core_agent.sh status
.venv/bin/python scripts/install_client_configs.py --codex-enabled
.venv/bin/python scripts/install_client_configs.py --codex-enabled --dry-run
```

The final dry-run must report profile `operational`,
`codex_mcp_enabled: true`, no pending changes, and
`restart_required: false`. Never restore the client before production health
and binding publication: a newly spawned wrapper would invalidate a still-live
certification or preflight window.

If activation fails only after schema v6 has been durably claimed, the original
v5 evidence pack describes bytes that no longer exist and must never be reused.
After correcting the non-identity-changing startup cause, use the dedicated
same-installation recovery action without an evidence argument:

```bash
scripts/install_core_agent.sh recover-existing
scripts/install_core_agent.sh status
```

`recover-existing` is not a replacement, restore-adoption, journal reset, or
general repair command. Before touching launchd it requires the exact existing
owner-only config, authentication token, current-build plist, candidate or
authoritative binding, unloaded label, exclusive existing authority and journal
locks, authoritative-v6 marker, store/root/lock/journal/embedding identities,
request-journal logical and row-state integrity, and either the exact complete
runtime-state binding or the core's already-supported same-generation pending
runtime publication. It accepts no cutover evidence and creates no second
recovery ticket; the core revalidates all identities again under its authority
lease. Only stable authenticated health plus embedded capture readiness permits
publication of `authoritative-core-v6`. Any activation failure attempts exact-
label bootout and disable; the result reports explicitly if cleanup could not be
verified, and every artifact is preserved. Repeating the action against the
same already-healthy service is idempotent. Any config, build, protocol,
embedding, root, lock, store, journal, runtime, binding, token, or restored-
target drift requires the ordinary fresh attested replacement or restore-
adoption procedure instead.

### Offline delivery-publication integrity repair

One installer-only maintenance lane exists for the specific crash boundary in
which canonical context events and target rows committed but the derived
target high-water or existing receipt-derived cursors did not. It is not an
MCP, dashboard, startup, migration, or general SQLite repair surface:

```bash
scripts/install_core_agent.sh stop
scripts/install_core_agent.sh context-delivery-integrity
scripts/install_core_agent.sh context-delivery-integrity \
  --repair --confirm \
  --expected-revision '<exact 64-hex audit revision>'
scripts/install_core_agent.sh context-delivery-integrity
```

The audit and repair run under the existing installer lock and require the
exact core LaunchAgent to be positively disabled and unloaded. The command
does not change launchd state. It then acquires one unclaimed exclusive core
lease, requires the exact authoritative-v6 marker/schema pair, validates every
event, target, delivery, receipt, tombstone, consumer-group, cursor, foreign-
key, and ledger prerequisite, and accepts no delivery defect other than the
reported deterministic receipt-derived cursor mismatch. Missing, malformed,
negative, noncanonical, or ahead-of-ledger target high-water values block the
operation.

The review revision hashes the exact raw derivation inputs as well as the
content-free audit result. Any event, target, consumer, group, delivery,
receipt, tombstone, cursor, or high-water change invalidates the revision even
when mismatch counts stay equal. Repair first creates and verifies an owner-
only SQLite safety backup. One exclusive transaction may update only the
existing target high-water metadata row, existing derived cursor rows, and one
`context-delivery-publication-repair` maintenance receipt. It does not create
events or targets, alter delivery/ACK evidence, replay work, or call broad
schema reconciliation. Commit is followed by a complete checkpoint, exact
receipt verification, SQLite quick/foreign-key checks, a no-mutation migration
contract check, and a fresh ready audit. Pre-commit failure rolls everything
back and discards the unused attempt backup; post-commit uncertainty preserves
the backup and leaves the service stopped.

The committed receipt remains `pending` until those post-commit proofs finish.
If the process is interrupted in that window, the next audit reports
`committed_unverified`, not `ready`. Review that new exact audit revision and
rerun the same `--repair --confirm --expected-revision ...` command; it rehashes
and reopens the existing backup, rechecks SQLite and the no-mutation migration
contract, and only then marks the receipt verified. It does not create a second
repair or backup. An already-ready repair invocation also reverifies the latest
verified receipt and backup instead of treating derived cursor equality alone
as proof.

The result reports `replacement_required: true` when the currently checked-out
source build differs from the durable marker. In that case, do not use
`recover-existing`; complete a fresh evidence-bound replacement. A same-build
incident may proceed to `recover-existing` only when all of that action's
independent identity and sealed-SQLite gates also pass.

### Offline secret-content preclaim repair

If replacement staging stops because its fresh backup fails only the secret-
content recovery invariants, do not retry staging and do not edit SQLite
directly. Use the installer-only preclaim lane while the exact core label and
all client writers remain stopped:

```bash
scripts/install_core_agent.sh stop
scripts/install_core_agent.sh secret-content-integrity
scripts/install_core_agent.sh secret-content-integrity \
  --repair --confirm \
  --expected-revision '<exact 64-hex audit revision>'
scripts/install_core_agent.sh secret-content-integrity
```

The first command is a content-free read-only audit. It reports only counts by
schema column, integrity booleans, and a digest of the row/column repair-plan
shape; it never hashes or returns a stored value. Identifier findings,
unclassified text columns, SQLite corruption, foreign-key errors, or any
noncanonical schema block repair. The repair requires the exact reviewed
revision, the existing installer lock, a positively disabled and unloaded
LaunchAgent, and one exclusive unclaimed core lease. It never starts or enables
a service.

Before mutation the lane creates and structurally verifies an owner-only
SQLite safety backup. That pre-repair artifact can contain the residue being
removed, so it is rollback evidence rather than a promotable recovery point.
One `BEGIN EXCLUSIVE` transaction runs only the deterministic legacy content
scrub: credential-bearing or raw-digest-derived memory source/tag rows are
deleted with cascading retrieval artifacts; metadata and non-derived event
content are redacted in place; derived surface terms are rebuilt. The existing
`secret-content-scrub` receipt and a separate
`secret-content-preclaim-repair` action proof contain counts and artifact
identities only. The action proof is inserted as `pending` in the same
transaction as the scrub and binds the reviewed revision, safety-backup
identity, and repaired-state revision. The scrub can therefore never become a
bare, apparently-ready commit without a resumable proof record.

After commit, the lane requires a complete checkpoint, SQLite quick and full
integrity checks, zero foreign-key errors, a no-mutation migration contract
check, and a fresh audit with zero redaction, raw-digest, identifier, or
unclassified-column findings. It then creates a second owner-only proof
snapshot and runs the complete recovery-invariant inspector; the action is
successful only when that snapshot is restore eligible. Only then is the exact
pending action receipt promoted to `verified`. If execution stops after the
scrub commit, the next audit reports `committed_unverified` with one pending
receipt rather than `ready`. Review its new exact audit revision and rerun the
same repair command; it resumes checkpoint, integrity, safety-backup, and proof-
backup verification and promotes that same receipt without scrubbing again.
A pre-commit failure rolls back and discards its unused backup. A post-commit
proof failure preserves the available backups and pending content-free action
receipt, leaves the service stopped, and blocks replacement staging until the
resume completes. Staging independently rechecks this audit immediately before
recovery publication and accepts only `ready` with zero pending or invalid
pending receipts.

The recovery admission proof requires both SQLite main databases to be sealed.
A rollback journal, incomplete WAL/SHM pair, nonzero WAL, nonprivate sidecar, or
sidecar drift fails closed. The only tolerated clean-close residue is an exact
owner-only pair consisting of a zero-byte WAL and a positive 32-KiB-aligned SHM
no larger than 8 MiB; both files are sealed by identity, metadata, and SHA-256 before and after immutable-main
inspection and are never opened by SQLite. `recover-existing` never checkpoints,
deletes, replays, or repairs residue. A crash that leaves a data-bearing WAL must
go through verified offline backup/recovery so frames are not silently discarded
or incorporated without an attested comparison.

After the first successful v6 cutover, exercise the exact restart lane while the
deployment window is still open and retain the JSON results:

```bash
scripts/install_core_agent.sh status
scripts/install_core_agent.sh stop
scripts/install_core_agent.sh recover-existing
scripts/install_core_agent.sh status
```

The final status must again report stable authenticated health, capture ready,
the expected numeric authority epoch, and `client_binding.ready: true`.

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
