from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import stat
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from image_capture import (
    ImageCaptureError,
    ImageCaptureNotFound,
    MediaObjectReader,
)
from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager
from replication_protocol import (
    ACK_SCHEMA,
    BASE_NODE_CAPABILITIES,
    CHECKPOINT_SCHEMA,
    LINEAGE_ID_RE,
    MEDIA_ARTIFACT_CAPABILITY,
    NODE_CAPABILITIES,
    NODE_ID_RE,
    REPLICATION_PROTOCOL_VERSION,
    ReplicationProtocolError,
    ack_id_for,
    checkpoint_id_for,
    node_id_for_key_id,
    read_private_bytes,
    read_private_json,
    sign_payload,
    signed_descriptor_transition,
    signed_node_descriptor,
    signed_node_descriptor_transition,
    validate_ack,
    validate_checkpoint,
    validate_descriptor_transition,
    validate_digest,
    validate_node_descriptor,
    validate_node_descriptor_transition,
    validate_private_directory,
    validate_safe_name,
    write_private_json_exclusive,
)
from replication_store import STATUS_PEER_PAGE_LIMIT, ReplicationLedger


_ARTIFACT_ORDER = (
    "database",
    "database_receipt",
    "capture",
    "media",
    "request_journal",
    "request_journal_binding",
    "runtime_state",
    "bundle_receipt",
)


class ReplicationManager:
    """Offline, target-bound, single-writer recovery-checkpoint replication.

    This class deliberately has no socket, SSH, discovery, or live-cutover API.
    The only accepted transport is an operator-mediated private directory.  A
    receiver materializes an isolated recovery proof and signs an ACK; it never
    replaces the live memory database.
    """

    def __init__(
        self,
        store: DurableMemoryStore,
        *,
        recovery_manager: VerifiedRecoveryManager | None = None,
    ) -> None:
        self.store = store
        self.recovery = recovery_manager or VerifiedRecoveryManager(
            store,
            capture_root=store.db_path.parent,
        )
        if self.recovery.store is not store:
            raise ValueError("replication and recovery managers must share one memory store")
        self.ledger = ReplicationLedger(store)
        self.root = self.ledger.root
        self.outgoing_root = self.root / "outgoing"
        self.incoming_root = self.root / "incoming"
        self.staged_root = self.root / "staged"
        self.acks_root = self.root / "acks"
        self.quarantine_root = self.root / "quarantine"
        self.peers_root = self.root / "peers"
        for path in (
            self.outgoing_root,
            self.incoming_root,
            self.staged_root,
            self.acks_root,
            self.quarantine_root,
            self.peers_root,
        ):
            self._ensure_private_directory(path)
        self.descriptor_path = self.root / "node-descriptor.json"
        self._descriptor = self._load_or_create_descriptor()
        self.node_id = str(self._descriptor["node_id"])

    def _ensure_private_directory(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            validate_private_directory(path)
        else:
            self.store._ensure_directory(path, owned=True)
        validate_private_directory(path)

    def _derived_path(self, root: Path, *names: str) -> Path:
        validate_private_directory(root)
        clean = [validate_safe_name(name, "replication path component") for name in names]
        candidate = root.joinpath(*clean)
        root_resolved = root.resolve()
        try:
            candidate.resolve(strict=False).relative_to(root_resolved)
        except ValueError as exc:
            raise ReplicationProtocolError("replication path escapes its managed root") from exc
        return candidate

    @staticmethod
    def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
        return (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_mtime_ns),
            int(metadata.st_ctime_ns),
        )

    @contextmanager
    def _private_directory_guard(
        self,
        path: Path,
        *,
        expected_names: set[str] | None = None,
        maximum_entries: int = 16,
    ):
        before = validate_private_directory(path)
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                self._directory_identity(before) != self._directory_identity(opened)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
            ):
                raise RuntimeError("replication source directory changed while opening")
            names = self._bounded_directory_names(descriptor, maximum_entries)
            if expected_names is not None and set(names) != expected_names:
                raise ReplicationProtocolError(
                    "checkpoint directory contains an unexpected entry"
                )
            yield descriptor
            after = os.fstat(descriptor)
            visible = os.lstat(path)
            final_names = self._bounded_directory_names(descriptor, maximum_entries)
            if (
                self._directory_identity(after) != self._directory_identity(opened)
                or self._directory_identity(visible) != self._directory_identity(opened)
                or after.st_uid != os.getuid()
                or stat.S_IMODE(after.st_mode) != 0o700
                or (
                    expected_names is not None
                    and set(final_names) != expected_names
                )
            ):
                raise RuntimeError("replication source directory changed during use")
        finally:
            os.close(descriptor)

    @staticmethod
    def _bounded_directory_names(descriptor: int, maximum_entries: int) -> list[str]:
        names: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum_entries:
                    raise ReplicationProtocolError(
                        "checkpoint directory exceeds its entry bound"
                    )
        return names

    def _load_or_create_descriptor(self) -> dict[str, Any]:
        _private, public_bytes, key_id = self.store._backup_receipt_signing_key(
            create=True
        )
        if public_bytes is None or key_id is None:
            raise RuntimeError("recovery signing authority is unavailable")
        encoded_public = base64.b64encode(public_bytes).decode("ascii")
        if self.descriptor_path.exists() or self.descriptor_path.is_symlink():
            return validate_node_descriptor(
                read_private_json(self.descriptor_path),
                expected_public_key=encoded_public,
                expected_key_id=key_id,
            )
        descriptor = signed_node_descriptor(self.store, created_at=time.time())
        write_private_json_exclusive(self.store, self.descriptor_path, descriptor)
        return descriptor

    @staticmethod
    def new_lineage_id() -> str:
        return f"s2lineage_{secrets.token_hex(16)}"

    def node_descriptor(self) -> dict[str, Any]:
        return copy.deepcopy(self._descriptor)

    @staticmethod
    def _document(value: dict[str, Any] | str | os.PathLike[str]) -> dict[str, Any]:
        if isinstance(value, dict):
            return copy.deepcopy(value)
        return read_private_json(Path(value).expanduser().absolute())

    def pair_peer(
        self,
        descriptor: dict[str, Any] | str | os.PathLike[str],
        *,
        lineage_id: str,
        direction: str,
        expected_descriptor_digest: str,
        expected_signing_key_id: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm=true is required to pin a replication peer")
        if LINEAGE_ID_RE.fullmatch(str(lineage_id)) is None:
            raise ReplicationProtocolError("replication lineage identifier is invalid")
        validated = validate_node_descriptor(self._document(descriptor))
        expected_descriptor = validate_digest(
            expected_descriptor_digest, "expected peer descriptor digest"
        )
        if (
            (
                expected_signing_key_id is not None
                and not secrets.compare_digest(
                    str(validated["auth_key_id"]),
                    validate_digest(
                        expected_signing_key_id,
                        "expected peer signing key identifier",
                    ),
                )
            )
            or not secrets.compare_digest(
                str(validated["receipt_digest"]), expected_descriptor
            )
        ):
            raise ReplicationProtocolError(
                "peer descriptor does not match the independently reviewed fingerprint"
            )
        peer_id = str(validated["node_id"])
        if secrets.compare_digest(peer_id, self.node_id):
            raise ReplicationProtocolError("a replication node cannot pair with itself")
        if direction not in {"send", "receive"}:
            raise ReplicationProtocolError("peer direction must be send or receive")
        now = time.time()
        with self.ledger.manager_lock():
            # Evidence is published (and fsynced) before the ledger pointer is
            # written: a crash between the two leaves only an inert
            # digest-addressed document that the retried pairing reuses.
            self._publish_peer_descriptor_evidence(peer_id, validated)
            record = self.ledger.pair_peer(
                peer_id=peer_id,
                lineage_id=str(lineage_id),
                direction=direction,
                signing_key_id=str(validated["auth_key_id"]),
                signing_public_key=str(validated["signing_public_key"]),
                descriptor_digest=str(validated["receipt_digest"]),
                now=now,
                audit=True,
            )
        return self._public_peer(record)

    def _peer_descriptor_evidence_path(self, peer_id: str, digest: str) -> Path:
        return self._derived_path(
            self.peers_root, f"{peer_id}.descriptor.{digest}.json"
        )

    def _peer_transition_path(self, peer_id: str, digest: str) -> Path:
        return self._derived_path(
            self.peers_root, f"{peer_id}.transition.{digest}.json"
        )

    def _publish_peer_descriptor_evidence(
        self, peer_id: str, validated: dict[str, Any]
    ) -> None:
        """Persist a signed peer descriptor as append-only, digest-addressed evidence."""

        evidence = self._peer_descriptor_evidence_path(
            peer_id, str(validated["receipt_digest"])
        )
        if evidence.exists() or evidence.is_symlink():
            existing = validate_node_descriptor(
                read_private_json(evidence),
                expected_public_key=str(validated["signing_public_key"]),
                expected_key_id=str(validated["auth_key_id"]),
            )
            if not secrets.compare_digest(
                str(existing["receipt_digest"]), str(validated["receipt_digest"])
            ) or str(existing["node_id"]) != peer_id:
                raise ReplicationProtocolError(
                    "peer descriptor evidence conflicts with its digest address"
                )
            return
        write_private_json_exclusive(self.store, evidence, validated)
        self.store._fsync_directory(self.peers_root)

    def _peer_capabilities(self, peer: dict[str, Any]) -> list[str]:
        """Return the pinned peer's signed capabilities, baseline if unknown.

        The current evidence document is resolved through the ledger's pinned
        descriptor digest, so a stale or replaced sidecar can never advertise
        capabilities the ledger has not accepted.
        """

        evidence = self._peer_descriptor_evidence_path(
            str(peer["peer_id"]), str(peer["descriptor_digest"])
        )
        if not evidence.exists() and not evidence.is_symlink():
            # Peers pinned before capability negotiation retain no descriptor
            # document; they are treated as baseline (no media capability)
            # until the operator upgrades them with a reviewed descriptor.
            return list(BASE_NODE_CAPABILITIES)
        document = validate_node_descriptor(
            read_private_json(evidence),
            expected_public_key=str(peer["signing_public_key"]),
            expected_key_id=str(peer["signing_key_id"]),
        )
        if (
            not secrets.compare_digest(
                str(document["receipt_digest"]), str(peer["descriptor_digest"])
            )
            or str(document["node_id"]) != str(peer["peer_id"])
        ):
            raise ReplicationProtocolError(
                "pinned peer descriptor document conflicts with the ledger"
            )
        return [str(item) for item in document["capabilities"]]

    def _active_node_descriptor(self) -> dict[str, Any]:
        """Return the active on-disk node descriptor, re-validated.

        The pointer file is re-validated on every use so a tampered or
        partially written descriptor can never silently activate media.
        """

        document = validate_node_descriptor(
            read_private_json(self.descriptor_path),
            expected_key_id=str(self._descriptor["auth_key_id"]),
        )
        if str(document["node_id"]) != self.node_id:
            raise ReplicationProtocolError(
                "active node descriptor does not match this node's identity"
            )
        return document

    def _local_capabilities(self) -> list[str]:
        return [
            str(item) for item in self._active_node_descriptor()["capabilities"]
        ]

    def _verified_peer_transition(
        self,
        peer: dict[str, Any],
        *,
        recorded_previous: str | None,
    ) -> dict[str, Any]:
        """Return the exactly cross-bound old->new receipt for an upgraded pin.

        The receipt must be locally signed and bind the recorder, peer,
        lineage, direction, signing key, and both descriptor digests; its
        predecessor must equal the anchored audit record written by the
        descriptor compare-and-swap, and when it claims the previous
        descriptor document as evidence, that retired document must still
        validate at its digest address.
        """

        transition_path = self._peer_transition_path(
            str(peer["peer_id"]), str(peer["descriptor_digest"])
        )
        if not transition_path.exists() and not transition_path.is_symlink():
            raise ReplicationProtocolError(
                "upgraded peer descriptor lacks its signed transition receipt"
            )
        record = validate_descriptor_transition(
            read_private_json(transition_path),
            expected_key_id=str(self._descriptor["auth_key_id"]),
        )
        if (
            str(record["recorder_node_id"]) != self.node_id
            or str(record["peer_id"]) != str(peer["peer_id"])
            or str(record["lineage_id"]) != str(peer["lineage_id"])
            or str(record["direction"]) != str(peer["direction"])
            or str(record["peer_signing_key_id"]) != str(peer["signing_key_id"])
            or not secrets.compare_digest(
                str(record["descriptor_digest"]), str(peer["descriptor_digest"])
            )
        ):
            raise ReplicationProtocolError(
                "peer descriptor transition receipt is not cross-bound to "
                "the pinned peer"
            )
        if recorded_previous is None:
            raise ReplicationProtocolError(
                "peer descriptor transition receipt has no anchored "
                "compare-and-swap predecessor record"
            )
        if not secrets.compare_digest(
            str(record["previous_descriptor_digest"]), recorded_previous
        ):
            raise ReplicationProtocolError(
                "peer descriptor transition receipt does not match the "
                "ledger-recorded predecessor"
            )
        if str(record["previous_evidence"]) == "descriptor-document":
            previous_digest = str(record["previous_descriptor_digest"])
            previous = validate_node_descriptor(
                read_private_json(
                    self._peer_descriptor_evidence_path(
                        str(peer["peer_id"]), previous_digest
                    )
                ),
                expected_public_key=str(peer["signing_public_key"]),
                expected_key_id=str(peer["signing_key_id"]),
            )
            if not secrets.compare_digest(
                str(previous["receipt_digest"]), previous_digest
            ) or str(previous["node_id"]) != str(peer["peer_id"]):
                raise ReplicationProtocolError(
                    "retired peer descriptor evidence conflicts with the "
                    "transition receipt"
                )
        return record

    def _peer_capability_report(
        self,
        peer: dict[str, Any],
        *,
        recorded_previous: str | None,
    ) -> dict[str, Any]:
        """Describe one peer's capability activation state for status surfaces.

        Descriptor evidence is integrity, not display: a missing or tampered
        pinned descriptor document, or a missing/non-cross-bound old->new
        transition receipt for an upgraded pin, surfaces as an evidence
        problem that empties the peer's capabilities and degrades the node's
        global integrity verdict. Whether a pin was upgraded comes from the
        anchored compare-and-swap audit record (recorded_previous), never
        from mutable peer timestamps.
        """

        report: dict[str, Any] = {
            "peer_id": str(peer["peer_id"]),
            "lineage_id": str(peer["lineage_id"]),
            "direction": str(peer["direction"]),
            "revoked": bool(peer["revoked"]),
            "descriptor_digest": str(peer["descriptor_digest"]),
            "previous_descriptor_digest": None,
            "evidence_problem": None,
        }
        evidence = self._peer_descriptor_evidence_path(
            str(peer["peer_id"]), str(peer["descriptor_digest"])
        )
        transition = self._peer_transition_path(
            str(peer["peer_id"]), str(peer["descriptor_digest"])
        )
        has_evidence = evidence.exists() or evidence.is_symlink()
        # A transition receipt addressed by the pinned digest without an
        # anchored predecessor record is itself inconsistent and must be
        # examined, never silently ignored.
        upgraded = (
            recorded_previous is not None
            or transition.exists()
            or transition.is_symlink()
        )
        try:
            if not has_evidence:
                if upgraded:
                    raise ReplicationProtocolError(
                        "upgraded peer descriptor evidence is missing"
                    )
                # Peers pinned before capability negotiation retain no
                # descriptor document; they stay visibly baseline.
                report["capability_state"] = "legacy-no-descriptor"
                report["capabilities"] = list(BASE_NODE_CAPABILITIES)
                return report
            capabilities = self._peer_capabilities(peer)
            if upgraded:
                record = self._verified_peer_transition(
                    peer, recorded_previous=recorded_previous
                )
                report["previous_descriptor_digest"] = str(
                    record["previous_descriptor_digest"]
                )
            report["capabilities"] = capabilities
            report["capability_state"] = (
                MEDIA_ARTIFACT_CAPABILITY
                if MEDIA_ARTIFACT_CAPABILITY in capabilities
                else "baseline"
            )
        except (OSError, ValueError, RuntimeError) as problem:
            report["capability_state"] = "invalid-descriptor-evidence"
            report["capabilities"] = []
            report["evidence_problem"] = str(problem)
        return report

    def _verified_peer_capabilities(self, peer: dict[str, Any]) -> list[str]:
        """Resolve a pinned peer's capabilities through full evidence integrity.

        Media enforcement and status share one resolver
        (_peer_capability_report): whether the pin was upgraded comes from
        the anchored compare-and-swap audit predecessor, the pinned
        descriptor document must validate at its digest address, and an
        upgraded pin must carry its exact cross-bound old->new transition
        receipt. Missing or tampered evidence fails closed here instead of
        quietly resolving to baseline while status is degraded.
        """

        report = self._peer_capability_report(
            peer,
            recorded_previous=self.ledger.peer_descriptor_predecessor(
                str(peer["peer_id"])
            ),
        )
        if report["evidence_problem"] is not None:
            raise ReplicationProtocolError(
                "pinned peer descriptor evidence failed integrity "
                f"verification: {report['evidence_problem']}"
            )
        return [str(item) for item in report["capabilities"]]

    def _publish_node_descriptor_evidence(
        self, digest: str, document: dict[str, Any]
    ) -> None:
        """Persist one node descriptor as append-only, digest-addressed evidence."""

        evidence = self._derived_path(self.root, f"node-descriptor.{digest}.json")
        if evidence.exists() or evidence.is_symlink():
            existing = validate_node_descriptor(
                read_private_json(evidence),
                expected_key_id=str(self._descriptor["auth_key_id"]),
            )
            if not secrets.compare_digest(str(existing["receipt_digest"]), digest):
                raise ReplicationProtocolError(
                    "node descriptor evidence conflicts with its digest address"
                )
            return
        write_private_json_exclusive(self.store, evidence, document)
        self.store._fsync_directory(self.root)

    def _node_transition_path(self, digest: str) -> Path:
        return self._derived_path(
            self.root, f"node-descriptor.transition.{digest}.json"
        )

    def _verified_node_transition(
        self, active: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Return the self-signed swap receipt for the ACTIVE descriptor.

        The receipt is addressed by the active digest, so candidate evidence
        that was published but never activated is never consulted: only the
        pointer swap that actually happened has a receipt at the active
        address. Returns None when the active descriptor was never swapped
        in (a natively full-capability node).
        """

        transition_path = self._node_transition_path(
            str(active["receipt_digest"])
        )
        if not transition_path.exists() and not transition_path.is_symlink():
            return None
        record = validate_node_descriptor_transition(
            read_private_json(transition_path),
            expected_key_id=str(active["auth_key_id"]),
        )
        if str(record["node_id"]) != self.node_id or not secrets.compare_digest(
            str(record["descriptor_digest"]), str(active["receipt_digest"])
        ):
            raise ReplicationProtocolError(
                "node descriptor transition receipt is not cross-bound to "
                "the active descriptor"
            )
        return record

    def _publish_node_transition_evidence(
        self, *, previous_digest: str, new_digest: str, now: float
    ) -> None:
        """Persist the signed local predecessor->new swap receipt, append-only."""

        transition_path = self._node_transition_path(new_digest)
        if transition_path.exists() or transition_path.is_symlink():
            existing = validate_node_descriptor_transition(
                read_private_json(transition_path),
                expected_key_id=str(self._descriptor["auth_key_id"]),
            )
            if (
                str(existing["node_id"]) != self.node_id
                or not secrets.compare_digest(
                    str(existing["previous_descriptor_digest"]), previous_digest
                )
                or not secrets.compare_digest(
                    str(existing["descriptor_digest"]), new_digest
                )
            ):
                raise ReplicationProtocolError(
                    "node descriptor transition evidence conflicts with its "
                    "digest address"
                )
            return
        transition = signed_node_descriptor_transition(
            self.store,
            node_id=self.node_id,
            previous_descriptor_digest=previous_digest,
            descriptor_digest=new_digest,
            created_at=float(now),
        )
        write_private_json_exclusive(self.store, transition_path, transition)
        self.store._fsync_directory(self.root)

    def upgrade_node_descriptor(
        self,
        *,
        expected_current_digest: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Re-sign this node's descriptor with the full capability list.

        Baseline nodes keep advertising only the original three capabilities
        until an operator explicitly upgrades. The upgrade is a
        compare-and-swap: the caller names the exact reviewed digest of the
        currently active descriptor, so a descriptor that changed after the
        operator's review can never be silently replaced. Both the previous
        and the upgraded descriptor are preserved as immutable,
        digest-addressed evidence and fsynced before the active pointer moves;
        the pointer swap itself is a compare-and-swap under the manager lock,
        and a lost response replays idempotently (the retried reviewed digest
        may name either the already-upgraded descriptor or the preserved
        pre-upgrade evidence it replaced). The upgraded descriptor must then
        be independently reviewed and re-pinned on every peer before this
        node may replicate media checkpoints.
        """

        expected_current = validate_digest(
            expected_current_digest, "expected current node descriptor digest"
        )
        with self.ledger.manager_lock():
            current = validate_node_descriptor(
                read_private_json(self.descriptor_path),
                expected_key_id=str(self._descriptor["auth_key_id"]),
            )
            if str(current["node_id"]) != self.node_id:
                raise ReplicationProtocolError(
                    "active node descriptor does not match this node's identity"
                )
            current_capabilities = [str(item) for item in current["capabilities"]]
            digest_matches_active = secrets.compare_digest(
                str(current["receipt_digest"]), expected_current
            )
            if current_capabilities == list(NODE_CAPABILITIES):
                if not digest_matches_active:
                    # Response-loss retry: the reviewed digest may only name
                    # the exact predecessor recorded by the signed swap
                    # receipt of the ACTIVE descriptor. Candidate evidence
                    # published before a swap that never happened is
                    # addressed by a digest that never became active, so a
                    # staged-but-never-active candidate is always rejected.
                    transition = self._verified_node_transition(current)
                    if transition is None or not secrets.compare_digest(
                        str(transition["previous_descriptor_digest"]),
                        expected_current,
                    ):
                        raise ReplicationProtocolError(
                            "node descriptor upgrade does not match the "
                            "reviewed current descriptor digest"
                        )
                self._descriptor = current
                return copy.deepcopy(current)
            if not digest_matches_active:
                raise ReplicationProtocolError(
                    "node descriptor upgrade does not match the reviewed "
                    "current descriptor digest"
                )
            if not confirm:
                raise ValueError(
                    "confirm=true is required to upgrade the node descriptor"
                )
            previous_digest = str(current["receipt_digest"])
            upgraded = signed_node_descriptor(self.store, created_at=time.time())
            if (
                str(upgraded["node_id"]) != self.node_id
                or str(upgraded["auth_key_id"]) != str(current["auth_key_id"])
            ):
                raise ReplicationProtocolError(
                    "upgraded node descriptor changed the node identity"
                )
            upgraded_capabilities = [str(item) for item in upgraded["capabilities"]]
            if not set(current_capabilities).issubset(upgraded_capabilities):
                raise ReplicationProtocolError(
                    "node descriptor upgrade must not drop capabilities"
                )
            new_digest = str(upgraded["receipt_digest"])
            self._publish_node_descriptor_evidence(previous_digest, current)
            self._publish_node_descriptor_evidence(new_digest, upgraded)
            # The swap receipt is addressed by the candidate digest and only
            # ever consulted once that digest is active, so publishing it
            # before the pointer swap keeps response-loss retries idempotent
            # without letting a never-activated candidate into history.
            self._publish_node_transition_evidence(
                previous_digest=previous_digest,
                new_digest=new_digest,
                now=time.time(),
            )
            pointer_swap = self._derived_path(
                self.root, f"node-descriptor.next.{new_digest}.json"
            )
            if pointer_swap.exists() or pointer_swap.is_symlink():
                staged = validate_node_descriptor(
                    read_private_json(pointer_swap),
                    expected_key_id=str(current["auth_key_id"]),
                )
                if not secrets.compare_digest(
                    str(staged["receipt_digest"]), new_digest
                ):
                    raise ReplicationProtocolError(
                        "staged node descriptor conflicts with its digest address"
                    )
                upgraded = staged
            else:
                write_private_json_exclusive(self.store, pointer_swap, upgraded)
            self.store._fsync_directory(self.root)
            active = validate_node_descriptor(
                read_private_json(self.descriptor_path),
                expected_key_id=str(current["auth_key_id"]),
            )
            if not secrets.compare_digest(
                str(active["receipt_digest"]), previous_digest
            ):
                raise ReplicationProtocolError(
                    "node descriptor pointer changed during the upgrade"
                )
            os.replace(pointer_swap, self.descriptor_path)
            self.store._fsync_directory(self.root)
            self._descriptor = upgraded
            return copy.deepcopy(upgraded)

    def upgrade_peer_descriptor(
        self,
        descriptor: dict[str, Any] | str | os.PathLike[str],
        *,
        expected_descriptor_digest: str,
        expected_previous_descriptor_digest: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Governed re-pin of a peer's upgraded, independently reviewed descriptor.

        The upgrade is a compare-and-swap: the caller names both the exact
        currently pinned digest and the reviewed digest of the new signed
        descriptor. The peer's identity, lineage, direction, and signing key
        never change, prior descriptor evidence is retired rather than
        deleted, and until this succeeds the peer remains baseline and media
        checkpoints to it stay blocked.
        """

        if not confirm:
            raise ValueError(
                "confirm=true is required to upgrade a replication peer descriptor"
            )
        validated = validate_node_descriptor(self._document(descriptor))
        new_capabilities = [str(item) for item in validated["capabilities"]]
        if new_capabilities != list(NODE_CAPABILITIES):
            raise ReplicationProtocolError(
                "peer descriptor upgrade must advertise the full capability list"
            )
        expected_new = validate_digest(
            expected_descriptor_digest, "expected peer descriptor digest"
        )
        expected_previous = validate_digest(
            expected_previous_descriptor_digest,
            "expected previous peer descriptor digest",
        )
        if not secrets.compare_digest(
            str(validated["receipt_digest"]), expected_new
        ):
            raise ReplicationProtocolError(
                "peer descriptor does not match the independently reviewed fingerprint"
            )
        peer_id = str(validated["node_id"])
        now = time.time()
        with self.ledger.manager_lock():
            peer = self.ledger.peer(peer_id)
            if peer is None:
                raise ReplicationProtocolError("replication peer is unknown")
            if bool(peer["revoked"]):
                raise ReplicationProtocolError("replication peer is revoked")
            if str(peer["signing_key_id"]) != str(validated["auth_key_id"]) or str(
                peer["signing_public_key"]
            ) != str(validated["signing_public_key"]):
                raise ReplicationProtocolError(
                    "peer descriptor upgrade changed the signing key"
                )
            previous_evidence_path = self._peer_descriptor_evidence_path(
                peer_id, expected_previous
            )
            previous_evidence = (
                "descriptor-document"
                if previous_evidence_path.exists()
                or previous_evidence_path.is_symlink()
                else "ledger-digest-only"
            )
            if secrets.compare_digest(str(peer["descriptor_digest"]), expected_new):
                # Idempotent replay after a lost response: the ledger
                # compare-and-swap already completed. The caller's claimed
                # predecessor must equal the anchored audit record written by
                # that CAS, and the transition receipt published before it
                # must still validate exactly — a replay never signs new
                # history, so a deleted or tampered receipt stays failed.
                recorded_previous = self.ledger.peer_descriptor_predecessor(
                    peer_id
                )
                if recorded_previous is None or not secrets.compare_digest(
                    recorded_previous, expected_previous
                ):
                    raise ReplicationProtocolError(
                        "peer descriptor upgrade replay does not match the "
                        "recorded predecessor"
                    )
                self._publish_peer_descriptor_evidence(peer_id, validated)
                self._verified_peer_transition(
                    peer, recorded_previous=recorded_previous
                )
                return self._public_peer(peer)
            if not secrets.compare_digest(
                str(peer["descriptor_digest"]), expected_previous
            ):
                raise ReplicationProtocolError(
                    "peer descriptor upgrade does not match the pinned record"
                )
            previous_capabilities = self._peer_capabilities(peer)
            if not set(previous_capabilities).issubset(new_capabilities):
                raise ReplicationProtocolError(
                    "peer descriptor upgrade must not drop capabilities"
                )
            # Evidence first: the new digest-addressed descriptor and the
            # signed old->new transition receipt are written and fsynced
            # before the anchored ledger pointer moves, so a crash between the
            # two leaves only inert evidence that a retry reuses; the previous
            # digest stays preserved in the ledger, the transition receipt,
            # and (when present) its own descriptor document.
            self._publish_peer_descriptor_evidence(peer_id, validated)
            self._publish_peer_transition_evidence(
                peer=peer,
                previous_descriptor_digest=expected_previous,
                new_descriptor_digest=expected_new,
                previous_evidence=previous_evidence,
                now=now,
            )
            record = self.ledger.update_peer_descriptor(
                peer_id,
                previous_descriptor_digest=expected_previous,
                descriptor_digest=expected_new,
                signing_key_id=str(validated["auth_key_id"]),
                signing_public_key=str(validated["signing_public_key"]),
                now=now,
                audit=True,
            )
        return self._public_peer(record)

    def _publish_peer_transition_evidence(
        self,
        *,
        peer: dict[str, Any],
        previous_descriptor_digest: str,
        new_descriptor_digest: str,
        previous_evidence: str,
        now: float,
    ) -> None:
        """Persist the signed old->new transition receipt, append-only."""

        transition_path = self._peer_transition_path(
            str(peer["peer_id"]), new_descriptor_digest
        )
        if transition_path.exists() or transition_path.is_symlink():
            existing = validate_descriptor_transition(
                read_private_json(transition_path),
                expected_key_id=str(self._descriptor["auth_key_id"]),
            )
            if (
                str(existing["recorder_node_id"]) != self.node_id
                or str(existing["peer_id"]) != str(peer["peer_id"])
                or str(existing["lineage_id"]) != str(peer["lineage_id"])
                or str(existing["direction"]) != str(peer["direction"])
                or str(existing["peer_signing_key_id"])
                != str(peer["signing_key_id"])
                or not secrets.compare_digest(
                    str(existing["previous_descriptor_digest"]),
                    previous_descriptor_digest,
                )
                or not secrets.compare_digest(
                    str(existing["descriptor_digest"]), new_descriptor_digest
                )
            ):
                raise ReplicationProtocolError(
                    "peer descriptor transition evidence conflicts with its digest address"
                )
            return
        transition = signed_descriptor_transition(
            self.store,
            recorder_node_id=self.node_id,
            peer_id=str(peer["peer_id"]),
            lineage_id=str(peer["lineage_id"]),
            direction=str(peer["direction"]),
            peer_signing_key_id=str(peer["signing_key_id"]),
            previous_descriptor_digest=previous_descriptor_digest,
            descriptor_digest=new_descriptor_digest,
            previous_evidence=previous_evidence,
            created_at=float(now),
        )
        write_private_json_exclusive(self.store, transition_path, transition)
        self.store._fsync_directory(self.peers_root)

    def revoke_peer(
        self,
        peer_id: str,
        *,
        reason: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm=true is required to revoke a replication peer")
        now = time.time()
        with self.ledger.manager_lock():
            record = self.ledger.revoke_peer(
                peer_id,
                reason=reason,
                now=now,
                audit_action="revoke-peer",
                audit_detail_code="operator-revocation",
            )
        return self._public_peer(record)

    @staticmethod
    def _public_peer(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "peer_id": str(record["peer_id"]),
            "lineage_id": str(record["lineage_id"]),
            "direction": str(record["direction"]),
            "signing_key_id": str(record["signing_key_id"]),
            "descriptor_digest": str(record["descriptor_digest"]),
            "revoked": bool(record["revoked"]),
            "revoke_reason": record["revoke_reason"],
            "paired_at": float(record["paired_at"]),
        }

    def _active_peer(self, peer_id: str, *, direction: str) -> dict[str, Any]:
        if NODE_ID_RE.fullmatch(str(peer_id)) is None:
            raise ReplicationProtocolError("replication peer identifier is invalid")
        peer = self.ledger.peer(str(peer_id))
        if peer is None or peer["direction"] != direction:
            raise ReplicationProtocolError("replication peer is not paired for this direction")
        if bool(peer["revoked"]):
            raise ReplicationProtocolError("replication peer is revoked")
        return peer

    @staticmethod
    def _private_regular_metadata(
        path: Path, *, expected_size: int | None = None
    ) -> os.stat_result:
        metadata = os.lstat(path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or int(metadata.st_nlink) != 1
            or metadata.st_size <= 0
            or (expected_size is not None and int(metadata.st_size) != expected_size)
        ):
            raise PermissionError("checkpoint artifact must be an exact private regular file")
        return metadata

    def _artifact_record(self, *, kind: str, path: Path) -> dict[str, Any]:
        self._private_regular_metadata(path)
        digest, size, opened = self.store._hash_stable_regular_file(path)
        if (
            opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or int(opened.st_nlink) != 1
        ):
            raise PermissionError("checkpoint artifact changed its private-file contract")
        return {
            "kind": kind,
            "name": validate_safe_name(path.name, "artifact name"),
            "sha256": digest,
            "size_bytes": size,
        }

    def _bundle_artifacts(
        self,
        *,
        receipt_path: Path,
        receipt: dict[str, Any],
    ) -> list[dict[str, Any]]:
        names: dict[str, str] = {
            "database": validate_safe_name(
                receipt.get("database_artifact_name"), "database artifact name"
            ),
            "database_receipt": validate_safe_name(
                receipt.get("database_receipt_name"), "database receipt name"
            ),
            "capture": validate_safe_name(
                receipt.get("capture_artifact_name"), "capture artifact name"
            ),
            "bundle_receipt": receipt_path.name,
        }
        if bool(receipt.get("media_included")):
            names["media"] = validate_safe_name(
                receipt.get("media_artifact_name"),
                "media artifact name",
            )
        if bool(receipt.get("request_journal_required")):
            names["request_journal"] = validate_safe_name(
                receipt.get("request_journal_artifact_name"),
                "request journal artifact name",
            )
            names["request_journal_binding"] = validate_safe_name(
                receipt.get("request_journal_binding_receipt_name"),
                "request journal binding receipt name",
            )
        if bool(receipt.get("runtime_state_required")):
            names["runtime_state"] = validate_safe_name(
                receipt.get("runtime_state_artifact_name"),
                "runtime state artifact name",
            )
        records = [
            self._artifact_record(kind=kind, path=receipt_path.parent / names[kind])
            for kind in _ARTIFACT_ORDER
            if kind in names
        ]
        by_kind = {str(record["kind"]): record for record in records}
        expected_digests = {
            "database": str(receipt.get("database_sha256") or ""),
            "capture": str(receipt.get("capture_sha256") or ""),
            "media": str(receipt.get("media_sha256") or ""),
            "request_journal": str(receipt.get("request_journal_sha256") or ""),
            "runtime_state": str(receipt.get("runtime_state_sha256") or ""),
        }
        for kind, expected in expected_digests.items():
            if kind in by_kind and not secrets.compare_digest(
                str(by_kind[kind]["sha256"]), validate_digest(expected, f"{kind} digest")
            ):
                raise RuntimeError(f"{kind} artifact digest does not match its recovery receipt")
        return records

    @staticmethod
    def _expected_directory_names(checkpoint: dict[str, Any]) -> set[str]:
        return {str(record["name"]) for record in checkpoint["artifacts"]} | {
            "checkpoint.manifest.json"
        }

    def _validate_checkpoint_directory(
        self,
        directory: Path,
        checkpoint: dict[str, Any],
        *,
        verify_hashes: bool,
    ) -> None:
        expected_names = self._expected_directory_names(checkpoint)
        with self._private_directory_guard(
            directory,
            expected_names=expected_names,
            maximum_entries=len(expected_names),
        ):
            for record in checkpoint["artifacts"]:
                path = directory / str(record["name"])
                self._private_regular_metadata(
                    path, expected_size=int(record["size_bytes"])
                )
                if verify_hashes:
                    digest, size, _metadata = self.store._hash_stable_regular_file(path)
                    if size != int(record["size_bytes"]) or not secrets.compare_digest(
                        digest, str(record["sha256"])
                    ):
                        raise ReplicationProtocolError(
                            "checkpoint artifact verification failed"
                        )
            manifest = directory / "checkpoint.manifest.json"
            self._private_regular_metadata(manifest)
            reread = validate_checkpoint(read_private_json(manifest))
            if not secrets.compare_digest(
                str(reread["receipt_digest"]), str(checkpoint["receipt_digest"])
            ):
                raise ReplicationProtocolError(
                    "checkpoint manifest changed after verification"
                )

    @staticmethod
    def _checkpoint_export_result(
        checkpoint: dict[str, Any],
        *,
        checkpoint_root: Path,
        manifest_path: Path,
        recovered: bool,
    ) -> dict[str, Any]:
        return {
            "schema": "synapse-s2.replication-checkpoint-export.v1",
            "checkpoint_id": str(checkpoint["checkpoint_id"]),
            "checkpoint_digest": str(checkpoint["receipt_digest"]),
            "lineage_id": str(checkpoint["lineage_id"]),
            "term": int(checkpoint["term"]),
            "sequence": int(checkpoint["sequence"]),
            "manifest_path": str(manifest_path),
            "checkpoint_directory": str(checkpoint_root),
            "target_node_id": str(checkpoint["target_node_id"]),
            "artifact_count": int(checkpoint["artifact_count"]),
            "artifact_total_bytes": int(checkpoint["artifact_total_bytes"]),
            "memory_recovery_cutover_ready": True,
            "replication_promotion_ready": False,
            "promotion_supported": False,
            "live_overwrite_performed": False,
            "recovered_publication": recovered,
            "verified": True,
        }

    def _recover_complete_outgoing_publication(
        self,
        *,
        peer: dict[str, Any],
        checkpoint_root: Path,
        checkpoint_id: str,
        lineage_id: str,
        term: int,
        sequence: int,
        parent_digest: str | None,
    ) -> dict[str, Any]:
        validate_private_directory(checkpoint_root)
        manifest_path = checkpoint_root / "checkpoint.manifest.json"
        checkpoint = validate_checkpoint(
            read_private_json(manifest_path),
            expected_public_key=str(self._descriptor["signing_public_key"]),
            expected_key_id=str(self._descriptor["auth_key_id"]),
        )
        expected = (
            checkpoint_id,
            lineage_id,
            term,
            sequence,
            parent_digest,
            self.node_id,
            peer["peer_id"],
        )
        actual = (
            checkpoint["checkpoint_id"],
            checkpoint["lineage_id"],
            checkpoint["term"],
            checkpoint["sequence"],
            checkpoint["parent_checkpoint_digest"],
            checkpoint["source_node_id"],
            checkpoint["target_node_id"],
        )
        if actual != expected:
            raise ReplicationProtocolError(
                "existing checkpoint publication conflicts with the expected chain position"
            )
        self._validate_checkpoint_directory(
            checkpoint_root, checkpoint, verify_hashes=True
        )
        now = time.time()
        self.ledger.record_checkpoint(
            checkpoint_digest=str(checkpoint["receipt_digest"]),
            checkpoint_id=checkpoint_id,
            lineage_id=lineage_id,
            direction="outgoing",
            peer_id=str(peer["peer_id"]),
            term=term,
            sequence=sequence,
            parent_checkpoint_digest=parent_digest,
            bundle_receipt_digest=str(checkpoint["bundle_receipt_digest"]),
            source_store_identity=str(checkpoint["source_store_identity"]),
            store_generation=str(checkpoint["store_generation"]),
            authority_epoch_number=int(checkpoint["authority_epoch_number"]),
            manifest_path=str(manifest_path),
            restore_root=None,
            state="exported",
            now=now,
            audit_action="repair-checkpoint",
            audit_detail_code="complete-publication-reconciled",
        )
        return self._checkpoint_export_result(
            checkpoint,
            checkpoint_root=checkpoint_root,
            manifest_path=manifest_path,
            recovered=True,
        )

    def _quarantine_incomplete_outgoing(
        self,
        *,
        checkpoint_root: Path,
        lineage_id: str,
        checkpoint_id: str,
    ) -> None:
        validate_private_directory(checkpoint_root)
        with self._private_directory_guard(
            checkpoint_root,
            maximum_entries=16,
        ):
            pass
        lineage_quarantine = self._derived_path(self.quarantine_root, lineage_id)
        self._ensure_private_directory(lineage_quarantine)
        destination = self._derived_path(
            lineage_quarantine,
            f"{checkpoint_id}-{uuid.uuid4().hex[:12]}",
        )
        os.rename(checkpoint_root, destination)
        self.store._fsync_directory(lineage_quarantine)
        self.store._fsync_directory(checkpoint_root.parent)

    def create_checkpoint(self, peer_id: str) -> dict[str, Any]:
        with self.ledger.manager_lock():
            peer = self._active_peer(peer_id, direction="send")
            lineage_id = str(peer["lineage_id"])
            latest = self.ledger.latest_checkpoint(
                lineage_id=lineage_id, direction="outgoing"
            )
            if latest is not None and str(latest["state"]) == "exported":
                checkpoint_root = self._derived_path(
                    self._derived_path(self.outgoing_root, lineage_id),
                    str(latest["checkpoint_id"]),
                )
                manifest_path = checkpoint_root / "checkpoint.manifest.json"
                if str(latest["manifest_path"]) != str(manifest_path):
                    raise ReplicationProtocolError(
                        "outgoing checkpoint ledger path is not protocol-derived"
                    )
                checkpoint = validate_checkpoint(
                    read_private_json(manifest_path),
                    expected_public_key=str(self._descriptor["signing_public_key"]),
                    expected_key_id=str(self._descriptor["auth_key_id"]),
                )
                if (
                    checkpoint["receipt_digest"] != latest["checkpoint_digest"]
                    or checkpoint["checkpoint_id"] != latest["checkpoint_id"]
                    or checkpoint["source_node_id"] != self.node_id
                    or checkpoint["target_node_id"] != peer["peer_id"]
                    or checkpoint["lineage_id"] != lineage_id
                    or checkpoint["source_store_identity"]
                    != latest["source_store_identity"]
                    or checkpoint["store_generation"] != latest["store_generation"]
                    or checkpoint["authority_epoch_number"]
                    != latest["authority_epoch_number"]
                ):
                    raise ReplicationProtocolError(
                        "in-flight checkpoint does not match its authenticated ledger row"
                    )
                self._validate_checkpoint_directory(
                    checkpoint_root, checkpoint, verify_hashes=True
                )
                return self._checkpoint_export_result(
                    checkpoint,
                    checkpoint_root=checkpoint_root,
                    manifest_path=manifest_path,
                    recovered=True,
                )
            if latest is not None and str(latest["state"]) != "acknowledged":
                raise ReplicationProtocolError(
                    "outgoing lineage is not ready for another checkpoint"
                )
            term = 1
            sequence = 1 if latest is None else int(latest["sequence"]) + 1
            parent_digest = None if latest is None else str(latest["checkpoint_digest"])
            checkpoint_id = checkpoint_id_for(
                source_node_id=self.node_id,
                target_node_id=str(peer["peer_id"]),
                lineage_id=lineage_id,
                term=term,
                sequence=sequence,
            )
            lineage_root = self.outgoing_root / lineage_id
            self._ensure_private_directory(lineage_root)
            checkpoint_root = lineage_root / checkpoint_id
            if checkpoint_root.exists() or checkpoint_root.is_symlink():
                if checkpoint_root.is_symlink():
                    raise PermissionError("outgoing checkpoint publication must not be a symlink")
                try:
                    return self._recover_complete_outgoing_publication(
                        peer=peer,
                        checkpoint_root=checkpoint_root,
                        checkpoint_id=checkpoint_id,
                        lineage_id=lineage_id,
                        term=term,
                        sequence=sequence,
                        parent_digest=parent_digest,
                    )
                except (FileNotFoundError, PermissionError, ReplicationProtocolError, RuntimeError):
                    self._quarantine_incomplete_outgoing(
                        checkpoint_root=checkpoint_root,
                        lineage_id=lineage_id,
                        checkpoint_id=checkpoint_id,
                    )
            os.mkdir(checkpoint_root, 0o700)
            self.store._fsync_directory(lineage_root)
            try:
                bundle = self.recovery.create_bundle(
                    checkpoint_root / f"{checkpoint_id}.sqlite3",
                    purpose="replication-checkpoint",
                    pinned=True,
                )
                if not bool(bundle.get("verified")) or not bool(bundle.get("cutover_ready")):
                    raise RuntimeError(
                        "recovery bundle is not memory-recovery ready"
                    )
                if (
                    bundle.get("governance_mode") != "authoritative-v6"
                    or type(bundle.get("authority_epoch_number")) is not int
                    or str(bundle.get("store_generation"))
                    != f"epoch-{int(bundle['authority_epoch_number'])}"
                ):
                    raise ReplicationProtocolError(
                        "replication checkpoints require an authoritative-v6 recovery bundle"
                    )
                receipt_path = Path(str(bundle["bundle_receipt_path"])).absolute()
                if receipt_path.parent.resolve() != checkpoint_root.resolve():
                    raise RuntimeError("recovery bundle escaped its checkpoint directory")
                receipt = read_private_json(receipt_path)
                bundle_digest = validate_digest(
                    receipt.get("receipt_digest"), "bundle receipt digest"
                )
                artifacts = self._bundle_artifacts(
                    receipt_path=receipt_path,
                    receipt=receipt,
                )
                if any(str(record["kind"]) == "media" for record in artifacts):
                    # Bilateral activation: media replication requires the
                    # capability on this node's active signed descriptor AND
                    # on the pinned target descriptor. A one-sided upgrade
                    # never publishes media.
                    if MEDIA_ARTIFACT_CAPABILITY not in self._local_capabilities():
                        raise ReplicationProtocolError(
                            "this node's active descriptor does not advertise "
                            "media-artifact-v1; upgrade the node descriptor "
                            "before replicating media checkpoints"
                        )
                    if (
                        MEDIA_ARTIFACT_CAPABILITY
                        not in self._verified_peer_capabilities(peer)
                    ):
                        raise ReplicationProtocolError(
                            "target peer does not advertise media-artifact-v1; "
                            "upgrade its pinned descriptor before replicating "
                            "media checkpoints"
                        )
                capture_binding = bundle.get("capture_ledger_binding")
                if (
                    not isinstance(capture_binding, dict)
                    or capture_binding.get("verified") is not True
                ):
                    raise RuntimeError(
                        "recovery bundle lacks a verified capture ledger binding"
                    )
                capture_revision = validate_digest(
                    capture_binding.get("revision"), "capture ledger revision"
                )
                created_at = time.time()
                unsigned = {
                    "schema": CHECKPOINT_SCHEMA,
                    "protocol_version": REPLICATION_PROTOCOL_VERSION,
                    "checkpoint_id": checkpoint_id,
                    "lineage_id": lineage_id,
                    "term": term,
                    "sequence": sequence,
                    "parent_checkpoint_digest": parent_digest,
                    "source_node_id": self.node_id,
                    "target_node_id": str(peer["peer_id"]),
                    "bundle_receipt_name": receipt_path.name,
                    "bundle_receipt_digest": bundle_digest,
                    "artifacts": artifacts,
                    "artifact_count": len(artifacts),
                    "artifact_total_bytes": sum(
                        int(record["size_bytes"]) for record in artifacts
                    ),
                    "source_store_identity": str(bundle["store_identity"]),
                    "store_generation": str(bundle["store_generation"]),
                    "authority_epoch_number": bundle["authority_epoch_number"],
                    "governance_mode": str(bundle["governance_mode"]),
                    "logical_snapshot_sha256": str(bundle["logical_snapshot_sha256"]),
                    "capture_ledger_revision": capture_revision,
                    "created_at": created_at,
                }
                checkpoint = sign_payload(self.store, unsigned)
                validate_checkpoint(checkpoint)
                manifest_path = checkpoint_root / "checkpoint.manifest.json"
                write_private_json_exclusive(self.store, manifest_path, checkpoint)
                self._validate_checkpoint_directory(
                    checkpoint_root, checkpoint, verify_hashes=True
                )
                checkpoint_digest = str(checkpoint["receipt_digest"])
                self.ledger.record_checkpoint(
                    checkpoint_digest=checkpoint_digest,
                    checkpoint_id=checkpoint_id,
                    lineage_id=lineage_id,
                    direction="outgoing",
                    peer_id=str(peer["peer_id"]),
                    term=term,
                    sequence=sequence,
                    parent_checkpoint_digest=parent_digest,
                    bundle_receipt_digest=bundle_digest,
                    source_store_identity=str(checkpoint["source_store_identity"]),
                    store_generation=str(checkpoint["store_generation"]),
                    authority_epoch_number=int(checkpoint["authority_epoch_number"]),
                    manifest_path=str(manifest_path),
                    restore_root=None,
                    state="exported",
                    now=created_at,
                    audit_action="create-checkpoint",
                    audit_detail_code="recovery-bundle-verified",
                )
                return self._checkpoint_export_result(
                    checkpoint,
                    checkpoint_root=checkpoint_root,
                    manifest_path=manifest_path,
                    recovered=False,
                )
            except BaseException:
                try:
                    self.ledger.audit(
                        action="create-checkpoint",
                        state="rejected",
                        peer_id=str(peer["peer_id"]),
                        lineage_id=lineage_id,
                        detail_code="checkpoint-publication-failed",
                    )
                except Exception:
                    pass
                raise

    @staticmethod
    def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_size),
            int(metadata.st_mtime_ns),
            int(metadata.st_ctime_ns),
        )

    def _copy_artifact(
        self,
        *,
        source: Path,
        destination: Path,
        expected_digest: str,
        expected_size: int,
    ) -> None:
        before = self._private_regular_metadata(source, expected_size=expected_size)
        source_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            source_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
        source_fd = os.open(source, source_flags)
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            destination_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            destination_flags |= os.O_NOFOLLOW
        destination_fd: int | None = None
        digest: Any = None
        copied = 0
        try:
            digest = hashlib.sha256()
            destination_fd = os.open(destination, destination_flags, 0o600)
            assert destination_fd is not None
            opened = os.fstat(source_fd)
            if self._identity(before) != self._identity(opened):
                raise RuntimeError("checkpoint artifact changed while opening")
            while True:
                chunk = os.read(source_fd, min(1024 * 1024, expected_size + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > expected_size:
                    raise ReplicationProtocolError("checkpoint artifact exceeds its declared size")
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    written = os.write(destination_fd, chunk[offset:])
                    if written <= 0:
                        raise OSError("checkpoint artifact copy made no write progress")
                    offset += written
            os.fsync(destination_fd)
            source_after = os.fstat(source_fd)
            destination_after = os.fstat(destination_fd)
        except BaseException:
            if destination_fd is not None:
                destination.unlink(missing_ok=True)
            raise
        finally:
            try:
                if destination_fd is not None:
                    os.close(destination_fd)
            finally:
                os.close(source_fd)
        path_after = os.lstat(source)
        if (
            self._identity(source_after) != self._identity(opened)
            or self._identity(path_after) != self._identity(opened)
            or int(destination_after.st_size) != expected_size
            or copied != expected_size
            or digest is None
            or not secrets.compare_digest(digest.hexdigest(), expected_digest)
        ):
            destination.unlink(missing_ok=True)
            raise ReplicationProtocolError("checkpoint artifact changed or failed verification")
        os.chmod(destination, 0o600, follow_symlinks=False)

    def _disk_guard(self, *, parent: Path, artifact_total_bytes: int) -> None:
        reserve = int(
            os.getenv(
                "SYNAPSE_S2_REPLICATION_MIN_FREE_BYTES",
                str(512 * 1024 * 1024),
            )
        )
        if reserve < 0:
            raise ValueError("SYNAPSE_S2_REPLICATION_MIN_FREE_BYTES must be non-negative")
        required = artifact_total_bytes * 3 + reserve
        if int(shutil.disk_usage(parent).free) < required:
            raise OSError("insufficient free space for verified replication staging")

    def _received_checkpoint(
        self,
        *,
        source_directory: Path,
        checkpoint: dict[str, Any],
    ) -> Path:
        lineage_root = self.incoming_root / str(checkpoint["lineage_id"])
        self._ensure_private_directory(lineage_root)
        target = lineage_root / str(checkpoint["checkpoint_id"])
        if target.exists() or target.is_symlink():
            self._validate_checkpoint_directory(target, checkpoint, verify_hashes=True)
            return target
        pending = lineage_root / (
            f".pending-{checkpoint['checkpoint_id']}-{uuid.uuid4().hex[:12]}"
        )
        os.mkdir(pending, 0o700)
        try:
            for record in checkpoint["artifacts"]:
                self._copy_artifact(
                    source=source_directory / str(record["name"]),
                    destination=pending / str(record["name"]),
                    expected_digest=str(record["sha256"]),
                    expected_size=int(record["size_bytes"]),
                )
            write_private_json_exclusive(
                self.store,
                pending / "checkpoint.manifest.json",
                checkpoint,
            )
            self._validate_checkpoint_directory(pending, checkpoint, verify_hashes=True)
            os.rename(pending, target)
            self.store._fsync_directory(lineage_root)
            return target
        except BaseException:
            if pending.exists() and pending.parent == lineage_root:
                shutil.rmtree(pending)
                self.store._fsync_directory(lineage_root)
            raise

    @staticmethod
    def _artifacts_by_kind(checkpoint: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {str(record["kind"]): dict(record) for record in checkpoint["artifacts"]}

    def _verify_recovery_checkpoint(
        self,
        *,
        received_root: Path,
        checkpoint: dict[str, Any],
    ) -> dict[str, Any]:
        records = self._artifacts_by_kind(checkpoint)
        receipt_path = received_root / str(checkpoint["bundle_receipt_name"])
        verified = self.recovery.verify_bundle(
            receipt_path,
            expected_database_sha256=str(records["database"]["sha256"]),
            expected_capture_sha256=str(records["capture"]["sha256"]),
            expected_request_journal_sha256=(
                str(records["request_journal"]["sha256"])
                if "request_journal" in records
                else None
            ),
            expected_runtime_state_sha256=(
                str(records["runtime_state"]["sha256"])
                if "runtime_state" in records
                else None
            ),
            expected_media_sha256=(
                str(records["media"]["sha256"]) if "media" in records else None
            ),
        )
        capture_binding = verified.get("capture_ledger_binding")
        if (
            verified.get("verified") is not True
            or bool(verified.get("media_included")) != ("media" in records)
            or verified.get("cutover_ready") is not True
            or not secrets.compare_digest(
                str(verified["bundle_receipt_digest"]),
                str(checkpoint["bundle_receipt_digest"]),
            )
            or verified.get("store_identity") != checkpoint["source_store_identity"]
            or verified.get("store_generation") != checkpoint["store_generation"]
            or verified.get("database", {}).get("authority_epoch_number")
            != checkpoint["authority_epoch_number"]
            or verified.get("governance_mode") != checkpoint["governance_mode"]
            or verified.get("logical_snapshot_sha256")
            != checkpoint["logical_snapshot_sha256"]
            or not isinstance(capture_binding, dict)
            or capture_binding.get("verified") is not True
            or capture_binding.get("revision") != checkpoint["capture_ledger_revision"]
        ):
            raise ReplicationProtocolError("checkpoint does not match its recovery proof inputs")
        return verified

    def _validated_existing_proof(
        self,
        *,
        proof_path: Path,
        checkpoint: dict[str, Any],
        records: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        proof = read_private_json(proof_path)
        digest = validate_digest(proof.get("receipt_digest"), "restore proof digest")
        if (
            not secrets.compare_digest(digest, self.store._canonical_payload_digest(proof))
            or not self.store._verify_receipt_authenticator(proof)
            or proof.get("cutover_ready") is not True
            or proof.get("bundle_receipt_name") != checkpoint["bundle_receipt_name"]
            or proof.get("database_sha256") != records["database"]["sha256"]
            or proof.get("capture_sha256") != records["capture"]["sha256"]
            or bool(proof.get("media_included")) != ("media" in records)
            or (
                "media" in records
                and (
                    proof.get("media_sha256") != records["media"]["sha256"]
                    or proof.get("media_recovery_complete") is not True
                )
            )
            or proof.get("database_logical_snapshot_sha256")
            != checkpoint["logical_snapshot_sha256"]
            or proof.get("store_identity") != checkpoint["source_store_identity"]
            or proof.get("store_generation") != checkpoint["store_generation"]
            or proof.get("governance_mode") != "authoritative-v6"
            or proof.get("authority_epoch_number")
            != checkpoint["authority_epoch_number"]
            or proof.get("request_journal_binding_verified") is not True
            or proof.get("runtime_state_required") is not True
            or proof.get("runtime_state_present") is not True
            or not isinstance(proof.get("capture_ledger_binding"), dict)
            or proof["capture_ledger_binding"].get("revision")
            != checkpoint["capture_ledger_revision"]
            or int(
                (proof.get("reconciliation") or {}).get(
                    "replay_required_file_count", -1
                )
            )
            != 0
        ):
            raise ReplicationProtocolError("existing isolated restore proof is invalid")
        return proof

    def _verify_current_isolated_restore(
        self,
        *,
        received_root: Path,
        restore_root: Path,
        checkpoint: dict[str, Any],
        proof: dict[str, Any],
        verified_bundle: dict[str, Any],
    ) -> dict[str, Any]:
        expected_received_root = self._derived_path(
            self._derived_path(self.incoming_root, str(checkpoint["lineage_id"])),
            str(checkpoint["checkpoint_id"]),
        )
        if received_root.absolute() != expected_received_root.absolute():
            raise ReplicationProtocolError("received checkpoint path is not protocol-derived")
        expected_root = self._derived_path(
            self._derived_path(self.staged_root, str(checkpoint["lineage_id"])),
            str(checkpoint["checkpoint_id"]),
        )
        if restore_root.absolute() != expected_root.absolute():
            raise ReplicationProtocolError("isolated restore path is not protocol-derived")
        expected_top_level = {
            "memory.sqlite3",
            "memory.sqlite3.restore.receipt.json",
            "core",
            "runtime_state.json",
            "capture-root",
            "recovery-proof.receipt.json",
        }
        if bool(proof.get("media_included")):
            expected_top_level.add("media-cache")
        with self._private_directory_guard(
            restore_root,
            expected_names=expected_top_level,
            maximum_entries=len(expected_top_level),
        ):
            core_root = restore_root / "core"
            capture_root = restore_root / "capture-root"
            validate_private_directory(core_root)
            validate_private_directory(capture_root)
            if bool(proof.get("media_included")):
                validate_private_directory(restore_root / "media-cache")
            for artifact in (
                restore_root / "memory.sqlite3",
                restore_root / "memory.sqlite3.restore.receipt.json",
                restore_root / "runtime_state.json",
                restore_root / "recovery-proof.receipt.json",
                core_root / "requests.sqlite3",
                core_root / "requests.sqlite3.binding.receipt.json",
            ):
                self._private_regular_metadata(artifact)
            binding = self.recovery.verify_restored_request_journal_binding(
                restore_root,
                expected_store_identity=str(checkpoint["source_store_identity"]),
                expected_store_generation=str(checkpoint["store_generation"]),
                expected_source_request_journal_binding_receipt_digest=str(
                    proof["source_request_journal_binding_receipt_digest"]
                ),
            )
            if (
                binding.get("verified") is not True
                or binding.get("store_identity")
                != checkpoint["source_store_identity"]
                or binding.get("store_generation") != checkpoint["store_generation"]
                or binding.get("authority_epoch_number")
                != checkpoint["authority_epoch_number"]
                or binding.get("memory_logical_snapshot_sha256")
                != checkpoint["logical_snapshot_sha256"]
            ):
                raise ReplicationProtocolError(
                    "current restored memory, journal, or runtime state is invalid"
                )
            memory_path = restore_root / "memory.sqlite3"
            self._private_regular_metadata(memory_path)
            uri = memory_path.resolve().as_uri() + "?mode=ro&immutable=1"
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                ledger_bindings = self.recovery._snapshot_capture_ledger_bindings(conn)
            records = self._artifacts_by_kind(checkpoint)
            capture_snapshot = self.recovery._verify_capture_archive(
                received_root / str(records["capture"]["name"]),
                expected_sha256=str(records["capture"]["sha256"]),
                expected_manifest_sha256=str(
                    verified_bundle["capture_manifest_sha256"]
                ),
                ledger_bindings=ledger_bindings,
                database_binding=dict(verified_bundle["capture_database_binding"]),
            )
            current_capture = self.recovery._verify_extracted_capture_ledger_bindings(
                capture_root / "capture_processed",
                ledger_bindings=ledger_bindings,
            )
            if (
                current_capture.get("verified") is not True
                or current_capture != proof["capture_ledger_binding"]
                or current_capture.get("revision")
                != checkpoint["capture_ledger_revision"]
            ):
                raise ReplicationProtocolError(
                    "current restored capture state is not bound to the checkpoint"
                )
            self._verify_current_capture_tree(
                capture_root=capture_root,
                manifest=dict(capture_snapshot["manifest"]),
            )
            if bool(proof.get("media_included")):
                media_verification = verified_bundle.get("media")
                if not isinstance(media_verification, dict) or "media" not in records:
                    raise ReplicationProtocolError(
                        "checkpoint media verification is missing"
                    )
                media_snapshot = self.recovery._verify_media_archive(
                    received_root / str(records["media"]["name"]),
                    expected_sha256=str(records["media"]["sha256"]),
                    expected_manifest_sha256=str(
                        media_verification["manifest_sha256"]
                    ),
                )
                self._verify_current_media_tree(
                    media_root=restore_root / "media-cache",
                    manifest=dict(media_snapshot["manifest"]),
                )
            ledger_ids = set(ledger_bindings)
            receipt_ids: set[str] = set()
            processed_ids: set[str] = set()
            max_files, max_total_bytes, max_file_bytes = (
                self.recovery._bounded_capture_limits()
            )
            scanned_files = 0
            scanned_bytes = 0
            for relative, target in (
                ("capture_receipts", receipt_ids),
                ("capture_processed", processed_ids),
            ):
                root = capture_root / relative
                if not root.exists() and not root.is_symlink():
                    continue
                for current, directory_names, file_names in os.walk(
                    root, followlinks=False
                ):
                    current_path = Path(current)
                    for directory_name in directory_names:
                        validate_private_directory(current_path / directory_name)
                    for file_name in sorted(file_names):
                        data, _metadata = self.recovery._read_private_regular(
                            current_path / file_name,
                            max_bytes=max_file_bytes,
                        )
                        scanned_files += 1
                        scanned_bytes += len(data)
                        if scanned_files > max_files or scanned_bytes > max_total_bytes:
                            raise RuntimeError(
                                "current restored capture verification exceeded its bounds"
                            )
                        try:
                            parsed = json.loads(data.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        target.update(self.recovery._capture_ids_from_payload(parsed))
            if (receipt_ids - ledger_ids) or (processed_ids - ledger_ids):
                raise ReplicationProtocolError(
                    "current restored capture transport lacks authoritative ledger rows"
                )
        self.store._fsync_directory(restore_root)
        self.store._fsync_directory(restore_root.parent)
        return binding

    def _verify_current_media_tree(
        self,
        *,
        media_root: Path,
        manifest: dict[str, Any],
    ) -> None:
        """Revalidate the complete restored media tree against its manifest.

        Idempotent stage replay must never accept a media-cache directory on
        the strength of its root alone: every restored object manifest,
        thumbnail, and optional feature print is re-read through the same
        digest-verifying reader the restore path uses, and symlinks, foreign
        entries, mode drift, extra files, and missing or tampered artifacts
        all fail closed.
        """

        objects = manifest.get("objects")
        if not isinstance(objects, list):
            raise ReplicationProtocolError("media manifest inventory is invalid")
        with self._private_directory_guard(
            media_root,
            expected_names={"objects"},
            maximum_entries=1,
        ):
            reader = MediaObjectReader(media_root)
            try:
                restored_ids = reader.object_ids()
                expected_ids = sorted(
                    str(record["media_id"]) for record in objects
                )
                if restored_ids != expected_ids:
                    raise ReplicationProtocolError(
                        "restored media objects do not match the checkpoint manifest"
                    )
                for record in objects:
                    media_id = str(record["media_id"])
                    _document, files = reader.read_object_artifacts(media_id)
                    expected_files = {
                        str(item["name"]): item for item in record["files"]
                    }
                    if set(files) != set(expected_files):
                        raise ReplicationProtocolError(
                            "restored media object inventory does not match the manifest"
                        )
                    for name, data in files.items():
                        item = expected_files[name]
                        if len(data) != int(item["size_bytes"]) or not secrets.compare_digest(
                            hashlib.sha256(data).hexdigest(), str(item["sha256"])
                        ):
                            raise ReplicationProtocolError(
                                "restored media artifact does not match its manifest digest"
                            )
            except (ImageCaptureError, ImageCaptureNotFound) as exc:
                raise ReplicationProtocolError(
                    "restored media tree failed validation"
                ) from exc

    def _verify_current_capture_tree(
        self,
        *,
        capture_root: Path,
        manifest: dict[str, Any],
    ) -> None:
        records = manifest.get("files")
        if not isinstance(records, list):
            raise ReplicationProtocolError("capture manifest file inventory is invalid")
        expected_files: dict[str, dict[str, Any]] = {}
        expected_directories: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                raise ReplicationProtocolError("capture manifest file record is invalid")
            relative = str(record.get("relative_path") or "")
            parts = Path(relative).parts
            if (
                not relative
                or relative.startswith("/")
                or not parts
                or ".." in parts
                or len(parts) > 64
                or relative in expected_files
            ):
                raise ReplicationProtocolError("capture manifest path is unsafe")
            expected_files[relative] = record
            for depth in range(1, len(parts)):
                expected_directories.add(str(Path(*parts[:depth])))

        max_files, max_total_bytes, max_file_bytes = (
            self.recovery._bounded_capture_limits()
        )
        if len(expected_files) > max_files:
            raise ReplicationProtocolError("capture manifest exceeds its file bound")
        verified_files: set[str] = set()
        verified_directories: set[str] = set()
        total_bytes = 0

        def verify_directory(directory: Path, relative_parts: tuple[str, ...]) -> None:
            nonlocal total_bytes
            prefix = Path(*relative_parts) if relative_parts else Path()
            child_directories = {
                Path(relative).name
                for relative in expected_directories
                if Path(relative).parent == prefix
            }
            child_files = {
                Path(relative).name
                for relative in expected_files
                if Path(relative).parent == prefix
            }
            expected_names = child_directories | child_files
            with self._private_directory_guard(
                directory,
                expected_names=expected_names,
                maximum_entries=len(expected_names),
            ):
                for name in sorted(child_files):
                    relative = str(prefix / name) if relative_parts else name
                    record = expected_files[relative]
                    try:
                        data, metadata = self.recovery._read_private_regular(
                            directory / name,
                            max_bytes=max_file_bytes,
                        )
                    except ValueError as exc:
                        raise ReplicationProtocolError(
                            "current restored capture file is unsafe"
                        ) from exc
                    if (
                        metadata.st_uid != os.getuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or int(metadata.st_nlink) != 1
                        or len(data) != int(record["size_bytes"])
                        or not secrets.compare_digest(
                            hashlib.sha256(data).hexdigest(),
                            str(record["sha256"]),
                        )
                    ):
                        raise ReplicationProtocolError(
                            "current restored capture file does not match its manifest"
                        )
                    self.recovery._assert_secret_safe_text(data)
                    total_bytes += len(data)
                    if total_bytes > max_total_bytes:
                        raise ReplicationProtocolError(
                            "current restored capture tree exceeds its byte bound"
                        )
                    verified_files.add(relative)
                for name in sorted(child_directories):
                    relative_parts_child = (*relative_parts, name)
                    relative = str(Path(*relative_parts_child))
                    verified_directories.add(relative)
                    verify_directory(directory / name, relative_parts_child)

        verify_directory(capture_root, ())
        if (
            verified_files != set(expected_files)
            or verified_directories != expected_directories
            or total_bytes != int(manifest.get("total_bytes", -1))
        ):
            raise ReplicationProtocolError(
                "current restored capture tree does not match its signed inventory"
            )

    def _restore_checkpoint(
        self,
        *,
        received_root: Path,
        checkpoint: dict[str, Any],
        verified_bundle: dict[str, Any],
    ) -> tuple[Path, dict[str, Any]]:
        records = self._artifacts_by_kind(checkpoint)
        lineage_root = self.staged_root / str(checkpoint["lineage_id"])
        self._ensure_private_directory(lineage_root)
        restore_root = lineage_root / str(checkpoint["checkpoint_id"])
        proof_path = restore_root / "recovery-proof.receipt.json"
        if restore_root.exists() or restore_root.is_symlink():
            validate_private_directory(restore_root)
            proof = self._validated_existing_proof(
                proof_path=proof_path,
                checkpoint=checkpoint,
                records=records,
            )
            self._verify_current_isolated_restore(
                received_root=received_root,
                restore_root=restore_root,
                checkpoint=checkpoint,
                proof=proof,
                verified_bundle=verified_bundle,
            )
            return restore_root, proof
        restored = self.recovery.restore_bundle_isolated(
            received_root / str(checkpoint["bundle_receipt_name"]),
            restore_root,
            expected_database_sha256=str(records["database"]["sha256"]),
            expected_capture_sha256=str(records["capture"]["sha256"]),
            expected_request_journal_sha256=(
                str(records["request_journal"]["sha256"])
                if "request_journal" in records
                else None
            ),
            expected_runtime_state_sha256=(
                str(records["runtime_state"]["sha256"])
                if "runtime_state" in records
                else None
            ),
            expected_media_sha256=(
                str(records["media"]["sha256"]) if "media" in records else None
            ),
            confirm=True,
        )
        if restored.get("verified") is not True or restored.get("cutover_ready") is not True:
            raise RuntimeError(
                "isolated replication restore is not memory-recovery ready"
            )
        if Path(str(restored["restore_root"])).absolute() != restore_root.absolute():
            raise RuntimeError("isolated replication restore escaped its staging root")
        proof = self._validated_existing_proof(
            proof_path=Path(str(restored["recovery_proof_path"])),
            checkpoint=checkpoint,
            records=records,
        )
        self._verify_current_isolated_restore(
            received_root=received_root,
            restore_root=restore_root,
            checkpoint=checkpoint,
            proof=proof,
            verified_bundle=verified_bundle,
        )
        return restore_root, proof

    def _acknowledge_staged_checkpoint(
        self,
        *,
        peer: dict[str, Any],
        checkpoint: dict[str, Any],
        proof: dict[str, Any],
    ) -> tuple[dict[str, Any], Path]:
        checkpoint_digest = str(checkpoint["receipt_digest"])
        ack_id = ack_id_for(
            checkpoint_digest=checkpoint_digest,
            receiver_node_id=self.node_id,
        )
        lineage_root = self.acks_root / str(checkpoint["lineage_id"])
        self._ensure_private_directory(lineage_root)
        ack_path = self._derived_path(lineage_root, f"{ack_id}.json")
        if ack_path.exists() or ack_path.is_symlink():
            ack = validate_ack(
                read_private_json(ack_path),
                expected_public_key=str(self._descriptor["signing_public_key"]),
                expected_key_id=str(self._descriptor["auth_key_id"]),
            )
        else:
            ack = sign_payload(
                self.store,
                {
                    "schema": ACK_SCHEMA,
                    "protocol_version": REPLICATION_PROTOCOL_VERSION,
                    "ack_id": ack_id,
                    "checkpoint_id": str(checkpoint["checkpoint_id"]),
                    "checkpoint_digest": checkpoint_digest,
                    "lineage_id": str(checkpoint["lineage_id"]),
                    "term": int(checkpoint["term"]),
                    "sequence": int(checkpoint["sequence"]),
                    "source_node_id": str(peer["peer_id"]),
                    "receiver_node_id": self.node_id,
                    "bundle_receipt_digest": str(checkpoint["bundle_receipt_digest"]),
                    "restore_proof_receipt_digest": str(proof["receipt_digest"]),
                    "memory_recovery_cutover_ready": True,
                    "acked_at": time.time(),
                },
            )
            validate_ack(ack)
            write_private_json_exclusive(self.store, ack_path, ack)
        expected = (
            checkpoint["checkpoint_id"],
            checkpoint_digest,
            checkpoint["lineage_id"],
            checkpoint["term"],
            checkpoint["sequence"],
            peer["peer_id"],
            self.node_id,
            checkpoint["bundle_receipt_digest"],
            proof["receipt_digest"],
            True,
        )
        actual = (
            ack["checkpoint_id"],
            ack["checkpoint_digest"],
            ack["lineage_id"],
            ack["term"],
            ack["sequence"],
            ack["source_node_id"],
            ack["receiver_node_id"],
            ack["bundle_receipt_digest"],
            ack["restore_proof_receipt_digest"],
            ack["memory_recovery_cutover_ready"],
        )
        if actual != expected:
            raise ReplicationProtocolError(
                "replication acknowledgement does not match staged proof"
            )
        return ack, ack_path

    def _idempotent_stage_result(
        self,
        *,
        checkpoint: dict[str, Any],
        existing: dict[str, Any],
    ) -> dict[str, Any]:
        peer = self._active_peer(
            str(checkpoint["source_node_id"]), direction="receive"
        )
        received_root = self._derived_path(
            self._derived_path(self.incoming_root, str(checkpoint["lineage_id"])),
            str(checkpoint["checkpoint_id"]),
        )
        restore_root = self._derived_path(
            self._derived_path(self.staged_root, str(checkpoint["lineage_id"])),
            str(checkpoint["checkpoint_id"]),
        )
        expected_manifest_path = received_root / "checkpoint.manifest.json"
        if (
            str(existing["manifest_path"]) != str(expected_manifest_path)
            or str(existing["restore_root"]) != str(restore_root)
        ):
            raise ReplicationProtocolError(
                "staged checkpoint ledger paths are not protocol-derived"
            )
        self._validate_checkpoint_directory(
            received_root, checkpoint, verify_hashes=True
        )
        verified_bundle = self._verify_recovery_checkpoint(
            received_root=received_root,
            checkpoint=checkpoint,
        )
        records = self._artifacts_by_kind(checkpoint)
        proof = self._validated_existing_proof(
            proof_path=restore_root / "recovery-proof.receipt.json",
            checkpoint=checkpoint,
            records=records,
        )
        self._verify_current_isolated_restore(
            received_root=received_root,
            restore_root=restore_root,
            checkpoint=checkpoint,
            proof=proof,
            verified_bundle=verified_bundle,
        )
        ack_record = self.ledger.acknowledgement_for_checkpoint(
            str(checkpoint["receipt_digest"])
        )
        if ack_record is None:
            ack, ack_path = self._acknowledge_staged_checkpoint(
                peer=peer,
                checkpoint=checkpoint,
                proof=proof,
            )
            ack_record = self.ledger.record_acknowledgement(
                ack_digest=str(ack["receipt_digest"]),
                ack_id=str(ack["ack_id"]),
                checkpoint_digest=str(checkpoint["receipt_digest"]),
                peer_id=str(peer["peer_id"]),
                ack_path=str(ack_path),
                now=float(ack["acked_at"]),
            )
            self.ledger.audit(
                action="repair-stage-ack",
                state="staged",
                peer_id=str(peer["peer_id"]),
                lineage_id=str(checkpoint["lineage_id"]),
                checkpoint_digest=str(checkpoint["receipt_digest"]),
                detail_code="ack-ledger-reconciled",
            )
        ack_path = self._derived_path(
            self._derived_path(self.acks_root, str(checkpoint["lineage_id"])),
            f"{ack_id_for(checkpoint_digest=str(checkpoint['receipt_digest']), receiver_node_id=self.node_id)}.json",
        )
        if str(ack_record["ack_path"]) != str(ack_path):
            raise ReplicationProtocolError(
                "stored acknowledgement path is not protocol-derived"
            )
        ack = validate_ack(
            read_private_json(ack_path),
            expected_public_key=str(self._descriptor["signing_public_key"]),
            expected_key_id=str(self._descriptor["auth_key_id"]),
        )
        if ack["checkpoint_digest"] != checkpoint["receipt_digest"]:
            raise ReplicationProtocolError("stored acknowledgement is bound to another checkpoint")
        return {
            "schema": "synapse-s2.replication-stage.v1",
            "checkpoint_id": str(checkpoint["checkpoint_id"]),
            "checkpoint_digest": str(checkpoint["receipt_digest"]),
            "lineage_id": str(checkpoint["lineage_id"]),
            "term": int(checkpoint["term"]),
            "sequence": int(checkpoint["sequence"]),
            "source_node_id": str(peer["peer_id"]),
            "restore_root": str(restore_root),
            "ack_path": str(ack_path),
            "ack_digest": str(ack["receipt_digest"]),
            "memory_recovery_cutover_ready": True,
            "replication_promotion_ready": False,
            "promotion_supported": False,
            "live_overwrite_performed": False,
            "idempotent_replay": True,
            "verified": True,
        }

    def stage_checkpoint(
        self,
        manifest: dict[str, Any] | str | os.PathLike[str],
    ) -> dict[str, Any]:
        source_manifest_path: Path | None = None
        if not isinstance(manifest, dict):
            source_manifest_path = Path(manifest).expanduser().absolute()
            if source_manifest_path.name != "checkpoint.manifest.json":
                raise ReplicationProtocolError("checkpoint manifest name is invalid")
            untrusted = read_private_json(source_manifest_path)
        else:
            untrusted = dict(manifest)
        if source_manifest_path is None:
            raise ReplicationProtocolError(
                "staging requires a private checkpoint directory, not a detached manifest"
            )
        source_id = str(untrusted.get("source_node_id") or "")
        with self.ledger.manager_lock():
            peer = self._active_peer(source_id, direction="receive")
            checkpoint = validate_checkpoint(
                untrusted,
                expected_public_key=str(peer["signing_public_key"]),
                expected_key_id=str(peer["signing_key_id"]),
            )
            checkpoint_digest = str(checkpoint["receipt_digest"])
            lineage_id = str(checkpoint["lineage_id"])
            if (
                checkpoint["target_node_id"] != self.node_id
                or checkpoint["source_node_id"] != peer["peer_id"]
                or lineage_id != peer["lineage_id"]
            ):
                self.ledger.audit(
                    action="stage-checkpoint",
                    state="rejected",
                    peer_id=str(peer["peer_id"]),
                    lineage_id=lineage_id,
                    checkpoint_digest=checkpoint_digest,
                    detail_code="target-or-lineage-mismatch",
                )
                raise ReplicationProtocolError(
                    "checkpoint target or lineage does not match the pairing"
                )
            if checkpoint["governance_mode"] != "authoritative-v6":
                raise ReplicationProtocolError(
                    "replication staging requires authoritative-v6 evidence"
                )
            if any(
                str(record["kind"]) == "media"
                for record in checkpoint["artifacts"]
            ) and (
                MEDIA_ARTIFACT_CAPABILITY not in self._local_capabilities()
                or MEDIA_ARTIFACT_CAPABILITY
                not in self._verified_peer_capabilities(peer)
            ):
                # Bilateral activation on the receiver: a media checkpoint is
                # rejected before any staging work unless this node's active
                # descriptor AND the pinned SOURCE descriptor both advertise
                # the capability, independent of what the sender enforced.
                self.ledger.audit(
                    action="stage-checkpoint",
                    state="rejected",
                    peer_id=str(peer["peer_id"]),
                    lineage_id=lineage_id,
                    checkpoint_digest=checkpoint_digest,
                    detail_code="media-capability-not-activated",
                )
                raise ReplicationProtocolError(
                    "media checkpoints require media-artifact-v1 on this "
                    "node's active descriptor and on the pinned source peer "
                    "descriptor"
                )
            position = self.ledger.checkpoint_at(
                lineage_id=lineage_id,
                direction="incoming",
                term=int(checkpoint["term"]),
                sequence=int(checkpoint["sequence"]),
            )
            if position is not None:
                if secrets.compare_digest(
                    str(position["checkpoint_digest"]), checkpoint_digest
                ):
                    return self._idempotent_stage_result(
                        checkpoint=checkpoint,
                        existing=position,
                    )
                self.ledger.revoke_peer(
                    str(peer["peer_id"]),
                    reason="checkpoint-equivocation",
                    now=time.time(),
                    audit_action="stage-checkpoint",
                    audit_detail_code="equivocation-peer-revoked",
                    checkpoint_digest=checkpoint_digest,
                )
                raise ReplicationProtocolError("checkpoint equivocation detected; peer revoked")
            latest = self.ledger.latest_checkpoint(
                lineage_id=lineage_id, direction="incoming"
            )
            expected_sequence = 1 if latest is None else int(latest["sequence"]) + 1
            expected_parent = None if latest is None else str(latest["checkpoint_digest"])
            if latest is not None and (
                str(latest["source_store_identity"])
                != str(checkpoint["source_store_identity"])
                or int(checkpoint["authority_epoch_number"])
                < int(latest["authority_epoch_number"])
            ):
                raise ReplicationProtocolError(
                    "checkpoint source identity or authority epoch rolled back"
                )
            if (
                int(checkpoint["term"]) != 1
                or int(checkpoint["sequence"]) != expected_sequence
                or checkpoint["parent_checkpoint_digest"] != expected_parent
            ):
                self.ledger.audit(
                    action="stage-checkpoint",
                    state="rejected",
                    peer_id=str(peer["peer_id"]),
                    lineage_id=lineage_id,
                    checkpoint_digest=checkpoint_digest,
                    detail_code="chain-gap-or-parent-mismatch",
                )
                raise ReplicationProtocolError("checkpoint chain has a gap or parent mismatch")
            source_directory = source_manifest_path.parent
            self._disk_guard(
                parent=self.incoming_root,
                artifact_total_bytes=int(checkpoint["artifact_total_bytes"]),
            )
            try:
                expected_source_names = self._expected_directory_names(checkpoint)
                with self._private_directory_guard(
                    source_directory,
                    expected_names=expected_source_names,
                    maximum_entries=len(expected_source_names),
                ):
                    self._validate_checkpoint_directory(
                        source_directory, checkpoint, verify_hashes=True
                    )
                    received_root = self._received_checkpoint(
                        source_directory=source_directory,
                        checkpoint=checkpoint,
                    )
                verified_bundle = self._verify_recovery_checkpoint(
                    received_root=received_root,
                    checkpoint=checkpoint,
                )
                restore_root, proof = self._restore_checkpoint(
                    received_root=received_root,
                    checkpoint=checkpoint,
                    verified_bundle=verified_bundle,
                )
                self.ledger.record_checkpoint(
                    checkpoint_digest=checkpoint_digest,
                    checkpoint_id=str(checkpoint["checkpoint_id"]),
                    lineage_id=lineage_id,
                    direction="incoming",
                    peer_id=str(peer["peer_id"]),
                    term=int(checkpoint["term"]),
                    sequence=int(checkpoint["sequence"]),
                    parent_checkpoint_digest=checkpoint["parent_checkpoint_digest"],
                    bundle_receipt_digest=str(checkpoint["bundle_receipt_digest"]),
                    source_store_identity=str(checkpoint["source_store_identity"]),
                    store_generation=str(checkpoint["store_generation"]),
                    authority_epoch_number=int(checkpoint["authority_epoch_number"]),
                    manifest_path=str(received_root / "checkpoint.manifest.json"),
                    restore_root=str(restore_root),
                    state="staged",
                    now=time.time(),
                    audit_action="stage-checkpoint",
                    audit_detail_code="isolated-restore-verified",
                )
                ack, ack_path = self._acknowledge_staged_checkpoint(
                    peer=peer,
                    checkpoint=checkpoint,
                    proof=proof,
                )
                self.ledger.record_acknowledgement(
                    ack_digest=str(ack["receipt_digest"]),
                    ack_id=str(ack["ack_id"]),
                    checkpoint_digest=checkpoint_digest,
                    peer_id=str(peer["peer_id"]),
                    ack_path=str(ack_path),
                    now=float(ack["acked_at"]),
                )
                return {
                    "schema": "synapse-s2.replication-stage.v1",
                    "checkpoint_id": str(checkpoint["checkpoint_id"]),
                    "checkpoint_digest": checkpoint_digest,
                    "lineage_id": lineage_id,
                    "term": int(checkpoint["term"]),
                    "sequence": int(checkpoint["sequence"]),
                    "source_node_id": str(peer["peer_id"]),
                    "restore_root": str(restore_root),
                    "ack_path": str(ack_path),
                    "ack_digest": str(ack["receipt_digest"]),
                    "memory_recovery_cutover_ready": True,
                    "replication_promotion_ready": False,
                    "promotion_supported": False,
                    "live_overwrite_performed": False,
                    "idempotent_replay": False,
                    "verified": True,
                }
            except BaseException:
                try:
                    self.ledger.audit(
                        action="stage-checkpoint",
                        state="rejected",
                        peer_id=str(peer["peer_id"]),
                        lineage_id=lineage_id,
                        checkpoint_digest=checkpoint_digest,
                        detail_code="verification-or-restore-failed",
                    )
                except Exception:
                    pass
                raise

    def record_acknowledgement(
        self,
        acknowledgement: dict[str, Any] | str | os.PathLike[str],
    ) -> dict[str, Any]:
        untrusted = self._document(acknowledgement)
        receiver_id = str(untrusted.get("receiver_node_id") or "")
        with self.ledger.manager_lock():
            peer = self._active_peer(receiver_id, direction="send")
            ack = validate_ack(
                untrusted,
                expected_public_key=str(peer["signing_public_key"]),
                expected_key_id=str(peer["signing_key_id"]),
            )
            checkpoint_digest = str(ack["checkpoint_digest"])
            checkpoint = self.ledger.checkpoint(checkpoint_digest)
            if checkpoint is None or checkpoint["direction"] != "outgoing":
                raise ReplicationProtocolError("acknowledgement references an unknown checkpoint")
            checkpoint_root = self._derived_path(
                self._derived_path(self.outgoing_root, str(checkpoint["lineage_id"])),
                str(checkpoint["checkpoint_id"]),
            )
            expected_manifest = checkpoint_root / "checkpoint.manifest.json"
            if str(checkpoint["manifest_path"]) != str(expected_manifest):
                raise ReplicationProtocolError(
                    "acknowledged checkpoint path is not protocol-derived"
                )
            manifest = validate_checkpoint(
                read_private_json(expected_manifest),
                expected_public_key=str(self._descriptor["signing_public_key"]),
                expected_key_id=str(self._descriptor["auth_key_id"]),
            )
            if manifest["receipt_digest"] != checkpoint_digest:
                raise ReplicationProtocolError(
                    "acknowledged checkpoint manifest does not match the ledger"
                )
            self._validate_checkpoint_directory(
                checkpoint_root, manifest, verify_hashes=True
            )
            expected = (
                checkpoint["checkpoint_id"],
                checkpoint["lineage_id"],
                int(checkpoint["term"]),
                int(checkpoint["sequence"]),
                self.node_id,
                peer["peer_id"],
                checkpoint["bundle_receipt_digest"],
                True,
            )
            actual = (
                ack["checkpoint_id"],
                ack["lineage_id"],
                ack["term"],
                ack["sequence"],
                ack["source_node_id"],
                ack["receiver_node_id"],
                ack["bundle_receipt_digest"],
                ack["memory_recovery_cutover_ready"],
            )
            if actual != expected or ack["lineage_id"] != peer["lineage_id"]:
                raise ReplicationProtocolError(
                    "acknowledgement does not match the exported checkpoint"
                )
            lineage_root = self._derived_path(
                self.acks_root, str(ack["lineage_id"])
            )
            self._ensure_private_directory(lineage_root)
            local_path = self._derived_path(
                lineage_root, f"received-{ack['ack_id']}.json"
            )
            if local_path.exists() or local_path.is_symlink():
                persisted = validate_ack(
                    read_private_json(local_path),
                    expected_public_key=str(peer["signing_public_key"]),
                    expected_key_id=str(peer["signing_key_id"]),
                )
                if persisted["receipt_digest"] != ack["receipt_digest"]:
                    self.ledger.revoke_peer(
                        str(peer["peer_id"]),
                        reason="ack-equivocation",
                        now=time.time(),
                        audit_action="record-ack",
                        audit_detail_code="equivocation-peer-revoked",
                        checkpoint_digest=checkpoint_digest,
                    )
                    raise ReplicationProtocolError(
                        "acknowledgement equivocation detected; peer revoked"
                    )
            else:
                write_private_json_exclusive(self.store, local_path, ack)
            existing = self.ledger.acknowledgement_for_checkpoint(checkpoint_digest)
            idempotent = existing is not None
            if existing is not None and (
                existing["ack_digest"] != ack["receipt_digest"]
                or existing["ack_id"] != ack["ack_id"]
                or existing["ack_path"] != str(local_path)
            ):
                self.ledger.revoke_peer(
                    str(peer["peer_id"]),
                    reason="ack-equivocation",
                    now=time.time(),
                    audit_action="record-ack",
                    audit_detail_code="equivocation-peer-revoked",
                    checkpoint_digest=checkpoint_digest,
                )
                raise ReplicationProtocolError(
                    "acknowledgement equivocation detected; peer revoked"
                )
            self.ledger.record_acknowledgement(
                ack_digest=str(ack["receipt_digest"]),
                ack_id=str(ack["ack_id"]),
                checkpoint_digest=checkpoint_digest,
                peer_id=str(peer["peer_id"]),
                ack_path=str(local_path),
                now=float(ack["acked_at"]),
                checkpoint_state="acknowledged",
                audit_action="record-ack",
                audit_detail_code=(
                    "idempotent-replay" if idempotent else "receiver-proof-accepted"
                ),
            )
            return {
                "schema": "synapse-s2.replication-ack-record.v1",
                "checkpoint_id": str(ack["checkpoint_id"]),
                "checkpoint_digest": checkpoint_digest,
                "ack_id": str(ack["ack_id"]),
                "ack_digest": str(ack["receipt_digest"]),
                "receiver_node_id": str(peer["peer_id"]),
                "state": "acknowledged",
                "idempotent_replay": idempotent,
                "verified": True,
            }

    def _validate_ack_semantics(
        self,
        *,
        checkpoint: dict[str, Any],
        peer: dict[str, Any],
        ack_record: dict[str, Any],
        ack: dict[str, Any],
        expected_path: Path,
    ) -> None:
        outgoing = str(checkpoint["direction"]) == "outgoing"
        source_node_id = self.node_id if outgoing else str(peer["peer_id"])
        receiver_node_id = str(peer["peer_id"]) if outgoing else self.node_id
        expected_ack_id = ack_id_for(
            checkpoint_digest=str(checkpoint["checkpoint_digest"]),
            receiver_node_id=receiver_node_id,
        )
        if (
            ack_record.get("checkpoint_digest") != checkpoint["checkpoint_digest"]
            or ack_record.get("peer_id") != checkpoint["peer_id"]
            or ack_record.get("peer_id") != peer["peer_id"]
            or ack_record.get("ack_id") != expected_ack_id
            or ack_record.get("ack_id") != ack.get("ack_id")
            or ack_record.get("ack_digest") != ack.get("receipt_digest")
            or ack_record.get("ack_path") != str(expected_path)
            or float(ack_record.get("created_at", -1.0))
            != float(ack.get("acked_at", -2.0))
            or ack.get("checkpoint_id") != checkpoint["checkpoint_id"]
            or ack.get("checkpoint_digest") != checkpoint["checkpoint_digest"]
            or ack.get("lineage_id") != checkpoint["lineage_id"]
            or int(ack.get("term", -1)) != int(checkpoint["term"])
            or int(ack.get("sequence", -1)) != int(checkpoint["sequence"])
            or ack.get("source_node_id") != source_node_id
            or ack.get("receiver_node_id") != receiver_node_id
            or ack.get("bundle_receipt_digest")
            != checkpoint["bundle_receipt_digest"]
            or ack.get("memory_recovery_cutover_ready") is not True
        ):
            raise ReplicationProtocolError(
                "replication acknowledgement semantics are inconsistent"
            )

    def _semantic_integrity_check(
        self,
        status: dict[str, Any],
        snapshot: dict[str, Any],
    ) -> None:
        peers = [dict(record) for record in snapshot["peers"]]
        if (
            int(status.get("peer_count", -1)) != len(peers)
            or int(status.get("peer_returned_count", -1))
            != min(len(peers), 128)
            or bool(status.get("peers_truncated")) != (len(peers) > 128)
        ):
            raise ReplicationProtocolError("replication peer status counts are inconsistent")
        for peer_record in peers:
            signing_key_id = validate_digest(
                peer_record.get("signing_key_id"), "peer signing key"
            )
            validate_digest(
                peer_record.get("descriptor_digest"), "peer descriptor digest"
            )
            try:
                public_key = base64.b64decode(
                    str(peer_record.get("signing_public_key") or ""),
                    validate=True,
                )
            except (TypeError, ValueError) as exc:
                raise ReplicationProtocolError(
                    "replication peer public key is invalid"
                ) from exc
            if (
                NODE_ID_RE.fullmatch(str(peer_record.get("peer_id") or "")) is None
                or str(peer_record["peer_id"]) != node_id_for_key_id(signing_key_id)
                or LINEAGE_ID_RE.fullmatch(
                    str(peer_record.get("lineage_id") or "")
                )
                is None
                or peer_record.get("direction") not in {"send", "receive"}
                or len(public_key) != 32
                or hashlib.sha256(public_key).hexdigest() != signing_key_id
                or bool(peer_record.get("revoked"))
                != (peer_record.get("revoke_reason") is not None)
            ):
                raise ReplicationProtocolError(
                    "replication peer semantic identity is inconsistent"
                )
        observed_acknowledgements: set[str] = set()
        checkpoints = [dict(record) for record in snapshot["checkpoints"]]
        peers_by_id = {str(record["peer_id"]): record for record in peers}
        acknowledgement_by_checkpoint = {
            str(record["checkpoint_digest"]): dict(record)
            for record in snapshot["acknowledgements"]
        }
        latest_count = len(
            {
                (str(checkpoint["lineage_id"]), str(checkpoint["direction"]))
                for checkpoint in checkpoints
            }
        )
        if (
            int(status.get("latest_checkpoint_count", -1)) != latest_count
            or int(status.get("latest_checkpoint_returned_count", -1))
            != min(latest_count, 256)
            or bool(status.get("latest_checkpoints_truncated"))
            != (latest_count > 256)
        ):
            raise ReplicationProtocolError(
                "replication latest-checkpoint status counts are inconsistent"
            )
        for checkpoint in checkpoints:
            peer = peers_by_id.get(str(checkpoint["peer_id"]))
            expected_direction = (
                "send" if checkpoint["direction"] == "outgoing" else "receive"
            )
            if peer is None or peer["direction"] != expected_direction:
                raise ReplicationProtocolError("checkpoint peer direction is inconsistent")
            if checkpoint["direction"] == "outgoing":
                root = self._derived_path(
                    self._derived_path(self.outgoing_root, str(checkpoint["lineage_id"])),
                    str(checkpoint["checkpoint_id"]),
                )
                expected_manifest = root / "checkpoint.manifest.json"
                if str(checkpoint["manifest_path"]) != str(expected_manifest):
                    raise ReplicationProtocolError(
                        "outgoing manifest path is not protocol-derived"
                    )
                manifest = validate_checkpoint(
                    read_private_json(expected_manifest),
                    expected_public_key=str(self._descriptor["signing_public_key"]),
                    expected_key_id=str(self._descriptor["auth_key_id"]),
                )
                if manifest["receipt_digest"] != checkpoint["checkpoint_digest"]:
                    raise ReplicationProtocolError("outgoing manifest digest is inconsistent")
                self._validate_checkpoint_directory(root, manifest, verify_hashes=True)
                ack_record = acknowledgement_by_checkpoint.get(
                    str(checkpoint["checkpoint_digest"])
                )
                if checkpoint["state"] == "acknowledged":
                    if ack_record is None:
                        raise ReplicationProtocolError(
                            "acknowledged checkpoint lacks its acknowledgement"
                        )
                    ack_id = ack_id_for(
                        checkpoint_digest=str(checkpoint["checkpoint_digest"]),
                        receiver_node_id=str(peer["peer_id"]),
                    )
                    expected_ack = self._derived_path(
                        self._derived_path(self.acks_root, str(checkpoint["lineage_id"])),
                        f"received-{ack_id}.json",
                    )
                    if str(ack_record["ack_path"]) != str(expected_ack):
                        raise ReplicationProtocolError(
                            "received acknowledgement path is not protocol-derived"
                        )
                    ack = validate_ack(
                        read_private_json(expected_ack),
                        expected_public_key=str(peer["signing_public_key"]),
                        expected_key_id=str(peer["signing_key_id"]),
                    )
                    self._validate_ack_semantics(
                        checkpoint=checkpoint,
                        peer=peer,
                        ack_record=ack_record,
                        ack=ack,
                        expected_path=expected_ack,
                    )
                    observed_acknowledgements.add(str(ack_record["ack_digest"]))
                elif ack_record is not None:
                    raise ReplicationProtocolError(
                        "unacknowledged outgoing checkpoint has an acknowledgement"
                    )
            else:
                received_root = self._derived_path(
                    self._derived_path(self.incoming_root, str(checkpoint["lineage_id"])),
                    str(checkpoint["checkpoint_id"]),
                )
                restore_root = self._derived_path(
                    self._derived_path(self.staged_root, str(checkpoint["lineage_id"])),
                    str(checkpoint["checkpoint_id"]),
                )
                expected_manifest = received_root / "checkpoint.manifest.json"
                if (
                    str(checkpoint["manifest_path"]) != str(expected_manifest)
                    or str(checkpoint["restore_root"]) != str(restore_root)
                ):
                    raise ReplicationProtocolError(
                        "incoming checkpoint paths are not protocol-derived"
                    )
                manifest = validate_checkpoint(
                    read_private_json(expected_manifest),
                    expected_public_key=str(peer["signing_public_key"]),
                    expected_key_id=str(peer["signing_key_id"]),
                )
                if manifest["receipt_digest"] != checkpoint["checkpoint_digest"]:
                    raise ReplicationProtocolError("incoming manifest digest is inconsistent")
                self._validate_checkpoint_directory(
                    received_root, manifest, verify_hashes=True
                )
                verified_bundle = self._verify_recovery_checkpoint(
                    received_root=received_root, checkpoint=manifest
                )
                proof = self._validated_existing_proof(
                    proof_path=restore_root / "recovery-proof.receipt.json",
                    checkpoint=manifest,
                    records=self._artifacts_by_kind(manifest),
                )
                self._verify_current_isolated_restore(
                    received_root=received_root,
                    restore_root=restore_root,
                    checkpoint=manifest,
                    proof=proof,
                    verified_bundle=verified_bundle,
                )
                ack_record = acknowledgement_by_checkpoint.get(
                    str(checkpoint["checkpoint_digest"])
                )
                if ack_record is None:
                    raise ReplicationProtocolError(
                        "staged checkpoint lacks its acknowledgement"
                    )
                ack_id = ack_id_for(
                    checkpoint_digest=str(checkpoint["checkpoint_digest"]),
                    receiver_node_id=self.node_id,
                )
                expected_ack = self._derived_path(
                    self._derived_path(self.acks_root, str(checkpoint["lineage_id"])),
                    f"{ack_id}.json",
                )
                if str(ack_record["ack_path"]) != str(expected_ack):
                    raise ReplicationProtocolError(
                        "staged acknowledgement path is not protocol-derived"
                    )
                ack = validate_ack(
                    read_private_json(expected_ack),
                    expected_public_key=str(self._descriptor["signing_public_key"]),
                    expected_key_id=str(self._descriptor["auth_key_id"]),
                )
                self._validate_ack_semantics(
                    checkpoint=checkpoint,
                    peer=peer,
                    ack_record=ack_record,
                    ack=ack,
                    expected_path=expected_ack,
                )
                observed_acknowledgements.add(str(ack_record["ack_digest"]))
        if len(observed_acknowledgements) != int(
            status.get("acknowledgement_count", -1)
        ):
            raise ReplicationProtocolError(
                "replication acknowledgement count is inconsistent"
            )

    def status(self) -> dict[str, Any]:
        base = {
            "schema": "synapse-s2.replication-status.v1",
            "mode": "offline-single-writer-checkpoint",
            "transport": "operator-mediated-directory",
            # Readiness belongs to the exact checkpoint/staging response whose
            # verified artifact and isolated proof were evaluated.  A healthy
            # ledger alone can never make the node globally cutover-ready.
            "memory_recovery_cutover_ready": False,
            "live_overwrite_supported": False,
            "live_overwrite_performed": False,
            "promotion_supported": False,
            "replication_promotion_ready": False,
            "node_id": self.node_id,
            "signing_key_id": str(self._descriptor["auth_key_id"]),
            "staging_policy": "verified-isolated-restore-only",
            "ack_policy": "receiver-signs-after-memory-recovery-ready-proof",
        }
        try:
            active = self._active_node_descriptor()
            local_capabilities = [str(item) for item in active["capabilities"]]
            base["descriptor_digest"] = str(active["receipt_digest"])
            base["node_descriptor_state"] = "valid"
        except (OSError, ValueError, RuntimeError, ReplicationProtocolError):
            local_capabilities = []
            base["descriptor_digest"] = str(self._descriptor["receipt_digest"])
            base["node_descriptor_state"] = "invalid-descriptor-evidence"
        base["capabilities"] = list(local_capabilities)
        local_media = MEDIA_ARTIFACT_CAPABILITY in local_capabilities
        base["media_artifact_capable"] = local_media
        try:
            with self.ledger.manager_lock():
                snapshot = self.ledger.integrity_snapshot()
                status = dict(snapshot["status"])
                self._semantic_integrity_check(status, snapshot)
        except (OSError, ValueError, RuntimeError, sqlite3.DatabaseError):
            return {
                **base,
                "memory_recovery_cutover_ready": False,
                "integrity": {
                    "state": "degraded",
                    "anchor_verified": False,
                    "semantic_paths_verified": False,
                    "descriptor_evidence_problems": (
                        []
                        if str(base["node_descriptor_state"]) == "valid"
                        else [
                            "active node descriptor evidence is missing "
                            "or tampered"
                        ]
                    ),
                    "descriptor_evidence_problem_total": (
                        0
                        if str(base["node_descriptor_state"]) == "valid"
                        else 1
                    ),
                    "descriptor_evidence_problems_truncated": False,
                },
            }
        status.update(base)
        # Descriptor evidence is integrity, not display: a missing or
        # tampered active node descriptor, pinned peer descriptor document,
        # or required old->new transition receipt degrades the global
        # verdict while every per-peer surface stays visible with its exact
        # evidence problem and media readiness.
        evidence_problems: list[str] = []
        if str(base["node_descriptor_state"]) != "valid":
            evidence_problems.append(
                "active node descriptor evidence is missing or tampered"
            )
        # Surface each pinned peer's capability activation: legacy peers with
        # no descriptor evidence stay visibly baseline, and media readiness is
        # bilateral (this node's active descriptor AND the pinned peer).
        # Evidence integrity is computed over EVERY pinned peer in the
        # authenticated snapshot; only the presentation page is capped.
        predecessors = {
            str(peer_id): str(previous)
            for peer_id, previous in snapshot.get(
                "descriptor_upgrade_predecessors", {}
            ).items()
        }
        reports_by_id: dict[str, dict[str, Any]] = {}
        for row in snapshot.get("peers", []):
            report = self._peer_capability_report(
                row,
                recorded_previous=predecessors.get(str(row["peer_id"])),
            )
            reports_by_id[str(row["peer_id"])] = report
            if report["evidence_problem"] is not None:
                evidence_problems.append(
                    f"peer {report['peer_id']}: {report['evidence_problem']}"
                )
        enriched_peers = []
        for entry in status.get("peers", []):
            merged = dict(entry)
            report = reports_by_id.get(str(entry["peer_id"]))
            if report is not None:
                merged.update(
                    {
                        "descriptor_digest": report["descriptor_digest"],
                        "capability_state": report["capability_state"],
                        "capabilities": list(report["capabilities"]),
                        "previous_descriptor_digest": report[
                            "previous_descriptor_digest"
                        ],
                        "evidence_problem": report["evidence_problem"],
                        "media_ready": (
                            local_media
                            and not report["revoked"]
                            and MEDIA_ARTIFACT_CAPABILITY
                            in report["capabilities"]
                        ),
                    }
                )
            enriched_peers.append(merged)
        status["peers"] = enriched_peers
        # The verdict is computed over every pinned peer, but the displayed
        # problem list is bounded like the peer page: the exact total is
        # always reported so truncation can never hide the degradation size.
        status["integrity"] = {
            "state": "ready" if not evidence_problems else "degraded",
            "anchor_verified": True,
            "semantic_paths_verified": not evidence_problems,
            "descriptor_evidence_problems": list(
                evidence_problems[:STATUS_PEER_PAGE_LIMIT]
            ),
            "descriptor_evidence_problem_total": len(evidence_problems),
            "descriptor_evidence_problems_truncated": (
                len(evidence_problems) > STATUS_PEER_PAGE_LIMIT
            ),
        }
        return status
