from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core_protocol import CoreProtocolError, canonical_json_bytes
from memory_store import DurableMemoryStore, _json_dumps


REPLICATION_PROTOCOL_VERSION = "synapse-s2.replication.v1"
NODE_DESCRIPTOR_SCHEMA = "synapse-s2.replication-node.v1"
CHECKPOINT_SCHEMA = "synapse-s2.replication-checkpoint.v1"
DESCRIPTOR_TRANSITION_SCHEMA = "synapse-s2.replication-descriptor-transition.v1"
NODE_DESCRIPTOR_TRANSITION_SCHEMA = (
    "synapse-s2.replication-node-descriptor-transition.v1"
)
ACK_SCHEMA = "synapse-s2.replication-ack.v1"
LEDGER_ANCHOR_SCHEMA = "synapse-s2.replication-ledger-anchor.v1"

# Signed-capability negotiation: baseline peers advertise exactly the three
# original capabilities; media-capable peers additionally advertise
# ``media-artifact-v1``. A sender must never publish a checkpoint carrying a
# media artifact to a peer whose pinned descriptor lacks that capability.
MEDIA_ARTIFACT_CAPABILITY = "media-artifact-v1"
BASE_NODE_CAPABILITIES = (
    "target-bound-checkpoints",
    "isolated-restore-proof",
    "receiver-signed-ack",
)
NODE_CAPABILITIES = BASE_NODE_CAPABILITIES + (MEDIA_ARTIFACT_CAPABILITY,)

AUTH_FIELDS = frozenset(
    {
        "auth_algorithm",
        "auth_key_id",
        "signing_public_key",
        "receipt_digest",
        "receipt_signature",
    }
)
NODE_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "node_id",
        "role",
        "capabilities",
        "created_at",
    }
) | AUTH_FIELDS
DESCRIPTOR_TRANSITION_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "recorder_node_id",
        "peer_id",
        "lineage_id",
        "direction",
        "peer_signing_key_id",
        "previous_descriptor_digest",
        "descriptor_digest",
        "previous_evidence",
        "created_at",
    }
) | AUTH_FIELDS
NODE_DESCRIPTOR_TRANSITION_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "node_id",
        "previous_descriptor_digest",
        "descriptor_digest",
        "created_at",
    }
) | AUTH_FIELDS
CHECKPOINT_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "checkpoint_id",
        "lineage_id",
        "term",
        "sequence",
        "parent_checkpoint_digest",
        "source_node_id",
        "target_node_id",
        "bundle_receipt_name",
        "bundle_receipt_digest",
        "artifacts",
        "artifact_count",
        "artifact_total_bytes",
        "source_store_identity",
        "store_generation",
        "authority_epoch_number",
        "governance_mode",
        "logical_snapshot_sha256",
        "capture_ledger_revision",
        "created_at",
    }
) | AUTH_FIELDS
ACK_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "ack_id",
        "checkpoint_id",
        "checkpoint_digest",
        "lineage_id",
        "term",
        "sequence",
        "source_node_id",
        "receiver_node_id",
        "bundle_receipt_digest",
        "restore_proof_receipt_digest",
        "memory_recovery_cutover_ready",
        "acked_at",
    }
) | AUTH_FIELDS
ARTIFACT_FIELDS = frozenset({"kind", "name", "sha256", "size_bytes"})
LEDGER_ANCHOR_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "node_id",
        "revision",
        "previous_anchor_digest",
        "ledger_snapshot_sha256",
        "created_at",
    }
) | AUTH_FIELDS

DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
NODE_ID_RE = re.compile(r"\As2node_[0-9a-f]{32}\Z")
LINEAGE_ID_RE = re.compile(r"\As2lineage_[0-9a-f]{32}\Z")
CHECKPOINT_ID_RE = re.compile(r"\As2checkpoint_[0-9a-f]{32}\Z")
ACK_ID_RE = re.compile(r"\As2ack_[0-9a-f]{32}\Z")
STORE_ID_RE = re.compile(r"\Astore-[0-9a-f]{24}\Z")
GENERATION_RE = re.compile(r"\A(?:legacy-v5|epoch-[1-9][0-9]{0,18})\Z")
ALLOWED_ARTIFACT_KINDS = frozenset(
    {
        "database",
        "database_receipt",
        "capture",
        "media",
        "bundle_receipt",
        "request_journal",
        "request_journal_binding",
        "runtime_state",
    }
)
REQUIRED_ARTIFACT_KINDS = frozenset(
    {"database", "database_receipt", "capture", "bundle_receipt"}
)
MAX_PROTOCOL_JSON_BYTES = 1024 * 1024
MAX_ARTIFACTS = 8
MAX_ARTIFACT_BYTES = 64 * 1024**3


class ReplicationProtocolError(ValueError):
    """A deterministic rejection at the offline replication trust boundary."""


def _require_exact_fields(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReplicationProtocolError(f"{label} contract is unsupported")
    return value


def _require_string(value: Any, label: str, *, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ReplicationProtocolError(f"{label} is invalid")
    return value


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 9_223_372_036_854_775_807:
        raise ReplicationProtocolError(f"{label} is invalid")
    return value


def _require_time(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReplicationProtocolError(f"{label} is invalid")
    bounded = float(value)
    if not math.isfinite(bounded) or bounded <= 0:
        raise ReplicationProtocolError(f"{label} is invalid")
    return bounded


def validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise ReplicationProtocolError(f"{label} must be lowercase SHA-256")
    return value


def validate_safe_name(value: Any, label: str) -> str:
    name = _require_string(value, label)
    if (
        name in {".", ".."}
        or Path(name).name != name
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise ReplicationProtocolError(f"{label} must be a single local file name")
    return name


def _derived_identifier(prefix: str, fields: Iterable[Any]) -> str:
    seed = canonical_json_bytes([REPLICATION_PROTOCOL_VERSION, prefix, *fields])
    return f"{prefix}_{hashlib.sha256(seed).hexdigest()[:32]}"


def node_id_for_key_id(key_id: str) -> str:
    validate_digest(key_id, "key identifier")
    return f"s2node_{key_id[:32]}"


def checkpoint_id_for(
    *, source_node_id: str, target_node_id: str, lineage_id: str, term: int, sequence: int
) -> str:
    return _derived_identifier(
        "s2checkpoint",
        [source_node_id, target_node_id, lineage_id, term, sequence],
    )


def ack_id_for(*, checkpoint_digest: str, receiver_node_id: str) -> str:
    return _derived_identifier("s2ack", [checkpoint_digest, receiver_node_id])


def sign_payload(store: DurableMemoryStore, payload: dict[str, Any]) -> dict[str, Any]:
    signed = dict(payload)
    if AUTH_FIELDS.intersection(signed):
        raise ReplicationProtocolError("unsigned payload contains authentication fields")
    store._authenticate_receipt(signed)
    return signed


def signed_node_descriptor(
    store: DurableMemoryStore, *, created_at: float
) -> dict[str, Any]:
    _private, _public, key_id = store._backup_receipt_signing_key(create=True)
    if key_id is None:
        raise RuntimeError("recovery signing authority is unavailable")
    descriptor = sign_payload(
        store,
        {
            "schema": NODE_DESCRIPTOR_SCHEMA,
            "protocol_version": REPLICATION_PROTOCOL_VERSION,
            "node_id": node_id_for_key_id(key_id),
            "role": "offline-checkpoint-peer",
            "capabilities": list(NODE_CAPABILITIES),
            "created_at": float(created_at),
        },
    )
    validate_node_descriptor(descriptor)
    return descriptor


def _verify_authentication(
    payload: dict[str, Any],
    *,
    expected_public_key: str | None,
    expected_key_id: str | None,
) -> tuple[str, str]:
    if payload.get("auth_algorithm") != "ed25519":
        raise ReplicationProtocolError("signature algorithm is unsupported")
    validate_digest(payload.get("auth_key_id"), "signing key identifier")
    validate_digest(payload.get("receipt_digest"), "receipt digest")
    try:
        public_bytes = base64.b64decode(
            _require_string(payload.get("signing_public_key"), "signing public key"),
            validate=True,
        )
        signature = base64.b64decode(
            _require_string(payload.get("receipt_signature"), "receipt signature"),
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise ReplicationProtocolError("signature encoding is invalid") from exc
    if len(public_bytes) != 32 or len(signature) != 64:
        raise ReplicationProtocolError("signature size is invalid")
    key_id = hashlib.sha256(public_bytes).hexdigest()
    if not secrets.compare_digest(str(payload["auth_key_id"]), key_id):
        raise ReplicationProtocolError("signing key identifier is invalid")
    digest = hashlib.sha256(
        _json_dumps(
            {
                key: value
                for key, value in payload.items()
                if key not in {"receipt_digest", "receipt_authenticator", "receipt_signature"}
            }
        ).encode("utf-8")
    ).hexdigest()
    if not secrets.compare_digest(str(payload["receipt_digest"]), digest):
        raise ReplicationProtocolError("receipt digest verification failed")
    signed_payload = {key: value for key, value in payload.items() if key != "receipt_signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature,
            _json_dumps(signed_payload).encode("utf-8"),
        )
    except InvalidSignature as exc:
        raise ReplicationProtocolError("signature verification failed") from exc
    encoded_public = base64.b64encode(public_bytes).decode("ascii")
    if expected_key_id is not None and not secrets.compare_digest(key_id, expected_key_id):
        raise ReplicationProtocolError("signing key does not match the pinned peer")
    if expected_public_key is not None and not secrets.compare_digest(
        encoded_public, expected_public_key
    ):
        raise ReplicationProtocolError("signing public key does not match the pinned peer")
    return key_id, encoded_public


def validate_node_descriptor(
    payload: Any,
    *,
    expected_public_key: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    descriptor = _require_exact_fields(payload, NODE_DESCRIPTOR_FIELDS, "node descriptor")
    if (
        descriptor["schema"] != NODE_DESCRIPTOR_SCHEMA
        or descriptor["protocol_version"] != REPLICATION_PROTOCOL_VERSION
        or descriptor["role"] != "offline-checkpoint-peer"
        # Accept exactly the baseline capability list or the media-capable
        # list, in canonical order; anything else is an unknown contract.
        or descriptor["capabilities"]
        not in (list(BASE_NODE_CAPABILITIES), list(NODE_CAPABILITIES))
    ):
        raise ReplicationProtocolError("node descriptor contract is unsupported")
    node_id = _require_string(descriptor["node_id"], "node identifier", maximum=40)
    if NODE_ID_RE.fullmatch(node_id) is None:
        raise ReplicationProtocolError("node identifier is invalid")
    _require_time(descriptor["created_at"], "descriptor creation time")
    key_id, _encoded = _verify_authentication(
        descriptor,
        expected_public_key=expected_public_key,
        expected_key_id=expected_key_id,
    )
    if not secrets.compare_digest(node_id, node_id_for_key_id(key_id)):
        raise ReplicationProtocolError("node identifier does not match its signing key")
    return copy.deepcopy(descriptor)


def signed_descriptor_transition(
    store: DurableMemoryStore,
    *,
    recorder_node_id: str,
    peer_id: str,
    lineage_id: str,
    direction: str,
    peer_signing_key_id: str,
    previous_descriptor_digest: str,
    descriptor_digest: str,
    previous_evidence: str,
    created_at: float,
) -> dict[str, Any]:
    """Sign an immutable receipt binding a peer descriptor upgrade old->new.

    The receipt is recorded by the local node before its ledger pointer moves,
    so a crash between evidence publication and the compare-and-swap always
    leaves an auditable, replayable record of the intended transition.
    """

    transition = sign_payload(
        store,
        {
            "schema": DESCRIPTOR_TRANSITION_SCHEMA,
            "protocol_version": REPLICATION_PROTOCOL_VERSION,
            "recorder_node_id": recorder_node_id,
            "peer_id": peer_id,
            "lineage_id": lineage_id,
            "direction": direction,
            "peer_signing_key_id": peer_signing_key_id,
            "previous_descriptor_digest": previous_descriptor_digest,
            "descriptor_digest": descriptor_digest,
            "previous_evidence": previous_evidence,
            "created_at": float(created_at),
        },
    )
    validate_descriptor_transition(transition)
    return transition


def validate_descriptor_transition(
    payload: Any,
    *,
    expected_public_key: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    transition = _require_exact_fields(
        payload, DESCRIPTOR_TRANSITION_FIELDS, "descriptor transition"
    )
    if (
        transition["schema"] != DESCRIPTOR_TRANSITION_SCHEMA
        or transition["protocol_version"] != REPLICATION_PROTOCOL_VERSION
        or transition["direction"] not in ("send", "receive")
        or transition["previous_evidence"]
        not in ("descriptor-document", "ledger-digest-only")
    ):
        raise ReplicationProtocolError("descriptor transition contract is unsupported")
    recorder_id = _require_string(
        transition["recorder_node_id"], "recorder node identifier", maximum=40
    )
    peer_id = _require_string(transition["peer_id"], "peer identifier", maximum=40)
    if (
        NODE_ID_RE.fullmatch(recorder_id) is None
        or NODE_ID_RE.fullmatch(peer_id) is None
        or LINEAGE_ID_RE.fullmatch(str(transition["lineage_id"])) is None
        or recorder_id == peer_id
    ):
        raise ReplicationProtocolError("descriptor transition identity is invalid")
    validate_digest(transition["peer_signing_key_id"], "peer signing key identifier")
    previous_digest = validate_digest(
        transition["previous_descriptor_digest"], "previous descriptor digest"
    )
    new_digest = validate_digest(transition["descriptor_digest"], "descriptor digest")
    if previous_digest == new_digest:
        raise ReplicationProtocolError("descriptor transition must change the digest")
    _require_time(transition["created_at"], "transition creation time")
    key_id, _encoded = _verify_authentication(
        transition,
        expected_public_key=expected_public_key,
        expected_key_id=expected_key_id,
    )
    if not secrets.compare_digest(recorder_id, node_id_for_key_id(key_id)):
        raise ReplicationProtocolError(
            "descriptor transition recorder does not match its signing key"
        )
    return copy.deepcopy(transition)


def signed_node_descriptor_transition(
    store: DurableMemoryStore,
    *,
    node_id: str,
    previous_descriptor_digest: str,
    descriptor_digest: str,
    created_at: float,
) -> dict[str, Any]:
    """Sign an immutable receipt binding this node's own descriptor swap.

    The receipt names the exact active predecessor a pointer swap replaces,
    so a candidate descriptor whose evidence was published but that never
    became active can never be laundered into upgrade history.
    """

    transition = sign_payload(
        store,
        {
            "schema": NODE_DESCRIPTOR_TRANSITION_SCHEMA,
            "protocol_version": REPLICATION_PROTOCOL_VERSION,
            "node_id": node_id,
            "previous_descriptor_digest": previous_descriptor_digest,
            "descriptor_digest": descriptor_digest,
            "created_at": float(created_at),
        },
    )
    validate_node_descriptor_transition(transition)
    return transition


def validate_node_descriptor_transition(
    payload: Any,
    *,
    expected_public_key: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    transition = _require_exact_fields(
        payload, NODE_DESCRIPTOR_TRANSITION_FIELDS, "node descriptor transition"
    )
    if (
        transition["schema"] != NODE_DESCRIPTOR_TRANSITION_SCHEMA
        or transition["protocol_version"] != REPLICATION_PROTOCOL_VERSION
    ):
        raise ReplicationProtocolError(
            "node descriptor transition contract is unsupported"
        )
    node_id = _require_string(transition["node_id"], "node identifier", maximum=40)
    if NODE_ID_RE.fullmatch(node_id) is None:
        raise ReplicationProtocolError(
            "node descriptor transition identity is invalid"
        )
    previous_digest = validate_digest(
        transition["previous_descriptor_digest"], "previous descriptor digest"
    )
    new_digest = validate_digest(transition["descriptor_digest"], "descriptor digest")
    if previous_digest == new_digest:
        raise ReplicationProtocolError(
            "node descriptor transition must change the digest"
        )
    _require_time(transition["created_at"], "transition creation time")
    key_id, _encoded = _verify_authentication(
        transition,
        expected_public_key=expected_public_key,
        expected_key_id=expected_key_id,
    )
    if not secrets.compare_digest(node_id, node_id_for_key_id(key_id)):
        raise ReplicationProtocolError(
            "node descriptor transition is not signed by its own node"
        )
    return copy.deepcopy(transition)


def validate_ledger_anchor(
    payload: Any,
    *,
    expected_public_key: str,
    expected_key_id: str,
) -> dict[str, Any]:
    anchor = _require_exact_fields(payload, LEDGER_ANCHOR_FIELDS, "ledger anchor")
    if (
        anchor["schema"] != LEDGER_ANCHOR_SCHEMA
        or anchor["protocol_version"] != REPLICATION_PROTOCOL_VERSION
    ):
        raise ReplicationProtocolError("ledger anchor contract is unsupported")
    node_id = _require_string(anchor["node_id"], "anchor node", maximum=40)
    if NODE_ID_RE.fullmatch(node_id) is None:
        raise ReplicationProtocolError("anchor node identifier is invalid")
    revision = _require_int(anchor["revision"], "anchor revision")
    previous = anchor["previous_anchor_digest"]
    if revision == 0:
        if previous is not None:
            raise ReplicationProtocolError("genesis anchor cannot have a parent")
    else:
        validate_digest(previous, "previous anchor digest")
    validate_digest(anchor["ledger_snapshot_sha256"], "ledger snapshot digest")
    _require_time(anchor["created_at"], "anchor creation time")
    key_id, _encoded = _verify_authentication(
        anchor,
        expected_public_key=expected_public_key,
        expected_key_id=expected_key_id,
    )
    if not secrets.compare_digest(node_id, node_id_for_key_id(key_id)):
        raise ReplicationProtocolError("anchor node does not match its signing key")
    return copy.deepcopy(anchor)


def _validate_artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not (4 <= len(value) <= MAX_ARTIFACTS):
        raise ReplicationProtocolError("checkpoint artifact list is invalid")
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    kinds: set[str] = set()
    for item in value:
        record = _require_exact_fields(item, ARTIFACT_FIELDS, "artifact")
        kind = _require_string(record["kind"], "artifact kind", maximum=40)
        if kind not in ALLOWED_ARTIFACT_KINDS or kind in kinds:
            raise ReplicationProtocolError("checkpoint artifact kind is invalid")
        name = validate_safe_name(record["name"], "artifact name")
        if name == "checkpoint.manifest.json":
            raise ReplicationProtocolError("artifact name is reserved for the checkpoint manifest")
        if name in names:
            raise ReplicationProtocolError("checkpoint artifact name is duplicated")
        validate_digest(record["sha256"], "artifact digest")
        _require_int(record["size_bytes"], "artifact size", minimum=1)
        if int(record["size_bytes"]) > MAX_ARTIFACT_BYTES:
            raise ReplicationProtocolError("checkpoint artifact exceeds its size bound")
        records.append(dict(record))
        names.add(name)
        kinds.add(kind)
    if not REQUIRED_ARTIFACT_KINDS.issubset(kinds):
        raise ReplicationProtocolError("checkpoint is missing a required artifact")
    return records


def validate_checkpoint(
    payload: Any,
    *,
    expected_public_key: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    checkpoint = _require_exact_fields(payload, CHECKPOINT_FIELDS, "checkpoint")
    if (
        checkpoint["schema"] != CHECKPOINT_SCHEMA
        or checkpoint["protocol_version"] != REPLICATION_PROTOCOL_VERSION
    ):
        raise ReplicationProtocolError("checkpoint contract is unsupported")
    source = _require_string(checkpoint["source_node_id"], "source node", maximum=40)
    target = _require_string(checkpoint["target_node_id"], "target node", maximum=40)
    lineage = _require_string(checkpoint["lineage_id"], "lineage", maximum=48)
    checkpoint_id = _require_string(
        checkpoint["checkpoint_id"], "checkpoint identifier", maximum=52
    )
    if (
        NODE_ID_RE.fullmatch(source) is None
        or NODE_ID_RE.fullmatch(target) is None
        or source == target
        or LINEAGE_ID_RE.fullmatch(lineage) is None
        or CHECKPOINT_ID_RE.fullmatch(checkpoint_id) is None
    ):
        raise ReplicationProtocolError("checkpoint identity fields are invalid")
    term = _require_int(checkpoint["term"], "checkpoint term", minimum=1)
    sequence = _require_int(checkpoint["sequence"], "checkpoint sequence", minimum=1)
    expected_id = checkpoint_id_for(
        source_node_id=source,
        target_node_id=target,
        lineage_id=lineage,
        term=term,
        sequence=sequence,
    )
    if not secrets.compare_digest(checkpoint_id, expected_id):
        raise ReplicationProtocolError("checkpoint identifier is invalid")
    parent = checkpoint["parent_checkpoint_digest"]
    if sequence == 1:
        if parent is not None:
            raise ReplicationProtocolError("first checkpoint cannot have a parent")
    else:
        validate_digest(parent, "parent checkpoint digest")
    validate_safe_name(checkpoint["bundle_receipt_name"], "bundle receipt name")
    validate_digest(checkpoint["bundle_receipt_digest"], "bundle receipt digest")
    records = _validate_artifacts(checkpoint["artifacts"])
    artifact_count = _require_int(
        checkpoint["artifact_count"], "artifact count", minimum=1
    )
    if artifact_count != len(records):
        raise ReplicationProtocolError("artifact count does not match the manifest")
    expected_total = sum(int(record["size_bytes"]) for record in records)
    artifact_total = _require_int(
        checkpoint["artifact_total_bytes"], "artifact byte count", minimum=1
    )
    if artifact_total > MAX_ARTIFACT_BYTES or artifact_total != expected_total:
        raise ReplicationProtocolError("artifact byte count does not match the manifest")
    receipt_records = [record for record in records if record["kind"] == "bundle_receipt"]
    if receipt_records[0]["name"] != checkpoint["bundle_receipt_name"]:
        raise ReplicationProtocolError("bundle receipt name does not match the artifact list")
    store_identity = _require_string(
        checkpoint["source_store_identity"], "source store identity", maximum=64
    )
    generation = _require_string(
        checkpoint["store_generation"], "store generation", maximum=64
    )
    if STORE_ID_RE.fullmatch(store_identity) is None or GENERATION_RE.fullmatch(generation) is None:
        raise ReplicationProtocolError("source store lineage fields are invalid")
    epoch = _require_int(checkpoint["authority_epoch_number"], "authority epoch", minimum=1)
    governance = checkpoint["governance_mode"]
    if governance != "authoritative-v6" or generation != f"epoch-{epoch}":
        raise ReplicationProtocolError(
            "replication checkpoints require an authoritative-v6 store generation"
        )
    validate_digest(checkpoint["logical_snapshot_sha256"], "logical snapshot digest")
    validate_digest(checkpoint["capture_ledger_revision"], "capture ledger revision")
    _require_time(checkpoint["created_at"], "checkpoint creation time")
    key_id, _encoded = _verify_authentication(
        checkpoint,
        expected_public_key=expected_public_key,
        expected_key_id=expected_key_id,
    )
    if not secrets.compare_digest(source, node_id_for_key_id(key_id)):
        raise ReplicationProtocolError("checkpoint source does not match its signing key")
    return dict(checkpoint)


def validate_ack(
    payload: Any,
    *,
    expected_public_key: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    ack = _require_exact_fields(payload, ACK_FIELDS, "acknowledgement")
    if ack["schema"] != ACK_SCHEMA or ack["protocol_version"] != REPLICATION_PROTOCOL_VERSION:
        raise ReplicationProtocolError("acknowledgement contract is unsupported")
    checkpoint_id = _require_string(ack["checkpoint_id"], "checkpoint identifier", maximum=52)
    lineage = _require_string(ack["lineage_id"], "lineage", maximum=48)
    source = _require_string(ack["source_node_id"], "source node", maximum=40)
    receiver = _require_string(ack["receiver_node_id"], "receiver node", maximum=40)
    ack_id = _require_string(ack["ack_id"], "acknowledgement identifier", maximum=45)
    if (
        CHECKPOINT_ID_RE.fullmatch(checkpoint_id) is None
        or LINEAGE_ID_RE.fullmatch(lineage) is None
        or NODE_ID_RE.fullmatch(source) is None
        or NODE_ID_RE.fullmatch(receiver) is None
        or source == receiver
        or ACK_ID_RE.fullmatch(ack_id) is None
    ):
        raise ReplicationProtocolError("acknowledgement identity fields are invalid")
    _require_int(ack["term"], "acknowledgement term", minimum=1)
    _require_int(ack["sequence"], "acknowledgement sequence", minimum=1)
    checkpoint_digest = validate_digest(ack["checkpoint_digest"], "checkpoint digest")
    validate_digest(ack["bundle_receipt_digest"], "bundle receipt digest")
    validate_digest(ack["restore_proof_receipt_digest"], "restore proof digest")
    if ack["memory_recovery_cutover_ready"] is not True:
        raise ReplicationProtocolError(
            "acknowledgement requires a memory-recovery-ready restore"
        )
    _require_time(ack["acked_at"], "acknowledgement time")
    if ack_id != ack_id_for(
        checkpoint_digest=checkpoint_digest, receiver_node_id=receiver
    ):
        raise ReplicationProtocolError("acknowledgement identifier is invalid")
    key_id, _encoded = _verify_authentication(
        ack,
        expected_public_key=expected_public_key,
        expected_key_id=expected_key_id,
    )
    if not secrets.compare_digest(receiver, node_id_for_key_id(key_id)):
        raise ReplicationProtocolError("acknowledgement receiver does not match its signing key")
    return dict(ack)


def validate_private_directory(path: Path) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"private directory does not exist: {path.name}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PermissionError("replication directory must be owner-only and non-symlink")
    return metadata


def read_private_bytes(path: Path, *, maximum_bytes: int = MAX_PROTOCOL_JSON_BYTES) -> bytes:
    before = os.lstat(path)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or int(before.st_nlink) != 1
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise PermissionError("replication input must be a bounded private regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise RuntimeError("replication input changed while opening")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum_bytes:
                raise ReplicationProtocolError("replication input exceeds its size bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(path)
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity
        or (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != identity
    ):
        raise RuntimeError("replication input changed while reading")
    return b"".join(chunks)


def read_private_json(path: Path) -> dict[str, Any]:
    raw = read_private_bytes(path)

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReplicationProtocolError("replication JSON contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ReplicationProtocolError("replication JSON contains a non-finite value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplicationProtocolError("replication JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ReplicationProtocolError("replication document must be a JSON object")
    try:
        canonical_json_bytes(value)
    except CoreProtocolError as exc:
        raise ReplicationProtocolError("replication JSON exceeds protocol bounds") from exc
    return value


def write_private_json_exclusive(
    store: DurableMemoryStore, path: Path, payload: dict[str, Any]
) -> None:
    try:
        canonical_json_bytes(payload)
    except CoreProtocolError as exc:
        raise ReplicationProtocolError("replication JSON exceeds protocol bounds") from exc
    store._write_private_json_exclusive(path, payload)
