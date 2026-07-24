from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import secrets
import signal
import socket
import sqlite3
import stat
import sys
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from core_authority import (
    CORE_AUTHORITY_SCHEMA_VERSION,
    CoreAuthorityError,
    CoreAuthorityLease,
)
from bridge_governance import (
    BridgeGovernanceError,
    BridgeGovernanceIntegrityError,
)
from core_protocol import (
    CORE_CONFIG_VERSION,
    DEFAULT_MAX_FRAME_BYTES,
    LONG_RECOVERY_OPERATIONS,
    MAX_DEADLINE_HORIZON_MS,
    PROTOCOL_VERSION,
    RECOVERY_MAX_DEADLINE_HORIZON_MS,
    CoreProtocolError,
    CoreTransportError,
    canonical_json_bytes,
    contains_secret_shape,
    decode_canonical_json,
    peer_uid,
    receive_frame,
    safe_error,
    send_frame,
    validate_max_frame_bytes,
    validate_request,
)
from core_path_policy import (
    AuthorizedPath,
    CorePathPolicy,
    CorePathPolicyError,
)
from core_request_journal import (
    JOURNAL_BINDING_SCHEMA,
    JOURNAL_SCHEMA_IDENTITY,
    JOURNAL_SCHEMA_VERSION,
    CoreRequestJournal,
    CoreRequestJournalCapacityError,
    CoreRequestJournalError,
    repair_empty_preclaim_journal_residue,
)
from core_runtime_paths import (
    CoreRuntimePathError,
    durable_core_root,
    supported_core_socket_path,
    validate_core_socket_path,
)
from memory_store import ContextDeliveryRejected, LOGICAL_SNAPSHOT_DIGEST_SCHEMA
from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    SecretRedactingFormatter,
    SecretSafeArgumentParser,
    reject_sensitive_identifier,
)


LOGGER = logging.getLogger("synapse_s2.core_service")
if not LOGGER.handlers:
    _LOG_HANDLER = logging.StreamHandler(sys.stderr)
    _LOG_HANDLER.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
    LOGGER.addHandler(_LOG_HANDLER)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False
DEFAULT_AUTHORITY_TIMEOUT_SECONDS = 15.0
DEFAULT_CAPTURE_POLL_SECONDS = 2.0
MAX_ACTIVE_CONNECTIONS = 32
MAX_PENDING_CONNECTIONS = MAX_ACTIVE_CONNECTIONS * 2
PREAUTH_FRAME_TIMEOUT_SECONDS = 1.0
AUTHENTICATED_CONNECTION_TIMEOUT_SECONDS = 5.0
MAX_REQUEST_CACHE_ENTRIES = 4_096
MAX_REQUEST_CACHE_BYTES = 32 * 1024 * 1024
MAX_NEURAL_MATRIX_BYTES = 384 * 1024 * 1024
NEURAL_ARRAY_BYTES_PER_ELEMENT = 4
STORE_GENERATION_SCHEMA = "synapse-s2.root-generation.v1"
STORE_GENERATION_ID_RE = re.compile(r"generation-[0-9a-f]{24}")
CUTOVER_MINIMUM_REMAINING_SECONDS = 30.0
CUTOVER_COMMIT_SAFETY_MARGIN_MS = 1_000
# First adoption recomputes the complete logical store under BEGIN IMMEDIATE
# with a 120-second default ceiling. Refuse a nearly-expired attestation before
# opening a request journal so an expiry cannot manufacture fresh residue.
CUTOVER_PRECLAIM_MINIMUM_REMAINING_SECONDS = 150.0
REPLACEMENT_ADMISSION_ENV = "SYNAPSE_S2_REPLACEMENT_ADMISSION"
REPLACEMENT_CERTIFICATION_MODE = "replacement-certification"
REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX = "replacement-certification:"
AUTHORITATIVE_DEPLOYMENT_MODE = "authoritative"
CORE_STARTUP_FAILURE_SCHEMA = "synapse-s2.core-startup-failure.v1"
CORE_STARTUP_FAILURE_CLASSES = MappingProxyType(
    {
        "initial_validation": "configuration_rejected",
        "durable_preflight": "durable_state_rejected",
        "authority_lock": "authority_lock_unavailable",
        "transport_auth": "transport_auth_unavailable",
        "backend_init": "backend_unavailable",
        "preclaim_inspection": "preclaim_state_rejected",
        "preclaim_journal_repair": "preclaim_journal_rejected",
        "cutover_attestation": "cutover_attestation_rejected",
        "request_journal_open": "request_journal_rejected",
        "request_journal_binding": "request_journal_binding_rejected",
        "capture_worker_prepare": "capture_worker_unavailable",
        "listener_bind": "transport_unavailable",
        "capture_thread_start": "capture_worker_unavailable",
        "durable_authority_claim": "authority_claim_rejected",
        "runtime_publication": "runtime_publication_rejected",
        "replication_init": "replication_unavailable",
        "path_policy_init": "path_policy_unavailable",
    }
)
BACKEND_LANE_CAPTURE_TIMEOUT_SECONDS = 60.0
BACKEND_LANE_CAPTURE_FILE_SECONDS = 5.0
BACKEND_LANE_RPC_TIMEOUT_SECONDS = 30.0
NEURAL_OPERATION_LANE_SECONDS = 120.0
SEMANTIC_INDEX_MAINTENANCE_LANE_SECONDS = 120.0
# Ordinary protocol requests remain capped at 300 seconds.  The authenticated,
# closed recovery allowlist receives one bounded hour because paired recovery
# on a large local store legitimately performs stable copies, hashing, capture
# reconciliation, and isolated restore proof.  It remains synchronous: a lost
# response is still reconciled through request_status and never blind-replayed.
RECOVERY_MAINTENANCE_LANE_SECONDS = (
    RECOVERY_MAX_DEADLINE_HORIZON_MS / 1000.0
)
RECOVERY_MAINTENANCE_QUEUE_SECONDS = MAX_DEADLINE_HORIZON_MS / 1000.0
REPLICATION_MAINTENANCE_LANE_SECONDS = RECOVERY_MAINTENANCE_LANE_SECONDS
BACKEND_LANE_CLOSE_GRACE_SECONDS = 2.0
CORE_STORE_SCHEMA_IDENTITY = "sqlite-53324442-v6"
BUILD_SOURCE_MANIFEST = (
    "backend_router.py",
    "bridge_governance.py",
    "capture_daemon.py",
    "core_authority.py",
    "core_client_binding.py",
    "core_client.py",
    "core_path_policy.py",
    "core_protocol.py",
    "core_request_journal.py",
    "core_runtime_paths.py",
    "core_service.py",
    "embedding_providers.py",
    "event_segmenter.py",
    "memory_store.py",
    "mlx_backend.py",
    "recovery_manager.py",
    "redaction.py",
    "replication_manager.py",
    "replication_protocol.py",
    "replication_store.py",
    "scripts/core_cutover_preflight.py",
    "transcript_capture.py",
    "pyproject.toml",
    "uv.lock",
)

CORE_CONFIG_FIELDS = frozenset(
    {
        "protocol_version",
        "socket_path",
        "state_path",
        "memory_path",
        "capture_root",
        "dimension",
        "num_neurons",
        "default_top_k",
        "recall_count",
        "quick_pruning_interval_seconds",
        "idle_deep_sleep_seconds",
        "embedding_provider_name",
        "embedding_neural_model_id",
        "embedding_neural_revision",
        "embedding_neural_cache_dir",
        "embedding_neural_pooling",
        "embedding_neural_max_tokens",
        "embedding_neural_normalize",
        "embedding_neural_local_files_only",
        "mlx_device",
        "require_native",
        "capture_poll_seconds",
        "capture_max_files",
        "poll_transcript_sources",
        "max_transcript_bytes",
        "max_frame_bytes",
        "authority_timeout_seconds",
    }
)


class CoreServiceError(RuntimeError):
    """Content-free authoritative-core startup or lifecycle failure."""

    def __init__(self, code: str = "service_unavailable") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CoreConfig:
    socket_path: Path
    state_path: Path
    memory_path: Path
    capture_root: Path | None = None
    dimension: int = 1024
    num_neurons: int = 8192
    default_top_k: int = 256
    recall_count: int = 10
    quick_pruning_interval_seconds: float = 300.0
    idle_deep_sleep_seconds: float = 1800.0
    embedding_provider_name: str = "semantic-hash"
    embedding_neural_model_id: str | None = None
    embedding_neural_revision: str | None = None
    embedding_neural_cache_dir: Path | None = None
    embedding_neural_pooling: str | None = None
    embedding_neural_max_tokens: int | None = None
    embedding_neural_normalize: bool | None = None
    embedding_neural_local_files_only: bool | None = None
    mlx_device: str = "default"
    require_native: bool = False
    capture_poll_seconds: float = DEFAULT_CAPTURE_POLL_SECONDS
    capture_max_files: int = 50
    poll_transcript_sources: bool = False
    max_transcript_bytes: int = 256_000
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
    authority_timeout_seconds: float = DEFAULT_AUTHORITY_TIMEOUT_SECONDS

    def to_wire(self) -> dict[str, Any]:
        return {
            "protocol_version": CORE_CONFIG_VERSION,
            "socket_path": str(self.socket_path),
            "state_path": str(self.state_path),
            "memory_path": str(self.memory_path),
            "capture_root": (
                None if self.capture_root is None else str(self.capture_root)
            ),
            "dimension": self.dimension,
            "num_neurons": self.num_neurons,
            "default_top_k": self.default_top_k,
            "recall_count": self.recall_count,
            "quick_pruning_interval_seconds": self.quick_pruning_interval_seconds,
            "idle_deep_sleep_seconds": self.idle_deep_sleep_seconds,
            "embedding_provider_name": self.embedding_provider_name,
            "embedding_neural_model_id": self.embedding_neural_model_id,
            "embedding_neural_revision": self.embedding_neural_revision,
            "embedding_neural_cache_dir": (
                None
                if self.embedding_neural_cache_dir is None
                else str(self.embedding_neural_cache_dir)
            ),
            "embedding_neural_pooling": self.embedding_neural_pooling,
            "embedding_neural_max_tokens": self.embedding_neural_max_tokens,
            "embedding_neural_normalize": self.embedding_neural_normalize,
            "embedding_neural_local_files_only": (
                self.embedding_neural_local_files_only
            ),
            "mlx_device": self.mlx_device,
            "require_native": self.require_native,
            "capture_poll_seconds": self.capture_poll_seconds,
            "capture_max_files": self.capture_max_files,
            "poll_transcript_sources": self.poll_transcript_sources,
            "max_transcript_bytes": self.max_transcript_bytes,
            "max_frame_bytes": self.max_frame_bytes,
            "authority_timeout_seconds": self.authority_timeout_seconds,
        }

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_wire())).hexdigest()

    @property
    def embedding_space_identity(self) -> str:
        """Return the immutable identity of every persisted retrieval coordinate.

        Deployment-only settings such as the model-cache pathname are excluded;
        every setting that can change an embedding, spike set, or neuron mapping
        is included. A future reindex migration must explicitly replace this
        identity rather than silently mixing incompatible coordinates.
        """

        provider = {
            "semantic-hash": "semantic-hash-v1",
            "semantic-hash-v1": "semantic-hash-v1",
            "lexical-hash": "lexical-hash-v1",
            "lexical-hash-v1": "lexical-hash-v1",
            "mlx-neural": "mlx-neural-v1",
            "mlx-neural-v1": "mlx-neural-v1",
        }[self.embedding_provider_name.strip().lower()]
        identity: dict[str, Any] = {
            "schema": "synapse-s2.embedding-space.v1",
            "provider": provider,
            "dimensions": self.dimension,
            "num_neurons": self.num_neurons,
            "spike_encoder": "zscore-top-k-v1",
            "default_top_k": self.default_top_k,
            "neuron_projection": "synaptic-matrix-v1",
        }
        if provider == "mlx-neural-v1":
            identity["neural"] = {
                "model_id": self.embedding_neural_model_id,
                "revision": self.embedding_neural_revision,
                "pooling": self.embedding_neural_pooling,
                "max_tokens": self.embedding_neural_max_tokens,
                "normalize": self.embedding_neural_normalize,
            }
        return hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


@dataclass(frozen=True)
class OperationContract:
    name: str
    allowed_arguments: frozenset[str]
    required_arguments: frozenset[str] = frozenset()
    mutation: bool = False
    retry_safe: bool = False

    def validate_arguments(self, arguments: Any) -> dict[str, Any]:
        if not isinstance(arguments, dict):
            raise CoreProtocolError()
        observed = frozenset(arguments)
        if not observed.issubset(self.allowed_arguments):
            raise CoreProtocolError()
        if not self.required_arguments.issubset(observed):
            raise CoreProtocolError()
        return arguments


def _contract(
    name: str,
    allowed: str = "",
    required: str = "",
    *,
    mutation: bool = False,
    retry_safe: bool = False,
) -> OperationContract:
    return OperationContract(
        name=name,
        allowed_arguments=frozenset(filter(None, allowed.split())),
        required_arguments=frozenset(filter(None, required.split())),
        mutation=mutation,
        retry_safe=retry_safe,
    )


# This closed registry is the complete input-controllable dispatch surface. A
# request name is never used with getattr; static method names are bound once at
# startup only after this contract has been selected.
_CONTRACT_LIST = (
    _contract("health", retry_safe=True),
    _contract(
        "request_status",
        "caller request_id",
        "caller request_id",
        retry_safe=True,
    ),
    _contract("status", "context_id", retry_safe=True),
    _contract("is_enabled", "context_id", retry_safe=True),
    _contract("set_enabled", "enabled context_id", "enabled", mutation=True),
    _contract("embedding_provider_info", retry_safe=True),
    _contract("embed_text_payload", "text dimensions", "text", retry_safe=True),
    _contract(
        "benchmark_embedding_provider",
        "text runs dimensions",
        "text",
        retry_safe=True,
    ),
    _contract(
        "register_text_trace",
        "tag text context_id metadata",
        "tag text",
        mutation=True,
    ),
    _contract(
        "register_trace",
        "tag embedding context_id metadata source_text",
        "tag embedding",
        mutation=True,
    ),
    _contract("query_text", "prompt context_id steps recall_scope", "prompt", mutation=True),
    _contract(
        "retrieve_text_v2",
        "prompt context_id recall_scope result_limit candidate_limit "
        "include_graph_neighbors",
        "prompt",
        retry_safe=True,
    ),
    _contract(
        "query",
        "embedding context_id steps prompt_text recall_scope",
        "embedding",
        mutation=True,
    ),
    _contract(
        "list_memory",
        "context_id limit include_global include_vectors recall_scope cursor response_mode",
        retry_safe=True,
    ),
    _contract(
        "publish_context_event",
        "context_id source_surface event_type summary payload agent_targets",
        "source_surface event_type summary",
        mutation=True,
    ),
    _contract(
        "list_context_events",
        "context_id since_event_id before_event_id agent_id order limit",
        retry_safe=True,
    ),
    _contract(
        "lease_context_events",
        "context_id agent_id consumer_instance_id limit lease_seconds",
        mutation=True,
    ),
    _contract(
        "ack_context_events",
        "context_id agent_id acknowledgements receipt_id last_event_id",
        mutation=True,
    ),
    _contract(
        "release_context_events",
        "context_id agent_id consumer_instance_id receipt_ids",
        "receipt_ids",
        mutation=True,
    ),
    _contract(
        "dead_letter_context_delivery",
        "context_id agent_id delivery_id reason confirm",
        "delivery_id reason",
        mutation=True,
    ),
    _contract("list_context_cursors", "context_id limit", retry_safe=True),
    _contract("context_delivery_health", "context_id", retry_safe=True),
    _contract(
        "enter_spiking_cortex",
        "context_id agent_id task mode recall_mode",
        "task",
        mutation=True,
    ),
    _contract(
        "cortex_tick",
        "context_id agent_id session_id observation proposed_action intended_files "
        "intended_tools mutation_intent confidence",
        "session_id",
        mutation=True,
    ),
    _contract(
        "close_spiking_cortex",
        "context_id agent_id session_id reason",
        "session_id",
        mutation=True,
    ),
    _contract(
        "commit_cortical_trace",
        "context_id agent_id session_id trace_type truth_posture text evidence confidence",
        "text",
        mutation=True,
    ),
    _contract(
        "get_cortex_state",
        "context_id agent_id limit cursor response_mode",
        retry_safe=True,
    ),
    _contract(
        "reap_orphaned_cortex_sessions",
        "context_id agent_id",
        mutation=True,
    ),
    _contract(
        "attach_client_cortex_session",
        "context_id agent_id session_id client_bridge_session_id owner_pid owner_ppid "
        "owner_started_at",
        "session_id client_bridge_session_id owner_pid",
        mutation=True,
    ),
    _contract(
        "finish_client_cortex_session",
        "context_id agent_id session_id client_bridge_session_id reason finished_at",
        "session_id client_bridge_session_id",
        mutation=True,
    ),
    _contract(
        "create_goal",
        "context_id agent_id title owner state next_action evidence",
        "title",
        mutation=True,
    ),
    _contract(
        "update_goal",
        "context_id agent_id goal_id title owner state next_action evidence",
        mutation=True,
    ),
    _contract("list_goals", "context_id limit", retry_safe=True),
    _contract(
        "moderate_cortex_trace",
        "context_id memory_id action reason source_surface confirm",
        "memory_id action",
        mutation=True,
    ),
    _contract(
        "hydrate_agent_context",
        "context_id agent_id prompt since_event_id event_limit graph_limit acknowledge "
        "claim_events consumer_instance_id lease_seconds recall_mode",
        mutation=True,
    ),
    _contract(
        "ingest_text_events",
        "text context_id source_tag surprise_threshold min_segment_sentences metadata",
        "text",
        mutation=True,
    ),
    _contract(
        "capture_conversation",
        "text context_id source_tag speaker surprise_threshold min_segment_sentences "
        "metadata capture_id",
        "text",
        mutation=True,
    ),
    _contract(
        "replay_capture_operation",
        "capture_id context_id source_tag speaker",
        "capture_id",
        mutation=True,
    ),
    _contract(
        "prune_memory",
        "context_id target_type memory_id tag relationship_id event_id reason "
        "source_surface publish_audit confirm",
        "target_type confirm",
        mutation=True,
    ),
    _contract(
        "approve_namespace_link",
        "source_context_id target_context_id relation_type weight evidence direction "
        "approved_by enabled reason link_expires_at governance_request_id confirm",
        "source_context_id target_context_id",
        mutation=True,
    ),
    _contract(
        "propose_namespace_link",
        "source_context_id target_context_id relation_type weight evidence direction "
        "proposed_by reason proposal_expires_at link_expires_at governance_request_id",
        "source_context_id target_context_id reason",
        mutation=True,
    ),
    _contract(
        "review_namespace_link",
        "proposal_id decision expected_revision reviewed_by reason governance_request_id",
        "proposal_id decision expected_revision reason",
        mutation=True,
    ),
    _contract(
        "disable_namespace_link",
        "context_link_id expected_revision disabled_by reason governance_request_id confirm",
        "context_link_id expected_revision reason confirm",
        mutation=True,
    ),
    _contract(
        "revoke_namespace_link",
        "context_link_id expected_revision revoked_by reason governance_request_id confirm",
        "context_link_id expected_revision reason confirm",
        mutation=True,
    ),
    _contract("expire_namespace_links", mutation=True),
    _contract(
        "delete_namespace_link",
        "context_link_id expected_revision revoked_by reason governance_request_id confirm",
        "context_link_id expected_revision confirm",
        mutation=True,
    ),
    _contract(
        "list_namespace_link_proposals",
        "context_id state limit",
        retry_safe=True,
    ),
    _contract(
        "list_namespace_link_history",
        "proposal_id context_link_id limit",
        retry_safe=True,
    ),
    _contract("audit_namespace_link_governance", retry_safe=True),
    _contract(
        "suggest_namespace_links",
        "context_id limit min_score include_linked max_visual_phase_delay_ticks",
        retry_safe=True,
    ),
    _contract(
        "list_namespace_map",
        "context_id limit include_suggestions suggestion_limit min_suggestion_score "
        "max_visual_phase_delay_ticks",
        retry_safe=True,
    ),
    _contract(
        "list_namespace_detail",
        "context_id level cluster_id limit",
        retry_safe=True,
    ),
    _contract(
        "list_memory_graph",
        "context_id limit cursor response_mode include_global",
        retry_safe=True,
    ),
    _contract(
        "audit_semantic_indexes",
        "context_id sample_limit",
        retry_safe=True,
    ),
    _contract(
        "repair_semantic_indexes",
        "context_id confirm expected_revision sample_limit",
        mutation=True,
    ),
    _contract(
        "resolve_recall_contexts",
        "context_id recall_scope",
        retry_safe=True,
    ),
    _contract(
        "memory_entries_revision",
        "context_id include_global context_ids",
        retry_safe=True,
    ),
    _contract(
        "get_memory_entry",
        "memory_id include_vectors",
        "memory_id",
        retry_safe=True,
    ),
    _contract(
        "resource_profile",
        "target_min_mb target_max_mb",
        retry_safe=True,
    ),
    _contract(
        "benchmark_resource_profile",
        "target_min_mb target_max_mb",
        mutation=True,
    ),
    _contract(
        "certify_runtime",
        "strict_native require_gpu benchmark_quick_prune require_resource_envelope "
        "target_min_mb target_max_mb output_path",
        mutation=True,
    ),
    _contract("export_memory", "path context_id limit", mutation=True),
    _contract("backup_memory", "path", mutation=True),
    _contract(
        "backup_recovery_bundle",
        "path purpose pinned",
        mutation=True,
    ),
    _contract(
        "audit_capture_ledger",
        "sample_limit",
        mutation=True,
    ),
    _contract(
        "repair_capture_ledger",
        "confirm expected_revision sample_limit",
        mutation=True,
    ),
    _contract(
        "verify_recovery_bundle",
        "receipt_path expected_database_sha256 expected_capture_sha256 "
        "expected_request_journal_sha256 expected_runtime_state_sha256",
        "receipt_path",
        mutation=True,
    ),
    _contract(
        "restore_recovery_bundle_isolated",
        "receipt_path output_root expected_database_sha256 "
        "expected_capture_sha256 expected_request_journal_sha256 "
        "expected_runtime_state_sha256 confirm",
        "receipt_path output_root",
        mutation=True,
    ),
    _contract(
        "plan_recovery_retention",
        "keep_latest max_age_days",
        mutation=True,
    ),
    _contract(
        "apply_recovery_retention",
        "plan_token cutoff_created_at keep_latest max_age_days confirm",
        "plan_token cutoff_created_at",
        mutation=True,
    ),
    _contract("restore_retired_recovery", "plan_token confirm", "plan_token", mutation=True),
    _contract("replication_identity", retry_safe=True),
    _contract("replication_status", retry_safe=True),
    _contract(
        "replication_pair_peer",
        "descriptor_path expected_descriptor_digest lineage_id direction confirm",
        "descriptor_path expected_descriptor_digest lineage_id direction confirm",
        mutation=True,
    ),
    _contract(
        "replication_revoke_peer",
        "peer_id reason confirm",
        "peer_id reason confirm",
        mutation=True,
    ),
    _contract(
        "replication_create_checkpoint",
        "peer_id",
        "peer_id",
        mutation=True,
    ),
    _contract(
        "replication_stage_checkpoint",
        "manifest_path",
        "manifest_path",
        mutation=True,
    ),
    _contract(
        "replication_record_acknowledgement",
        "acknowledgement_path",
        "acknowledgement_path",
        mutation=True,
    ),
    _contract("run_quick_pruning", "trigger", mutation=True),
    _contract("run_idle_maintenance", "force_deep_sleep", mutation=True),
    _contract("run_deep_sleep_consolidation", "trigger", mutation=True),
)
CORE_OPERATION_CONTRACTS: Mapping[str, OperationContract] = MappingProxyType(
    {contract.name: contract for contract in _CONTRACT_LIST}
)
SAFE_READ_OPERATIONS = frozenset(
    name for name, contract in CORE_OPERATION_CONTRACTS.items() if contract.retry_safe
)
SERVICE_CONTROL_OPERATIONS = frozenset({"health", "request_status"})
REPLICATION_OPERATIONS = frozenset(
    {
        "replication_identity",
        "replication_status",
        "replication_pair_peer",
        "replication_revoke_peer",
        "replication_create_checkpoint",
        "replication_stage_checkpoint",
        "replication_record_acknowledgement",
    }
)
LONG_REPLICATION_OPERATIONS = frozenset(
    {
        "replication_create_checkpoint",
        "replication_stage_checkpoint",
    }
)
LONG_SEMANTIC_INDEX_OPERATIONS = frozenset(
    {
        "audit_semantic_indexes",
        "repair_semantic_indexes",
    }
)
LONG_NEURAL_OPERATIONS = frozenset(
    {
        "embed_text_payload",
        "benchmark_embedding_provider",
        "register_text_trace",
        "register_trace",
        "query_text",
        "retrieve_text_v2",
        "query",
        "enter_spiking_cortex",
        "cortex_tick",
        "commit_cortical_trace",
        "create_goal",
        "update_goal",
        "hydrate_agent_context",
        "ingest_text_events",
        "capture_conversation",
        "benchmark_resource_profile",
        "certify_runtime",
        "run_quick_pruning",
        "run_idle_maintenance",
        "run_deep_sleep_consolidation",
    }
)
DETERMINISTIC_DELIVERY_REJECTION_OPERATIONS = frozenset(
    {
        "ack_context_events",
        "release_context_events",
        "dead_letter_context_delivery",
    }
)
DETERMINISTIC_GOVERNANCE_REJECTION_OPERATIONS = frozenset(
    {
        "approve_namespace_link",
        "propose_namespace_link",
        "review_namespace_link",
        "disable_namespace_link",
        "revoke_namespace_link",
        "delete_namespace_link",
        "expire_namespace_links",
    }
)


@dataclass(frozen=True)
class _ArgumentRule:
    """A closed, pure wire-value rule applied before durable acceptance."""

    kind: str
    nullable: bool = False
    minimum: float | None = None
    maximum: float | None = None
    min_items: int = 0
    max_items: int = 0
    min_bytes: int = 0
    max_bytes: int = 0
    allowed_values: frozenset[str] | None = None
    pattern: re.Pattern[str] | None = None


def _rule(
    kind: str,
    *,
    nullable: bool = False,
    minimum: float | None = None,
    maximum: float | None = None,
    min_items: int = 0,
    max_items: int = 0,
    min_bytes: int = 0,
    max_bytes: int = 0,
    allowed_values: frozenset[str] | None = None,
    pattern: re.Pattern[str] | None = None,
) -> _ArgumentRule:
    return _ArgumentRule(
        kind=kind,
        nullable=nullable,
        minimum=minimum,
        maximum=maximum,
        min_items=min_items,
        max_items=max_items,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        allowed_values=allowed_values,
        pattern=pattern,
    )


_BOOL = _rule("bool")
_TRUE = _rule("true")
_INT_NONNEGATIVE = _rule("int", minimum=0, maximum=10_000_000)
_INT_POSITIVE = _rule("int", minimum=1, maximum=10_000_000)
_LIMIT = _rule("int", minimum=1, maximum=100_000)
_SAMPLE_LIMIT = _rule("int", minimum=1, maximum=1_000)
_STEPS = _rule("int", minimum=1, maximum=64)
_PID = _rule("int", minimum=1, maximum=2_147_483_647)
_PPID = _rule("int", minimum=0, maximum=2_147_483_647)
_UNIT_INTERVAL = _rule("number", minimum=0.0, maximum=1.0)
_POSITIVE_TIMESTAMP = _rule("number", minimum=0.000001, maximum=100_000_000_000.0)
_OPTIONAL_TIMESTAMP = _rule(
    "number",
    nullable=True,
    minimum=0.000001,
    maximum=100_000_000_000.0,
)
_LEASE_SECONDS = _rule("number", minimum=1.0, maximum=3_600.0)
_RESOURCE_MB = _rule("number", minimum=0.0, maximum=1_048_576.0)
_RETENTION_DAYS = _rule("number", minimum=0.0, maximum=36_500.0)
_SHORT_STRING = _rule("string", max_bytes=4_096)
_NONEMPTY_SHORT_STRING = _rule("string", min_bytes=1, max_bytes=4_096)
_OPTIONAL_SHORT_STRING = _rule("string", nullable=True, max_bytes=4_096)
_IDENTIFIER = _rule("string", max_bytes=512)
_NONEMPTY_IDENTIFIER = _rule("string", min_bytes=1, max_bytes=512)
_OPTIONAL_IDENTIFIER = _rule("string", nullable=True, max_bytes=512)
_TEXT = _rule("string", max_bytes=262_144)
_NONEMPTY_TEXT = _rule("string", min_bytes=1, max_bytes=262_144)
_PATH = _rule("string", min_bytes=1, max_bytes=4_096)
_OPTIONAL_PATH = _rule("string", nullable=True, min_bytes=1, max_bytes=4_096)
_JSON_OBJECT = _rule("json_object", nullable=True, max_items=256)
_STRING_LIST = _rule("string_list", nullable=True, max_items=500, max_bytes=4_096)
_NONEMPTY_STRING_LIST = _rule(
    "string_list",
    min_items=1,
    max_items=500,
    min_bytes=1,
    max_bytes=4_096,
)
_INTENT_LIST = _rule(
    "string_or_string_list",
    nullable=True,
    max_items=128,
    max_bytes=32_768,
)
_EMBEDDING = _rule(
    "number_list",
    min_items=1,
    max_items=32_768,
)
_ACKNOWLEDGEMENTS = _rule(
    "acknowledgements",
    nullable=True,
    max_items=500,
)
_DIGEST = _rule(
    "string",
    min_bytes=64,
    max_bytes=64,
    pattern=re.compile(r"[0-9a-f]{64}"),
)
_OPTIONAL_DIGEST = _rule(
    "string",
    nullable=True,
    min_bytes=64,
    max_bytes=64,
    pattern=re.compile(r"[0-9a-f]{64}"),
)
_CAPTURE_ID = _rule(
    "string",
    min_bytes=38,
    max_bytes=38,
    pattern=re.compile(r"s2cap_[0-9a-f]{32}"),
)
_OPTIONAL_CAPTURE_ID = _rule(
    "string",
    nullable=True,
    min_bytes=38,
    max_bytes=38,
    pattern=re.compile(r"s2cap_[0-9a-f]{32}"),
)
_RECALL_SCOPE = _rule(
    "string",
    max_bytes=16,
    allowed_values=frozenset({"local", "connected", "all", "broad"}),
)
_RECALL_MODE = _rule(
    "string",
    max_bytes=32,
    allowed_values=frozenset(
        {
            "neural",
            "surface",
            "none",
            "full",
            "spiking",
            "surface-bootstrap",
            "surface_bootstrap",
            "lexical",
            "off",
            "disabled",
        }
    ),
)
_CORTEX_MODE = _rule(
    "string",
    max_bytes=16,
    allowed_values=frozenset({"strict", "creative", "operator", "security", "demo"}),
)
_GOAL_STATE = _rule(
    "string",
    max_bytes=32,
    allowed_values=frozenset(
        {"", "planned", "in_progress", "in-progress", "blocked", "done", "stale"}
    ),
)
_MODERATION_ACTION = _rule(
    "string",
    min_bytes=1,
    max_bytes=16,
    allowed_values=frozenset({"promote", "demote", "prune"}),
)
_PRUNE_TARGET = _rule(
    "string",
    min_bytes=1,
    max_bytes=32,
    allowed_values=frozenset(
        {
            "memory",
            "node",
            "trace",
            "event",
            "relationship",
            "edge",
            "temporal",
            "associative",
            "context_event",
            "context-event",
            "deployment",
            "context_deployment",
            "context-deployment",
        }
    ),
)
_LINK_DIRECTION = _rule(
    "string",
    max_bytes=32,
    allowed_values=frozenset(
        {
            "directed",
            "bidirectional",
            "both",
            "two-way",
            "two_way",
            "undirected",
            "one-way",
            "one_way",
            "outbound",
        }
    ),
)
_REPLICATION_NODE_ID = _rule(
    "string",
    min_bytes=39,
    max_bytes=39,
    pattern=re.compile(r"s2node_[0-9a-f]{32}"),
)
_REPLICATION_LINEAGE_ID = _rule(
    "string",
    min_bytes=42,
    max_bytes=42,
    pattern=re.compile(r"s2lineage_[0-9a-f]{32}"),
)
_REPLICATION_DIRECTION = _rule(
    "string",
    min_bytes=4,
    max_bytes=7,
    allowed_values=frozenset({"send", "receive"}),
)


def _schema(**rules: _ArgumentRule) -> Mapping[str, _ArgumentRule]:
    return MappingProxyType(dict(rules))


# Every mutation has an explicit schema. The registry intentionally contains no
# fallback-by-field-name: adding a mutation or argument without choosing a rule
# is a startup error instead of an unvalidated path into the durable journal.
MUTATION_ARGUMENT_SCHEMAS: Mapping[str, Mapping[str, _ArgumentRule]] = MappingProxyType(
    {
        "set_enabled": _schema(enabled=_BOOL, context_id=_OPTIONAL_IDENTIFIER),
        "register_text_trace": _schema(
            tag=_SHORT_STRING,
            text=_TEXT,
            context_id=_IDENTIFIER,
            metadata=_JSON_OBJECT,
        ),
        "register_trace": _schema(
            tag=_SHORT_STRING,
            embedding=_EMBEDDING,
            context_id=_IDENTIFIER,
            metadata=_JSON_OBJECT,
            source_text=_TEXT,
        ),
        "query_text": _schema(
            prompt=_NONEMPTY_TEXT,
            context_id=_IDENTIFIER,
            steps=_STEPS,
            recall_scope=_RECALL_SCOPE,
        ),
        "query": _schema(
            embedding=_EMBEDDING,
            context_id=_IDENTIFIER,
            steps=_STEPS,
            prompt_text=_TEXT,
            recall_scope=_RECALL_SCOPE,
        ),
        "publish_context_event": _schema(
            context_id=_IDENTIFIER,
            source_surface=_SHORT_STRING,
            event_type=_SHORT_STRING,
            summary=_TEXT,
            payload=_JSON_OBJECT,
            agent_targets=_STRING_LIST,
        ),
        "lease_context_events": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            consumer_instance_id=_IDENTIFIER,
            limit=_rule("int", minimum=1, maximum=500),
            lease_seconds=_LEASE_SECONDS,
        ),
        "ack_context_events": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            acknowledgements=_ACKNOWLEDGEMENTS,
            receipt_id=_IDENTIFIER,
            last_event_id=_rule("int", nullable=True, minimum=0, maximum=10_000_000_000),
        ),
        "release_context_events": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            consumer_instance_id=_IDENTIFIER,
            receipt_ids=_NONEMPTY_STRING_LIST,
        ),
        "dead_letter_context_delivery": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            delivery_id=_NONEMPTY_IDENTIFIER,
            reason=_NONEMPTY_TEXT,
            confirm=_TRUE,
        ),
        "enter_spiking_cortex": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            task=_NONEMPTY_TEXT,
            mode=_CORTEX_MODE,
            recall_mode=_RECALL_MODE,
        ),
        "cortex_tick": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            session_id=_NONEMPTY_IDENTIFIER,
            observation=_TEXT,
            proposed_action=_TEXT,
            intended_files=_INTENT_LIST,
            intended_tools=_INTENT_LIST,
            mutation_intent=_BOOL,
            confidence=_UNIT_INTERVAL,
        ),
        "close_spiking_cortex": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            session_id=_NONEMPTY_IDENTIFIER,
            reason=_SHORT_STRING,
        ),
        "commit_cortical_trace": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            session_id=_IDENTIFIER,
            trace_type=_IDENTIFIER,
            truth_posture=_IDENTIFIER,
            text=_NONEMPTY_TEXT,
            evidence=_JSON_OBJECT,
            confidence=_rule("number", nullable=True, minimum=0.0, maximum=1.0),
        ),
        "reap_orphaned_cortex_sessions": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
        ),
        "attach_client_cortex_session": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            session_id=_NONEMPTY_IDENTIFIER,
            client_bridge_session_id=_NONEMPTY_IDENTIFIER,
            owner_pid=_PID,
            owner_ppid=_PPID,
            owner_started_at=_OPTIONAL_TIMESTAMP,
        ),
        "finish_client_cortex_session": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            session_id=_NONEMPTY_IDENTIFIER,
            client_bridge_session_id=_NONEMPTY_IDENTIFIER,
            reason=_SHORT_STRING,
            finished_at=_OPTIONAL_TIMESTAMP,
        ),
        "create_goal": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            title=_NONEMPTY_TEXT,
            owner=_SHORT_STRING,
            state=_GOAL_STATE,
            next_action=_TEXT,
            evidence=_TEXT,
        ),
        "update_goal": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            goal_id=_IDENTIFIER,
            title=_TEXT,
            owner=_SHORT_STRING,
            state=_GOAL_STATE,
            next_action=_TEXT,
            evidence=_TEXT,
        ),
        "moderate_cortex_trace": _schema(
            context_id=_IDENTIFIER,
            memory_id=_NONEMPTY_IDENTIFIER,
            action=_MODERATION_ACTION,
            reason=_TEXT,
            source_surface=_IDENTIFIER,
            confirm=_BOOL,
        ),
        "hydrate_agent_context": _schema(
            context_id=_IDENTIFIER,
            agent_id=_IDENTIFIER,
            prompt=_TEXT,
            since_event_id=_rule(
                "int",
                nullable=True,
                minimum=0,
                maximum=10_000_000_000,
            ),
            event_limit=_rule("int", minimum=1, maximum=100),
            graph_limit=_rule("int", minimum=1, maximum=200),
            acknowledge=_BOOL,
            claim_events=_BOOL,
            consumer_instance_id=_IDENTIFIER,
            lease_seconds=_LEASE_SECONDS,
            recall_mode=_RECALL_MODE,
        ),
        "ingest_text_events": _schema(
            text=_TEXT,
            context_id=_IDENTIFIER,
            source_tag=_SHORT_STRING,
            surprise_threshold=_UNIT_INTERVAL,
            min_segment_sentences=_INT_POSITIVE,
            metadata=_JSON_OBJECT,
        ),
        "capture_conversation": _schema(
            text=_NONEMPTY_TEXT,
            context_id=_IDENTIFIER,
            source_tag=_SHORT_STRING,
            speaker=_IDENTIFIER,
            surprise_threshold=_UNIT_INTERVAL,
            min_segment_sentences=_INT_POSITIVE,
            metadata=_JSON_OBJECT,
            capture_id=_OPTIONAL_CAPTURE_ID,
        ),
        "replay_capture_operation": _schema(
            capture_id=_CAPTURE_ID,
            context_id=_OPTIONAL_IDENTIFIER,
            source_tag=_OPTIONAL_SHORT_STRING,
            speaker=_OPTIONAL_IDENTIFIER,
        ),
        "prune_memory": _schema(
            context_id=_IDENTIFIER,
            target_type=_PRUNE_TARGET,
            memory_id=_IDENTIFIER,
            tag=_SHORT_STRING,
            relationship_id=_IDENTIFIER,
            event_id=_INT_NONNEGATIVE,
            reason=_TEXT,
            source_surface=_IDENTIFIER,
            publish_audit=_BOOL,
            confirm=_TRUE,
        ),
        "approve_namespace_link": _schema(
            source_context_id=_NONEMPTY_IDENTIFIER,
            target_context_id=_NONEMPTY_IDENTIFIER,
            relation_type=_SHORT_STRING,
            weight=_UNIT_INTERVAL,
            evidence=_JSON_OBJECT,
            direction=_LINK_DIRECTION,
            approved_by=_IDENTIFIER,
            enabled=_BOOL,
            reason=_NONEMPTY_SHORT_STRING,
            link_expires_at=_OPTIONAL_TIMESTAMP,
            governance_request_id=_OPTIONAL_IDENTIFIER,
            confirm=_TRUE,
        ),
        "propose_namespace_link": _schema(
            source_context_id=_NONEMPTY_IDENTIFIER,
            target_context_id=_NONEMPTY_IDENTIFIER,
            relation_type=_SHORT_STRING,
            weight=_UNIT_INTERVAL,
            evidence=_JSON_OBJECT,
            direction=_LINK_DIRECTION,
            proposed_by=_IDENTIFIER,
            reason=_NONEMPTY_SHORT_STRING,
            proposal_expires_at=_OPTIONAL_TIMESTAMP,
            link_expires_at=_OPTIONAL_TIMESTAMP,
            governance_request_id=_OPTIONAL_IDENTIFIER,
        ),
        "review_namespace_link": _schema(
            proposal_id=_NONEMPTY_IDENTIFIER,
            decision=_SHORT_STRING,
            expected_revision=_DIGEST,
            reviewed_by=_IDENTIFIER,
            reason=_NONEMPTY_SHORT_STRING,
            governance_request_id=_OPTIONAL_IDENTIFIER,
        ),
        "disable_namespace_link": _schema(
            context_link_id=_NONEMPTY_IDENTIFIER,
            expected_revision=_DIGEST,
            disabled_by=_IDENTIFIER,
            reason=_NONEMPTY_SHORT_STRING,
            governance_request_id=_OPTIONAL_IDENTIFIER,
            confirm=_TRUE,
        ),
        "revoke_namespace_link": _schema(
            context_link_id=_NONEMPTY_IDENTIFIER,
            expected_revision=_DIGEST,
            revoked_by=_IDENTIFIER,
            reason=_NONEMPTY_SHORT_STRING,
            governance_request_id=_OPTIONAL_IDENTIFIER,
            confirm=_TRUE,
        ),
        "expire_namespace_links": _schema(),
        "delete_namespace_link": _schema(
            context_link_id=_NONEMPTY_IDENTIFIER,
            expected_revision=_DIGEST,
            revoked_by=_IDENTIFIER,
            reason=_NONEMPTY_SHORT_STRING,
            governance_request_id=_OPTIONAL_IDENTIFIER,
            confirm=_TRUE,
        ),
        "repair_semantic_indexes": _schema(
            context_id=_OPTIONAL_IDENTIFIER,
            confirm=_TRUE,
            expected_revision=_DIGEST,
            sample_limit=_SAMPLE_LIMIT,
        ),
        "benchmark_resource_profile": _schema(
            target_min_mb=_RESOURCE_MB,
            target_max_mb=_RESOURCE_MB,
        ),
        "certify_runtime": _schema(
            strict_native=_BOOL,
            require_gpu=_BOOL,
            benchmark_quick_prune=_BOOL,
            require_resource_envelope=_BOOL,
            target_min_mb=_RESOURCE_MB,
            target_max_mb=_RESOURCE_MB,
            output_path=_OPTIONAL_PATH,
        ),
        "export_memory": _schema(
            path=_OPTIONAL_PATH,
            context_id=_OPTIONAL_IDENTIFIER,
            limit=_LIMIT,
        ),
        "backup_memory": _schema(path=_OPTIONAL_PATH),
        "backup_recovery_bundle": _schema(
            path=_OPTIONAL_PATH,
            purpose=_SHORT_STRING,
            pinned=_BOOL,
        ),
        "audit_capture_ledger": _schema(
            sample_limit=_SAMPLE_LIMIT,
        ),
        "repair_capture_ledger": _schema(
            confirm=_TRUE,
            expected_revision=_DIGEST,
            sample_limit=_SAMPLE_LIMIT,
        ),
        "verify_recovery_bundle": _schema(
            receipt_path=_PATH,
            expected_database_sha256=_OPTIONAL_DIGEST,
            expected_capture_sha256=_OPTIONAL_DIGEST,
            expected_request_journal_sha256=_OPTIONAL_DIGEST,
            expected_runtime_state_sha256=_OPTIONAL_DIGEST,
        ),
        "restore_recovery_bundle_isolated": _schema(
            receipt_path=_PATH,
            output_root=_PATH,
            expected_database_sha256=_OPTIONAL_DIGEST,
            expected_capture_sha256=_OPTIONAL_DIGEST,
            expected_request_journal_sha256=_OPTIONAL_DIGEST,
            expected_runtime_state_sha256=_OPTIONAL_DIGEST,
            confirm=_TRUE,
        ),
        "plan_recovery_retention": _schema(
            keep_latest=_rule("int", minimum=1, maximum=10_000),
            max_age_days=_RETENTION_DAYS,
        ),
        "apply_recovery_retention": _schema(
            plan_token=_DIGEST,
            cutoff_created_at=_POSITIVE_TIMESTAMP,
            keep_latest=_rule("int", minimum=1, maximum=10_000),
            max_age_days=_RETENTION_DAYS,
            confirm=_TRUE,
        ),
        "restore_retired_recovery": _schema(plan_token=_DIGEST, confirm=_TRUE),
        "replication_pair_peer": _schema(
            descriptor_path=_PATH,
            expected_descriptor_digest=_DIGEST,
            lineage_id=_REPLICATION_LINEAGE_ID,
            direction=_REPLICATION_DIRECTION,
            confirm=_TRUE,
        ),
        "replication_revoke_peer": _schema(
            peer_id=_REPLICATION_NODE_ID,
            reason=_NONEMPTY_SHORT_STRING,
            confirm=_TRUE,
        ),
        "replication_create_checkpoint": _schema(peer_id=_REPLICATION_NODE_ID),
        "replication_stage_checkpoint": _schema(manifest_path=_PATH),
        "replication_record_acknowledgement": _schema(
            acknowledgement_path=_PATH,
        ),
        "run_quick_pruning": _schema(trigger=_SHORT_STRING),
        "run_idle_maintenance": _schema(force_deep_sleep=_BOOL),
        "run_deep_sleep_consolidation": _schema(trigger=_SHORT_STRING),
    }
)


def _validate_bounded_json_object(value: Any, *, max_root_items: int) -> None:
    if not isinstance(value, dict) or len(value) > max_root_items:
        raise CoreProtocolError()
    remaining_nodes = 4_096
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        remaining_nodes -= 1
        if remaining_nodes < 0 or depth > 8:
            raise CoreProtocolError()
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise CoreProtocolError()
            continue
        if isinstance(current, str):
            if len(current.encode("utf-8")) > 32_768:
                raise CoreProtocolError()
            continue
        if isinstance(current, list):
            if len(current) > 256:
                raise CoreProtocolError()
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if len(current) > 256:
                raise CoreProtocolError()
            for key, item in current.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise CoreProtocolError()
                stack.append((item, depth + 1))
            continue
        raise CoreProtocolError()


def _validate_argument_rule(value: Any, rule: _ArgumentRule) -> None:
    if value is None:
        if rule.nullable:
            return
        raise CoreProtocolError()
    if rule.kind in {"bool", "true"}:
        if not isinstance(value, bool) or (rule.kind == "true" and value is not True):
            raise CoreProtocolError()
        return
    if rule.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise CoreProtocolError()
        numeric = float(value)
    elif rule.kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CoreProtocolError()
        numeric = float(value)
        if not math.isfinite(numeric):
            raise CoreProtocolError()
    else:
        numeric = None
    if numeric is not None:
        if rule.minimum is not None and numeric < rule.minimum:
            raise CoreProtocolError()
        if rule.maximum is not None and numeric > rule.maximum:
            raise CoreProtocolError()
        return
    if rule.kind == "string":
        if not isinstance(value, str):
            raise CoreProtocolError()
        length = len(value.encode("utf-8"))
        if length < rule.min_bytes or length > rule.max_bytes:
            raise CoreProtocolError()
        if rule.allowed_values is not None:
            normalized = value.strip().lower()
            candidates = {
                value,
                normalized,
                normalized.replace("_", "-"),
                normalized.replace("-", "_"),
                normalized.replace(" ", "_"),
            }
            if candidates.isdisjoint(rule.allowed_values):
                raise CoreProtocolError()
        if rule.pattern is not None and rule.pattern.fullmatch(value) is None:
            raise CoreProtocolError()
        return
    if rule.kind == "json_object":
        _validate_bounded_json_object(value, max_root_items=rule.max_items)
        return
    if rule.kind in {"string_list", "number_list"}:
        if not isinstance(value, list):
            raise CoreProtocolError()
        if len(value) < rule.min_items or len(value) > rule.max_items:
            raise CoreProtocolError()
        if rule.kind == "number_list":
            for item in value:
                if (
                    isinstance(item, bool)
                    or not isinstance(item, (int, float))
                    or not math.isfinite(float(item))
                ):
                    raise CoreProtocolError()
        else:
            for item in value:
                if not isinstance(item, str):
                    raise CoreProtocolError()
                length = len(item.encode("utf-8"))
                if length < rule.min_bytes or length > rule.max_bytes:
                    raise CoreProtocolError()
        return
    if rule.kind == "string_or_string_list":
        if isinstance(value, str):
            if len(value.encode("utf-8")) > rule.max_bytes:
                raise CoreProtocolError()
            return
        _validate_argument_rule(
            value,
            _rule(
                "string_list",
                min_items=rule.min_items,
                max_items=rule.max_items,
                min_bytes=rule.min_bytes,
                max_bytes=4_096,
            ),
        )
        return
    if rule.kind == "acknowledgements":
        if not isinstance(value, list) or len(value) > rule.max_items:
            raise CoreProtocolError()
        for acknowledgement in value:
            if not isinstance(acknowledgement, dict) or not 1 <= len(acknowledgement) <= 2:
                raise CoreProtocolError()
            keys = frozenset(acknowledgement)
            if not keys.issubset({"receipt_id", "lease_token"}):
                raise CoreProtocolError()
            for receipt in acknowledgement.values():
                _validate_argument_rule(receipt, _NONEMPTY_IDENTIFIER)
        return
    raise CoreProtocolError()


def _estimated_neural_substrate_bytes(*, dimension: int, num_neurons: int) -> int:
    """Return the exact steady-state float32 dense-topology footprint."""

    return NEURAL_ARRAY_BYTES_PER_ELEMENT * (
        dimension * num_neurons
        + num_neurons * num_neurons
        + (3 * num_neurons)  # membrane, spikes, and active-trace vectors
    )


def _validate_mutation_arguments(
    operation: str,
    arguments: Mapping[str, Any],
    *,
    expected_embedding_dimension: int,
    num_neurons: int,
) -> None:
    schema = MUTATION_ARGUMENT_SCHEMAS.get(operation)
    if schema is None:
        raise CoreProtocolError()
    for key, value in arguments.items():
        rule = schema.get(key)
        if rule is None:
            raise CoreProtocolError()
        _validate_argument_rule(value, rule)

    # Raw embeddings are the only request-controlled path that can resize the
    # sensory projection.  Keep the authoritative embedding space immutable
    # and prove its dense topology fits before journal admission or backend
    # array materialization.  Text embeddings are generated by the closed
    # provider at the configured dimension instead.
    if operation in {"register_trace", "query"}:
        embedding_dimension = len(arguments["embedding"])
        if embedding_dimension != expected_embedding_dimension:
            raise CoreProtocolError()
        if _estimated_neural_substrate_bytes(
            dimension=embedding_dimension,
            num_neurons=num_neurons,
        ) > MAX_NEURAL_MATRIX_BYTES:
            raise CoreProtocolError()

    # Delivery identifiers are normalized by the backend before any store
    # transaction. Credential-shaped identifiers are deliberately rejected at
    # that boundary, so reject the identical input here before journal
    # admission instead of turning a deterministic no-effect failure into an
    # ambiguous mutation outcome.
    if operation in DETERMINISTIC_DELIVERY_REJECTION_OPERATIONS:
        identity_fields = {
            "ack_context_events": (
                "context_id",
                "agent_id",
                "receipt_id",
            ),
            "release_context_events": (
                "context_id",
                "agent_id",
                "consumer_instance_id",
            ),
            "dead_letter_context_delivery": (
                "context_id",
                "agent_id",
                "delivery_id",
            ),
        }[operation]
        identity_values = [
            arguments[field]
            for field in identity_fields
            if arguments.get(field) is not None
        ]
        identity_values.extend(arguments.get("receipt_ids") or [])
        for acknowledgement in arguments.get("acknowledgements") or []:
            identity_values.extend(acknowledgement.values())
        for identity in identity_values:
            try:
                reject_sensitive_identifier(identity, field="delivery identity")
            except ValueError as exc:
                raise CoreProtocolError() from exc

    # Pure cross-field invariants that the backend otherwise discovers only
    # after the mutation has consumed a journal row.
    if operation in {
        "dead_letter_context_delivery",
        "prune_memory",
        "approve_namespace_link",
        "disable_namespace_link",
        "revoke_namespace_link",
        "delete_namespace_link",
        "repair_semantic_indexes",
        "repair_capture_ledger",
        "restore_recovery_bundle_isolated",
        "apply_recovery_retention",
        "restore_retired_recovery",
        "replication_pair_peer",
        "replication_revoke_peer",
    } and arguments.get("confirm") is not True:
        raise CoreProtocolError()
    if operation in {"repair_semantic_indexes", "repair_capture_ledger"}:
        if "expected_revision" not in arguments:
            raise CoreProtocolError()
    if operation == "hydrate_agent_context":
        if arguments.get("acknowledge") is True:
            raise CoreProtocolError()
        if arguments.get("claim_events", True) and arguments.get("since_event_id") is not None:
            raise CoreProtocolError()
    if operation == "moderate_cortex_trace":
        action = str(arguments.get("action") or "").strip().lower().replace("-", "_")
        if action == "prune" and arguments.get("confirm") is not True:
            raise CoreProtocolError()
    if operation == "update_goal":
        if not str(arguments.get("goal_id") or "").strip() and not str(
            arguments.get("title") or ""
        ).strip():
            raise CoreProtocolError()
    if operation == "prune_memory":
        target = str(arguments.get("target_type") or "").strip().lower().replace("-", "_")
        if target in {"memory", "node", "trace", "event"}:
            if not str(arguments.get("memory_id") or "").strip() and not str(
                arguments.get("tag") or ""
            ).strip():
                raise CoreProtocolError()
        elif target in {"relationship", "edge"}:
            if not str(arguments.get("relationship_id") or "").strip():
                raise CoreProtocolError()
        elif target in {"context_event", "deployment", "context_deployment"}:
            if int(arguments.get("event_id") or 0) <= 0:
                raise CoreProtocolError()
    if operation in {"approve_namespace_link", "propose_namespace_link"}:
        if arguments.get("source_context_id") == arguments.get("target_context_id"):
            raise CoreProtocolError()
    if operation == "approve_namespace_link" and arguments.get("enabled", True) is not True:
        raise CoreProtocolError()
    if operation == "review_namespace_link":
        if str(arguments.get("decision") or "").strip().lower() not in {
            "approve",
            "reject",
        }:
            raise CoreProtocolError()
    if operation in {"benchmark_resource_profile", "certify_runtime"}:
        minimum = arguments.get("target_min_mb")
        maximum = arguments.get("target_max_mb")
        if minimum is not None and maximum is not None and float(minimum) > float(maximum):
            raise CoreProtocolError()


_GOVERNANCE_ACTOR_FIELDS: Mapping[str, str] = MappingProxyType(
    {
        "approve_namespace_link": "approved_by",
        "propose_namespace_link": "proposed_by",
        "review_namespace_link": "reviewed_by",
        "disable_namespace_link": "disabled_by",
        "revoke_namespace_link": "revoked_by",
        "delete_namespace_link": "revoked_by",
    }
)


def _bind_authenticated_governance_actor(
    operation: str,
    arguments: Mapping[str, Any],
    *,
    authenticated_principal: str,
) -> dict[str, Any]:
    """Bind bridge actors to OS-verified local ownership, never caller labels."""

    field = _GOVERNANCE_ACTOR_FIELDS.get(operation)
    if field is None:
        return dict(arguments)
    try:
        clean_principal = reject_sensitive_identifier(
            authenticated_principal,
            field="authenticated_principal",
        ).strip()
    except ValueError as exc:
        raise CoreProtocolError() from exc
    if not clean_principal:
        raise CoreProtocolError()
    digest = hashlib.sha256(clean_principal.encode("utf-8")).hexdigest()[:24]
    actor = f"core:local-owner:{digest}"
    bound = dict(arguments)
    bound[field] = actor
    return bound


_MUTATION_CONTRACT_NAMES = frozenset(
    name for name, contract in CORE_OPERATION_CONTRACTS.items() if contract.mutation
)
if frozenset(MUTATION_ARGUMENT_SCHEMAS) != _MUTATION_CONTRACT_NAMES:
    raise RuntimeError("closed mutation argument registry is incomplete")
for _operation_name, _operation_schema in MUTATION_ARGUMENT_SCHEMAS.items():
    if frozenset(_operation_schema) != CORE_OPERATION_CONTRACTS[_operation_name].allowed_arguments:
        raise RuntimeError("closed mutation argument registry does not match its contract")


def _normal_absolute_path(value: Any, *, optional: bool = False) -> Path | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CoreServiceError("invalid_config")
    if contains_secret_shape(value):
        raise CoreServiceError("invalid_config")
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise CoreServiceError("invalid_config")
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CoreServiceError("invalid_config") from exc


def _bounded_int(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CoreServiceError("invalid_config")
    if value < minimum or value > maximum:
        raise CoreServiceError("invalid_config")
    return value


def _bounded_float(value: Any, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CoreServiceError("invalid_config")
    result = float(value)
    if result < minimum or result > maximum or result != result:
        raise CoreServiceError("invalid_config")
    return result


def config_from_wire(value: Any) -> CoreConfig:
    if not isinstance(value, dict) or frozenset(value) != CORE_CONFIG_FIELDS:
        raise CoreServiceError("invalid_config")
    if value["protocol_version"] != CORE_CONFIG_VERSION:
        raise CoreServiceError("invalid_config")
    provider = value["embedding_provider_name"]
    if (
        not isinstance(provider, str)
        or not provider
        or len(provider) > 64
        or contains_secret_shape(provider)
    ):
        raise CoreServiceError("invalid_config")
    provider = provider.strip().lower()
    if provider not in {
        "semantic-hash",
        "semantic-hash-v1",
        "lexical-hash",
        "lexical-hash-v1",
        "mlx-neural",
        "mlx-neural-v1",
    }:
        raise CoreServiceError("invalid_config")
    mlx_device = value["mlx_device"]
    if not isinstance(mlx_device, str) or mlx_device.strip().lower() not in {
        "default",
        "cpu",
        "gpu",
    }:
        raise CoreServiceError("invalid_config")
    mlx_device = mlx_device.strip().lower()
    for boolean_key in (
        "require_native",
        "poll_transcript_sources",
    ):
        if not isinstance(value[boolean_key], bool):
            raise CoreServiceError("invalid_config")
    neural_wire = {
        "model_id": value["embedding_neural_model_id"],
        "revision": value["embedding_neural_revision"],
        "cache_dir": value["embedding_neural_cache_dir"],
        "pooling": value["embedding_neural_pooling"],
        "max_tokens": value["embedding_neural_max_tokens"],
        "normalize": value["embedding_neural_normalize"],
        "local_files_only": value["embedding_neural_local_files_only"],
    }
    neural_config = None
    if provider in {"mlx-neural", "mlx-neural-v1"}:
        if any(item is None for item in neural_wire.values()):
            raise CoreServiceError("invalid_config")
        if value["embedding_neural_local_files_only"] is not True:
            raise CoreServiceError("invalid_config")
        try:
            from embedding_providers import (
                EmbeddingProviderConfig,
                MLXNeuralEmbeddingConfig,
                MLXNeuralEmbeddingProvider,
            )

            validated_provider = MLXNeuralEmbeddingProvider(
                config=MLXNeuralEmbeddingConfig(
                    model_id=value["embedding_neural_model_id"],
                    revision=value["embedding_neural_revision"],
                    cache_dir=value["embedding_neural_cache_dir"],
                    pooling=value["embedding_neural_pooling"],
                    max_tokens=value["embedding_neural_max_tokens"],
                    normalize=value["embedding_neural_normalize"],
                    local_files_only=value["embedding_neural_local_files_only"],
                )
            )
            neural_config = validated_provider.runtime_config
            # Construct the closed wrapper here as a type/contract assertion;
            # backend creation repeats no environment-dependent resolution.
            EmbeddingProviderConfig(provider="mlx-neural", neural=neural_config)
        except Exception as exc:
            raise CoreServiceError("invalid_config") from exc
    elif any(item is not None for item in neural_wire.values()):
        raise CoreServiceError("invalid_config")
    dimension = _bounded_int(value["dimension"], minimum=1, maximum=65_536)
    num_neurons = _bounded_int(
        value["num_neurons"], minimum=1, maximum=131_072
    )
    default_top_k = _bounded_int(
        value["default_top_k"], minimum=1, maximum=65_536
    )
    if default_top_k > num_neurons:
        raise CoreServiceError("invalid_config")
    estimated_neural_matrix_bytes = _estimated_neural_substrate_bytes(
        dimension=dimension,
        num_neurons=num_neurons,
    )
    if estimated_neural_matrix_bytes > MAX_NEURAL_MATRIX_BYTES:
        raise CoreServiceError("invalid_config")
    socket_path = _normal_absolute_path(value["socket_path"])
    state_path = _normal_absolute_path(value["state_path"])
    memory_path = _normal_absolute_path(value["memory_path"])
    capture_root = _normal_absolute_path(value["capture_root"], optional=True)
    assert socket_path is not None
    assert state_path is not None
    assert memory_path is not None
    try:
        socket_path = supported_core_socket_path(
            socket_path,
            memory_path=memory_path,
        )
    except CoreRuntimePathError as exc:
        raise CoreServiceError("invalid_config") from exc
    if state_path != memory_path.parent / "runtime_state.json":
        raise CoreServiceError("invalid_config")
    return CoreConfig(
        socket_path=socket_path,
        state_path=state_path,
        memory_path=memory_path,
        capture_root=capture_root,
        dimension=dimension,
        num_neurons=num_neurons,
        default_top_k=default_top_k,
        recall_count=_bounded_int(value["recall_count"], minimum=1, maximum=10_000),
        quick_pruning_interval_seconds=_bounded_float(
            value["quick_pruning_interval_seconds"], minimum=0.0, maximum=86_400.0
        ),
        idle_deep_sleep_seconds=_bounded_float(
            value["idle_deep_sleep_seconds"], minimum=0.0, maximum=604_800.0
        ),
        embedding_provider_name=provider,
        embedding_neural_model_id=(
            None if neural_config is None else neural_config.model_id
        ),
        embedding_neural_revision=(
            None if neural_config is None else neural_config.revision
        ),
        embedding_neural_cache_dir=(
            None
            if neural_config is None
            else Path(str(neural_config.cache_dir))
        ),
        embedding_neural_pooling=(
            None if neural_config is None else neural_config.pooling
        ),
        embedding_neural_max_tokens=(
            None if neural_config is None else neural_config.max_tokens
        ),
        embedding_neural_normalize=(
            None if neural_config is None else neural_config.normalize
        ),
        embedding_neural_local_files_only=(
            None if neural_config is None else neural_config.local_files_only
        ),
        mlx_device=mlx_device,
        require_native=value["require_native"],
        capture_poll_seconds=_bounded_float(
            value["capture_poll_seconds"], minimum=0.25, maximum=300.0
        ),
        capture_max_files=_bounded_int(
            value["capture_max_files"], minimum=1, maximum=1_000
        ),
        poll_transcript_sources=value["poll_transcript_sources"],
        max_transcript_bytes=_bounded_int(
            value["max_transcript_bytes"], minimum=1_024, maximum=16_777_216
        ),
        max_frame_bytes=validate_max_frame_bytes(value["max_frame_bytes"]),
        authority_timeout_seconds=_bounded_float(
            value["authority_timeout_seconds"], minimum=0.0, maximum=300.0
        ),
    )


def _private_file_bytes(path: Path) -> bytes:
    try:
        parent = path.parent.lstat()
        observed = path.lstat()
    except FileNotFoundError as exc:
        raise CoreServiceError("invalid_config") from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise CoreServiceError("invalid_config")
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise CoreServiceError("invalid_config")
    if (
        observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise CoreServiceError("invalid_config")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (observed.st_dev, observed.st_ino):
            raise CoreServiceError("invalid_config")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > 1_048_576:
                raise CoreServiceError("invalid_config")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_core_config(path: str | os.PathLike[str]) -> CoreConfig:
    config_path = Path(path).expanduser()
    raw = _private_file_bytes(config_path)
    try:
        value = decode_canonical_json(raw)
    except CoreProtocolError as exc:
        raise CoreServiceError("invalid_config") from exc
    return config_from_wire(value)


def _ensure_private_directory(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise CoreServiceError()
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            component_stat = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CoreServiceError("invalid_config") from exc
        if stat.S_ISLNK(component_stat.st_mode):
            # macOS exposes /var as a platform-owned compatibility symlink.
            if current == Path("/var") and os.readlink(current) == "private/var":
                continue
            raise CoreServiceError("invalid_config")
        if current != path and not stat.S_ISDIR(component_stat.st_mode):
            raise CoreServiceError("invalid_config")
    created = False
    try:
        observed = path.lstat()
    except FileNotFoundError:
        if not path.parent.is_dir():
            raise CoreServiceError()
        try:
            path.mkdir(mode=0o700, parents=False)
            created = True
        except FileExistsError:
            pass
        observed = path.lstat()
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
    ):
        raise CoreServiceError("invalid_config")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise CoreServiceError("invalid_config")
        if created:
            # The runtime may tighten only the leaf it atomically created.
            # Existing configured paths are caller-owned inputs and must never
            # be silently chmodded into compliance.
            os.fchmod(descriptor, 0o700)
            opened = os.fstat(descriptor)
        if stat.S_IMODE(opened.st_mode) != 0o700:
            raise CoreServiceError("invalid_config")
        visible = path.lstat()
        if (
            stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISDIR(visible.st_mode)
            or visible.st_uid != os.getuid()
            or stat.S_IMODE(visible.st_mode) != 0o700
            or (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise CoreServiceError("invalid_config")
    finally:
        os.close(descriptor)


def write_core_config(path: str | os.PathLike[str], config: CoreConfig) -> Path:
    config_path = Path(path).expanduser()
    _ensure_private_directory(config_path.parent)
    payload = canonical_json_bytes(config.to_wire())
    lock_path = config_path.with_name(f".{config_path.name}.lock")
    lock_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_created = False
    try:
        lock_descriptor = os.open(
            lock_path,
            lock_flags | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        lock_created = True
    except FileExistsError:
        try:
            lock_descriptor = os.open(lock_path, lock_flags)
        except OSError as exc:
            raise CoreServiceError("invalid_config") from exc
    try:
        lock_identity = os.fstat(lock_descriptor)
        if lock_created:
            os.fchmod(lock_descriptor, 0o600)
            lock_identity = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_identity.st_mode)
            or lock_identity.st_uid != os.getuid()
            or lock_identity.st_nlink != 1
            or stat.S_IMODE(lock_identity.st_mode) != 0o600
        ):
            raise CoreServiceError("invalid_config")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        visible_lock = lock_path.lstat()
        if (
            stat.S_ISLNK(visible_lock.st_mode)
            or not stat.S_ISREG(visible_lock.st_mode)
            or visible_lock.st_uid != os.getuid()
            or visible_lock.st_nlink != 1
            or stat.S_IMODE(visible_lock.st_mode) != 0o600
            or (visible_lock.st_dev, visible_lock.st_ino)
            != (lock_identity.st_dev, lock_identity.st_ino)
        ):
            raise CoreServiceError("invalid_config")
        try:
            existing = config_path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            stat.S_ISLNK(existing.st_mode)
            or not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.getuid()
            or existing.st_nlink != 1
            or stat.S_IMODE(existing.st_mode) != 0o600
        ):
            raise CoreServiceError("invalid_config")
        temporary = config_path.with_name(
            f".{config_path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        )
        try:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(temporary, flags, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise CoreServiceError("invalid_config")
                    view = view[written:]
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o600)
                staged = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            try:
                current = config_path.lstat()
            except FileNotFoundError:
                current = None
            if existing is None:
                if current is not None:
                    raise CoreServiceError("invalid_config")
            elif current is None or (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino)
                != (existing.st_dev, existing.st_ino)
            ):
                raise CoreServiceError("invalid_config")
            os.replace(temporary, config_path)
            published = config_path.lstat()
            if (
                stat.S_ISLNK(published.st_mode)
                or not stat.S_ISREG(published.st_mode)
                or published.st_uid != os.getuid()
                or published.st_nlink != 1
                or stat.S_IMODE(published.st_mode) != 0o600
                or (published.st_dev, published.st_ino)
                != (staged.st_dev, staged.st_ino)
            ):
                raise CoreServiceError("invalid_config")
            if _private_file_bytes(config_path) != payload:
                raise CoreServiceError("invalid_config")
            directory_fd = os.open(
                config_path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)
    return config_path


def _token_path(socket_path: Path) -> Path:
    return socket_path.with_suffix(socket_path.suffix + ".token")


def _fsync_directory_strict(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _repair_atomic_link_orphan(
    path: Path,
    observed: os.stat_result,
) -> os.stat_result:
    """Remove one proven crash-left temporary hardlink in a private core dir."""

    if observed.st_nlink == 1:
        return observed
    if (
        observed.st_nlink != 2
        or stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise CoreServiceError("service_unavailable")
    prefix = f".{path.name}.tmp-"
    matches: list[Path] = []
    try:
        candidates = tuple(path.parent.iterdir())
    except OSError as exc:
        raise CoreServiceError("service_unavailable") from exc
    for candidate in candidates:
        if not candidate.name.startswith(prefix):
            continue
        suffix = candidate.name[len(prefix) :]
        if re.fullmatch(r"[0-9]+-[0-9a-f]{12}", suffix) is None:
            continue
        try:
            candidate_stat = candidate.lstat()
        except OSError:
            continue
        if (
            not stat.S_ISLNK(candidate_stat.st_mode)
            and stat.S_ISREG(candidate_stat.st_mode)
            and candidate_stat.st_uid == os.getuid()
            and stat.S_IMODE(candidate_stat.st_mode) == 0o600
            and candidate_stat.st_nlink == 2
            and (candidate_stat.st_dev, candidate_stat.st_ino)
            == (observed.st_dev, observed.st_ino)
        ):
            matches.append(candidate)
    if len(matches) != 1:
        raise CoreServiceError("service_unavailable")
    matches[0].unlink()
    _fsync_directory_strict(path.parent)
    repaired = path.lstat()
    if (
        repaired.st_nlink != 1
        or (repaired.st_dev, repaired.st_ino)
        != (observed.st_dev, observed.st_ino)
    ):
        raise CoreServiceError("service_unavailable")
    return repaired


def _load_or_create_authentication_key(path: Path) -> bytes:
    try:
        observed = path.lstat()
    except FileNotFoundError:
        raw = secrets.token_bytes(32)
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(raw.hex().encode("ascii"))
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CoreServiceError("service_unavailable")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            pass
        finally:
            temporary.unlink()
        _fsync_directory_strict(path.parent)
        observed = path.lstat()
    observed = _repair_atomic_link_orphan(path, observed)
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise CoreServiceError()
    if (
        observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise CoreServiceError()
    raw_text = _private_file_bytes(path)
    try:
        raw = bytes.fromhex(raw_text.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise CoreServiceError() from exc
    if len(raw) != 32:
        raise CoreServiceError()
    return raw


def _load_or_create_store_generation(
    path: Path,
    *,
    store_identity: str,
) -> str:
    """Publish or verify the immutable root-generation sentinel.

    Publication deliberately precedes database creation. If the process dies
    after this receipt is durable but before SQLite exists, the next startup
    fails closed instead of treating a previously initialized deployment as a
    brand-new empty store.
    """

    if not re.fullmatch(r"store-[0-9a-f]{24}", store_identity):
        raise CoreServiceError("service_unavailable")
    payload: dict[str, Any] | None = None
    try:
        path.lstat()
    except FileNotFoundError:
        payload = {
            "schema": STORE_GENERATION_SCHEMA,
            "root_generation_id": f"generation-{secrets.token_hex(12)}",
            "store_identity": store_identity,
        }
        encoded = canonical_json_bytes(payload)
        temporary = path.with_name(
            f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        )
        descriptor = -1
        try:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(temporary, flags, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CoreServiceError("service_unavailable")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
            staged = os.fstat(descriptor)
            if (
                not stat.S_ISREG(staged.st_mode)
                or staged.st_uid != os.getuid()
                or staged.st_nlink != 1
                or stat.S_IMODE(staged.st_mode) != 0o600
            ):
                raise CoreServiceError("service_unavailable")
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                pass
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            raise CoreServiceError("service_unavailable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        _fsync_directory_strict(path.parent)

    try:
        observed_stat = _repair_atomic_link_orphan(path, path.lstat())
        if observed_stat.st_nlink != 1:
            raise CoreServiceError("service_unavailable")
        raw = _private_file_bytes(path)
        observed = decode_canonical_json(raw)
    except (CoreServiceError, CoreProtocolError, OSError) as exc:
        raise CoreServiceError("service_unavailable") from exc
    if (
        not isinstance(observed, dict)
        or set(observed)
        != {"schema", "root_generation_id", "store_identity"}
        or observed.get("schema") != STORE_GENERATION_SCHEMA
        or STORE_GENERATION_ID_RE.fullmatch(
            str(observed.get("root_generation_id") or "")
        )
        is None
        or not secrets.compare_digest(
            str(observed.get("store_identity") or ""),
            store_identity,
        )
    ):
        raise CoreServiceError("service_unavailable")
    if payload is not None and observed != payload:
        # A concurrently published identity is never silently adopted. The
        # authority lock should make this unreachable, so fail closed.
        raise CoreServiceError("service_unavailable")
    return str(observed["root_generation_id"])


def _manifest_build_id(source_root: Path) -> str:
    digest = hashlib.sha256()
    for filename in BUILD_SOURCE_MANIFEST:
        source = source_root / filename
        try:
            payload = source.read_bytes()
        except OSError as exc:
            raise CoreServiceError("service_unavailable") from exc
        encoded_name = filename.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return f"source-{digest.hexdigest()[:24]}"


def _source_build_id() -> str:
    computed = _manifest_build_id(Path(__file__).resolve().parent)
    configured = os.getenv("SYNAPSE_S2_BUILD_ID", "").strip()
    if not configured:
        return computed
    if (
        len(configured) > 96
        or contains_secret_shape(configured)
        or any(
            not (character.isalnum() or character in "._:-")
            for character in configured
        )
        or configured != computed
    ):
        raise CoreServiceError("service_unavailable")
    return computed


def _sqlite_schema_identity(path: Path) -> str:
    try:
        uri = f"file:{path.resolve()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=1.0)
        try:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        finally:
            connection.close()
    except (OSError, sqlite3.Error, TypeError, ValueError):
        application_id = 0
        user_version = 0
    return f"sqlite-{application_id:x}-v{user_version}"


def _store_identity(path: Path) -> str:
    return f"store-{hashlib.sha256(str(path.resolve()).encode('utf-8')).hexdigest()[:24]}"


def _bind_default_backend_handlers(backend: Any) -> dict[str, Callable[..., Any]]:
    """Bind a static operation table; request data never controls attribute access."""

    static_method_names = {
        name: "resource_profile" if name == "benchmark_resource_profile" else name
        for name in CORE_OPERATION_CONTRACTS
        if name not in (SERVICE_CONTROL_OPERATIONS | REPLICATION_OPERATIONS)
    }
    handlers: dict[str, Callable[..., Any]] = {}
    missing: list[str] = []
    for operation, method_name in static_method_names.items():
        # method_name is sourced only from the closed module constant above.
        handler = getattr(backend, method_name, None)
        if callable(handler):
            if operation == "benchmark_resource_profile":
                handlers[operation] = lambda _handler=handler, **arguments: _handler(
                    benchmark_quick_prune=True,
                    **arguments,
                )
            else:
                handlers[operation] = handler
        else:
            missing.append(operation)
    if missing:
        raise CoreServiceError("operation_unavailable")
    return handlers


def _bind_replication_handlers(manager: Any) -> dict[str, Callable[..., Any]]:
    """Bind the closed offline-replication API to one core-owned manager."""

    def pair_peer(
        *,
        descriptor_path: str,
        expected_descriptor_digest: str,
        lineage_id: str,
        direction: str,
        confirm: bool,
    ) -> dict[str, Any]:
        return manager.pair_peer(
            descriptor_path,
            expected_descriptor_digest=expected_descriptor_digest,
            lineage_id=lineage_id,
            direction=direction,
            confirm=confirm,
        )

    return {
        "replication_identity": manager.node_descriptor,
        "replication_status": manager.status,
        "replication_pair_peer": pair_peer,
        "replication_revoke_peer": (
            lambda *, peer_id, reason, confirm: manager.revoke_peer(
                peer_id,
                reason=reason,
                confirm=confirm,
            )
        ),
        "replication_create_checkpoint": (
            lambda *, peer_id: manager.create_checkpoint(peer_id)
        ),
        "replication_stage_checkpoint": (
            lambda *, manifest_path: manager.stage_checkpoint(manifest_path)
        ),
        "replication_record_acknowledgement": (
            lambda *, acknowledgement_path: manager.record_acknowledgement(
                acknowledgement_path
            )
        ),
    }


def _read_authorized_replication_json(
    authorization: AuthorizedPath,
    *,
    maximum_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    """Read one already-authorized private file through its pinned vnode."""

    descriptor = authorization.duplicate_target_fd()
    try:
        before = os.fstat(descriptor)
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise CoreProtocolError("invalid_request")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum_bytes:
                raise CoreProtocolError("invalid_request")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CoreProtocolError("invalid_request")
    except (OSError, ValueError, OverflowError) as exc:
        raise CoreProtocolError("invalid_request") from exc
    finally:
        os.close(descriptor)

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CoreProtocolError("invalid_request")
            value[key] = item
        return value

    try:
        decoded = json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CoreProtocolError("invalid_request")
            ),
        )
        if not isinstance(decoded, dict):
            raise CoreProtocolError("invalid_request")
        canonical_json_bytes(decoded)
    except CoreProtocolError:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise CoreProtocolError("invalid_request") from exc
    return decoded


class AuthoritativeCoreService:
    """One fenced backend behind a private, bounded Unix-domain RPC service."""

    def __init__(
        self,
        config: CoreConfig,
        *,
        backend_factory: Callable[[CoreAuthorityLease], Any] | None = None,
        operation_handlers_factory: (
            Callable[[Any], Mapping[str, Callable[..., Any]]] | None
        ) = None,
        operation_contracts: Mapping[str, OperationContract] | None = None,
        capture_worker_factory: Callable[[Any, Path], Any] | None = None,
    ) -> None:
        self.config = config_from_wire(config.to_wire())
        self._backend_factory = backend_factory or self._default_backend_factory
        self._operation_handlers_factory = (
            operation_handlers_factory or _bind_default_backend_handlers
        )
        self._contracts = dict(operation_contracts or CORE_OPERATION_CONTRACTS)
        if "health" not in self._contracts:
            raise CoreServiceError("operation_unavailable")
        for operation, contract in self._contracts.items():
            if not contract.mutation:
                continue
            schema = MUTATION_ARGUMENT_SCHEMAS.get(operation)
            if schema is None or frozenset(schema) != contract.allowed_arguments:
                raise CoreServiceError("operation_unavailable")
        self._capture_worker_factory = capture_worker_factory
        self._authority_lease: CoreAuthorityLease | None = None
        self._backend: Any = None
        self._handlers: dict[str, Callable[..., Any]] = {}
        self._authentication_key: bytes | None = None
        self._listener: socket.socket | None = None
        self._bound_socket_identity: tuple[int, int] | None = None
        self._start_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._started_event = threading.Event()
        self._backend_lane = threading.Lock()
        self._backend_lane_state_lock = threading.Lock()
        self._backend_lane_owner: str | None = None
        self._backend_lane_started_monotonic: float | None = None
        self._backend_lane_deadline_monotonic: float | None = None
        self._poisoned_reason: str | None = None
        self._sequence_lock = threading.Lock()
        self._operation_sequence = 0
        self._connection_slots = threading.BoundedSemaphore(MAX_ACTIVE_CONNECTIONS)
        self._workers_lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self._request_cache_lock = threading.Lock()
        self._request_cache: OrderedDict[
            tuple[str, str], tuple[str, dict[str, Any], int]
        ] = OrderedDict()
        self._request_cache_bytes = 0
        self._request_journal: CoreRequestJournal | None = None
        self._path_policy: CorePathPolicy | None = None
        self._replication_manager: Any = None
        self._capture_thread: threading.Thread | None = None
        self._capture_worker: Any = None
        self._capture_activation_event = threading.Event()
        self._root_generation_id: str | None = None
        self._capture_heartbeat_lock = threading.Lock()
        self._capture_heartbeat: dict[str, Any] = {
            "enabled": self.config.capture_root is not None,
            "ready": self.config.capture_root is None,
            "iteration_count": 0,
            "processed_count": 0,
            "error_count": 0,
            "last_success_unix_ms": 0,
            "last_error_code": None,
        }
        self._build_id = _source_build_id()
        self._deployment_mode = AUTHORITATIVE_DEPLOYMENT_MODE
        self._replacement_admission_receipt_digest: str | None = None
        self._replacement_admission_expires_at_unix_ms: int | None = None
        self._replacement_admission_deadline_monotonic: float | None = None
        self._close_lock = threading.Lock()
        self._shutdown_teardown_thread: threading.Thread | None = None
        self._shutdown_teardown_complete = threading.Event()
        self._shutdown_teardown_succeeded = False
        self._startup_stage = "initial_validation"
        self._startup_store_state = "unknown"
        self._startup_journal_state = "absent"
        self._identity: dict[str, str] = {
            "authority_id": f"core-{uuid.uuid4().hex}",
            "neural_epoch": f"epoch-{uuid.uuid4().hex}",
            "config_fingerprint": self.config.fingerprint,
            "build_id": self._build_id,
            "store_identity": _store_identity(self.config.memory_path),
            "schema_identity": "sqlite-0-v0",
        }

    @property
    def identity(self) -> dict[str, str]:
        return dict(self._identity)

    @property
    def socket_path(self) -> Path:
        return self.config.socket_path

    def _fence_service(self, reason: str) -> None:
        """Make a poisoned authority unreachable without releasing its lease.

        A lost filesystem/database fence or a writer that has exceeded its
        bounded lane may still be executing.  Closing the listener and setting
        the stop flag makes the process fail closed; cleanup deliberately keeps
        the lease until the lane is proven quiescent or the supervisor ends the
        process.
        """

        with self._backend_lane_state_lock:
            if self._poisoned_reason is None:
                self._poisoned_reason = reason
        self._stop_event.set()
        self._capture_activation_event.set()
        with self._capture_heartbeat_lock:
            self._capture_heartbeat.update(
                {"ready": False, "last_error_code": "service_unavailable"}
            )
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    def _assert_live_authority(self) -> None:
        authority = self._authority_lease
        try:
            with self._backend_lane_state_lock:
                poisoned = self._poisoned_reason
            if poisoned is not None:
                raise CoreAuthorityError("authoritative core process is poisoned")
            if authority is None:
                raise CoreAuthorityError("authoritative core lease is unavailable")
            if self._deployment_mode == REPLACEMENT_CERTIFICATION_MODE:
                expires_at = self._replacement_admission_expires_at_unix_ms
                deadline = self._replacement_admission_deadline_monotonic
                if (
                    type(expires_at) is not int
                    or not isinstance(deadline, float)
                    or not math.isfinite(deadline)
                    or int(time.time() * 1000) >= expires_at
                    or time.monotonic() >= deadline
                ):
                    raise CoreAuthorityError(
                        "replacement admission expired before certification"
                    )
            authority.assert_core_for(self.config.memory_path)
            if (
                type(authority.durable_epoch) is not int
                or authority.durable_epoch <= 0
                or self._identity["neural_epoch"]
                != f"epoch-{authority.durable_epoch}"
                or authority.config_fingerprint != self.config.fingerprint
                or authority.build_id != self._build_id
                or authority.protocol_version != PROTOCOL_VERSION
            ):
                raise CoreAuthorityError(
                    "authoritative core durable fence is unavailable"
                )
            store = getattr(self._backend, "memory_store", None)
            assert_store_authority = getattr(
                store,
                "assert_active_authority",
                None,
            )
            if not callable(assert_store_authority):
                raise CoreAuthorityError(
                    "authoritative memory store fence is unavailable"
                )
            assert_store_authority()
        except (CoreAuthorityError, OSError, sqlite3.Error):
            self._fence_service("authority_lost")
            raise CoreServiceError("service_unavailable") from None

    def _authority_ready(self) -> bool:
        try:
            self._assert_live_authority()
        except CoreServiceError:
            return False
        return True

    def _acquire_backend_lane(
        self,
        *,
        owner: str,
        timeout: float | None,
        deadline_monotonic: float,
    ) -> bool:
        acquired = (
            self._backend_lane.acquire()
            if timeout is None
            else self._backend_lane.acquire(timeout=max(0.0, timeout))
        )
        if not acquired:
            return False
        with self._backend_lane_state_lock:
            self._backend_lane_owner = owner
            self._backend_lane_started_monotonic = time.monotonic()
            self._backend_lane_deadline_monotonic = deadline_monotonic
        return True

    @contextmanager
    def _backend_execution_context(self) -> Any:
        backend = self._backend
        execution_context = getattr(backend, "execution_context", None)
        if not callable(execution_context):
            yield
            return
        with execution_context():
            yield

    def _backend_lane_timeout_floor(self, operation: str) -> float:
        if operation in LONG_RECOVERY_OPERATIONS:
            return RECOVERY_MAINTENANCE_LANE_SECONDS
        if operation in LONG_SEMANTIC_INDEX_OPERATIONS:
            return SEMANTIC_INDEX_MAINTENANCE_LANE_SECONDS
        if operation in LONG_NEURAL_OPERATIONS:
            return NEURAL_OPERATION_LANE_SECONDS
        return BACKEND_LANE_RPC_TIMEOUT_SECONDS

    @staticmethod
    def _backend_lane_acquire_timeout(
        operation: str,
        remaining_seconds: float,
    ) -> float:
        """Keep the long recovery execution budget out of the worker queue."""

        if operation in LONG_RECOVERY_OPERATIONS:
            return min(
                remaining_seconds,
                RECOVERY_MAINTENANCE_QUEUE_SECONDS,
            )
        return remaining_seconds

    def _release_backend_lane(self) -> None:
        with self._backend_lane_state_lock:
            self._backend_lane_owner = None
            self._backend_lane_started_monotonic = None
            self._backend_lane_deadline_monotonic = None
        self._backend_lane.release()

    def _backend_lane_health(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._backend_lane_state_lock:
            owner = self._backend_lane_owner
            started = self._backend_lane_started_monotonic
            deadline = self._backend_lane_deadline_monotonic
            poisoned = self._poisoned_reason
        stale = bool(
            owner is not None
            and deadline is not None
            and now > deadline
        )
        if stale:
            self._fence_service("backend_lane_stalled")
            poisoned = "backend_lane_stalled"
        maintenance = owner in {
            "recovery-maintenance",
            "replication-maintenance",
            "semantic-index-maintenance",
        }
        return {
            "ready": not stale and poisoned is None,
            "active": owner is not None,
            "owner": owner,
            "maintenance": maintenance,
            "degraded": maintenance or stale or poisoned is not None,
            "accepting_ordinary_operations": (
                owner is None and not stale and poisoned is None
            ),
            "active_age_ms": (
                None
                if owner is None or started is None
                else max(0, int((now - started) * 1000))
            ),
            "deadline_remaining_ms": (
                None
                if owner is None or deadline is None
                else max(0, int((deadline - now) * 1000))
            ),
            "blocker": poisoned,
        }

    def _default_backend_factory(self, authority_lease: CoreAuthorityLease) -> Any:
        from embedding_providers import (
            EmbeddingProviderConfig,
            MLXNeuralEmbeddingConfig,
        )
        inherited_mlx_device = os.getenv("MLX_DEVICE", "default").strip().lower()
        if inherited_mlx_device != self.config.mlx_device:
            raise CoreServiceError("service_unavailable")
        from mlx_backend import SpikingAttentionBackend

        neural = None
        if self.config.embedding_provider_name in {"mlx-neural", "mlx-neural-v1"}:
            assert self.config.embedding_neural_model_id is not None
            assert self.config.embedding_neural_revision is not None
            assert self.config.embedding_neural_cache_dir is not None
            assert self.config.embedding_neural_pooling is not None
            assert self.config.embedding_neural_max_tokens is not None
            assert self.config.embedding_neural_normalize is not None
            assert self.config.embedding_neural_local_files_only is not None
            neural = MLXNeuralEmbeddingConfig(
                model_id=self.config.embedding_neural_model_id,
                revision=self.config.embedding_neural_revision,
                cache_dir=str(self.config.embedding_neural_cache_dir),
                pooling=self.config.embedding_neural_pooling,
                max_tokens=self.config.embedding_neural_max_tokens,
                normalize=self.config.embedding_neural_normalize,
                local_files_only=self.config.embedding_neural_local_files_only,
            )

        backend = SpikingAttentionBackend(
            dimension=self.config.dimension,
            num_neurons=self.config.num_neurons,
            default_top_k=self.config.default_top_k,
            recall_count=self.config.recall_count,
            quick_pruning_interval_seconds=self.config.quick_pruning_interval_seconds,
            idle_deep_sleep_seconds=self.config.idle_deep_sleep_seconds,
            state_path=self.config.state_path,
            memory_path=self.config.memory_path,
            embedding_provider_config=EmbeddingProviderConfig(
                provider=self.config.embedding_provider_name,
                neural=neural,
            ),
            require_native=self.config.require_native,
            control_plane_only=False,
            authority_lease=authority_lease,
        )
        if neural is not None:
            try:
                probe = backend.embedding_provider.embed(
                    "synapse-s2 authoritative provider readiness",
                    dimensions=min(8, self.config.dimension),
                )
                if (
                    len(probe.vector) != min(8, self.config.dimension)
                    or not all(
                        isinstance(value, (int, float))
                        and not isinstance(value, bool)
                        and float("-inf") < float(value) < float("inf")
                        for value in probe.vector
                    )
                    or probe.provenance.get("native_mlx") is not True
                ):
                    raise CoreServiceError("service_unavailable")
            except Exception as exc:
                try:
                    backend.close()
                except Exception:
                    pass
                raise CoreServiceError("service_unavailable") from exc
        return backend

    def _claim_durable_authority(
        self,
        *,
        inspection: Mapping[str, Any] | None,
        journal_binding: Mapping[str, Any],
        attestation: Mapping[str, Any] | None,
    ) -> None:
        store = getattr(self._backend, "memory_store", None)
        if store is None:
            raise CoreServiceError("service_unavailable")
        claim_method = getattr(store, "claim_core_authority", None)
        if not callable(claim_method):
            raise CoreServiceError("service_unavailable")
        if inspection is None:
            raise CoreServiceError("service_unavailable")
        logical_snapshot = inspection.get("logical_snapshot")
        if not isinstance(logical_snapshot, dict):
            raise CoreServiceError("service_unavailable")
        claim = claim_method(
            instance_id=self._identity["authority_id"],
            config_fingerprint=self.config.fingerprint,
            build_id=self._build_id,
            protocol_version=PROTOCOL_VERSION,
            expected_store_identity=str(inspection["store_identity"]),
            request_journal_id=str(journal_binding["journal_id"]),
            request_journal_binding_schema=str(journal_binding["schema"]),
            request_journal_schema_version=int(
                journal_binding["journal_schema_version"]
            ),
            expected_preclaim_logical_snapshot_sha256=str(
                logical_snapshot["sha256"]
            ),
            expected_previous_epoch=int(inspection["previous_epoch"]),
            expected_next_epoch=int(inspection["next_epoch"]),
            root_generation_id=str(self._root_generation_id or ""),
            embedding_space_identity=self.config.embedding_space_identity,
            attestation_receipt_digest=(
                None
                if attestation is None
                else str(attestation["receipt_digest"])
            ),
            restored_target_binding_receipt_digest=(
                None
                if attestation is None
                else attestation.get(
                    "restored_target_binding_receipt_digest"
                )
            ),
            attestation_expires_at_unix_ms=(
                None
                if attestation is None
                else int(attestation["expires_at_unix_ms"])
            ),
        )
        expected_claim_keys = {
            "schema_version",
            "service_required",
            "epoch",
            "instance_id",
            "config_fingerprint",
            "build_id",
            "protocol_version",
            "lock_generation_id",
            "store_identity",
            "request_journal_id",
            "request_journal_binding_schema",
            "request_journal_schema_version",
            "root_generation_id",
            "embedding_space_identity",
            "restored_target_binding_receipt_digest",
            "claimed_at",
            "updated_at",
            "authority_epoch",
            "neural_epoch",
            "authority_epoch_number",
            "schema_identity",
        }
        if not isinstance(claim, dict) or set(claim) != expected_claim_keys:
            raise CoreServiceError("service_unavailable")
        expected_epoch_number = int(inspection["next_epoch"])
        expected_epoch = f"epoch-{expected_epoch_number}"
        inspected_marker = inspection.get("marker")
        existing_restored_digest = (
            None
            if not isinstance(inspected_marker, Mapping)
            else inspected_marker.get(
                "restored_target_binding_receipt_digest"
            )
        )
        attested_restored_digest = (
            None
            if attestation is None
            else attestation.get("restored_target_binding_receipt_digest")
        )
        expected_restored_digest = (
            attested_restored_digest
            if attested_restored_digest is not None
            else existing_restored_digest
        )
        expected_values = {
            "schema_version": CORE_AUTHORITY_SCHEMA_VERSION,
            "service_required": True,
            "epoch": expected_epoch_number,
            "instance_id": self._identity["authority_id"],
            "config_fingerprint": self.config.fingerprint,
            "build_id": self._build_id,
            "protocol_version": PROTOCOL_VERSION,
            "lock_generation_id": (
                self._authority_lease.lock_generation_id
                if self._authority_lease is not None
                else None
            ),
            "store_identity": str(inspection["store_identity"]),
            "request_journal_id": str(journal_binding["journal_id"]),
            "request_journal_binding_schema": JOURNAL_BINDING_SCHEMA,
            "request_journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "root_generation_id": str(self._root_generation_id or ""),
            "embedding_space_identity": self.config.embedding_space_identity,
            "restored_target_binding_receipt_digest": expected_restored_digest,
            "authority_epoch": expected_epoch,
            "neural_epoch": expected_epoch,
            "authority_epoch_number": expected_epoch_number,
            "schema_identity": CORE_STORE_SCHEMA_IDENTITY,
        }
        if (
            claim.get("service_required") is not True
            or any(
                type(claim.get(key)) is not int
                for key in (
                    "schema_version",
                    "epoch",
                    "request_journal_schema_version",
                    "authority_epoch_number",
                )
            )
            or any(claim.get(key) != value for key, value in expected_values.items())
        ):
            raise CoreServiceError("service_unavailable")
        for timestamp_key in ("claimed_at", "updated_at"):
            timestamp = claim.get(timestamp_key)
            if (
                not isinstance(timestamp, (int, float))
                or isinstance(timestamp, bool)
                or not math.isfinite(float(timestamp))
                or float(timestamp) <= 0.0
            ):
                raise CoreServiceError("service_unavailable")
        if float(claim["claimed_at"]) > float(claim["updated_at"]):
            raise CoreServiceError("service_unavailable")
        authority = self._authority_lease
        if (
            authority is None
            or authority.durable_epoch != expected_epoch_number
            or authority.config_fingerprint != self.config.fingerprint
            or authority.build_id != self._build_id
            or authority.protocol_version != PROTOCOL_VERSION
        ):
            raise CoreServiceError("service_unavailable")
        authority.assert_core_for(self.config.memory_path)
        self._identity["neural_epoch"] = expected_epoch
        self._identity["store_identity"] = str(claim["store_identity"])
        self._identity["schema_identity"] = str(claim["schema_identity"])

    @staticmethod
    def _cutover_attestation_expectations(path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(_private_file_bytes(path).decode("utf-8"))
        except (CoreServiceError, UnicodeError, ValueError, TypeError) as exc:
            raise CoreServiceError("service_unavailable") from exc
        if not isinstance(payload, dict):
            raise CoreServiceError("service_unavailable")
        evidence_manifest = _normal_absolute_path(
            payload.get("evidence_manifest_path")
        )
        git_head = payload.get("git_head")
        evidence_sha256 = payload.get("evidence_manifest_sha256")
        if (
            not isinstance(git_head, str)
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", git_head) is None
            or not isinstance(evidence_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None
        ):
            raise CoreServiceError("service_unavailable")
        assert evidence_manifest is not None
        return {
            "evidence_manifest": evidence_manifest,
            "git_head": git_head,
            "evidence_manifest_sha256": evidence_sha256,
        }

    def _verify_required_cutover_attestation(
        self,
        *,
        inspection: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self.config.capture_root is None:
            raise CoreServiceError("service_unavailable")
        attestation_path = (
            self.config.memory_path.parent / "core" / "cutover-attestation.json"
        )
        expected = self._cutover_attestation_expectations(attestation_path)
        try:
            from scripts.core_cutover_preflight import (
                verify_cutover_attestation_for_core,
            )

            verification = verify_cutover_attestation_for_core(
                root=Path(__file__).resolve().parent,
                memory_db=self.config.memory_path,
                capture_root=self.config.capture_root,
                attestation_path=attestation_path,
                evidence_manifest=expected["evidence_manifest"],
                expected_build_id=self._build_id,
                expected_config_fingerprint=self.config.fingerprint,
                expected_git_head=expected["git_head"],
                expected_evidence_manifest_sha256=expected[
                    "evidence_manifest_sha256"
                ],
                minimum_remaining_seconds=CUTOVER_MINIMUM_REMAINING_SECONDS,
            )
        except Exception as exc:
            raise CoreServiceError("service_unavailable") from exc
        logical_snapshot = inspection["logical_snapshot"]
        marker = inspection.get("marker")
        expected_epoch = None if marker is None else int(marker["epoch"])
        if (
            not isinstance(verification, dict)
            or verification.get("verified") is not True
            or verification.get("build_id") != self._build_id
            or verification.get("config_fingerprint") != self.config.fingerprint
            or verification.get("governance_mode")
            != inspection["governance_mode"]
            or verification.get("store_identity") != inspection["store_identity"]
            or verification.get("authority_epoch_number") != expected_epoch
            or verification.get("database_schema_identity")
            != inspection["schema_identity"]
            or verification.get("database_logical_snapshot_schema")
            != logical_snapshot["schema"]
            or not secrets.compare_digest(
                str(verification.get("database_logical_snapshot_sha256") or ""),
                str(logical_snapshot["sha256"]),
            )
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(verification.get("receipt_digest") or ""),
            )
            is None
            or type(verification.get("expires_at_unix_ms")) is not int
            or int(verification["expires_at_unix_ms"])
            <= int(time.time() * 1000)
            + CUTOVER_COMMIT_SAFETY_MARGIN_MS
        ):
            raise CoreServiceError("service_unavailable")
        return dict(verification)

    @staticmethod
    def _replacement_admission_requested() -> bool:
        """Recognize only the installer-owned provisional launch signal."""

        configured = os.getenv(REPLACEMENT_ADMISSION_ENV)
        if configured is None:
            return False
        if configured != "1":
            raise CoreServiceError("service_unavailable")
        return True

    @staticmethod
    def _replacement_certification_pending(
        marker: Mapping[str, Any] | None,
    ) -> bool:
        """Return whether the durable marker still awaits final certification."""

        return bool(
            isinstance(marker, Mapping)
            and isinstance(marker.get("instance_id"), str)
            and str(marker["instance_id"]).startswith(
                REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
            )
        )

    def _assert_build_only_replacement_candidate(
        self,
        *,
        inspection: Mapping[str, Any],
        marker: Mapping[str, Any] | None,
        authority: CoreAuthorityLease,
    ) -> None:
        """Admit only an exact-layout, build-only successor of live v6."""

        data_root = self.config.memory_path.parent
        logical_snapshot = inspection.get("logical_snapshot")
        runtime_publication = inspection.get("runtime_publication")
        if (
            not isinstance(marker, Mapping)
            or inspection.get("governance_mode") != "authoritative-v6"
            or inspection.get("schema_identity") != CORE_STORE_SCHEMA_IDENTITY
            or inspection.get("new_empty_bootstrap") is not False
            or self.config.state_path != data_root / "runtime_state.json"
            or self.config.capture_root != data_root
            or (
                marker.get("build_id") == self._build_id
                and not self._replacement_certification_pending(marker)
            )
            or marker.get("config_fingerprint") != self.config.fingerprint
            or marker.get("protocol_version") != PROTOCOL_VERSION
            or marker.get("root_generation_id") != self._root_generation_id
            or marker.get("lock_generation_id") != authority.lock_generation_id
            or marker.get("embedding_space_identity")
            != self.config.embedding_space_identity
            or marker.get("store_identity") != inspection.get("store_identity")
            or type(marker.get("epoch")) is not int
            or inspection.get("previous_epoch") != marker.get("epoch")
            or inspection.get("next_epoch") != int(marker["epoch"]) + 1
            or not isinstance(logical_snapshot, Mapping)
            or not isinstance(logical_snapshot.get("schema"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(logical_snapshot.get("sha256") or ""),
            )
            is None
            or not isinstance(runtime_publication, Mapping)
            or runtime_publication.get("status") != "complete"
            or runtime_publication.get("build_id") != marker.get("build_id")
            or runtime_publication.get("authority_epoch_number")
            != marker.get("epoch")
        ):
            raise CoreServiceError("service_unavailable")

    @staticmethod
    def _assert_ready_replacement_delivery_audit(
        audit: Mapping[str, Any] | None,
    ) -> None:
        zero_fields = (
            "cursor_mismatch_count",
            "delivery_schema_error_count",
            "unrelated_delivery_error_count",
            "target_integrity_error_count",
            "event_ledger_integrity_error_count",
            "target_highwater_error_count",
            "highwater_contract_error_count",
            "repair_receipt_integrity_error_count",
            "repair_receipt_semantic_error_count",
            "pending_repair_receipt_semantic_error_count",
            "verified_repair_receipt_semantic_error_count",
            "pending_repair_receipt_count",
        )
        nonnegative_fields = (
            "derivation_source_row_count",
            "target_highwater",
            "latest_event_id",
        )
        if (
            not isinstance(audit, Mapping)
            or audit.get("protocol_version")
            != "context-delivery-publication-repair.v1"
            or audit.get("status") != "ready"
            or audit.get("repair_required") is not False
            or audit.get("repairable") is not True
            or audit.get("target_reconciliation_needed") is not False
            or audit.get("target_canonicalization_needed") is not False
            or any(type(audit.get(field)) is not int for field in zero_fields)
            or any(int(audit[field]) != 0 for field in zero_fields)
            or any(
                type(audit.get(field)) is not int
                for field in nonnegative_fields
            )
            or any(int(audit[field]) < 0 for field in nonnegative_fields)
            or audit.get("target_highwater") != audit.get("latest_event_id")
            or re.fullmatch(
                r"[0-9a-f]{64}", str(audit.get("audit_revision") or "")
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(audit.get("settled_audit_revision") or ""),
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(audit.get("derivation_source_sha256") or ""),
            )
            is None
        ):
            raise CoreServiceError("service_unavailable")

    def _verify_required_replacement_admission(
        self,
        *,
        inspection: Mapping[str, Any],
        delivery_audit: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self.config.capture_root is None:
            raise CoreServiceError("service_unavailable")
        try:
            from scripts.core_cutover_preflight import (
                REPLACEMENT_ADMISSION_NAME,
                REPLACEMENT_ADMISSION_VERIFICATION_SCHEMA,
                verify_replacement_admission_for_core,
            )

            attestation_path = (
                self.config.memory_path.parent
                / "core"
                / REPLACEMENT_ADMISSION_NAME
            )

            verification = verify_replacement_admission_for_core(
                root=Path(__file__).resolve().parent,
                memory_db=self.config.memory_path,
                capture_root=self.config.capture_root,
                attestation_path=attestation_path,
                expected_build_id=self._build_id,
                expected_config_fingerprint=self.config.fingerprint,
                inspection=inspection,
                delivery_audit=delivery_audit,
                minimum_remaining_seconds=CUTOVER_MINIMUM_REMAINING_SECONDS,
            )
        except Exception as exc:
            raise CoreServiceError("service_unavailable") from exc

        logical_snapshot = inspection.get("logical_snapshot")
        marker = inspection.get("marker")
        runtime_publication = inspection.get("runtime_publication")
        try:
            predecessor_marker_sha256 = hashlib.sha256(
                canonical_json_bytes(dict(marker))
            ).hexdigest()
            predecessor_runtime_publication_sha256 = hashlib.sha256(
                canonical_json_bytes(dict(runtime_publication))
            ).hexdigest()
            delivery_audit_sha256 = hashlib.sha256(
                canonical_json_bytes(dict(delivery_audit))
            ).hexdigest()
        except (CoreProtocolError, TypeError, ValueError) as exc:
            raise CoreServiceError("service_unavailable") from exc
        signed_sha256_fields = (
            "capture_manifest_sha256",
            "runtime_state_canonical_sha256",
            "request_journal_logical_snapshot_sha256",
            "request_journal_binding_receipt_digest",
            "recovery_bundle_receipt_digest",
            "recovery_restore_proof_receipt_digest",
        )
        if (
            not isinstance(verification, dict)
            or verification.get("schema")
            != REPLACEMENT_ADMISSION_VERIFICATION_SCHEMA
            or verification.get("verified") is not True
            or verification.get("candidate_build_id") != self._build_id
            or verification.get("candidate_config_fingerprint")
            != self.config.fingerprint
            or verification.get("governance_mode") != "authoritative-v6"
            or verification.get("store_identity") != inspection.get("store_identity")
            or not isinstance(marker, Mapping)
            or verification.get("authority_epoch_number") != marker.get("epoch")
            or verification.get("next_authority_epoch_number")
            != inspection.get("next_epoch")
            or verification.get("store_generation")
            != f"epoch-{marker.get('epoch')}"
            or verification.get("database_schema_identity")
            != inspection.get("schema_identity")
            or not isinstance(logical_snapshot, Mapping)
            or not isinstance(runtime_publication, Mapping)
            or verification.get("database_logical_snapshot_schema")
            != logical_snapshot.get("schema")
            or not secrets.compare_digest(
                str(verification.get("database_logical_snapshot_sha256") or ""),
                str(logical_snapshot.get("sha256") or ""),
            )
            or re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                str(verification.get("git_head") or ""),
            )
            is None
            or any(
                re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(verification.get(field) or ""),
                )
                is None
                for field in signed_sha256_fields
            )
            or type(verification.get("recovery_pending_file_count")) is not int
            or int(verification["recovery_pending_file_count"]) < 0
            or int(verification["recovery_pending_file_count"])
            > self.config.capture_max_files
            or type(
                verification.get("recovery_replay_required_file_count")
            )
            is not int
            or int(verification["recovery_replay_required_file_count"]) < 0
            or int(verification["recovery_replay_required_file_count"])
            > int(verification["recovery_pending_file_count"])
            or type(
                verification.get("recovery_replay_required_capture_count")
            )
            is not int
            or verification.get("recovery_replay_required_capture_count")
            != verification.get("recovery_replay_required_file_count")
            or verification.get("runtime_state_required") is not True
            or verification.get("runtime_state_present") is not True
            or verification.get("request_journal_id")
            != marker.get("request_journal_id")
            or verification.get("request_journal_schema_identity")
            != JOURNAL_SCHEMA_IDENTITY
            or verification.get("request_journal_logical_snapshot_schema")
            != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(verification.get("receipt_digest") or ""),
            )
            is None
            or type(verification.get("expires_at_unix_ms")) is not int
            or int(verification["expires_at_unix_ms"])
            <= int(time.time() * 1000) + CUTOVER_COMMIT_SAFETY_MARGIN_MS
            or verification.get("restored_target_binding_receipt_digest")
            is not None
            or verification.get("restored_target") is not False
            or verification.get("predecessor_marker_sha256")
            != predecessor_marker_sha256
            or verification.get("predecessor_marker_schema_version")
            != marker.get("schema_version")
            or verification.get("predecessor_service_required") is not True
            or verification.get("predecessor_instance_id")
            != marker.get("instance_id")
            or verification.get("predecessor_build_id")
            != marker.get("build_id")
            or verification.get("predecessor_config_fingerprint")
            != marker.get("config_fingerprint")
            or verification.get("predecessor_protocol_version")
            != marker.get("protocol_version")
            or verification.get("predecessor_lock_generation_id")
            != marker.get("lock_generation_id")
            or verification.get("predecessor_root_generation_id")
            != marker.get("root_generation_id")
            or verification.get("predecessor_embedding_space_identity")
            != marker.get("embedding_space_identity")
            or verification.get("predecessor_request_journal_id")
            != marker.get("request_journal_id")
            or verification.get("predecessor_request_journal_binding_schema")
            != marker.get("request_journal_binding_schema")
            or verification.get("predecessor_request_journal_schema_version")
            != marker.get("request_journal_schema_version")
            or verification.get(
                "predecessor_restored_target_binding_receipt_digest"
            )
            != marker.get("restored_target_binding_receipt_digest")
            or verification.get("predecessor_runtime_publication_sha256")
            != predecessor_runtime_publication_sha256
            or verification.get("delivery_audit_sha256")
            != delivery_audit_sha256
            or verification.get("delivery_audit_revision")
            != delivery_audit.get("audit_revision")
            or verification.get("delivery_settled_audit_revision")
            != delivery_audit.get("settled_audit_revision")
            or verification.get("delivery_derivation_source_sha256")
            != delivery_audit.get("derivation_source_sha256")
            or verification.get("delivery_derivation_source_row_count")
            != delivery_audit.get("derivation_source_row_count")
            or verification.get("delivery_target_highwater")
            != delivery_audit.get("target_highwater")
            or verification.get("delivery_latest_event_id")
            != delivery_audit.get("latest_event_id")
        ):
            raise CoreServiceError("service_unavailable")
        return dict(verification)

    def _verify_existing_restored_target_binding(
        self,
        *,
        inspection: Mapping[str, Any],
        journal_binding: Mapping[str, Any],
    ) -> None:
        marker = inspection.get("marker")
        if not isinstance(marker, dict):
            return
        expected_digest = marker.get("restored_target_binding_receipt_digest")
        if expected_digest is None:
            return
        if self.config.capture_root is None:
            raise CoreServiceError("service_unavailable")
        try:
            from recovery_manager import VerifiedRecoveryManager

            manager = VerifiedRecoveryManager(
                getattr(self._backend, "memory_store"),
                capture_root=self.config.capture_root,
                runtime_state_path=self.config.state_path,
            )
            verified = manager.verify_adopted_restored_request_journal_lineage(
                self.config.memory_path.parent,
                expected_store_identity=str(marker["store_identity"]),
                expected_request_journal_id=str(journal_binding["journal_id"]),
                expected_authority_epoch_number=int(marker["epoch"]),
                expected_restore_binding_receipt_digest=str(expected_digest),
            )
        except Exception as exc:
            raise CoreServiceError("service_unavailable") from exc
        if (
            verified.get("verified") is not True
            or not secrets.compare_digest(
                str(verified.get("receipt_digest") or ""),
                str(expected_digest),
            )
        ):
            raise CoreServiceError("service_unavailable")

    def _verify_attested_request_journal_after_open(
        self,
        *,
        attestation: Mapping[str, Any] | None,
        inspection: Mapping[str, Any] | None,
        journal_binding: Mapping[str, Any],
    ) -> None:
        if attestation is None or inspection is None:
            return
        expected_digest = attestation.get(
            "request_journal_logical_snapshot_sha256"
        )
        if expected_digest is None:
            return
        marker = inspection.get("marker")
        maximum_epoch = 0 if not isinstance(marker, dict) else int(marker["epoch"])
        try:
            from recovery_manager import VerifiedRecoveryManager

            manager = VerifiedRecoveryManager(
                getattr(self._backend, "memory_store"),
                capture_root=self.config.capture_root,
                runtime_state_path=self.config.state_path,
            )
            live = manager.recompute_request_journal_logical_digest(
                durable_core_root(self.config.memory_path) / "requests.sqlite3",
                maximum_authority_epoch=maximum_epoch,
            )
        except Exception as exc:
            raise CoreServiceError("service_unavailable") from exc
        if (
            not isinstance(expected_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
            or live.get("verified") is not True
            or not secrets.compare_digest(
                str(live.get("logical_snapshot_sha256") or ""),
                expected_digest,
            )
            or live.get("journal_id") != journal_binding.get("journal_id")
            or live.get("store_identity") != journal_binding.get("store_identity")
        ):
            raise CoreServiceError("service_unavailable")

    def start(self) -> None:
        with self._start_lock:
            try:
                self._start_once()
            except BaseException:
                failure = {
                    "schema": CORE_STARTUP_FAILURE_SCHEMA,
                    "stage": self._startup_stage,
                    "failure_class": CORE_STARTUP_FAILURE_CLASSES.get(
                        self._startup_stage,
                        "internal_unclassified",
                    ),
                    "safe_code": "service_unavailable",
                    "store_state": self._startup_store_state,
                    "journal_state": self._startup_journal_state,
                }
                LOGGER.error(
                    "authoritative core startup failed %s",
                    canonical_json_bytes(failure).decode("utf-8"),
                )
                raise

    def _assert_database_bootstrap_is_not_silent_data_loss(self) -> None:
        """Permit a new store only when no durable deployment evidence remains."""

        memory_path = self.config.memory_path
        if memory_path.exists() or memory_path.is_symlink():
            return
        data_root = memory_path.parent
        core_root = durable_core_root(memory_path)
        direct_evidence = (
            self.config.state_path,
            core_root / "store-generation.json",
            core_root / "requests.sqlite3",
            core_root / "requests.sqlite3-wal",
            core_root / "requests.sqlite3-shm",
            core_root / "requests.sqlite3.binding.receipt.json",
        )
        if any(path.exists() or path.is_symlink() for path in direct_evidence):
            raise CoreServiceError("service_unavailable")

        evidence_directories = (
            data_root / "backups",
            data_root / "recovery",
            data_root / "replication",
            *(
                ()
                if self.config.capture_root is None
                else tuple(
                    self.config.capture_root / name
                    for name in (
                        "capture_processing",
                        "capture_processed",
                        "capture_errors",
                        "capture_receipts",
                    )
                )
            ),
        )
        for directory in evidence_directories:
            try:
                observed = directory.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise CoreServiceError("service_unavailable") from exc
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                raise CoreServiceError("service_unavailable")
            try:
                next(directory.iterdir())
            except StopIteration:
                continue
            except OSError as exc:
                raise CoreServiceError("service_unavailable") from exc
            raise CoreServiceError("service_unavailable")

    def _start_once(self) -> None:
        if self._started_event.is_set():
            return
        if self._stop_event.is_set():
            raise CoreServiceError("service_unavailable")
        self._startup_stage = "durable_preflight"
        replacement_admission_requested = self._replacement_admission_requested()
        if replacement_admission_requested:
            # Persist the provisional state in the existing durable authority
            # marker.  A crash, expiry, logout, or manual restart therefore
            # cannot silently turn an admitted candidate into production.
            self._identity["authority_id"] = (
                REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
                + uuid.uuid4().hex
            )
        self._assert_database_bootstrap_is_not_silent_data_loss()
        _ensure_private_directory(self.config.socket_path.parent)
        self._startup_stage = "authority_lock"
        authority = CoreAuthorityLease.acquire_core(
            self.config.memory_path,
            timeout_seconds=self.config.authority_timeout_seconds,
            instance_id=self._identity["authority_id"],
        )
        self._authority_lease = authority
        try:
            # Token and generation publication are serialized by the exact
            # authority lease.  This avoids concurrent first-start publishers
            # and makes narrowly safe crash cleanup possible.
            self._startup_stage = "transport_auth"
            self._authentication_key = _load_or_create_authentication_key(
                _token_path(self.config.socket_path)
            )
            data_root = self.config.memory_path.parent
            self._root_generation_id = _load_or_create_store_generation(
                durable_core_root(self.config.memory_path)
                / "store-generation.json",
                store_identity=_store_identity(self.config.memory_path),
            )
            for managed_root in (
                data_root / "exports",
                data_root / "backups",
                data_root / "recovery",
            ):
                _ensure_private_directory(managed_root)
            if self.config.capture_root is not None:
                _ensure_private_directory(self.config.capture_root)
            # Full backend construction precedes the durable service claim. An
            # OOM or native-init failure therefore cannot publish readiness.
            self._startup_stage = "backend_init"
            self._backend = self._backend_factory(authority)
            self._handlers = dict(self._operation_handlers_factory(self._backend))
            store = getattr(self._backend, "memory_store", None)
            inspect_method = getattr(store, "inspect_core_authority_preclaim", None)
            claim_method = getattr(store, "claim_core_authority", None)
            if (
                store is None
                or not callable(inspect_method)
                or not callable(claim_method)
            ):
                raise CoreServiceError("service_unavailable")
            requested_replication = REPLICATION_OPERATIONS.intersection(
                self._contracts
            )
            if frozenset(self._handlers) != (
                frozenset(self._contracts)
                - SERVICE_CONTROL_OPERATIONS
                - requested_replication
            ):
                raise CoreServiceError("operation_unavailable")
            inspection: Mapping[str, Any] | None = None
            attestation: Mapping[str, Any] | None = None
            attestation_required = False
            journal_must_exist = False
            expected_journal_id: str | None = None
            self._startup_stage = "preclaim_inspection"
            inspection = inspect_method()
            if not isinstance(inspection, Mapping):
                raise CoreServiceError("service_unavailable")
            marker = inspection.get("marker")
            self._startup_store_state = (
                "authoritative_v6"
                if isinstance(marker, dict)
                else "unclaimed_v5"
            )
            if not isinstance(marker, dict):
                try:
                    self._startup_stage = "preclaim_journal_repair"
                    repair_empty_preclaim_journal_residue(
                        durable_core_root(self.config.memory_path)
                        / "requests.sqlite3",
                        expected_store_identity=str(inspection["store_identity"]),
                        memory_db_path=self.config.memory_path,
                        authority_lease=authority,
                    )
                    reinspected = inspect_method()
                except (
                    CoreAuthorityError,
                    CoreRequestJournalError,
                    OSError,
                ) as exc:
                    raise CoreServiceError("service_unavailable") from exc
                if (
                    not isinstance(reinspected, Mapping)
                    or dict(reinspected) != dict(inspection)
                ):
                    raise CoreServiceError("service_unavailable")
                inspection = reinspected
                marker = inspection.get("marker")
            journal_must_exist = isinstance(marker, dict)
            expected_journal_id = (
                None
                if not isinstance(marker, dict)
                else str(marker["request_journal_id"])
            )
            self._identity["store_identity"] = str(
                inspection["store_identity"]
            )
            self._identity["schema_identity"] = str(
                inspection["schema_identity"]
            )
            self._identity["neural_epoch"] = (
                f"epoch-{int(inspection['next_epoch'])}"
            )
            identity_changed = isinstance(marker, dict) and (
                marker["config_fingerprint"] != self.config.fingerprint
                or marker["build_id"] != self._build_id
                or marker["protocol_version"] != PROTOCOL_VERSION
            )
            if isinstance(marker, dict):
                if (
                    marker["embedding_space_identity"]
                    != self.config.embedding_space_identity
                ):
                    raise CoreServiceError("service_unavailable")
                root_generation_changed = (
                    marker["root_generation_id"]
                    != self._root_generation_id
                )
                lock_generation_changed = (
                    marker["lock_generation_id"]
                    != authority.lock_generation_id
                )
            else:
                root_generation_changed = False
                lock_generation_changed = False
            if isinstance(marker, dict):
                assert_runtime_binding = getattr(
                    self._backend,
                    "assert_runtime_state_authority_marker",
                    None,
                )
                if not callable(assert_runtime_binding):
                    raise CoreServiceError("service_unavailable")
                try:
                    assert_runtime_binding(dict(marker))
                except Exception as original_error:
                    publication = inspection.get("runtime_publication")
                    recover_runtime_binding = getattr(
                        self._backend,
                        "recover_interrupted_runtime_state_authority_publication",
                        None,
                    )
                    recoverable_identity = (
                        isinstance(publication, dict)
                        and publication.get("status") == "pending"
                        and not identity_changed
                        and not root_generation_changed
                        and not lock_generation_changed
                        and marker["embedding_space_identity"]
                        == self.config.embedding_space_identity
                    )
                    if not recoverable_identity or not callable(
                        recover_runtime_binding
                    ):
                        raise CoreServiceError("service_unavailable") from original_error
                    try:
                        recover_runtime_binding(
                            marker=dict(marker),
                            publication=dict(publication),
                            expected_config_fingerprint=self.config.fingerprint,
                            expected_build_id=self._build_id,
                            expected_protocol_version=PROTOCOL_VERSION,
                            expected_root_generation_id=str(
                                self._root_generation_id or ""
                            ),
                            expected_embedding_space_identity=(
                                self.config.embedding_space_identity
                            ),
                        )
                        assert_runtime_binding(dict(marker))
                    except Exception as recovery_error:
                        raise CoreServiceError("service_unavailable") from recovery_error
            restored_binding_path = (
                self.config.memory_path.parent
                / "core"
                / "requests.sqlite3.binding.receipt.json"
            )
            restored_adoption_required = (
                (
                    restored_binding_path.exists()
                    or restored_binding_path.is_symlink()
                )
                and (
                    not isinstance(marker, dict)
                    or marker.get(
                        "restored_target_binding_receipt_digest"
                    )
                    is None
                )
            )
            attestation_required = (
                (
                    not isinstance(marker, dict)
                    and not bool(inspection.get("new_empty_bootstrap"))
                )
                or identity_changed
                or root_generation_changed
                or lock_generation_changed
                or restored_adoption_required
                or self._replacement_certification_pending(marker)
            )
            if replacement_admission_requested:
                self._startup_stage = "cutover_attestation"
                self._assert_build_only_replacement_candidate(
                    inspection=inspection,
                    marker=marker,
                    authority=authority,
                )
                delivery_audit_method = getattr(
                    store,
                    "audit_context_delivery_publication_repair",
                    None,
                )
                if not callable(delivery_audit_method):
                    raise CoreServiceError("service_unavailable")
                try:
                    delivery_audit = delivery_audit_method()
                except Exception as exc:
                    raise CoreServiceError("service_unavailable") from exc
                self._assert_ready_replacement_delivery_audit(delivery_audit)
                attestation = self._verify_required_replacement_admission(
                    inspection=inspection,
                    delivery_audit=delivery_audit,
                )
                self._deployment_mode = REPLACEMENT_CERTIFICATION_MODE
                self._replacement_admission_receipt_digest = str(
                    attestation["receipt_digest"]
                )
                self._replacement_admission_expires_at_unix_ms = int(
                    attestation["expires_at_unix_ms"]
                )
                remaining_seconds = (
                    self._replacement_admission_expires_at_unix_ms
                    - int(time.time() * 1000)
                ) / 1000.0
                if remaining_seconds <= 0.0 or not math.isfinite(
                    remaining_seconds
                ):
                    raise CoreServiceError("service_unavailable")
                self._replacement_admission_deadline_monotonic = (
                    time.monotonic() + remaining_seconds
                )
            elif attestation_required:
                self._startup_stage = "cutover_attestation"
                attestation = self._verify_required_cutover_attestation(
                    inspection=inspection
                )
            if (
                not replacement_admission_requested
                and not isinstance(marker, dict)
                and attestation is not None
                and (
                    int(attestation["expires_at_unix_ms"])
                    - int(time.time() * 1000)
                )
                <= int(CUTOVER_PRECLAIM_MINIMUM_REMAINING_SECONDS * 1000)
            ):
                raise CoreServiceError("service_unavailable")
            self._startup_stage = "request_journal_open"
            self._request_journal = CoreRequestJournal(
                durable_core_root(self.config.memory_path)
                / "requests.sqlite3",
                authority_epoch=self._identity["neural_epoch"],
                require_existing=journal_must_exist,
                prune_on_open=False,
                allow_migration=not journal_must_exist,
                store_identity=self._identity["store_identity"],
                expected_journal_id=expected_journal_id,
            )
            self._startup_journal_state = "opened"
            self._startup_stage = "request_journal_binding"
            journal_binding = self._request_journal.binding()
            if (
                inspection is not None
                and not attestation_required
            ):
                self._verify_existing_restored_target_binding(
                    inspection=inspection,
                    journal_binding=journal_binding,
                )
            self._verify_attested_request_journal_after_open(
                attestation=attestation,
                inspection=inspection,
                journal_binding=journal_binding,
            )
            self._startup_stage = "capture_worker_prepare"
            self._prepare_capture_worker_if_enabled()
            self._startup_stage = "listener_bind"
            self._listener = self._bind_listener()
            # Every fallible readiness action must complete before the durable
            # v6 claim. The capture thread is started but parked behind an
            # activation event, so thread creation is proven without allowing
            # it to mutate the v5 store before adoption commits.
            self._startup_stage = "capture_thread_start"
            self._start_prepared_capture_worker()
            self._startup_stage = "durable_authority_claim"
            self._claim_durable_authority(
                inspection=inspection,
                journal_binding=journal_binding,
                attestation=attestation,
            )
            publish_runtime_binding = getattr(
                self._backend,
                "publish_runtime_state_authority_binding",
                None,
            )
            if not callable(publish_runtime_binding):
                raise CoreServiceError("service_unavailable")
            self._startup_stage = "runtime_publication"
            try:
                publish_runtime_binding()
            except Exception as exc:
                raise CoreServiceError("service_unavailable") from exc
            complete_runtime_publication = getattr(
                store,
                "complete_runtime_state_authority_publication",
                None,
            )
            if not callable(complete_runtime_publication):
                raise CoreServiceError("service_unavailable")
            try:
                completed_publication = complete_runtime_publication(
                    runtime_state_path=self.config.state_path,
                )
            except Exception as exc:
                raise CoreServiceError("service_unavailable") from exc
            if (
                not isinstance(completed_publication, dict)
                or completed_publication.get("status") != "complete"
                or completed_publication.get("authority_epoch_number")
                != self._authority_lease.durable_epoch
            ):
                raise CoreServiceError("service_unavailable")
            # Replication is a v6-authoritative subsystem. Constructing its
            # ledger creates durable files and rows, so it must occur only
            # after the durable authority claim and runtime publication have
            # both completed. A failed preclaim startup therefore cannot leave
            # behind false replication deployment evidence.
            if requested_replication:
                self._startup_stage = "replication_init"
                try:
                    from recovery_manager import VerifiedRecoveryManager
                    from replication_manager import ReplicationManager

                    recovery = VerifiedRecoveryManager(
                        store,
                        capture_root=self.config.capture_root or data_root,
                    )
                    self._replication_manager = ReplicationManager(
                        store,
                        recovery_manager=recovery,
                    )
                    replication_handlers = _bind_replication_handlers(
                        self._replication_manager
                    )
                    self._handlers.update(
                        {
                            name: replication_handlers[name]
                            for name in requested_replication
                        }
                    )
                except Exception as exc:
                    raise CoreServiceError("service_unavailable") from exc
            _ensure_private_directory(data_root / "replication")
            _ensure_private_directory(data_root / "replication" / "inbox")
            self._startup_stage = "path_policy_init"
            self._path_policy = CorePathPolicy(
                export_root=data_root / "exports",
                backup_root=data_root / "backups",
                recovery_root=data_root / "recovery",
                replication_root=data_root / "replication" / "inbox",
                capture_root=self.config.capture_root or data_root,
            )
            if frozenset(self._handlers) != (
                frozenset(self._contracts) - SERVICE_CONTROL_OPERATIONS
            ):
                raise CoreServiceError("operation_unavailable")
            self._capture_activation_event.set()
            self._started_event.set()
            self._startup_stage = "ready"
        except BaseException:
            self.close()
            raise

    def _authorize_operation_arguments(
        self,
        operation: str,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any], tuple[AuthorizedPath, ...]]:
        policy = self._path_policy
        if policy is None:
            raise CorePathPolicyError()
        authorized = dict(arguments)
        tokens: list[AuthorizedPath] = []

        def future(key: str, root: str) -> None:
            if key not in authorized:
                return
            if authorized[key] is None:
                # ``None`` selects the backend's closed, server-owned default:
                # no artifact for exports/certification, or a unique artifact
                # under this store's backups tree. Empty strings and every
                # client-supplied path still require normal authorization.
                return
            token = policy.authorize_future_output(root, authorized[key])
            authorized[key] = str(token.path)
            tokens.append(token)

        def existing(
            key: str,
            root: str,
            *,
            kind: str = "file",
        ) -> AuthorizedPath | None:
            if key not in authorized:
                return None
            token = policy.authorize_existing_input(
                root,
                authorized[key],
                kind=kind,
            )
            authorized[key] = str(token.path)
            tokens.append(token)
            return token

        try:
            if operation in {"certify_runtime", "export_memory"}:
                future("output_path" if operation == "certify_runtime" else "path", "export")
            elif operation == "backup_memory":
                future("path", "backup")
            elif operation == "backup_recovery_bundle":
                future("path", "backup")
                if "capture_root" in authorized or "allow_noncanonical_capture_root" in authorized:
                    raise CorePathPolicyError()
                if self.config.capture_root is None:
                    raise CorePathPolicyError()
                capture = policy.authorize_capture_root()
                authorized["capture_root"] = str(capture.path)
                authorized["allow_noncanonical_capture_root"] = False
                tokens.append(capture)
            elif operation in {"audit_capture_ledger", "repair_capture_ledger"}:
                if "capture_root" in authorized or self.config.capture_root is None:
                    raise CorePathPolicyError()
                capture = policy.authorize_capture_root()
                authorized["capture_root"] = str(capture.path)
                tokens.append(capture)
            elif operation in {
                "verify_recovery_bundle",
                "restore_recovery_bundle_isolated",
            }:
                existing("receipt_path", "backup")
                if "capture_root" in authorized or self.config.capture_root is None:
                    raise CorePathPolicyError()
                capture = policy.authorize_capture_root()
                authorized["capture_root"] = str(capture.path)
                tokens.append(capture)
                if operation == "restore_recovery_bundle_isolated":
                    future("output_root", "recovery")
            elif operation in {
                "plan_recovery_retention",
                "apply_recovery_retention",
            }:
                if "directory" in authorized:
                    raise CorePathPolicyError()
                backup_root = policy.authorize_existing_input(
                    "backup",
                    policy.configured_root("backup"),
                    kind="directory",
                )
                authorized["directory"] = str(backup_root.path)
                tokens.append(backup_root)
            elif operation == "replication_pair_peer":
                descriptor_token = existing("descriptor_path", "replication")
                if descriptor_token is None:
                    raise CoreProtocolError("invalid_request")
                try:
                    from replication_protocol import (
                        ReplicationProtocolError,
                        validate_node_descriptor,
                    )

                    descriptor = validate_node_descriptor(
                        _read_authorized_replication_json(descriptor_token)
                    )
                except (
                    CoreProtocolError,
                    ReplicationProtocolError,
                ) as exc:
                    raise CoreProtocolError("invalid_request") from exc
                if not secrets.compare_digest(
                    str(descriptor["receipt_digest"]),
                    str(authorized["expected_descriptor_digest"]),
                ):
                    raise CoreProtocolError("invalid_request")
                # Dispatch the immutable validated document. The manager never
                # reopens a client pathname after journal admission.
                authorized["descriptor_path"] = descriptor
            elif operation == "replication_stage_checkpoint":
                existing("manifest_path", "replication")
            elif operation == "replication_record_acknowledgement":
                existing("acknowledgement_path", "replication")
            return authorized, tuple(tokens)
        except BaseException:
            for token in tokens:
                token.close()
            raise

    def _bind_listener(self) -> socket.socket:
        try:
            socket_path = validate_core_socket_path(self.config.socket_path)
        except CoreRuntimePathError as exc:
            raise CoreServiceError("service_unavailable") from exc
        try:
            observed = socket_path.lstat()
        except FileNotFoundError:
            observed = None
        if observed is not None:
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISSOCK(observed.st_mode)
                or observed.st_uid != os.getuid()
            ):
                raise CoreServiceError()
            socket_path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous_umask = os.umask(0o077)
        try:
            listener.bind(str(socket_path))
        except BaseException:
            listener.close()
            raise
        finally:
            os.umask(previous_umask)
        os.chmod(socket_path, 0o600)
        observed = socket_path.lstat()
        self._bound_socket_identity = (int(observed.st_dev), int(observed.st_ino))
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISSOCK(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            listener.close()
            raise CoreServiceError()
        listener.listen(MAX_PENDING_CONNECTIONS)
        listener.settimeout(0.2)
        return listener

    def _prepare_capture_worker_if_enabled(self) -> None:
        if self.config.capture_root is None:
            return
        if self._capture_worker_factory is not None:
            worker = self._capture_worker_factory(self._backend, self.config.capture_root)
        else:
            from capture_daemon import CaptureInboxDaemon

            worker = CaptureInboxDaemon(
                root=self.config.capture_root,
                backend=self._backend,
            )
        self._capture_worker = worker

    def _start_prepared_capture_worker(self) -> None:
        if self._capture_worker is None:
            return
        self._capture_thread = threading.Thread(
            target=self._capture_loop_after_authority,
            name="synapse-core-capture",
            daemon=True,
        )
        self._capture_thread.start()

    def _capture_loop_after_authority(self) -> None:
        while not self._stop_event.is_set():
            if self._capture_activation_event.wait(0.1):
                break
        if self._stop_event.is_set():
            return
        self._capture_loop()

    def _capture_loop(self) -> None:
        while not self._stop_event.is_set():
            acquired = False
            try:
                acquired = self._acquire_backend_lane(
                    owner="capture",
                    timeout=None,
                    deadline_monotonic=(
                        time.monotonic()
                        + max(
                            BACKEND_LANE_CAPTURE_TIMEOUT_SECONDS,
                            self.config.capture_max_files
                            * BACKEND_LANE_CAPTURE_FILE_SECONDS,
                        )
                    ),
                )
                self._assert_live_authority()
                if self._stop_event.is_set():
                    break
                with self._backend_execution_context():
                    result = self._capture_worker.process_once(
                        max_files=self.config.capture_max_files
                    )
                    if self.config.poll_transcript_sources:
                        from capture_daemon import _poll_transcript_sources

                        _poll_transcript_sources(
                            root=self.config.capture_root,
                            backend=self._backend,
                            max_bytes=self.config.max_transcript_bytes,
                        )
                self._assert_live_authority()
                processed = int(result.get("processed_file_count", 0))
                errors = int(result.get("error_file_count", 0))
                with self._capture_heartbeat_lock:
                    self._capture_heartbeat.update(
                        {
                            "ready": True,
                            "iteration_count": int(
                                self._capture_heartbeat["iteration_count"]
                            )
                            + 1,
                            "processed_count": int(
                                self._capture_heartbeat["processed_count"]
                            )
                            + max(0, processed),
                            "error_count": int(
                                self._capture_heartbeat["error_count"]
                            )
                            + max(0, errors),
                            "last_success_unix_ms": int(time.time() * 1000),
                            "last_error_code": None,
                        }
                    )
            except CoreServiceError:
                break
            except Exception:
                LOGGER.error("capture worker iteration failed")
                with self._capture_heartbeat_lock:
                    self._capture_heartbeat.update(
                        {"ready": False, "last_error_code": "operation_failed"}
                    )
            finally:
                if acquired:
                    self._release_backend_lane()
            self._stop_event.wait(self.config.capture_poll_seconds)

    def serve_forever(self) -> None:
        self.start()
        while not self._stop_event.is_set():
            if not self._authority_ready():
                break
            if not self._backend_lane_health()["ready"]:
                break
            if not self._connection_slots.acquire(timeout=0.05):
                continue
            try:
                listener = self._listener
                if listener is None:
                    self._connection_slots.release()
                    break
                connection, _address = listener.accept()
            except socket.timeout:
                self._connection_slots.release()
                continue
            except OSError:
                self._connection_slots.release()
                if self._stop_event.is_set():
                    break
                raise CoreServiceError()
            worker = threading.Thread(
                target=self._connection_worker,
                args=(connection,),
                name="synapse-core-rpc",
                daemon=True,
            )
            with self._workers_lock:
                self._workers.add(worker)
            try:
                worker.start()
            except BaseException:
                with self._workers_lock:
                    self._workers.discard(worker)
                self._connection_slots.release()
                connection.close()
                raise

    def _connection_worker(self, connection: socket.socket) -> None:
        try:
            try:
                connection.settimeout(PREAUTH_FRAME_TIMEOUT_SECONDS)
                observed_uid = peer_uid(connection)
                if observed_uid != os.getuid():
                    raise CoreProtocolError("authentication_failed")
                raw_request = receive_frame(
                    connection,
                    max_frame_bytes=self.config.max_frame_bytes,
                )
                assert self._authentication_key is not None
                request = validate_request(
                    raw_request,
                    authentication_key=self._authentication_key,
                    now_unix_ms=int(time.time() * 1000),
                )
                connection.settimeout(AUTHENTICATED_CONNECTION_TIMEOUT_SECONDS)
                response = self._execute_request(
                    request,
                    authenticated_principal=f"local-uid:{observed_uid}",
                )
            except CoreProtocolError as exc:
                response = self._invalid_request_response(exc.code)
            except (CoreTransportError, OSError, TimeoutError):
                return
            except Exception:
                LOGGER.error("core request failed before dispatch")
                response = self._invalid_request_response("operation_failed")
            try:
                send_frame(
                    connection,
                    response,
                    max_frame_bytes=self.config.max_frame_bytes,
                )
            except (CoreProtocolError, CoreTransportError):
                return
        finally:
            try:
                connection.close()
            except OSError:
                pass
            self._connection_slots.release()
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def _invalid_request_response(self, code: str) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "invalid",
            "caller": "unknown",
            "operation": "invalid",
            "request_fingerprint": "0" * 64,
            "operation_sequence": self._next_sequence(),
            "server_time_unix_ms": int(time.time() * 1000),
            "identity": self.identity,
            "ok": False,
            "result": None,
            "error": safe_error(code),
        }

    def _cache_lookup(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        key = (request["caller"], request["request_id"])
        with self._request_cache_lock:
            cached = self._request_cache.get(key)
            if cached is None:
                return None
            fingerprint, response, _response_bytes = cached
            if fingerprint != request["request_fingerprint"]:
                raise CoreProtocolError("request_conflict")
            self._request_cache.move_to_end(key)
            return response

    def _cache_store(
        self,
        request: Mapping[str, Any],
        response: dict[str, Any],
    ) -> None:
        response_bytes = self._bounded_response_bytes(response)
        key = (request["caller"], request["request_id"])
        with self._request_cache_lock:
            previous = self._request_cache.pop(key, None)
            if previous is not None:
                self._request_cache_bytes -= previous[2]
            self._request_cache[key] = (
                request["request_fingerprint"],
                response,
                response_bytes,
            )
            self._request_cache_bytes += response_bytes
            self._request_cache.move_to_end(key)
            while (
                len(self._request_cache) > MAX_REQUEST_CACHE_ENTRIES
                or self._request_cache_bytes > MAX_REQUEST_CACHE_BYTES
            ):
                _evicted_key, (_fingerprint, _response, evicted_bytes) = (
                    self._request_cache.popitem(last=False)
                )
                self._request_cache_bytes -= evicted_bytes

    def _bounded_response_bytes(self, response: Mapping[str, Any]) -> int:
        payload = canonical_json_bytes(response)
        if not payload or len(payload) > self.config.max_frame_bytes:
            raise CoreProtocolError()
        return len(payload)

    def _cached_request_keys(self) -> frozenset[tuple[str, str]]:
        with self._request_cache_lock:
            return frozenset(
                key
                for key, (_fingerprint, response, _response_bytes) in self._request_cache.items()
                if not (
                    isinstance(response.get("error"), dict)
                    and response["error"].get("code") == "outcome_unknown"
                )
            )

    def _cache_mutation_response(
        self,
        request: Mapping[str, Any],
        response: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            self._cache_store(request, response)
            return response
        except Exception:
            LOGGER.error("mutation response cache unavailable")
            return self._response(
                request,
                error=safe_error("outcome_unknown"),
            )

    def _journal_accept(self, request: Mapping[str, Any]) -> str:
        journal = self._request_journal
        if journal is None:
            raise CoreRequestJournalError()
        decision = journal.accept(
            caller=request["caller"],
            request_id=request["request_id"],
            operation=request["operation"],
            request_fingerprint=request["request_fingerprint"],
        )
        return decision.disposition

    def _journal_finish(
        self,
        request: Mapping[str, Any],
        response: dict[str, Any],
    ) -> None:
        journal = self._request_journal
        if journal is None:
            raise CoreRequestJournalError()
        error = response["error"]
        journal.finish(
            caller=request["caller"],
            request_id=request["request_id"],
            operation=request["operation"],
            request_fingerprint=request["request_fingerprint"],
            result=response["result"],
            safe_error_code=None if error is None else error["code"],
        )

    def _execute_request(
        self,
        request: dict[str, Any],
        *,
        authenticated_principal: str | None = None,
    ) -> dict[str, Any]:
        expected_config = request.get("expected_config_fingerprint")
        if expected_config is not None and not secrets.compare_digest(
            expected_config,
            self.config.fingerprint,
        ):
            # The client binding is stale or points at a different authority.
            # Reject before cache lookup, path handling, journal admission, or
            # any operation dispatch so a mutation cannot reach the wrong core.
            return self._response(
                request,
                error=safe_error("service_unavailable"),
            )
        contract = self._contracts.get(request["operation"])
        if contract is None:
            return self._response(
                request,
                error=safe_error("operation_unavailable"),
            )
        if contract.name != "health":
            try:
                self._assert_live_authority()
            except CoreServiceError:
                return self._response(
                    request,
                    error=safe_error(
                        "service_unavailable",
                        retryable=contract.retry_safe,
                    ),
                )
        try:
            contract.validate_arguments(request["arguments"])
            if contract.mutation:
                _validate_mutation_arguments(
                    contract.name,
                    request["arguments"],
                    expected_embedding_dimension=self.config.dimension,
                    num_neurons=self.config.num_neurons,
                )
            cached = self._cache_lookup(request)
        except CoreProtocolError as exc:
            return self._response(request, error=safe_error(exc.code))
        if cached is not None:
            return cached
        path_tokens: tuple[AuthorizedPath, ...] = ()
        try:
            authorized_arguments, path_tokens = self._authorize_operation_arguments(
                contract.name,
                request["arguments"],
            )
            authorized_arguments = _bind_authenticated_governance_actor(
                contract.name,
                authorized_arguments,
                authenticated_principal=(
                    authenticated_principal
                    if authenticated_principal is not None
                    else f"local-uid:{os.getuid()}"
                ),
            )
        except CorePathPolicyError:
            return self._response(
                request,
                error=safe_error("path_not_authorized"),
            )
        except CoreProtocolError as exc:
            for token in path_tokens:
                token.close()
            return self._response(request, error=safe_error(exc.code))
        if self._stop_event.is_set():
            for token in path_tokens:
                token.close()
            return self._response(
                request,
                error=safe_error("service_unavailable", retryable=contract.retry_safe),
            )
        if contract.name == "health":
            for token in path_tokens:
                token.close()
            response = self._response(request, result=self._health_result())
            try:
                self._bounded_response_bytes(response)
            except CoreProtocolError:
                return self._response(request, error=safe_error("operation_failed"))
            return response
        if contract.name == "request_status":
            for token in path_tokens:
                token.close()
            journal = self._request_journal
            if journal is None:
                return self._response(
                    request,
                    error=safe_error("service_unavailable", retryable=True),
                )
            try:
                result = journal.request_status(**request["arguments"])
                response = self._response(request, result=result)
                self._bounded_response_bytes(response)
            except (CoreRequestJournalError, OSError, sqlite3.Error):
                LOGGER.error("mutation request reconciliation unavailable")
                return self._response(
                    request,
                    error=safe_error("service_unavailable", retryable=True),
                )
            except CoreProtocolError:
                LOGGER.error("mutation request reconciliation response invalid")
                return self._response(request, error=safe_error("operation_failed"))
            return response

        remaining = (request["deadline_unix_ms"] / 1000.0) - time.time()
        lane_floor_seconds = self._backend_lane_timeout_floor(contract.name)
        lane_acquire_timeout = self._backend_lane_acquire_timeout(
            contract.name,
            remaining,
        )
        if remaining <= 0 or not self._acquire_backend_lane(
            owner=(
                "replication-maintenance"
                if contract.name in LONG_REPLICATION_OPERATIONS
                else (
                    "recovery-maintenance"
                    if contract.name in LONG_RECOVERY_OPERATIONS
                    else (
                        "semantic-index-maintenance"
                        if contract.name in LONG_SEMANTIC_INDEX_OPERATIONS
                        else "rpc"
                    )
                )
            ),
            timeout=lane_acquire_timeout,
            deadline_monotonic=(
                time.monotonic()
                + max(remaining, lane_floor_seconds)
            ),
        ):
            for token in path_tokens:
                token.close()
            return self._response(
                request,
                error=safe_error("deadline_exceeded", retryable=contract.retry_safe),
            )
        try:
            if self._stop_event.is_set():
                return self._response(
                    request,
                    error=safe_error(
                        "service_unavailable",
                        retryable=contract.retry_safe,
                    ),
                )
            try:
                self._assert_live_authority()
            except CoreServiceError:
                return self._response(
                    request,
                    error=safe_error(
                        "service_unavailable",
                        retryable=contract.retry_safe,
                    ),
                )
            cached = self._cache_lookup(request)
            if cached is not None:
                return cached
            if int(time.time() * 1000) > request["deadline_unix_ms"]:
                return self._response(
                    request,
                    error=safe_error(
                        "deadline_exceeded",
                        retryable=contract.retry_safe,
                    ),
                )
            try:
                for token in path_tokens:
                    token.assert_stable()
            except CorePathPolicyError:
                return self._response(
                    request,
                    error=safe_error("path_not_authorized"),
                )
            if contract.mutation:
                try:
                    self._assert_live_authority()
                    journal_disposition = self._journal_accept(request)
                except CoreServiceError:
                    return self._response(
                        request,
                        error=safe_error("service_unavailable"),
                    )
                except CoreRequestJournalCapacityError:
                    LOGGER.error("mutation request journal is at safe capacity")
                    return self._response(
                        request,
                        error=safe_error("service_unavailable"),
                    )
                except (CoreRequestJournalError, OSError, sqlite3.Error):
                    LOGGER.error("mutation request journal unavailable")
                    return self._response(
                        request,
                        error=safe_error("service_unavailable"),
                    )
                if journal_disposition == "conflict":
                    return self._response(
                        request,
                        error=safe_error("request_conflict"),
                    )
                if journal_disposition == "existing":
                    # There is no exact response in this process (the cache was
                    # checked above), so replay would be unsafe regardless of
                    # the journal's epoch or terminal state.
                    response = self._response(
                        request,
                        error=safe_error("outcome_unknown"),
                    )
                    return self._cache_mutation_response(request, response)
                try:
                    for token in path_tokens:
                        token.assert_stable()
                    self._assert_live_authority()
                    with self._backend_execution_context():
                        result = self._handlers[contract.name](**authorized_arguments)
                    self._assert_live_authority()
                    response = self._response(request, result=result)
                    self._bounded_response_bytes(response)
                except CoreServiceError:
                    response = self._response(
                        request,
                        error=safe_error("outcome_unknown"),
                    )
                    return self._cache_mutation_response(request, response)
                except CorePathPolicyError:
                    response = self._response(
                        request,
                        error=safe_error("path_not_authorized"),
                    )
                    try:
                        self._journal_finish(request, response)
                    except (CoreRequestJournalError, OSError, sqlite3.Error):
                        LOGGER.error(
                            "path authorization failure could not be finalized"
                        )
                    return self._cache_mutation_response(request, response)
                except BridgeGovernanceIntegrityError:
                    LOGGER.error(
                        "bridge governance integrity failure operation=%s",
                        contract.name,
                    )
                    response = self._response(
                        request,
                        error=safe_error("service_unavailable"),
                    )
                    try:
                        self._journal_finish(request, response)
                    except (CoreRequestJournalError, OSError, sqlite3.Error):
                        LOGGER.error(
                            "governance integrity failure could not be finalized"
                        )
                    return self._cache_mutation_response(request, response)
                except BridgeGovernanceError:
                    if contract.name not in DETERMINISTIC_GOVERNANCE_REJECTION_OPERATIONS:
                        response = self._response(
                            request,
                            error=safe_error("outcome_unknown"),
                        )
                    else:
                        response = self._response(
                            request,
                            error=safe_error("invalid_request"),
                        )
                    try:
                        self._journal_finish(request, response)
                    except (CoreRequestJournalError, OSError, sqlite3.Error):
                        LOGGER.error(
                            "governance rejection could not be finalized"
                        )
                    return self._cache_mutation_response(request, response)
                except ContextDeliveryRejected:
                    # This exception is reserved for delivery requests whose
                    # store transaction made no commit (or rolled back before
                    # returning). Other backend failures remain outcome_unknown.
                    if (
                        contract.name
                        not in DETERMINISTIC_DELIVERY_REJECTION_OPERATIONS
                    ):
                        LOGGER.error(
                            "unexpected delivery rejection operation=%s",
                            contract.name,
                        )
                        response = self._response(
                            request,
                            error=safe_error("outcome_unknown"),
                        )
                        try:
                            self._journal_finish(request, response)
                        except (CoreRequestJournalError, OSError, sqlite3.Error):
                            LOGGER.error(
                                "ambiguous mutation outcome could not be finalized"
                            )
                        return self._cache_mutation_response(request, response)
                    response = self._response(
                        request,
                        error=safe_error("invalid_request"),
                    )
                    try:
                        self._journal_finish(request, response)
                    except (CoreRequestJournalError, OSError, sqlite3.Error):
                        LOGGER.error(
                            "deterministic delivery rejection could not be finalized"
                        )
                    return self._cache_mutation_response(request, response)
                except Exception:
                    LOGGER.error("backend operation failed operation=%s", contract.name)
                    response = self._response(
                        request,
                        error=safe_error("outcome_unknown"),
                    )
                    try:
                        self._journal_finish(request, response)
                    except (CoreRequestJournalError, OSError, sqlite3.Error):
                        LOGGER.error("ambiguous mutation outcome could not be finalized")
                    return self._cache_mutation_response(request, response)
                try:
                    self._journal_finish(request, response)
                except (CoreRequestJournalError, OSError, sqlite3.Error):
                    LOGGER.error("mutation request outcome could not be finalized")
                    response = self._response(
                        request,
                        error=safe_error("outcome_unknown"),
                    )
                return self._cache_mutation_response(request, response)
            else:
                try:
                    for token in path_tokens:
                        token.assert_stable()
                    self._assert_live_authority()
                    with self._backend_execution_context():
                        result = self._handlers[contract.name](**authorized_arguments)
                    self._assert_live_authority()
                    response = self._response(request, result=result)
                    # Prove the complete envelope fits before publishing it.
                    self._bounded_response_bytes(response)
                except CorePathPolicyError:
                    response = self._response(
                        request,
                        error=safe_error("path_not_authorized"),
                    )
                except CoreServiceError:
                    response = self._response(
                        request,
                        error=safe_error(
                            "service_unavailable",
                            retryable=contract.retry_safe,
                        ),
                    )
                except Exception:
                    LOGGER.error("backend operation failed operation=%s", contract.name)
                    response = self._response(
                        request,
                        error=safe_error(
                            "operation_failed",
                            retryable=contract.retry_safe,
                        ),
                    )
                return response
        finally:
            self._release_backend_lane()
            for token in path_tokens:
                token.close()

    def _next_sequence(self) -> int:
        with self._sequence_lock:
            self._operation_sequence += 1
            return self._operation_sequence

    def _response(
        self,
        request: Mapping[str, Any],
        *,
        result: Any = None,
        error: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request["request_id"],
            "caller": request["caller"],
            "operation": request["operation"],
            "request_fingerprint": request["request_fingerprint"],
            "operation_sequence": self._next_sequence(),
            "server_time_unix_ms": int(time.time() * 1000),
            "identity": self.identity,
            "ok": error is None,
            "result": result if error is None else None,
            "error": error,
        }

    def _health_result(self) -> dict[str, Any]:
        authority_ready = self._authority_ready()
        lane_health = self._backend_lane_health()
        with self._capture_heartbeat_lock:
            capture = dict(self._capture_heartbeat)
        last_success = int(capture.pop("last_success_unix_ms", 0))
        capture["last_success_age_ms"] = (
            None if last_success <= 0 else max(0, int(time.time() * 1000) - last_success)
        )
        journal_health: dict[str, Any] = {
            "ready": False,
            "accepted_count": 0,
            "completed_count": 0,
            "failed_count": 0,
            "explicit_ambiguous_count": 0,
            "ambiguous_count": 0,
            "last_prune_age_ms": None,
            "max_rows": 0,
            "used_rows": 0,
            "remaining_rows": 0,
            "max_accepted_rows": 0,
            "accepted_capacity_remaining": 0,
            "accepting_mutations": False,
            "blocker": "request_journal_unavailable",
        }
        if self._request_journal is not None:
            try:
                journal_health = self._request_journal.health(
                    exact_response_keys=self._cached_request_keys()
                )
            except (CoreRequestJournalError, OSError, sqlite3.Error):
                LOGGER.error("mutation request journal health failed")
        ready = (
            self._started_event.is_set()
            and not self._stop_event.is_set()
            and authority_ready
            and lane_health["ready"]
            and journal_health["ready"]
        )
        return {
            "ready": ready,
            "operational_state": (
                "unavailable"
                if not ready
                else REPLACEMENT_CERTIFICATION_MODE
                if self._deployment_mode == REPLACEMENT_CERTIFICATION_MODE
                else "maintenance"
                if lane_health["maintenance"]
                else "ready"
            ),
            "protocol_version": PROTOCOL_VERSION,
            "deployment_mode": self._deployment_mode,
            "replacement_admission_receipt_digest": (
                self._replacement_admission_receipt_digest
            ),
            "replacement_admission_expires_at_unix_ms": (
                self._replacement_admission_expires_at_unix_ms
            ),
            "authority": {
                "ready": authority_ready,
                "blocker": None if authority_ready else "authority_lost",
            },
            "backend_lane": lane_health,
            "capture": capture,
            "request_journal": journal_health,
        }

    def shutdown(self) -> None:
        self._stop_event.set()
        self._capture_activation_event.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    def _run_shutdown_teardown(self) -> None:
        """Close owned resources in order without publishing partial success.

        This runs on a daemon thread because a third-party/backend close hook is
        not trusted to honor a deadline.  The service retains every reference
        and keeps the backend lane reserved until the complete sequence returns
        successfully.  If any step raises, later authority-bearing steps are
        deliberately not attempted.
        """

        try:
            backend = self._backend
            if backend is not None:
                close_method = getattr(backend, "close", None)
                if callable(close_method):
                    close_method()
                else:
                    store = getattr(backend, "memory_store", None)
                    store_close = getattr(store, "close", None)
                    if callable(store_close):
                        store_close()
            journal = self._request_journal
            if journal is not None:
                journal.close()
            authority = self._authority_lease
            if authority is not None:
                authority.close()
        except BaseException:
            LOGGER.critical("authoritative core teardown failed")
        else:
            self._shutdown_teardown_succeeded = True
        finally:
            self._shutdown_teardown_complete.set()

    def _await_shutdown_teardown(self, *, deadline_monotonic: float) -> bool:
        thread = self._shutdown_teardown_thread
        if thread is None:
            self._shutdown_teardown_complete.clear()
            self._shutdown_teardown_succeeded = False
            thread = threading.Thread(
                target=self._run_shutdown_teardown,
                name="synapse-s2-core-teardown",
                daemon=True,
            )
            self._shutdown_teardown_thread = thread
            thread.start()
        remaining = max(0.0, deadline_monotonic - time.monotonic())
        self._shutdown_teardown_complete.wait(timeout=remaining)
        return (
            self._shutdown_teardown_complete.is_set()
            and self._shutdown_teardown_succeeded
        )

    def close(self) -> None:
        with self._start_lock, self._close_lock:
            self.shutdown()
            # A bounded drain prevents shutdown from lying about progress.  If
            # a writer cannot quiesce, keep the lease and backend open: the
            # process supervisor must terminate this poisoned process so the OS
            # closes the fence.  Releasing authority while a daemon writer may
            # resume would create overlapping writable epochs.
            close_deadline = (
                time.monotonic() + BACKEND_LANE_CLOSE_GRACE_SECONDS
            )
            with self._backend_lane_state_lock:
                teardown_already_reserved = (
                    self._backend_lane_owner == "shutdown"
                    and self._shutdown_teardown_thread is not None
                )
            lane_acquired = teardown_already_reserved or self._backend_lane.acquire(
                timeout=max(0.0, close_deadline - time.monotonic())
            )
            if lane_acquired:
                if not teardown_already_reserved:
                    with self._backend_lane_state_lock:
                        self._backend_lane_owner = "shutdown"
                        self._backend_lane_started_monotonic = time.monotonic()
                        self._backend_lane_deadline_monotonic = None
                teardown_complete = self._await_shutdown_teardown(
                    deadline_monotonic=close_deadline
                )
                if teardown_complete:
                    self._backend = None
                    self._request_journal = None
                    self._authority_lease = None
                    self._path_policy = None
                    with self._backend_lane_state_lock:
                        self._backend_lane_owner = None
                        self._backend_lane_started_monotonic = None
                        self._backend_lane_deadline_monotonic = None
                    self._backend_lane.release()
                else:
                    LOGGER.critical(
                        "authoritative core teardown did not complete; authority retained"
                    )
                    self._fence_service("shutdown_teardown_failed")
            else:
                LOGGER.critical("backend lane did not quiesce; authority retained")
                self._fence_service("backend_lane_stalled")
            drain_deadline = (
                time.monotonic() + BACKEND_LANE_CLOSE_GRACE_SECONDS
            )
            if self._capture_thread is not None and self._capture_thread.is_alive():
                self._capture_thread.join(
                    timeout=max(0.0, drain_deadline - time.monotonic())
                )
            with self._workers_lock:
                workers = list(self._workers)
            for worker in workers:
                if worker is not threading.current_thread():
                    remaining = max(0.0, drain_deadline - time.monotonic())
                    if remaining <= 0.0:
                        break
                    worker.join(timeout=remaining)
            try:
                observed = self.config.socket_path.lstat()
                identity = (int(observed.st_dev), int(observed.st_ino))
                if (
                    stat.S_ISSOCK(observed.st_mode)
                    and observed.st_uid == os.getuid()
                    and identity == self._bound_socket_identity
                ):
                    self.config.socket_path.unlink()
            except FileNotFoundError:
                pass
            self._bound_socket_identity = None
            self._started_event.clear()

    def __enter__(self) -> "AuthoritativeCoreService":
        self.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _direct_config_from_args(args: argparse.Namespace) -> CoreConfig:
    if not args.socket or not args.state or not args.memory_db:
        raise CoreServiceError("invalid_config")
    return CoreConfig(
        socket_path=Path(args.socket).expanduser(),
        state_path=Path(args.state).expanduser(),
        memory_path=Path(args.memory_db).expanduser(),
        capture_root=Path(args.capture_root).expanduser() if args.capture_root else None,
        dimension=args.dimension,
        num_neurons=args.neurons,
        default_top_k=args.top_k,
        recall_count=args.recall_count,
        require_native=args.require_native,
    )


def _config_for_args(args: argparse.Namespace) -> CoreConfig:
    config_path = args.config or os.getenv("SYNAPSE_S2_CORE_CONFIG")
    direct_values = (args.socket, args.state, args.memory_db, args.capture_root)
    if config_path:
        if any(value is not None for value in direct_values):
            raise CoreServiceError("invalid_config")
        return load_core_config(config_path)
    return config_from_wire(_direct_config_from_args(args).to_wire())


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Run the SYNAPSE-S2 authoritative core."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--config", default=None)
    serve.add_argument("--socket", default=None)
    serve.add_argument("--state", default=None)
    serve.add_argument("--memory-db", default=None)
    serve.add_argument("--capture-root", default=None)
    serve.add_argument("--dimension", type=int, default=1024)
    serve.add_argument("--neurons", type=int, default=8192)
    serve.add_argument("--top-k", type=int, default=256)
    serve.add_argument("--recall-count", type=int, default=10)
    serve.add_argument("--require-native", action="store_true")
    health = subparsers.add_parser("health")
    health.add_argument("--config", default=None)
    health.add_argument("--socket", default=None)
    health.add_argument("--timeout", type=float, default=2.0)
    return parser


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "health":
        from core_client import CoreClient, CoreRemoteError, CoreUnavailable

        expected_config_fingerprint: str | None = None
        reviewed_config: CoreConfig | None = None
        if args.config:
            reviewed_config = load_core_config(args.config)
            socket_path = reviewed_config.socket_path
            expected_config_fingerprint = reviewed_config.fingerprint
        elif args.socket:
            socket_path = Path(args.socket).expanduser()
        else:
            raise CoreServiceError("invalid_config")
        try:
            client = CoreClient(
                socket_path=socket_path,
                state_path=(
                    None
                    if reviewed_config is None
                    else reviewed_config.state_path
                ),
                expected_config_fingerprint=expected_config_fingerprint,
            )
            result = client.health(timeout_seconds=args.timeout)
        except (CoreRemoteError, CoreUnavailable):
            return 1
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "health": result,
                    "identity": client.authority_identity,
                }
            )
            + b"\n"
        )
        return 0 if isinstance(result, Mapping) and result.get("ready") is True else 1
    config = _config_for_args(args)
    service = AuthoritativeCoreService(config)

    def request_shutdown(_signum: int, _frame: Any) -> None:
        service.shutdown()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    try:
        service.serve_forever()
        return 0
    finally:
        service.close()


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except Exception:
        LOGGER.error("authoritative core command failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
