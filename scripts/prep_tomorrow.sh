#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="${HOME}/.local/bin/synapse-s2-mcp"
CONTEXT="${SYNAPSE_S2_PREFLIGHT_CONTEXT:-default}"
STAMP="$(date +%Y%m%d-%H%M%S)"
VERIFY_ONLY="${SYNAPSE_S2_PREFLIGHT_VERIFY_ONLY:-0}"
APPLY=0
INSTALL_CORE=0
EVIDENCE_MANIFEST=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --verify-only|--check-only|--dry-run)
      VERIFY_ONLY=1
      shift
      ;;
    --apply)
      APPLY=1
      VERIFY_ONLY=0
      shift
      ;;
    --install-core)
      if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        echo "--install-core requires a fresh operator-readiness evidence manifest" >&2
        exit 2
      fi
      INSTALL_CORE=1
      EVIDENCE_MANIFEST="$2"
      shift 2
      ;;
    *)
      echo "usage: scripts/prep_tomorrow.sh [--verify-only] [--apply --install-core /absolute/path/to/manifest.json]" >&2
      exit 2
      ;;
  esac
done
if [ "$INSTALL_CORE" = "1" ] && [ "$APPLY" != "1" ]; then
  echo "--install-core requires the explicit --apply stage" >&2
  exit 2
fi
if [ "$APPLY" = "1" ] && [ -z "$EVIDENCE_MANIFEST" ]; then
  echo "--apply requires a fresh operator-readiness evidence manifest via --install-core" >&2
  exit 2
fi

cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1

export SYNAPSE_S2_EXPORT_DIR="${SYNAPSE_S2_EXPORT_DIR:-$ROOT/.synapse_s2}"
export SYNAPSE_S2_CAPTURE_ROOT="${SYNAPSE_S2_CAPTURE_ROOT:-$ROOT/.synapse_s2}"
export SYNAPSE_S2_DEFAULT_RESPONSE_MODE="${SYNAPSE_S2_DEFAULT_RESPONSE_MODE:-compact}"
export SYNAPSE_S2_MAX_RESPONSE_BYTES="${SYNAPSE_S2_MAX_RESPONSE_BYTES:-12288}"

if [ ! -x ".venv/bin/python" ]; then
  echo "Certification requires the existing reviewed .venv; run uv sync separately, then rerun." >&2
  exit 2
fi

# Resolve the same owner-only layout binding consumed by installed clients.
# Apply/cutover is never allowed to invent a direct socket or data layout.
CORE_BINDING_PATH="${SYNAPSE_S2_CORE_BINDING:-}"
if [ -z "$CORE_BINDING_PATH" ] \
  && { [ -e "$HOME/.config/synapse-s2/core-binding.json" ] \
    || [ -L "$HOME/.config/synapse-s2/core-binding.json" ]; }; then
  CORE_BINDING_PATH="$HOME/.config/synapse-s2/core-binding.json"
fi
unset SYNAPSE_S2_CORE_SOCKET SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT
unset SYNAPSE_S2_STATE_PATH SYNAPSE_S2_MEMORY_DB
if [ -n "$CORE_BINDING_PATH" ]; then
  BINDING_VALUES="$(.venv/bin/python - "$CORE_BINDING_PATH" "$ROOT" <<'PY'
import sys
from pathlib import Path

from core_client_binding import load_core_client_binding

binding = load_core_client_binding(Path(sys.argv[1]))
if binding.repo_root != Path(sys.argv[2]).absolute():
    raise SystemExit("core binding belongs to a different repository")
print(
    "\t".join(
        (
            str(binding.export_root),
            str(binding.capture_root),
            binding.authority_mode,
        )
    )
)
PY
)"
  IFS=$'\t' read -r SYNAPSE_S2_EXPORT_DIR SYNAPSE_S2_CAPTURE_ROOT BINDING_MODE \
    <<< "$BINDING_VALUES"
  if [ -z "$SYNAPSE_S2_EXPORT_DIR" ] || [ -z "$SYNAPSE_S2_CAPTURE_ROOT" ] \
    || [ -z "$BINDING_MODE" ]; then
    echo "Core binding did not resolve a complete reviewed layout" >&2
    exit 2
  fi
  SYNAPSE_S2_CORE_BINDING="$CORE_BINDING_PATH"
  export SYNAPSE_S2_CORE_BINDING SYNAPSE_S2_EXPORT_DIR SYNAPSE_S2_CAPTURE_ROOT
elif [ "$APPLY" = "1" ]; then
  echo "Apply requires a reviewed candidate or authoritative core binding" >&2
  exit 2
else
  unset SYNAPSE_S2_CORE_BINDING
  export SYNAPSE_S2_STATE_PATH="$ROOT/.synapse_s2/runtime_state.json"
  export SYNAPSE_S2_MEMORY_DB="$ROOT/.synapse_s2/memory.sqlite3"
fi

echo "=== immutable certification preflight ==="
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  echo "Certification requires a clean worktree before any apply-stage mutation." >&2
  exit 1
fi
if [ "$INSTALL_CORE" = "1" ]; then
  case "$EVIDENCE_MANIFEST" in
    /*) ;;
    *)
      echo "Core evidence manifest must be an absolute path" >&2
      exit 2
      ;;
  esac
  EVIDENCE_MANIFEST="$EVIDENCE_MANIFEST" .venv/bin/python - <<'PY'
import os
from pathlib import Path
from scripts.core_cutover_preflight import validate_evidence_contract

validate_evidence_contract(
    Path(os.environ["EVIDENCE_MANIFEST"]),
    root=Path.cwd(),
    maximum_age_seconds=7200,
    require_git_binding=True,
)
PY
fi

echo "=== unit tests ==="
(
  export PYTHONDONTWRITEBYTECODE=1
  # The exported paths above belong to the live operational checks below.
  # Keep unit tests hermetic so injected TemporaryDirectory state is authoritative.
  unset MLX_DEVICE
  unset SYNAPSE_S2_CORE_BINDING SYNAPSE_S2_CORE_SOCKET SYNAPSE_S2_CORE_CONFIG
  unset SYNAPSE_S2_CORE_DATA_ROOT SYNAPSE_S2_CORE_RUNTIME_ROOT
  unset SYNAPSE_S2_CORE_STATE SYNAPSE_S2_CORE_LOG SYNAPSE_S2_CORE_PYTHON
  unset SYNAPSE_S2_CORE_LABEL SYNAPSE_S2_CORE_REQUIRE_NATIVE SYNAPSE_S2_BUILD_ID
  unset SYNAPSE_S2_EMBEDDING_PROVIDER SYNAPSE_S2_NEURAL_MODEL
  unset SYNAPSE_S2_NEURAL_CACHE_DIR SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY
  unset SYNAPSE_S2_DIMENSION SYNAPSE_S2_NEURONS SYNAPSE_S2_TOP_K
  unset SYNAPSE_S2_RECALL_COUNT SYNAPSE_S2_REQUIRE_NATIVE
  unset SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS
  unset SYNAPSE_S2_STATE_PATH SYNAPSE_S2_MEMORY_DB
  unset SYNAPSE_S2_EXPORT_DIR SYNAPSE_S2_CAPTURE_ROOT
  unset SYNAPSE_S2_CAPTURE_POLL_INTERVAL SYNAPSE_S2_CAPTURE_MAX_FILES
  unset SYNAPSE_S2_TRANSCRIPT_POLL SYNAPSE_S2_MAX_TRANSCRIPT_BYTES
  unset SYNAPSE_S2_DEFAULT_RESPONSE_MODE SYNAPSE_S2_MAX_RESPONSE_BYTES
  unset SYNAPSE_S2_PREFLIGHT_CONTEXT SYNAPSE_S2_PREFLIGHT_VERIFY_ONLY
  unset CODEX_PROJECT_DIR CLAUDE_PROJECT_DIR
  .venv/bin/python -m unittest discover -s tests -v
)

echo "=== compile check ==="
.venv/bin/python - <<'PY'
from pathlib import Path

paths = """apple_vision_enrichment.py backend_router.py capture_daemon.py client_session_bridge.py core_authority.py core_client.py core_client_binding.py core_protocol.py core_request_journal.py core_service.py cortex_contract.py embedding_providers.py event_segmenter.py harmonic_memory.py hygiene_scan.py image_capture.py namespace_enrichment.py process_metrics.py longmem_eval.py media_similarity.py memora_governance.py memora_shadow.py memory_store.py mlx_backend.py mcp_client_wrapper.py mcp_server.py synapse_cli.py token_contracts.py dashboard_server.py client_config.py official_longmem/__init__.py official_longmem/bootstrap.py official_longmem/synapse_s2_memory.py scripts/benchmark_recall.py scripts/core_agent_installer.py scripts/core_cutover_preflight.py scripts/install_client_configs.py scripts/measure_longmem_v2.py scripts/measure_memory_confidence.py scripts/run_longmem_v2_official.py scripts/secure_installer_support.py scripts/smoke_dashboard.py scripts/operator_readiness_certify.py scripts/measure_token_contracts.py""".split()
for raw in paths:
    path = Path(raw)
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY

if command -v xcrun >/dev/null 2>&1; then
  xcrun --sdk macosx swiftc -parse native/apple_vision_enrich.swift
else
  echo "Apple Vision helper parse skipped: xcrun unavailable (optional lane)."
fi

echo "=== build identity ==="
BUILD_ID="$(.venv/bin/python - <<'PY'
from pathlib import Path
from core_service import _manifest_build_id
print(_manifest_build_id(Path.cwd()))
PY
)"
case "$BUILD_ID" in
  ""|*[!A-Za-z0-9._:-]*)
    echo "Build identity validation failed" >&2
    exit 1
    ;;
esac
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  echo "Certification changed the worktree or the worktree was not stable." >&2
  exit 1
fi
echo "certified build: $BUILD_ID"

if [ "$APPLY" != "1" ]; then
  echo "=== verify-only read-only-ish checks ==="
  echo "Skipping launcher/client/LaunchAgent installs, memory writes, inbox processing, MCP wrapper launches, dashboard smoke, maintenance, and backup."
  .venv/bin/python synapse_cli.py --json status --context "$CONTEXT"
  .venv/bin/python synapse_cli.py --json profile
  .venv/bin/python synapse_cli.py --json certify-runtime \
    --strict-native \
    --require-resource-envelope
  .venv/bin/python synapse_cli.py --json preflight \
    --context "$CONTEXT" \
    --require-resource-envelope \
    --require-native \
    --launcher "$LAUNCHER"
  echo "=== verify-only ready ==="
  exit 0
fi

echo "=== apply stage (all immutable gates passed) ==="
mkdir -p "$SYNAPSE_S2_EXPORT_DIR"
echo "=== explicit authoritative core install ==="
scripts/install_core_agent.sh install \
  --evidence-manifest "$EVIDENCE_MANIFEST" \
  --maximum-evidence-age-seconds 7200

echo "=== authoritative core status ==="
CORE_STATUS_PAYLOAD="$(scripts/install_core_agent.sh status)"
printf '%s\n' "$CORE_STATUS_PAYLOAD"
printf '%s' "$CORE_STATUS_PAYLOAD" | .venv/bin/python -c '
import json, sys
payload = json.load(sys.stdin)
if payload.get("ok") is not True:
    raise SystemExit(1)
if not all(
    payload.get(key) is True
    for key in (
        "loaded",
        "running",
        "healthy",
        "runtime_healthy",
        "production_ready",
        "capture_ready",
    )
):
    raise SystemExit(1)
binding = payload.get("client_binding")
if not isinstance(binding, dict) or binding.get("ready") is not True:
    raise SystemExit(1)
' || {
  echo "Authoritative core or active client binding is not ready; apply stopped before client publication." >&2
  exit 1
}

echo "=== install lightweight launcher ==="
scripts/install_local_launcher.sh

echo "=== install lightweight client configs ==="
scripts/install_client_configs.py

echo "=== install binding-routed dashboard adapter ==="
scripts/install_dashboard_agent.sh

# install_capture_daemon.sh is a v5-only maintenance compatibility lane.
# The authoritative core owns the single embedded capture worker.

echo "=== factual preflight evidence ==="
.venv/bin/python synapse_cli.py --json remember-text \
  --context "$CONTEXT" \
  --tag "production-memory-contract" \
  --text "SYNAPSE-S2 stores durable local memory in the shared .synapse_s2 SQLite substrate. Codex, Claude Desktop, Claude Code, the CLI, the dashboard, and direct FastMCP launches use the same local launcher and memory database." \
  --metadata '{"source":"prep_tomorrow","operator_ready":true}'
.venv/bin/python synapse_cli.py --json ingest-text \
  --context "$CONTEXT" \
  --tag "production-preflight-brief" \
  --text "The SYNAPSE-S2 backend imports mlx.core and mlxsnn on Apple Silicon. The recurrent LIF backend uses z-score top-k spike coding, immutable MLX state updates, STDP lateral-weight updates, quick-pruning maintenance, and deep-sleep consolidation. The context bus stores durable deployment events that connected local clients pull with fenced receipts, acknowledge exactly after consumption, and track through derived delivery cursors." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1 \
  --metadata '{"source":"prep_tomorrow","event_graph":true,"factual_preflight":true}'
.venv/bin/python synapse_cli.py --json graph --context "$CONTEXT" --limit 10
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune

echo "=== native runtime certification ==="
.venv/bin/python synapse_cli.py --json certify-runtime \
  --strict-native \
  --benchmark-quick-prune \
  --require-resource-envelope \
  --output "$SYNAPSE_S2_EXPORT_DIR/native-certification-$STAMP.json"

echo "=== capture inbox smoke ==="
# Apply has already installed and verified the authoritative core; there is no
# local-v5 processor fallback in this stage. Preserve the exact ID on failure.
CAPTURE_SMOKE_ID="$(.venv/bin/python -c 'from capture_daemon import new_capture_id; print(new_capture_id())')"
CAPTURE_SMOKE_STARTED="$(date +%s)"
printf 'Capture smoke ID: %s\n' "$CAPTURE_SMOKE_ID"
CAPTURE_SMOKE_DROP="$(.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context "$CONTEXT" \
  --capture-id "$CAPTURE_SMOKE_ID" \
  --tag "production-capture-inbox" \
  --speaker "codex" \
  --text "SYNAPSE-S2 authoritative capture worker accepts explicit sanitized session payloads and writes an exact transport receipt after capture.")"
printf '%s\n' "$CAPTURE_SMOKE_DROP"
CAPTURE_SMOKE_DROP="$CAPTURE_SMOKE_DROP" CAPTURE_SMOKE_ID="$CAPTURE_SMOKE_ID" \
CAPTURE_SMOKE_STARTED="$CAPTURE_SMOKE_STARTED" CAPTURE_SMOKE_CONTEXT="$CONTEXT" \
.venv/bin/python - <<'PY_CAPTURE_SMOKE'
import json
import math
import os
import re
import time
from pathlib import Path


def wait_for_capture_receipt(drop, *, capture_id, context_id, started_at,
                             read_receipt, read_health, monotonic=time.monotonic,
                             sleep=time.sleep, timeout=60.0):
    """Observe one fresh exact transport receipt; never process or replay drops."""
    if (not isinstance(drop, dict) or re.fullmatch(r"s2cap_[0-9a-f]{32}", capture_id) is None
            or drop.get("capture_id") != capture_id or drop.get("context_id") != context_id
            or drop.get("source_tag") != "production-capture-inbox"
            or drop.get("capture_protocol") != "capture.v2"
            or not math.isfinite(started_at)):
        raise ValueError("capture smoke drop binding is invalid")
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        receipt = read_receipt()
        if receipt is not None:
            result = receipt.get("result")
            committed_at = receipt.get("committed_at")
            if (receipt.get("capture_id") != capture_id or not isinstance(result, dict)
                    or result.get("capture_id") != capture_id
                    or result.get("context_id") != context_id
                    or result.get("source_tag") != "production-capture-inbox"
                    or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("request_fingerprint") or "")) is None
                    or type(committed_at) not in (int, float) or not math.isfinite(committed_at)
                    or committed_at < started_at):
                raise ValueError("capture smoke receipt binding is invalid; retain the drop and receipt")
            health = read_health()
            capture_age = health.get("capture", {}).get("last_success_age_ms")
            if (health.get("ready") is True and health.get("authority", {}).get("ready") is True
                    and health.get("capture", {}).get("ready") is True
                    and type(capture_age) in (int, float) and math.isfinite(capture_age)
                    and 0 <= capture_age <= 15000):
                return {"status": "exact-transport-receipt-observed", "capture_id": capture_id,
                        "context_id": context_id, "committed_at": committed_at,
                        "capture_worker_ready": True, "ledger_independently_verified": False}
        sleep(min(1.0, max(0.0, deadline - monotonic())))
    raise TimeoutError(f"Capture outcome remains unverified for {capture_id}; preserve the ID and inspect receipts without replay")


if __name__ == "__main__":
    from backend_router import core_client_if_required
    from capture_daemon import CaptureInboxDaemon
    from core_client_binding import binding_from_environment

    binding = binding_from_environment()
    if binding is None or binding.authority_mode != "authoritative-core-v6":
        raise SystemExit("Capture smoke requires the verified authoritative binding; no manual processor fallback")
    client = core_client_if_required()
    if client is None:
        raise SystemExit("Authoritative capture observer is unavailable")
    drop = json.loads(os.environ["CAPTURE_SMOKE_DROP"])
    capture_id = os.environ["CAPTURE_SMOKE_ID"]
    if re.fullmatch(r"s2cap_[0-9a-f]{32}", capture_id) is None:
        raise SystemExit("Invalid capture smoke ID")
    if Path(drop.get("drop_path", "")).parent != binding.capture_root / "capture_inbox":
        raise SystemExit("Capture smoke drop belongs to another transport root")
    daemon = CaptureInboxDaemon(root=binding.capture_root)
    receipt_path = daemon.paths()["receipt_dir"] / f"{capture_id}.json"

    def read_receipt():
        try:
            receipt_path.lstat()
        except FileNotFoundError:
            return None
        return daemon._read_receipt(receipt_path)

    result = wait_for_capture_receipt(
        drop, capture_id=capture_id, context_id=os.environ["CAPTURE_SMOKE_CONTEXT"],
        started_at=float(os.environ["CAPTURE_SMOKE_STARTED"]), read_receipt=read_receipt,
        read_health=lambda: client.health(timeout_seconds=2.0),
    )
    print(json.dumps(result, sort_keys=True))
PY_CAPTURE_SMOKE
.venv/bin/python synapse_cli.py --json capture-inbox-status

echo "=== cortex governor smoke ==="
CORTEX_SESSION_ID="$(
  .venv/bin/python synapse_cli.py --json enter-cortex \
    --context "$CONTEXT" \
    --agent-id "prep-tomorrow" \
    --task "Validate SYNAPSE-S2 Cortex Governor before tomorrow's operator review." \
    --mode strict | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["session_id"])'
)"
echo "cortex session: $CORTEX_SESSION_ID"
.venv/bin/python synapse_cli.py --json cortex-tick \
  --context "$CONTEXT" \
  --agent-id "prep-tomorrow" \
  --session-id "$CORTEX_SESSION_ID" \
  --observation "Prep script is about to continue mutating runtime evidence and readiness artifacts." \
  --proposed-action "Proceed only after smoke validations and commit a factual validation trace." \
  --mutation-intent \
  --confidence 0.82
.venv/bin/python synapse_cli.py --json commit-cortex \
  --context "$CONTEXT" \
  --agent-id "prep-tomorrow" \
  --session-id "$CORTEX_SESSION_ID" \
  --type validation \
  --truth-posture test-validated \
  --text "Prep script verified the Cortex Governor enter, tick, commit, and state path." \
  --evidence '{"source":"prep_tomorrow","tests":["cortex enter tick commit state"],"test_command":"scripts/prep_tomorrow.sh cortex validation path"}'
.venv/bin/python synapse_cli.py --json cortex-state \
  --context "$CONTEXT" \
  --agent-id "prep-tomorrow" \
  --limit 10

echo "=== cli preflight ==="
.venv/bin/python synapse_cli.py --json preflight \
  --context "$CONTEXT" \
  --minimum-memory 3 \
  --minimum-relationships 1 \
  --require-resource-envelope \
  --require-native \
  --launcher "$LAUNCHER" \
  --retrieval-prompt "durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients"

echo "=== mcp tool list ==="
.venv/bin/fastmcp list --command "$LAUNCHER" --json --timeout 15

echo "=== mcp recall smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target retrieve_spiking_memory_v2 \
  --input-json "{\"context_id\":\"$CONTEXT\",\"prompt\":\"durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients\",\"recall_scope\":\"local\",\"result_limit\":8,\"candidate_limit\":64,\"include_graph_neighbors\":true,\"response_mode\":\"compact\",\"max_response_bytes\":24576}" \
  --json --timeout 15

echo "=== mcp graph smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target list_spiking_memory_graph \
  --input-json "{\"context_id\":\"$CONTEXT\",\"limit\":10}" \
  --json --timeout 15

echo "=== mcp resource profile smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target profile_spiking_resources \
  --input-json "{\"benchmark_quick_prune\":true}" \
  --json --timeout 15

echo "=== mcp native certification smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target certify_spiking_runtime \
  --input-json "{\"strict_native\":true,\"benchmark_quick_prune\":true,\"require_resource_envelope\":true}" \
  --json --timeout 15

echo "=== mcp context deployment smoke ==="
PREFLIGHT_AGENT="prep-tomorrow-smoke"
SMOKE_CONTEXT="${CONTEXT}--system-delivery-smoke"
export SYNAPSE_S2_CLIENT_AGENT_ID="$PREFLIGHT_AGENT"
SMOKE_EVENT_ID="$(
  SMOKE_CONTEXT="$SMOKE_CONTEXT" PREFLIGHT_AGENT="$PREFLIGHT_AGENT" \
  .venv/bin/python - <<'PY'
import os
import mlx_backend
event = mlx_backend.get_backend().publish_context_event(
    context_id=os.environ["SMOKE_CONTEXT"],
    source_surface="prep-tomorrow",
    event_type="delivery-receipt-smoke",
    summary="Dedicated receipt-driven delivery smoke event.",
    payload={"purpose": "production-readiness", "contains_secret": False},
    agent_targets=[os.environ["PREFLIGHT_AGENT"]],
)
print(event["event_id"])
PY
)"
PULL_OUTPUT="$(.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target pull_spiking_context_deployments \
  --input-json "{\"context_id\":\"$SMOKE_CONTEXT\",\"agent_id\":\"$PREFLIGHT_AGENT\",\"limit\":10}" \
  --json --timeout 15)"
printf '%s\n' "$PULL_OUTPUT"
RECEIPT_IDS_JSON="$(
  PULL_OUTPUT="$PULL_OUTPUT" SMOKE_EVENT_ID="$SMOKE_EVENT_ID" \
  .venv/bin/python - <<'PY'
import json
import os

def decoded(value):
    if isinstance(value, str):
        try:
            return decoded(json.loads(value))
        except json.JSONDecodeError:
            return None
    if isinstance(value, dict):
        if isinstance(value.get("deliveries"), list):
            return value
        for key in ("result", "data", "structuredContent", "text"):
            found = decoded(value.get(key))
            if found is not None:
                return found
        for item in value.get("content", []) if isinstance(value.get("content"), list) else []:
            found = decoded(item)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = decoded(item)
            if found is not None:
                return found
    return None

root = json.loads(os.environ["PULL_OUTPUT"])
payload = decoded(root)
if payload is None:
    raise SystemExit("could not decode FastMCP delivery payload")
smoke_event_id = int(os.environ["SMOKE_EVENT_ID"])
deliveries = list(payload.get("deliveries") or [])
matches = [
    item for item in deliveries
    if int(item.get("event_id", -1)) == smoke_event_id
]
if len(matches) != 1:
    raise SystemExit("dedicated delivery smoke event was not leased")
if len(deliveries) != 1:
    raise SystemExit("unexpected delivery was leased with the dedicated smoke event")
receipts = [str(matches[0].get("receipt_id") or "")]
if not receipts[0]:
    raise SystemExit("delivery smoke returned no durable receipt ids")
print(json.dumps(receipts, separators=(",", ":")))
PY
)"

echo "=== mcp context deployment ack smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target ack_spiking_context_deployments \
  --input-json "{\"context_id\":\"$SMOKE_CONTEXT\",\"agent_id\":\"$PREFLIGHT_AGENT\",\"receipt_ids\":$RECEIPT_IDS_JSON}" \
  --json --timeout 15
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target list_spiking_context_cursors \
  --input-json "{\"context_id\":\"$SMOKE_CONTEXT\",\"limit\":5}" \
  --json --timeout 15

echo "=== mcp capture inbox status smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target get_spiking_capture_inbox_status \
  --input-json "{}" \
  --json --timeout 15

echo "=== dashboard smoke ==="
.venv/bin/python scripts/smoke_dashboard.py "$CONTEXT"

echo "=== proposal lifecycle smoke ==="
.venv/bin/python synapse_cli.py --json quick-prune
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep

echo "=== create verified paired recovery point ==="
.venv/bin/python synapse_cli.py --json backup-recovery \
  --purpose preflight \
  --pinned

echo "=== ready ==="
.venv/bin/python synapse_cli.py --json status --context "$CONTEXT"
