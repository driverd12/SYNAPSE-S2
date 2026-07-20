#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="/Users/dan.driver/.local/bin/synapse-s2-mcp"
CONTEXT="${SYNAPSE_S2_PREFLIGHT_CONTEXT:-default}"
STAMP="$(date +%Y%m%d-%H%M%S)"
VERIFY_ONLY="${SYNAPSE_S2_PREFLIGHT_VERIFY_ONLY:-0}"

case "${1:-}" in
  --verify-only|--check-only|--dry-run)
    VERIFY_ONLY=1
    shift
    ;;
  "")
    ;;
  *)
    echo "usage: scripts/prep_tomorrow.sh [--verify-only]" >&2
    exit 2
    ;;
esac

cd "$ROOT"

export MLX_DEVICE="${MLX_DEVICE:-gpu}"
export SYNAPSE_S2_EMBEDDING_PROVIDER="${SYNAPSE_S2_EMBEDDING_PROVIDER:-mlx-neural}"
export SYNAPSE_S2_NEURAL_MODEL="${SYNAPSE_S2_NEURAL_MODEL:-mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ}"
export SYNAPSE_S2_NEURAL_CACHE_DIR="${SYNAPSE_S2_NEURAL_CACHE_DIR:-$ROOT/.synapse_s2/models}"
export SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY="${SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY:-1}"
export SYNAPSE_S2_DIMENSION="${SYNAPSE_S2_DIMENSION:-1024}"
export SYNAPSE_S2_NEURONS="${SYNAPSE_S2_NEURONS:-8192}"
export SYNAPSE_S2_TOP_K="${SYNAPSE_S2_TOP_K:-256}"
export SYNAPSE_S2_RECALL_COUNT="${SYNAPSE_S2_RECALL_COUNT:-10}"
export SYNAPSE_S2_STATE_PATH="${SYNAPSE_S2_STATE_PATH:-$ROOT/.synapse_s2/runtime_state.json}"
export SYNAPSE_S2_MEMORY_DB="${SYNAPSE_S2_MEMORY_DB:-$ROOT/.synapse_s2/memory.sqlite3}"
export SYNAPSE_S2_EXPORT_DIR="${SYNAPSE_S2_EXPORT_DIR:-$ROOT/.synapse_s2}"
export SYNAPSE_S2_CAPTURE_ROOT="${SYNAPSE_S2_CAPTURE_ROOT:-$ROOT/.synapse_s2}"
export SYNAPSE_S2_DEFAULT_RESPONSE_MODE="${SYNAPSE_S2_DEFAULT_RESPONSE_MODE:-compact}"
export SYNAPSE_S2_MAX_RESPONSE_BYTES="${SYNAPSE_S2_MAX_RESPONSE_BYTES:-12288}"

mkdir -p "$SYNAPSE_S2_EXPORT_DIR"

if [ ! -x ".venv/bin/python" ]; then
  if command -v uv >/dev/null 2>&1; then
    uv sync
  elif [ -x "/opt/homebrew/bin/uv" ]; then
    /opt/homebrew/bin/uv sync
  else
    echo "uv is required to create .venv" >&2
    exit 2
  fi
fi

if [ "$VERIFY_ONLY" = "1" ]; then
  echo "=== verify-only mode ==="
  echo "Skipping launcher/client/LaunchAgent installs, memory writes, inbox processing, MCP wrapper launches, dashboard smoke, maintenance, and backup."
else
  echo "=== install launcher ==="
  scripts/install_local_launcher.sh

  echo "=== install client configs ==="
  scripts/install_client_configs.py

  echo "=== install capture inbox daemon ==="
  scripts/install_capture_daemon.sh
fi

echo "=== unit tests ==="
SYNAPSE_S2_EMBEDDING_PROVIDER=semantic-hash .venv/bin/python -m unittest discover -s tests -v

echo "=== compile check ==="
.venv/bin/python -m py_compile capture_daemon.py client_session_bridge.py embedding_providers.py event_segmenter.py memory_store.py mlx_backend.py mcp_client_wrapper.py mcp_server.py synapse_cli.py token_contracts.py dashboard_server.py client_config.py scripts/install_client_configs.py scripts/smoke_dashboard.py scripts/operator_readiness_certify.py scripts/measure_token_contracts.py

if [ "$VERIFY_ONLY" = "1" ]; then
  echo "=== verify-only read-only-ish checks ==="
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

echo "=== factual preflight evidence ==="
.venv/bin/python synapse_cli.py --json remember-text \
  --context "$CONTEXT" \
  --tag "production-memory-contract" \
  --text "SYNAPSE-S2 stores durable local memory in the shared .synapse_s2 SQLite substrate. Codex, Claude Desktop, Claude Code, the CLI, the dashboard, and direct FastMCP launches use the same local launcher and memory database." \
  --metadata '{"source":"prep_tomorrow","operator_ready":true}'
.venv/bin/python synapse_cli.py --json ingest-text \
  --context "$CONTEXT" \
  --tag "production-preflight-brief" \
  --text "The SYNAPSE-S2 backend imports mlx.core and mlxsnn on Apple Silicon. The recurrent LIF backend uses z-score top-k spike coding, immutable MLX state updates, STDP relationship updates, quick-pruning maintenance, and deep-sleep consolidation. The context bus stores durable deployment events that connected local clients pull with fenced receipts, acknowledge exactly after consumption, and track through derived delivery cursors." \
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
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context "$CONTEXT" \
  --tag "production-capture-inbox" \
  --speaker "codex" \
  --text "SYNAPSE-S2 capture inbox sidecar accepts explicit session payloads, redacts common secret patterns like api_key=sk-preflight-redaction-test123, and ingests cleaned temporal events into the same local graph."
.venv/bin/python synapse_cli.py --json capture-inbox-process
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
  --query-text "durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients"

echo "=== mcp tool list ==="
.venv/bin/fastmcp list --command "$LAUNCHER" --json --timeout 15

echo "=== mcp recall smoke ==="
.venv/bin/fastmcp call --command "$LAUNCHER" \
  --target query_spiking_attention_text \
  --input-json "{\"context_id\":\"$CONTEXT\",\"prompt\":\"durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients\"}" \
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
  --output "$SYNAPSE_S2_EXPORT_DIR/preflight-recovery-$STAMP.sqlite3" \
  --capture-root "$SYNAPSE_S2_CAPTURE_ROOT" \
  --purpose preflight \
  --pinned

echo "=== ready ==="
.venv/bin/python synapse_cli.py --json status --context "$CONTEXT"
