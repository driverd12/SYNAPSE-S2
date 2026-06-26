#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/dan.driver/Documents/Neuromorphic Spiking Attention Plugin for Local AI Clients: An Apple Silicon Optimized MCP Architecture"
LAUNCHER="/Users/dan.driver/.local/bin/synapse-s2-mcp"
CONTEXT="${SYNAPSE_S2_PREFLIGHT_CONTEXT:-board-demo}"
STAMP="$(date +%Y%m%d-%H%M%S)"

cd "$ROOT"

export MLX_DEVICE="${MLX_DEVICE:-gpu}"
export SYNAPSE_S2_STATE_PATH="${SYNAPSE_S2_STATE_PATH:-$ROOT/.synapse_s2/runtime_state.json}"
export SYNAPSE_S2_MEMORY_DB="${SYNAPSE_S2_MEMORY_DB:-$ROOT/.synapse_s2/memory.sqlite3}"
export SYNAPSE_S2_EXPORT_DIR="${SYNAPSE_S2_EXPORT_DIR:-$ROOT/.synapse_s2}"

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

echo "=== install launcher ==="
scripts/install_local_launcher.sh

echo "=== unit tests ==="
.venv/bin/python -m unittest discover -s tests -v

echo "=== compile check ==="
.venv/bin/python -m py_compile event_segmenter.py memory_store.py mlx_backend.py mcp_server.py synapse_cli.py

echo "=== seed durable memory ==="
.venv/bin/python synapse_cli.py --json seed-demo --context "$CONTEXT"
.venv/bin/python synapse_cli.py --json remember-text \
  --context "$CONTEXT" \
  --tag "production-memory-contract" \
  --text "SYNAPSE-S2 stores durable real memory in a local SQLite substrate with MCP tools to list, export, backup, toggle, remember, and recall context across local clients." \
  --metadata '{"source":"prep_tomorrow","operator_ready":true}'
.venv/bin/python synapse_cli.py --json ingest-text \
  --context "$CONTEXT" \
  --tag "proposal-event-brief" \
  --text "Apple Silicon MLX compiles spiking neural kernels into Metal for local recall. Sparse top-k spike populations reduce context pressure and keep associative traces on-device. Procurement reviews supplier budget exposure, renewal timing, and contract risk. Operators need graph relationships that connect technical runtime evidence to tomorrow morning approval actions." \
  --surprise-threshold 0.58 \
  --min-segment-sentences 1 \
  --metadata '{"source":"prep_tomorrow","event_graph":true}'
.venv/bin/python synapse_cli.py --json graph --context "$CONTEXT" --limit 10
.venv/bin/python synapse_cli.py --json profile --benchmark-quick-prune

echo "=== cli preflight ==="
.venv/bin/python synapse_cli.py --json preflight \
  --context "$CONTEXT" \
  --minimum-memory 3 \
  --minimum-relationships 1 \
  --require-resource-envelope \
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

echo "=== proposal lifecycle smoke ==="
.venv/bin/python synapse_cli.py --json quick-prune
.venv/bin/python synapse_cli.py --json idle-maintenance --force-deep-sleep

echo "=== backup durable memory ==="
.venv/bin/python synapse_cli.py --json backup-memory \
  --output "$SYNAPSE_S2_EXPORT_DIR/preflight-memory-$STAMP.sqlite3"

echo "=== ready ==="
.venv/bin/python synapse_cli.py --json status --context "$CONTEXT"
