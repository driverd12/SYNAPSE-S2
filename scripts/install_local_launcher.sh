#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
LAUNCHER_DIR="${HOME}/.local/bin"
LAUNCHER="${LAUNCHER_DIR}/synapse-s2-mcp"

mkdir -p "$LAUNCHER_DIR"
cat > "$LAUNCHER" <<EOF
#!/bin/sh
set -eu
REPO_ROOT='${REPO_ROOT}'
cd "\$REPO_ROOT"
if [ -n "\${PYTHONPATH:-}" ]; then
  PYTHONPATH="\$REPO_ROOT:\$PYTHONPATH"
else
  PYTHONPATH="\$REPO_ROOT"
fi
: "\${MLX_DEVICE:=gpu}"
: "\${SYNAPSE_S2_EMBEDDING_PROVIDER:=mlx-neural}"
: "\${SYNAPSE_S2_NEURAL_MODEL:=mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ}"
: "\${SYNAPSE_S2_NEURAL_CACHE_DIR:=\$REPO_ROOT/.synapse_s2/models}"
: "\${SYNAPSE_S2_STATE_PATH:=\$REPO_ROOT/.synapse_s2/runtime_state.json}"
: "\${SYNAPSE_S2_MEMORY_DB:=\$REPO_ROOT/.synapse_s2/memory.sqlite3}"
: "\${SYNAPSE_S2_EXPORT_DIR:=\$REPO_ROOT/.synapse_s2}"
: "\${SYNAPSE_S2_CAPTURE_ROOT:=\$REPO_ROOT/.synapse_s2}"
: "\${SYNAPSE_S2_CLIENT_SESSION_BRIDGE:=1}"
export PYTHONPATH
export MLX_DEVICE
export SYNAPSE_S2_EMBEDDING_PROVIDER
export SYNAPSE_S2_NEURAL_MODEL
export SYNAPSE_S2_NEURAL_CACHE_DIR
export SYNAPSE_S2_STATE_PATH
export SYNAPSE_S2_MEMORY_DB
export SYNAPSE_S2_EXPORT_DIR
export SYNAPSE_S2_CAPTURE_ROOT
export SYNAPSE_S2_CLIENT_SESSION_BRIDGE
exec "\$REPO_ROOT/.venv/bin/python" "\$REPO_ROOT/mcp_client_wrapper.py"
EOF
chmod 755 "$LAUNCHER"

printf '%s\n' "$LAUNCHER"
