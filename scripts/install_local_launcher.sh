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
exec "\$REPO_ROOT/.venv/bin/python" "\$REPO_ROOT/mcp_server.py"
EOF
chmod 755 "$LAUNCHER"

printf '%s\n' "$LAUNCHER"
