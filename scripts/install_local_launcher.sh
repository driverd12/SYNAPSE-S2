#!/bin/sh
set -eu
umask 077

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
REPO_ROOT_SHELL=$(printf '%s' "$REPO_ROOT" | sed "s/'/'\\\\''/g")
LAUNCHER_DIR="${HOME}/.local/bin"
LAUNCHER="${LAUNCHER_DIR}/synapse-s2-mcp"
LAUNCHER_TEMP=""
INSTALL_LOCK=""
FSYNC_PYTHON="${REPO_ROOT}/.venv/bin/python"

contains_secret_shape() {
  printf '%s\n' "$1" | LC_ALL=C grep -Eiq -- \
    '(^|[^A-Za-z0-9])(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{16,}|xox[abprs]-[A-Za-z0-9-]{16,}|(AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ya29\.[0-9A-Za-z_-]{20,}|[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})|((api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|passphrase|authorization|credentials?)[[:space:]]*[:=][[:space:]]*[^/[:space:]]+)|([A-Za-z][A-Za-z0-9+.-]*://[^/[:space:]:@]+:[^/[:space:]@]+@)'
}

for configured_value in "$REPO_ROOT" "$LAUNCHER_DIR" "$LAUNCHER" "$FSYNC_PYTHON"; do
  if contains_secret_shape "$configured_value"; then
    echo "Local launcher installer rejected credential-shaped configuration" >&2
    exit 2
  fi
done

if [ ! -x "$FSYNC_PYTHON" ]; then
  echo "Local launcher runtime is missing or not executable" >&2
  exit 2
fi

fsync_file_and_parent() {
  "$FSYNC_PYTHON" - "$1" >/dev/null 2>&1 <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(1)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
directory = os.open(path.parent, directory_flags)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

cleanup() {
  if [ -n "$LAUNCHER_TEMP" ]; then
    rm -f -- "$LAUNCHER_TEMP"
  fi
  if [ -n "$INSTALL_LOCK" ]; then
    rmdir -- "$INSTALL_LOCK" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' HUP INT TERM

if [ -L "$LAUNCHER_DIR" ] || { [ -e "$LAUNCHER_DIR" ] && [ ! -d "$LAUNCHER_DIR" ]; }; then
  echo "Local launcher directory must be a real directory" >&2
  exit 2
fi
mkdir -p "$LAUNCHER_DIR"
INSTALL_LOCK_CANDIDATE="${LAUNCHER_DIR}/.synapse-s2-mcp.install.lock"
if ! mkdir -m 700 "$INSTALL_LOCK_CANDIDATE" 2>/dev/null; then
  echo "Another local launcher install is already in progress" >&2
  exit 1
fi
INSTALL_LOCK="$INSTALL_LOCK_CANDIDATE"
if [ -L "$LAUNCHER" ] || { [ -e "$LAUNCHER" ] && [ ! -f "$LAUNCHER" ]; }; then
  echo "Local launcher target must be a regular non-symlink file" >&2
  exit 2
fi
LAUNCHER_TEMP=$(mktemp "${LAUNCHER_DIR}/.synapse-s2-mcp.XXXXXX")
cat > "$LAUNCHER_TEMP" <<EOF
#!/bin/sh
set -eu
umask 077
REPO_ROOT='${REPO_ROOT_SHELL}'
cd "\$REPO_ROOT"
# The wrapper is executed by absolute path, so Python places REPO_ROOT at
# sys.path[0]. Do not serialize the checkout into PYTHONPATH: POSIX cannot
# represent a path containing its ':' list separator, and inherited entries
# would be an unnecessary import-override surface.
unset PYTHONPATH PYTHONHOME PYTHONSAFEPATH
PYTHONNOUSERSITE=1
unset MLX_DEVICE SYNAPSE_S2_DIMENSION SYNAPSE_S2_EMBEDDING_PROVIDER
unset SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS SYNAPSE_S2_MEMORY_DB
unset SYNAPSE_S2_NEURAL_CACHE_DIR SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY
unset SYNAPSE_S2_NEURAL_MODEL SYNAPSE_S2_NEURAL_MODEL_ID
unset SYNAPSE_S2_NEURAL_REVISION SYNAPSE_S2_NEURAL_POOLING
unset SYNAPSE_S2_NEURAL_MAX_TOKENS SYNAPSE_S2_NEURAL_NORMALIZE
unset SYNAPSE_S2_NEURONS
unset SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS SYNAPSE_S2_RECALL_COUNT
unset SYNAPSE_S2_REQUIRE_NATIVE SYNAPSE_S2_STATE_PATH SYNAPSE_S2_TOP_K
unset SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT
unset SYNAPSE_S2_CORE_SOCKET SYNAPSE_S2_EXPORT_DIR SYNAPSE_S2_CAPTURE_ROOT
if [ "\${SYNAPSE_S2_CORE_BINDING+x}" = x ]; then
  if [ -z "\$SYNAPSE_S2_CORE_BINDING" ]; then
    echo "SYNAPSE-S2 core binding is empty" >&2
    exit 2
  fi
  : # An explicit client registration must fail closed if its binding is bad.
elif [ -e "\$HOME/.config/synapse-s2/core-binding.json" ] || \
     [ -L "\$HOME/.config/synapse-s2/core-binding.json" ]; then
  SYNAPSE_S2_CORE_BINDING="\$HOME/.config/synapse-s2/core-binding.json"
else
  # Preserve the canonical local-v5 route until a reviewed binding exists, but
  # inspect durable governance before exporting neural fields.  A governed v6
  # store keeps only its canonical memory/state constraint so backend_router
  # derives the core socket from the marker and cannot fall back locally.
  SYNAPSE_S2_STATE_PATH="\$REPO_ROOT/.synapse_s2/runtime_state.json"
  SYNAPSE_S2_MEMORY_DB="\$REPO_ROOT/.synapse_s2/memory.sqlite3"
  SYNAPSE_S2_EXPORT_DIR="\$REPO_ROOT/.synapse_s2"
  SYNAPSE_S2_CAPTURE_ROOT="\$REPO_ROOT/.synapse_s2"
  MARKER_STATUS=0
  "\$REPO_ROOT/.venv/bin/python" - "\$SYNAPSE_S2_MEMORY_DB" <<'PY' || MARKER_STATUS=\$?
import sys
from pathlib import Path

from backend_router import database_requires_core

try:
    governed = database_requires_core(Path(sys.argv[1]))
except Exception:
    raise SystemExit(11)
raise SystemExit(0 if governed else 10)
PY
  case "\$MARKER_STATUS" in
    0)
      : # Durable v6 marker: backend_router derives and requires the core.
      ;;
    10)
      MLX_DEVICE="gpu"
      SYNAPSE_S2_EMBEDDING_PROVIDER="mlx-neural"
      SYNAPSE_S2_NEURAL_MODEL="mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
      SYNAPSE_S2_NEURAL_CACHE_DIR="\$REPO_ROOT/.synapse_s2/models"
      SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY="1"
      SYNAPSE_S2_DIMENSION="1024"
      SYNAPSE_S2_NEURONS="8192"
      SYNAPSE_S2_TOP_K="256"
      SYNAPSE_S2_RECALL_COUNT="10"
      ;;
    *)
      echo "SYNAPSE-S2 database governance could not be verified" >&2
      exit 2
      ;;
  esac
fi
: "\${SYNAPSE_S2_DEFAULT_RESPONSE_MODE:=compact}"
: "\${SYNAPSE_S2_MAX_RESPONSE_BYTES:=12288}"
: "\${SYNAPSE_S2_CLIENT_SESSION_BRIDGE:=1}"
: "\${SYNAPSE_S2_CLIENT_STARTUP_RECALL_MODE:=surface}"
export MLX_DEVICE
export SYNAPSE_S2_EMBEDDING_PROVIDER
export SYNAPSE_S2_NEURAL_MODEL
export SYNAPSE_S2_NEURAL_CACHE_DIR
export SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY
export SYNAPSE_S2_DIMENSION
export SYNAPSE_S2_NEURONS
export SYNAPSE_S2_TOP_K
export SYNAPSE_S2_RECALL_COUNT
export SYNAPSE_S2_STATE_PATH
export SYNAPSE_S2_MEMORY_DB
export SYNAPSE_S2_CORE_BINDING
export SYNAPSE_S2_CORE_SOCKET
export SYNAPSE_S2_EXPORT_DIR
export SYNAPSE_S2_CAPTURE_ROOT
export SYNAPSE_S2_DEFAULT_RESPONSE_MODE
export SYNAPSE_S2_MAX_RESPONSE_BYTES
export SYNAPSE_S2_CLIENT_SESSION_BRIDGE
export SYNAPSE_S2_CLIENT_STARTUP_RECALL_MODE
export PYTHONNOUSERSITE
exec "\$REPO_ROOT/.venv/bin/python" "\$REPO_ROOT/mcp_client_wrapper.py"
EOF
/bin/sh -n "$LAUNCHER_TEMP"
chmod 755 "$LAUNCHER_TEMP"
fsync_file_and_parent "$LAUNCHER_TEMP"
mv -f -- "$LAUNCHER_TEMP" "$LAUNCHER"
LAUNCHER_TEMP=""
fsync_file_and_parent "$LAUNCHER"

printf '%s\n' "$LAUNCHER"
