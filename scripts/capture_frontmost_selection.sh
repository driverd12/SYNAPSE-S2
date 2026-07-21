#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="${SYNAPSE_S2_PYTHON:-$ROOT/.venv/bin/python}"
CONTEXT="${SYNAPSE_S2_SELECTION_CONTEXT:-default}"
TAG="${SYNAPSE_S2_SELECTION_TAG:-frontmost-selection}"
SPEAKER="${SYNAPSE_S2_SELECTION_SPEAKER:-operator}"
CORE_BINDING=""
CANONICAL_CAPTURE_ROOT="$ROOT/.synapse_s2"
CANONICAL_CORE_SOCKET="$CANONICAL_CAPTURE_ROOT/core/service.sock"
CANONICAL_STATE_PATH="$CANONICAL_CAPTURE_ROOT/runtime_state.json"
CANONICAL_MEMORY_DB="$CANONICAL_CAPTURE_ROOT/memory.sqlite3"
CLIPBOARD_BACKUP="$(mktemp)"
SELECTION_FILE="$(mktemp)"
CLIPBOARD_BACKED_UP=0

cleanup() {
  if [ "$CLIPBOARD_BACKED_UP" = "1" ] && [ -f "$CLIPBOARD_BACKUP" ]; then
    pbcopy < "$CLIPBOARD_BACKUP" || true
  fi
  rm -f "$CLIPBOARD_BACKUP" "$SELECTION_FILE"
}
trap cleanup EXIT

if [ ! -x "$PYTHON" ]; then
  echo "Python runtime is missing or not executable: $PYTHON" >&2
  exit 2
fi

resolve_core_binding() {
  "$PYTHON" - "$ROOT" "$HOME" <<'PY'
import os
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).absolute()
home = Path(sys.argv[2]).expanduser().absolute()
sys.path.insert(0, str(repo_root))

from core_client_binding import (  # noqa: E402
    BINDING_ENV,
    CoreClientBindingError,
    default_binding_path,
    load_core_client_binding,
)

raw = str(os.environ.get(BINDING_ENV, "") or "").strip()
binding_path = Path(raw).expanduser() if raw else default_binding_path(home)
if not raw and not (binding_path.exists() or binding_path.is_symlink()):
    raise SystemExit(0)
try:
    binding = load_core_client_binding(binding_path)
except CoreClientBindingError:
    raise SystemExit(2) from None
if binding.repo_root != repo_root:
    raise SystemExit(2)
print(binding_path.absolute())
PY
}

if ! CORE_BINDING="$(resolve_core_binding)"; then
  echo "Selection capture core binding is invalid" >&2
  exit 2
fi

if [ -n "$CORE_BINDING" ]; then
  unset SYNAPSE_S2_CORE_SOCKET SYNAPSE_S2_CAPTURE_ROOT
  unset SYNAPSE_S2_EXPORT_DIR SYNAPSE_S2_MEMORY_DB SYNAPSE_S2_STATE_PATH
  unset SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT
  export SYNAPSE_S2_CORE_BINDING="$CORE_BINDING"
else
  if { [ -n "${SYNAPSE_S2_CORE_SOCKET:-}" ] \
      && [ "$SYNAPSE_S2_CORE_SOCKET" != "$CANONICAL_CORE_SOCKET" ]; } \
    || { [ -n "${SYNAPSE_S2_CAPTURE_ROOT:-}" ] \
      && [ "$SYNAPSE_S2_CAPTURE_ROOT" != "$CANONICAL_CAPTURE_ROOT" ]; }; then
    echo "Noncanonical selection capture paths require a reviewed core binding" >&2
    exit 2
  fi
  unset SYNAPSE_S2_CORE_BINDING
  unset SYNAPSE_S2_CORE_SOCKET SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT
fi

if ! pbpaste > "$CLIPBOARD_BACKUP"; then
  echo "Could not preserve the current clipboard; selection capture was not attempted." >&2
  exit 4
fi
CLIPBOARD_BACKED_UP=1

osascript <<'APPLESCRIPT'
tell application "System Events"
  keystroke "c" using command down
end tell
APPLESCRIPT

sleep "${SYNAPSE_S2_SELECTION_COPY_DELAY:-0.25}"
pbpaste > "$SELECTION_FILE"

if [ ! -s "$SELECTION_FILE" ]; then
  echo "No selected text was copied. Select transcript text first, then rerun this helper." >&2
  exit 3
fi

cd "$ROOT"
# Installed adapters carry one authority pointer.  Scrub stale local-backend
# tuning inherited from interactive shells so the router cannot silently
# construct a second neural backend.
unset MLX_DEVICE SYNAPSE_S2_DIMENSION SYNAPSE_S2_EMBEDDING_PROVIDER
unset SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS SYNAPSE_S2_NEURAL_CACHE_DIR
unset SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY SYNAPSE_S2_NEURAL_MODEL
unset SYNAPSE_S2_NEURONS SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS
unset SYNAPSE_S2_RECALL_COUNT SYNAPSE_S2_REQUIRE_NATIVE SYNAPSE_S2_TOP_K
unset SYNAPSE_S2_STATE_PATH SYNAPSE_S2_MEMORY_DB
if [ -n "$CORE_BINDING" ]; then
  "$PYTHON" synapse_cli.py --json \
    capture-clipboard \
    --context "$CONTEXT" \
    --tag "$TAG" \
    --speaker "$SPEAKER" \
    --text-file "$SELECTION_FILE"
else
  "$PYTHON" synapse_cli.py --json \
    --state "$CANONICAL_STATE_PATH" \
    --memory-db "$CANONICAL_MEMORY_DB" \
    capture-clipboard \
    --context "$CONTEXT" \
    --tag "$TAG" \
    --speaker "$SPEAKER" \
    --text-file "$SELECTION_FILE" \
    --capture-root "$CANONICAL_CAPTURE_ROOT"
fi
