#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="${SYNAPSE_S2_PYTHON:-$ROOT/.venv/bin/python}"
CONTEXT="${SYNAPSE_S2_SELECTION_CONTEXT:-default}"
TAG="${SYNAPSE_S2_SELECTION_TAG:-frontmost-selection}"
SPEAKER="${SYNAPSE_S2_SELECTION_SPEAKER:-operator}"
CAPTURE_ROOT="${SYNAPSE_S2_CAPTURE_ROOT:-$ROOT/.synapse_s2}"
STATE_PATH="${SYNAPSE_S2_STATE_PATH:-$ROOT/.synapse_s2/runtime_state.json}"
MEMORY_DB="${SYNAPSE_S2_MEMORY_DB:-$ROOT/.synapse_s2/memory.sqlite3}"
CLIPBOARD_BACKUP="$(mktemp)"
SELECTION_FILE="$(mktemp)"

cleanup() {
  if [ -f "$CLIPBOARD_BACKUP" ]; then
    pbcopy < "$CLIPBOARD_BACKUP" || true
  fi
  rm -f "$CLIPBOARD_BACKUP" "$SELECTION_FILE"
}
trap cleanup EXIT

if [ ! -x "$PYTHON" ]; then
  echo "Python runtime is missing or not executable: $PYTHON" >&2
  exit 2
fi

pbpaste > "$CLIPBOARD_BACKUP" || true

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
exec "$PYTHON" synapse_cli.py --json \
  --state "$STATE_PATH" \
  --memory-db "$MEMORY_DB" \
  capture-clipboard \
  --context "$CONTEXT" \
  --tag "$TAG" \
  --speaker "$SPEAKER" \
  --text-file "$SELECTION_FILE" \
  --capture-root "$CAPTURE_ROOT"
