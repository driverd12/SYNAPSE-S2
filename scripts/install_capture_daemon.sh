#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LABEL="${SYNAPSE_S2_CAPTURE_LABEL:-aero.boom.synapse-s2.capture-daemon}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
CAPTURE_ROOT="${SYNAPSE_S2_CAPTURE_ROOT:-$ROOT/.synapse_s2}"
STATE_PATH="${SYNAPSE_S2_STATE_PATH:-$ROOT/.synapse_s2/runtime_state.json}"
MEMORY_DB="${SYNAPSE_S2_MEMORY_DB:-$ROOT/.synapse_s2/memory.sqlite3}"
LOG_PATH="${SYNAPSE_S2_CAPTURE_LOG:-$ROOT/.synapse_s2/capture-daemon.log}"
PYTHON="${SYNAPSE_S2_PYTHON:-$ROOT/.venv/bin/python}"
POLL_INTERVAL="${SYNAPSE_S2_CAPTURE_POLL_INTERVAL:-2}"
TRANSCRIPT_POLL="${SYNAPSE_S2_TRANSCRIPT_POLL:-1}"
MAX_TRANSCRIPT_BYTES="${SYNAPSE_S2_MAX_TRANSCRIPT_BYTES:-256000}"
EMBEDDING_PROVIDER="${SYNAPSE_S2_EMBEDDING_PROVIDER:-mlx-neural}"
NEURAL_MODEL="${SYNAPSE_S2_NEURAL_MODEL:-mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ}"
NEURAL_CACHE_DIR="${SYNAPSE_S2_NEURAL_CACHE_DIR:-$ROOT/.synapse_s2/models}"
NEURAL_LOCAL_FILES_ONLY="${SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY:-1}"
DIMENSION="${SYNAPSE_S2_DIMENSION:-1024}"
NEURONS="${SYNAPSE_S2_NEURONS:-6800}"
TOP_K="${SYNAPSE_S2_TOP_K:-256}"
RECALL_COUNT="${SYNAPSE_S2_RECALL_COUNT:-10}"
UID_VALUE="$(id -u)"

if [ ! -x "$PYTHON" ]; then
  echo "Python runtime is missing or not executable: $PYTHON" >&2
  echo "Run uv sync first." >&2
  exit 2
fi

mkdir -p "$CAPTURE_ROOT" "$(dirname "$STATE_PATH")" "$(dirname "$MEMORY_DB")" "$(dirname "$LOG_PATH")" "$HOME/Library/LaunchAgents"

TRANSCRIPT_ARGS=""
if [ "$TRANSCRIPT_POLL" = "1" ] || [ "$TRANSCRIPT_POLL" = "true" ]; then
  TRANSCRIPT_ARGS=" --poll-transcript-sources --max-transcript-bytes '$MAX_TRANSCRIPT_BYTES'"
fi

COMMAND="cd '$ROOT' || exit 2; export MLX_DEVICE='${MLX_DEVICE:-gpu}' SYNAPSE_S2_EMBEDDING_PROVIDER='$EMBEDDING_PROVIDER' SYNAPSE_S2_NEURAL_MODEL='$NEURAL_MODEL' SYNAPSE_S2_NEURAL_CACHE_DIR='$NEURAL_CACHE_DIR' SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY='$NEURAL_LOCAL_FILES_ONLY' SYNAPSE_S2_DIMENSION='$DIMENSION' SYNAPSE_S2_NEURONS='$NEURONS' SYNAPSE_S2_TOP_K='$TOP_K' SYNAPSE_S2_RECALL_COUNT='$RECALL_COUNT' SYNAPSE_S2_CAPTURE_ROOT='$CAPTURE_ROOT' SYNAPSE_S2_STATE_PATH='$STATE_PATH' SYNAPSE_S2_MEMORY_DB='$MEMORY_DB' SYNAPSE_S2_TRANSCRIPT_POLL='$TRANSCRIPT_POLL'; exec '$PYTHON' capture_daemon.py --capture-root '$CAPTURE_ROOT' --state '$STATE_PATH' --memory-db '$MEMORY_DB' --dimension '$DIMENSION' --neurons '$NEURONS' --top-k '$TOP_K' --poll-interval '$POLL_INTERVAL'$TRANSCRIPT_ARGS"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/zsh</string>
    <string>-lc</string>
    <string>$COMMAND</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_PATH</string>
  <key>StandardErrorPath</key>
  <string>$LOG_PATH</string>
  <key>WorkingDirectory</key>
  <string>$ROOT</string>
</dict>
</plist>
PLIST

launchctl bootout "gui/$UID_VALUE" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID_VALUE" "$PLIST"
launchctl enable "gui/$UID_VALUE/$LABEL"
launchctl kickstart -k "gui/$UID_VALUE/$LABEL"

echo "installed: $PLIST"
echo "capture_root: $CAPTURE_ROOT"
echo "log: $LOG_PATH"
