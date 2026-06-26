#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LABEL="${SYNAPSE_S2_DASHBOARD_LABEL:-aero.boom.synapse-s2.dashboard}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HOST="${SYNAPSE_S2_DASHBOARD_HOST:-127.0.0.1}"
PORT="${SYNAPSE_S2_DASHBOARD_PORT:-8765}"
CONTEXT="${SYNAPSE_S2_DASHBOARD_CONTEXT:-default}"
LOG_PATH="${SYNAPSE_S2_DASHBOARD_LOG:-$ROOT/.synapse_s2/dashboard.log}"
PYTHON="${SYNAPSE_S2_PYTHON:-$ROOT/.venv/bin/python}"
EMBEDDING_PROVIDER="${SYNAPSE_S2_EMBEDDING_PROVIDER:-mlx-neural}"
NEURAL_MODEL="${SYNAPSE_S2_NEURAL_MODEL:-mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ}"
NEURAL_CACHE_DIR="${SYNAPSE_S2_NEURAL_CACHE_DIR:-$ROOT/.synapse_s2/models}"
STATE_PATH="${SYNAPSE_S2_STATE_PATH:-$ROOT/.synapse_s2/runtime_state.json}"
MEMORY_DB="${SYNAPSE_S2_MEMORY_DB:-$ROOT/.synapse_s2/memory.sqlite3}"
EXPORT_DIR="${SYNAPSE_S2_EXPORT_DIR:-$ROOT/.synapse_s2}"
CAPTURE_ROOT="${SYNAPSE_S2_CAPTURE_ROOT:-$ROOT/.synapse_s2}"
UID_VALUE="$(id -u)"

if [ ! -x "$PYTHON" ]; then
  echo "Python runtime is missing or not executable: $PYTHON" >&2
  echo "Run uv sync first." >&2
  exit 2
fi

mkdir -p "$HOME/Library/LaunchAgents" "$EXPORT_DIR" "$(dirname "$LOG_PATH")"

COMMAND="cd '$ROOT' || exit 2; export MLX_DEVICE='${MLX_DEVICE:-gpu}' SYNAPSE_S2_EMBEDDING_PROVIDER='$EMBEDDING_PROVIDER' SYNAPSE_S2_NEURAL_MODEL='$NEURAL_MODEL' SYNAPSE_S2_NEURAL_CACHE_DIR='$NEURAL_CACHE_DIR' SYNAPSE_S2_STATE_PATH='$STATE_PATH' SYNAPSE_S2_MEMORY_DB='$MEMORY_DB' SYNAPSE_S2_EXPORT_DIR='$EXPORT_DIR' SYNAPSE_S2_CAPTURE_ROOT='$CAPTURE_ROOT'; exec '$PYTHON' dashboard_server.py --host '$HOST' --port '$PORT' --context '$CONTEXT'"

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

plutil -lint "$PLIST" >/dev/null
launchctl bootout "gui/$UID_VALUE" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID_VALUE" "$PLIST"
launchctl enable "gui/$UID_VALUE/$LABEL"
launchctl kickstart -k "gui/$UID_VALUE/$LABEL"

echo "installed: $PLIST"
echo "dashboard: http://$HOST:$PORT/?context_id=$CONTEXT"
echo "log: $LOG_PATH"
