#!/usr/bin/env bash
set -euo pipefail
umask 077

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
NEURONS="${SYNAPSE_S2_NEURONS:-8192}"
TOP_K="${SYNAPSE_S2_TOP_K:-256}"
RECALL_COUNT="${SYNAPSE_S2_RECALL_COUNT:-10}"
UID_VALUE="$(id -u)"
PLIST_DIR="$(dirname "$PLIST")"
PLIST_TEMP=""
PLIST_ROLLBACK=""
INSTALL_LOCK=""
PLIST_REPLACED=0
INSTALL_HEALTHY=0
HAD_PRIOR_PLIST=0
PRIOR_LOADED=0
PRIOR_DISABLED=0
PRIOR_RUNNING=0
PRIOR_PID=""
NEW_PID=""
HEALTH_ATTEMPTS="${SYNAPSE_S2_INSTALL_HEALTH_ATTEMPTS:-120}"
HEALTH_DELAY="${SYNAPSE_S2_INSTALL_HEALTH_DELAY:-0.25}"
STABLE_CHECKS="${SYNAPSE_S2_INSTALL_STABLE_CHECKS:-3}"
STABILIZATION_SECONDS="${SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS:-1.0}"
REQUIRED_STABLE_CHECKS=0

case "$LABEL" in
  ""|*[!A-Za-z0-9._-]*)
    echo "Capture LaunchAgent label contains unsupported characters" >&2
    exit 2
    ;;
esac

case "$HEALTH_ATTEMPTS" in
  ""|*[!0-9]*)
    echo "Install health attempts must be an integer" >&2
    exit 2
    ;;
esac
if ! awk -v value="$HEALTH_ATTEMPTS" \
  'BEGIN { exit(value >= 2 && value <= 120 ? 0 : 1) }'; then
  echo "Install health attempts must be between 2 and 120" >&2
  exit 2
fi

case "$STABLE_CHECKS" in
  ""|*[!0-9]*)
    echo "Install stable checks must be an integer" >&2
    exit 2
    ;;
esac
if ! awk -v value="$STABLE_CHECKS" \
  'BEGIN { exit(value >= 2 && value <= 60 ? 0 : 1) }'; then
  echo "Install stable checks must be between 2 and 60" >&2
  exit 2
fi

is_nonnegative_decimal() {
  [[ "$1" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]]
}

if ! is_nonnegative_decimal "$HEALTH_DELAY"; then
  echo "Install health delay must be a nonnegative decimal" >&2
  exit 2
fi
if ! is_nonnegative_decimal "$STABILIZATION_SECONDS"; then
  echo "Install stabilization seconds must be a nonnegative decimal" >&2
  exit 2
fi
if ! awk -v delay="$HEALTH_DELAY" -v window="$STABILIZATION_SECONDS" \
  'BEGIN { exit(delay <= 5 && window >= 0.1 && window <= 60 ? 0 : 1) }'; then
  echo "Install health delay or stabilization window is outside its safety bound" >&2
  exit 2
fi
if awk -v delay="$HEALTH_DELAY" -v window="$STABILIZATION_SECONDS" \
  'BEGIN { exit !(delay == 0 && window > 0) }'; then
  echo "Install health delay must be positive when stabilization is requested" >&2
  exit 2
fi
REQUIRED_STABLE_CHECKS="$(awk \
  -v delay="$HEALTH_DELAY" \
  -v window="$STABILIZATION_SECONDS" \
  -v minimum="$STABLE_CHECKS" \
  'BEGIN {
    required = minimum
    if (delay > 0) {
      elapsed_required = int(window / delay)
      if (elapsed_required * delay < window) elapsed_required++
      elapsed_required++
      if (elapsed_required > required) required = elapsed_required
    }
    print required
  }')"
if [ "$HEALTH_ATTEMPTS" -lt "$REQUIRED_STABLE_CHECKS" ]; then
  echo "Install health attempts cannot satisfy the stabilization window" >&2
  exit 2
fi

contains_secret_shape() {
  printf '%s\n' "$1" | LC_ALL=C grep -Eiq -- \
    '(^|[^A-Za-z0-9])(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{16,}|xox[abprs]-[A-Za-z0-9-]{16,}|(AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ya29\.[0-9A-Za-z_-]{20,}|[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})|((api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|passphrase|authorization|credentials?)[[:space:]]*[:=][[:space:]]*[^/[:space:]]+)|([A-Za-z][A-Za-z0-9+.-]*://[^/[:space:]:@]+:[^/[:space:]@]+@)'
}

for configured_value in \
  "$LABEL" "$PLIST" "$CAPTURE_ROOT" "$STATE_PATH" "$MEMORY_DB" \
  "$LOG_PATH" "$PYTHON" "$NEURAL_CACHE_DIR" "$EMBEDDING_PROVIDER" \
  "$NEURAL_MODEL" "${MLX_DEVICE:-gpu}"; do
  if contains_secret_shape "$configured_value"; then
    echo "Capture installer rejected credential-shaped configuration" >&2
    exit 2
  fi
done

service_running() {
  launchctl print "gui/$UID_VALUE/$LABEL" 2>/dev/null \
    | awk '$1 == "state" && $2 == "=" && $3 == "running" { found = 1 } END { exit(found ? 0 : 1) }'
}

service_loaded() {
  launchctl print "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1
}

service_disabled() {
  launchctl print-disabled "gui/$UID_VALUE" 2>/dev/null \
    | awk -v label="$LABEL" '
      index($0, "\"" label "\"") && $0 ~ /=>[[:space:]]*true/ { found = 1 }
      END { exit(found ? 0 : 1) }
    '
}

service_pid() {
  launchctl print "gui/$UID_VALUE/$LABEL" 2>/dev/null \
    | awk '$1 == "pid" && $2 == "=" && $3 ~ /^[0-9]+$/ { print $3; found = 1; exit } END { exit(found ? 0 : 1) }'
}

capture_functional_probe() {
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" \
    - "$CAPTURE_ROOT" "$MEMORY_DB" >/dev/null 2>&1 <<'PY'
import os
import signal
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

def fail_on_timeout(_signum, _frame):
    raise TimeoutError("capture health probe timed out")

signal.signal(signal.SIGALRM, fail_on_timeout)
signal.alarm(5)
from capture_daemon import CaptureInboxDaemon

capture_root = Path(sys.argv[1]).expanduser().resolve()
memory_db = Path(sys.argv[2]).expanduser().resolve()
status = CaptureInboxDaemon(root=capture_root).status()
if Path(str(status.get("root") or "")).resolve() != capture_root:
    raise SystemExit(1)
for key in ("inbox_dir", "processing_dir", "processed_dir", "error_dir", "receipt_dir"):
    if not Path(str(status.get(key) or "")).is_dir():
        raise SystemExit(1)
uri = f"file:{quote(str(memory_db), safe='/')}?mode=ro"
connection = sqlite3.connect(uri, uri=True, timeout=1.0)
try:
    connection.execute("PRAGMA query_only = ON")
    if connection.execute("PRAGMA query_only").fetchone() != (1,):
        raise SystemExit(1)
    required = {"memory_entries", "capture_operations", "store_migrations"}
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN (?, ?, ?)",
            tuple(sorted(required)),
        )
    }
    if present != required:
        raise SystemExit(1)
    connection.execute("SELECT 1 FROM memory_entries LIMIT 1").fetchone()
finally:
    connection.close()
signal.alarm(0)
PY
}

verify_capture_health() {
  local attempt=1
  local observed_pid=""
  local stable_pid=""
  local consecutive=0
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    if service_running; then
      observed_pid="$(service_pid 2>/dev/null || true)"
      if [ -n "$observed_pid" ] \
        && { [ -z "$PRIOR_PID" ] || [ "$observed_pid" != "$PRIOR_PID" ]; } \
        && capture_functional_probe; then
        if [ -z "$stable_pid" ] || [ "$stable_pid" = "$observed_pid" ]; then
          stable_pid="$observed_pid"
          consecutive=$((consecutive + 1))
          if [ "$consecutive" -ge "$REQUIRED_STABLE_CHECKS" ]; then
            NEW_PID="$observed_pid"
            return 0
          fi
        else
          stable_pid="$observed_pid"
          consecutive=1
        fi
      else
        stable_pid=""
        consecutive=0
      fi
    else
      stable_pid=""
      consecutive=0
    fi
    if [ "$attempt" -lt "$HEALTH_ATTEMPTS" ]; then
      sleep "$HEALTH_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

fsync_file_and_parent() {
  "$PYTHON" - "$1" >/dev/null 2>&1 <<'PY'
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

prepare_private_log() {
  "$PYTHON" - "$1" >/dev/null 2>&1 <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    current = path.lstat()
except FileNotFoundError:
    current = None
if current is not None and (stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)):
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(1)
    os.fchmod(descriptor, 0o600)
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

wait_until_service_stops() {
  local attempt=1
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    if ! service_running; then
      return 0
    fi
    if [ "$attempt" -lt "$HEALTH_ATTEMPTS" ]; then
      sleep "$HEALTH_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

wait_until_service_unloads() {
  local attempt=1
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    if ! service_loaded; then
      return 0
    fi
    if [ "$attempt" -lt "$HEALTH_ATTEMPTS" ]; then
      sleep "$HEALTH_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

bootout_service() {
  if ! service_loaded; then
    return 0
  fi
  launchctl bootout "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || true
  wait_until_service_unloads
}

wait_until_service_runs() {
  local attempt=1
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    if service_running; then
      return 0
    fi
    if [ "$attempt" -lt "$HEALTH_ATTEMPTS" ]; then
      sleep "$HEALTH_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

restore_loaded_service_policy() {
  # launchd refuses to bootstrap a disabled service. Load it while temporarily
  # enabled, then restore both its recorded disabled bit and process state.
  if ! launchctl enable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1; then
    return 1
  fi
  if ! launchctl bootstrap "gui/$UID_VALUE" "$PLIST" >/dev/null 2>&1; then
    if [ "$PRIOR_DISABLED" -eq 1 ]; then
      launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || true
    fi
    return 1
  fi
  if [ "$PRIOR_RUNNING" -eq 1 ]; then
    if ! wait_until_service_runs; then
      if ! launchctl kickstart "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 \
        || ! wait_until_service_runs; then
        if [ "$PRIOR_DISABLED" -eq 1 ]; then
          launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || true
        fi
        return 1
      fi
    fi
    if [ "$PRIOR_DISABLED" -eq 1 ]; then
      launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || return 1
    fi
    service_running || return 1
    return 0
  fi

  # Suppress KeepAlive before terminating a process started by RunAtLoad.
  launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || return 1
  if service_running \
    && ! launchctl kill SIGTERM "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1; then
    return 1
  fi
  wait_until_service_stops || return 1
  if [ "$PRIOR_DISABLED" -eq 0 ]; then
    launchctl enable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || return 1
  fi
  if service_running; then
    return 1
  fi
}

rollback_definition() {
  local rollback_status=0
  if ! bootout_service; then
    echo "Capture LaunchAgent rollback could not unload the failed definition" >&2
    rollback_status=1
  fi
  if [ "$HAD_PRIOR_PLIST" -eq 1 ] && [ -n "$PLIST_ROLLBACK" ] && [ -f "$PLIST_ROLLBACK" ]; then
    if mv -f -- "$PLIST_ROLLBACK" "$PLIST"; then
      PLIST_ROLLBACK=""
      chmod 600 "$PLIST"
      fsync_file_and_parent "$PLIST" || rollback_status=1
    else
      echo "Capture LaunchAgent rollback could not restore the prior plist" >&2
      rollback_status=1
    fi
    if [ "$rollback_status" -eq 0 ] && [ "$PRIOR_LOADED" -eq 1 ]; then
      if ! restore_loaded_service_policy; then
        rollback_status=1
      fi
    elif [ "$rollback_status" -eq 0 ]; then
      if [ "$PRIOR_DISABLED" -eq 1 ]; then
        launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || rollback_status=1
      else
        launchctl enable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 || rollback_status=1
      fi
    fi
    if [ "$rollback_status" -ne 0 ]; then
      echo "Capture LaunchAgent rollback could not restore the prior service policy" >&2
    fi
  else
    if [ -e "$PLIST" ] && [ ! -L "$PLIST" ]; then
      if ! rm -f -- "$PLIST"; then
        echo "Capture LaunchAgent rollback could not remove the failed first-install plist" >&2
        rollback_status=1
      fi
    fi
    if [ "$rollback_status" -eq 0 ] && [ "$PRIOR_DISABLED" -eq 1 ] \
      && ! launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1; then
      echo "Capture LaunchAgent rollback could not restore the prior disabled policy" >&2
      rollback_status=1
    fi
  fi
  if [ "$rollback_status" -eq 0 ]; then
    PLIST_REPLACED=0
  fi
  return "$rollback_status"
}

cleanup() {
  local exit_status=$?
  trap - EXIT HUP INT TERM
  if [ "$PLIST_REPLACED" -eq 1 ] && [ "$INSTALL_HEALTHY" -ne 1 ]; then
    rollback_definition || true
  fi
  if [ -n "$PLIST_TEMP" ]; then
    rm -f -- "$PLIST_TEMP"
  fi
  if [ -n "$INSTALL_LOCK" ]; then
    rmdir -- "$INSTALL_LOCK" >/dev/null 2>&1 || true
  fi
  if { [ "$INSTALL_HEALTHY" -eq 1 ] || [ "$PLIST_REPLACED" -eq 0 ]; } \
    && [ -n "$PLIST_ROLLBACK" ]; then
    rm -f -- "$PLIST_ROLLBACK"
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

ensure_private_directory() {
  local target="$1"
  if [ -d "$target" ]; then
    return 0
  fi
  if [ -e "$target" ]; then
    echo "Expected directory but found another file type: $target" >&2
    return 2
  fi
  local parent
  parent="$(dirname "$target")"
  if [ "$parent" != "$target" ]; then
    ensure_private_directory "$parent"
  fi
  mkdir -m 700 "$target"
}

if [ ! -x "$PYTHON" ]; then
  echo "Python runtime is missing or not executable" >&2
  echo "Run uv sync first." >&2
  exit 2
fi

ensure_private_directory "$CAPTURE_ROOT"
ensure_private_directory "$(dirname "$STATE_PATH")"
ensure_private_directory "$(dirname "$MEMORY_DB")"
ensure_private_directory "$(dirname "$LOG_PATH")"
ensure_private_directory "$PLIST_DIR"
INSTALL_LOCK_CANDIDATE="$PLIST_DIR/.${LABEL}.install.lock"
if ! mkdir -m 700 "$INSTALL_LOCK_CANDIDATE" 2>/dev/null; then
  echo "Another Capture LaunchAgent install is already in progress" >&2
  exit 1
fi
INSTALL_LOCK="$INSTALL_LOCK_CANDIDATE"
if ! prepare_private_log "$LOG_PATH"; then
  echo "Capture log target must be a regular non-symlink file" >&2
  exit 2
fi

PLIST_TEMP="$(mktemp "$PLIST_DIR/.${LABEL}.plist.XXXXXX")"
plutil -create xml1 "$PLIST_TEMP"
plutil -insert Label -string "$LABEL" "$PLIST_TEMP"
plutil -insert ProgramArguments -xml '<array/>' "$PLIST_TEMP"

PROGRAM_ARGUMENT_INDEX=0
add_program_argument() {
  plutil -insert "ProgramArguments.$PROGRAM_ARGUMENT_INDEX" -string "$1" "$PLIST_TEMP"
  PROGRAM_ARGUMENT_INDEX=$((PROGRAM_ARGUMENT_INDEX + 1))
}

add_program_argument "$PYTHON"
add_program_argument "$ROOT/capture_daemon.py"
add_program_argument "--capture-root"
add_program_argument "$CAPTURE_ROOT"
add_program_argument "--state"
add_program_argument "$STATE_PATH"
add_program_argument "--memory-db"
add_program_argument "$MEMORY_DB"
add_program_argument "--dimension"
add_program_argument "$DIMENSION"
add_program_argument "--neurons"
add_program_argument "$NEURONS"
add_program_argument "--top-k"
add_program_argument "$TOP_K"
add_program_argument "--poll-interval"
add_program_argument "$POLL_INTERVAL"
if [ "$TRANSCRIPT_POLL" = "1" ] || [ "$TRANSCRIPT_POLL" = "true" ]; then
  add_program_argument "--poll-transcript-sources"
  add_program_argument "--max-transcript-bytes"
  add_program_argument "$MAX_TRANSCRIPT_BYTES"
fi

plutil -insert EnvironmentVariables -xml '<dict/>' "$PLIST_TEMP"
plutil -insert EnvironmentVariables.MLX_DEVICE -string "${MLX_DEVICE:-gpu}" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_EMBEDDING_PROVIDER -string "$EMBEDDING_PROVIDER" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURAL_MODEL -string "$NEURAL_MODEL" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURAL_CACHE_DIR -string "$NEURAL_CACHE_DIR" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY -string "$NEURAL_LOCAL_FILES_ONLY" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_DIMENSION -string "$DIMENSION" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURONS -string "$NEURONS" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_TOP_K -string "$TOP_K" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_RECALL_COUNT -string "$RECALL_COUNT" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_CAPTURE_ROOT -string "$CAPTURE_ROOT" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_STATE_PATH -string "$STATE_PATH" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_MEMORY_DB -string "$MEMORY_DB" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_TRANSCRIPT_POLL -string "$TRANSCRIPT_POLL" "$PLIST_TEMP"
plutil -insert RunAtLoad -bool YES "$PLIST_TEMP"
plutil -insert KeepAlive -bool YES "$PLIST_TEMP"
plutil -insert Umask -integer 63 "$PLIST_TEMP"
plutil -insert StandardOutPath -string "$LOG_PATH" "$PLIST_TEMP"
plutil -insert StandardErrorPath -string "$LOG_PATH" "$PLIST_TEMP"
plutil -insert WorkingDirectory -string "$ROOT" "$PLIST_TEMP"

chmod 600 "$PLIST_TEMP"
plutil -lint "$PLIST_TEMP" >/dev/null
fsync_file_and_parent "$PLIST_TEMP"

if [ -L "$PLIST" ]; then
  echo "Refusing to replace a symlinked Capture LaunchAgent plist" >&2
  exit 2
fi
if [ -e "$PLIST" ] && [ ! -f "$PLIST" ]; then
  echo "Refusing to replace a non-regular Capture LaunchAgent plist" >&2
  exit 2
fi

if service_loaded; then
  PRIOR_LOADED=1
  if service_running; then
    PRIOR_RUNNING=1
    PRIOR_PID="$(service_pid 2>/dev/null || true)"
  fi
fi
if service_disabled; then
  PRIOR_DISABLED=1
fi
if [ "$PRIOR_LOADED" -eq 1 ] && [ ! -f "$PLIST" ]; then
  echo "Capture LaunchAgent is loaded without a restorable local plist" >&2
  exit 2
fi
if [ -f "$PLIST" ]; then
  HAD_PRIOR_PLIST=1
  PLIST_ROLLBACK="$(mktemp "$PLIST_DIR/.${LABEL}.rollback.XXXXXX")"
  cp -- "$PLIST" "$PLIST_ROLLBACK"
  chmod 600 "$PLIST_ROLLBACK"
  fsync_file_and_parent "$PLIST_ROLLBACK"
fi

PLIST_REPLACED=1
mv -f -- "$PLIST_TEMP" "$PLIST"
PLIST_TEMP=""
fsync_file_and_parent "$PLIST"

if ! bootout_service; then
  echo "Capture LaunchAgent could not quiesce its prior launchd definition" >&2
  exit 1
fi
if ! launchctl enable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 \
  || ! launchctl bootstrap "gui/$UID_VALUE" "$PLIST" >/dev/null 2>&1; then
  echo "Capture LaunchAgent activation failed; restoring the prior definition" >&2
  exit 1
fi

if ! verify_capture_health; then
  echo "Capture LaunchAgent failed its stabilized process, inbox-status, or read-only database health gate; restoring the prior definition" >&2
  exit 1
fi

INSTALL_HEALTHY=1
echo "Capture LaunchAgent installed and healthy"
