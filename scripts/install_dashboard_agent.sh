#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$#" -gt 1 ]; then
  echo "Usage: $0 [install|status]" >&2
  exit 2
fi
if [ "$#" -eq 0 ]; then
  DASHBOARD_AGENT_ACTION="install"
else
  DASHBOARD_AGENT_ACTION="$1"
fi
case "$DASHBOARD_AGENT_ACTION" in
  install|status) ;;
  -h|--help|help)
    echo "Usage: $0 [install|status]"
    exit 0
    ;;
  *)
    echo "Usage: $0 [install|status]" >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LABEL="${SYNAPSE_S2_DASHBOARD_LABEL:-aero.boom.synapse-s2.dashboard}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HOST="${SYNAPSE_S2_DASHBOARD_HOST:-127.0.0.1}"
PORT="${SYNAPSE_S2_DASHBOARD_PORT:-8765}"
CONTEXT="${SYNAPSE_S2_DASHBOARD_CONTEXT:-default}"
LOG_PATH="${SYNAPSE_S2_DASHBOARD_LOG:-$ROOT/.synapse_s2/dashboard.log}"
PYTHON="${SYNAPSE_S2_PYTHON:-$ROOT/.venv/bin/python}"
CORE_BINDING=""
CANONICAL_DATA_ROOT="$ROOT/.synapse_s2"
STATE_PATH="$CANONICAL_DATA_ROOT/runtime_state.json"
MEMORY_DB="$CANONICAL_DATA_ROOT/memory.sqlite3"
EXPORT_DIR="$CANONICAL_DATA_ROOT"
CAPTURE_ROOT="$CANONICAL_DATA_ROOT"
DASHBOARD_AUTH_FILE="${SYNAPSE_S2_DASHBOARD_AUTH_FILE:-$CANONICAL_DATA_ROOT/dashboard-auth.json}"
NEURAL_CACHE_DIR="$CANONICAL_DATA_ROOT/models"
EMBEDDING_PROVIDER="${SYNAPSE_S2_EMBEDDING_PROVIDER:-mlx-neural}"
NEURAL_MODEL="${SYNAPSE_S2_NEURAL_MODEL:-mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ}"
NEURAL_LOCAL_FILES_ONLY="${SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY:-1}"
DIMENSION="${SYNAPSE_S2_DIMENSION:-1024}"
NEURONS="${SYNAPSE_S2_NEURONS:-8192}"
TOP_K="${SYNAPSE_S2_TOP_K:-256}"
RECALL_COUNT="${SYNAPSE_S2_RECALL_COUNT:-10}"
DEFAULT_RESPONSE_MODE="${SYNAPSE_S2_DEFAULT_RESPONSE_MODE:-compact}"
MAX_RESPONSE_BYTES="${SYNAPSE_S2_MAX_RESPONSE_BYTES:-12288}"
UID_VALUE="$(id -u)"
PLIST_DIR="$(dirname "$PLIST")"
PLIST_TEMP=""
PLIST_ROLLBACK=""
PLIST_REPLACED=0
INSTALL_HEALTHY=0
HAD_PRIOR_PLIST=0
PRIOR_LOADED=0
PRIOR_DISABLED=0
PRIOR_RUNNING=0
PRIOR_PID=""
NEW_PID=""
HEALTH_COOKIE_FILE=""
HEALTH_ATTEMPTS="${SYNAPSE_S2_INSTALL_HEALTH_ATTEMPTS:-120}"
HEALTH_DELAY="${SYNAPSE_S2_INSTALL_HEALTH_DELAY:-0.25}"
STABLE_CHECKS="${SYNAPSE_S2_INSTALL_STABLE_CHECKS:-3}"
STABILIZATION_SECONDS="${SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS:-1.0}"
REQUIRED_STABLE_CHECKS=0

if [ ! -x "$PYTHON" ]; then
  echo "Python runtime is missing or not executable" >&2
  echo "Run uv sync first." >&2
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
  echo "Dashboard core binding is invalid" >&2
  exit 2
fi

require_canonical_or_unset() {
  local variable_name="$1"
  local expected="$2"
  local configured="${!variable_name:-}"
  if [ -n "$configured" ] && [ "$configured" != "$expected" ]; then
    echo "Noncanonical dashboard paths require a reviewed core binding" >&2
    exit 2
  fi
}

if [ -z "$CORE_BINDING" ]; then
  if [ -n "${SYNAPSE_S2_CORE_SOCKET:-}" ] \
    || [ -n "${SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT:-}" ]; then
    echo "Authoritative dashboard routing requires a reviewed core binding" >&2
    exit 2
  fi
  require_canonical_or_unset SYNAPSE_S2_STATE_PATH "$STATE_PATH"
  require_canonical_or_unset SYNAPSE_S2_MEMORY_DB "$MEMORY_DB"
  require_canonical_or_unset SYNAPSE_S2_EXPORT_DIR "$EXPORT_DIR"
  require_canonical_or_unset SYNAPSE_S2_CAPTURE_ROOT "$CAPTURE_ROOT"
  require_canonical_or_unset SYNAPSE_S2_NEURAL_CACHE_DIR "$NEURAL_CACHE_DIR"
fi

case "$LABEL" in
  ""|*[!A-Za-z0-9._-]*)
    echo "Dashboard LaunchAgent label contains unsupported characters" >&2
    exit 2
    ;;
esac

case "$PORT" in
  ""|*[!0-9]*)
    echo "Dashboard port must be an integer between 1 and 65535" >&2
    exit 2
    ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "Dashboard port must be an integer between 1 and 65535" >&2
  exit 2
fi

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
  "$LABEL" "$PLIST" "$LOG_PATH" "$PYTHON" "$CORE_BINDING" \
  "$DEFAULT_RESPONSE_MODE" "$MAX_RESPONSE_BYTES" "$CONTEXT" \
  "$DASHBOARD_AUTH_FILE"; do
  if contains_secret_shape "$configured_value"; then
    echo "Dashboard installer rejected credential-shaped configuration" >&2
    exit 2
  fi
done
if [ -z "$CORE_BINDING" ]; then
  for configured_value in \
    "$STATE_PATH" "$MEMORY_DB" "$EXPORT_DIR" "$CAPTURE_ROOT" \
    "$NEURAL_CACHE_DIR" "$EMBEDDING_PROVIDER" "$NEURAL_MODEL" \
    "${MLX_DEVICE:-gpu}"; do
    if contains_secret_shape "$configured_value"; then
      echo "Dashboard installer rejected credential-shaped configuration" >&2
      exit 2
    fi
  done
fi

service_running() {
  launchctl print "gui/$UID_VALUE/$LABEL" 2>/dev/null \
    | awk '$1 == "state" && $2 == "=" && $3 == "running" { found = 1 } END { exit(found ? 0 : 1) }'
}

service_loaded() {
  local domain_inventory=""
  if launchctl print "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1; then
    return 0
  fi
  domain_inventory="$(launchctl print "gui/$UID_VALUE" 2>/dev/null)" || return 2
  if printf '%s\n' "$domain_inventory" \
    | awk -v label="$LABEL" '$NF == label { found = 1 } END { exit(found ? 0 : 1) }'; then
    return 2
  fi
  return 1
}

service_disabled() {
  local disabled_inventory=""
  disabled_inventory="$(launchctl print-disabled "gui/$UID_VALUE" 2>/dev/null)" || return 2
  printf '%s\n' "$disabled_inventory" | awk -v label="$LABEL" '
      index($0, "\"" label "\"") && $0 ~ /=>[[:space:]]*true/ { found = 1 }
      END { exit(found ? 0 : 1) }
    '
}

service_pid() {
  launchctl print "gui/$UID_VALUE/$LABEL" 2>/dev/null \
    | awk '$1 == "pid" && $2 == "=" && $3 ~ /^[0-9]+$/ { print $3; found = 1; exit } END { exit(found ? 0 : 1) }'
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

dashboard_curl_config() {
  "$PYTHON" - "$DASHBOARD_AUTH_FILE" "$HOST" "$PORT" "$CONTEXT" "$1" <<'PY'
import json
import os
import re
import stat
import sys
import urllib.parse
from pathlib import Path

path = Path(sys.argv[1])
host = sys.argv[2]
port = int(sys.argv[3])
context = sys.argv[4]
mode = sys.argv[5]
visible = path.lstat()
if (
    stat.S_ISLNK(visible.st_mode)
    or not stat.S_ISREG(visible.st_mode)
    or visible.st_uid != os.geteuid()
    or visible.st_nlink != 1
    or stat.S_IMODE(visible.st_mode) != 0o600
    or visible.st_size > 4096
):
    raise SystemExit(1)
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    chunks = []
    remaining = 4097
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    finished = os.fstat(descriptor)
finally:
    os.close(descriptor)
raw = b"".join(chunks)
if (
    (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
    or (finished.st_size, finished.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns)
    or len(raw) > 4096
):
    raise SystemExit(1)
auth = json.loads(raw)
bootstrap_url = auth.get("bootstrap_url")
session_header = auth.get("session_header")
parsed = urllib.parse.urlparse(bootstrap_url)
params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
tokens = params.get("token", [])
if (
    auth.get("schema") != "synapse-s2.dashboard-auth.v1"
    or parsed.scheme != "http"
    or parsed.hostname != host
    or int(parsed.port or 80) != port
    or parsed.path != "/__dashboard_bootstrap"
    or parsed.username is not None
    or parsed.password is not None
    or parsed.params
    or parsed.fragment
    or set(params) != {"token"}
    or len(tokens) != 1
    or re.fullmatch(r"[A-Za-z0-9_-]{40,128}", tokens[0]) is None
    or not isinstance(session_header, str)
    or re.fullmatch(r"[A-Za-z0-9_-]{40,128}", session_header) is None
):
    raise SystemExit(1)
if any(character in bootstrap_url for character in ('"', "\\", "\r", "\n")):
    raise SystemExit(1)
if mode == "bootstrap":
    print(f'url = "{bootstrap_url}"')
elif mode == "health":
    rendered_host = f"[{host}]" if ":" in host else host
    health_url = (
        f"http://{rendered_host}:{port}/api/status?"
        f"{urllib.parse.urlencode({'context': context})}"
    )
    print(f'url = "{health_url}"')
    print(f'header = "X-Synapse-Dashboard-Session: {session_header}"')
else:
    raise SystemExit(1)
PY
}

dashboard_http_healthy() {
  local bootstrap_status=""
  local response=""
  if [ -z "$HEALTH_COOKIE_FILE" ]; then
    HEALTH_COOKIE_FILE="$(mktemp "$(dirname "$DASHBOARD_AUTH_FILE")/.dashboard-health-cookie.XXXXXX")"
    chmod 600 "$HEALTH_COOKIE_FILE"
  else
    : > "$HEALTH_COOKIE_FILE"
    chmod 600 "$HEALTH_COOKIE_FILE"
  fi
  bootstrap_status="$(
    dashboard_curl_config bootstrap \
      | curl --fail --silent --show-error --noproxy '*' \
          --connect-timeout 1 --max-time 3 --proto '=http' \
          --cookie-jar "$HEALTH_COOKIE_FILE" --cookie "$HEALTH_COOKIE_FILE" \
          --output /dev/null --write-out '%{http_code}' --config -
  )" || return 1
  [ "$bootstrap_status" = "303" ] || return 1
  response="$(
    dashboard_curl_config health \
      | curl --fail --silent --show-error --noproxy '*' \
          --connect-timeout 1 --max-time 3 --proto '=http' \
          --cookie "$HEALTH_COOKIE_FILE" --config - 2>/dev/null
  )" || return 1
  printf '%s' "$response" | "$PYTHON" -c '
import json, sys
payload = json.load(sys.stdin)
if not isinstance(payload, dict):
    raise SystemExit(1)
if payload.get("runtime") != "ready" or payload.get("effective_enabled") is not True:
    raise SystemExit(1)
if not isinstance(payload.get("memory_db_path"), str) or not payload["memory_db_path"]:
    raise SystemExit(1)
count = payload.get("memory_context_entry_count")
if type(count) is not int or count < 0:
    raise SystemExit(1)
' >/dev/null 2>&1
}

verify_dashboard_health() {
  local attempt=1
  local observed_pid=""
  local stable_pid=""
  local consecutive=0
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    if service_running; then
      observed_pid="$(service_pid 2>/dev/null || true)"
      if [ -n "$observed_pid" ] \
        && { [ -z "$PRIOR_PID" ] || [ "$observed_pid" != "$PRIOR_PID" ]; } \
        && listener_is_loopback "$observed_pid" \
        && dashboard_http_healthy; then
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

dashboard_status() {
  local disabled_status=0
  local load_status=0
  local plist_present=false
  local plist_safe=false
  local loaded=false
  local running=false
  local disabled=false
  local loopback_listener=false
  local process_ready=false
  local observed_pid=""
  local rendered_pid="null"

  if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then
    plist_present=true
    if "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" validate-regular \
      --path "$PLIST" >/dev/null 2>&1; then
      plist_safe=true
    else
      printf '{"action":"status","error":"launch-agent-plist-unsafe","label":"%s","plist_present":true,"plist_safe":false,"process_ready":false}\n' "$LABEL"
      return 2
    fi
  fi

  if service_loaded; then
    load_status=0
  else
    load_status=$?
  fi
  case "$load_status" in
    0) loaded=true ;;
    1) ;;
    *)
      printf '{"action":"status","error":"launch-agent-state-unclassified","label":"%s","plist_present":%s,"plist_safe":%s,"process_ready":false}\n' \
        "$LABEL" "$plist_present" "$plist_safe"
      return 2
      ;;
  esac
  if [ "$loaded" = true ] && [ "$plist_present" = false ]; then
    printf '{"action":"status","error":"loaded-without-restorable-plist","label":"%s","loaded":true,"plist_present":false,"plist_safe":false,"process_ready":false}\n' "$LABEL"
    return 2
  fi

  if service_disabled; then
    disabled_status=0
  else
    disabled_status=$?
  fi
  case "$disabled_status" in
    0) disabled=true ;;
    1) ;;
    *)
      printf '{"action":"status","error":"launch-agent-policy-unclassified","label":"%s","loaded":%s,"plist_present":%s,"plist_safe":%s,"process_ready":false}\n' \
        "$LABEL" "$loaded" "$plist_present" "$plist_safe"
      return 2
      ;;
  esac

  if [ "$loaded" = true ] && service_running; then
    running=true
    observed_pid="$(service_pid 2>/dev/null || true)"
    if [ -n "$observed_pid" ]; then
      rendered_pid="$observed_pid"
      if listener_is_loopback "$observed_pid"; then
        loopback_listener=true
      fi
    fi
  fi
  if [ "$plist_present" = true ] \
    && [ "$plist_safe" = true ] \
    && [ "$loaded" = true ] \
    && [ "$running" = true ] \
    && [ "$disabled" = false ] \
    && [ "$rendered_pid" != null ] \
    && [ "$loopback_listener" = true ]; then
    process_ready=true
  fi
  printf '{"action":"status","disabled":%s,"host":"%s","label":"%s","loaded":%s,"loopback_listener":%s,"pid":%s,"plist_present":%s,"plist_safe":%s,"port":%s,"process_ready":%s,"running":%s}\n' \
    "$disabled" "$HOST" "$LABEL" "$loaded" "$loopback_listener" "$rendered_pid" \
    "$plist_present" "$plist_safe" "$PORT" "$process_ready" "$running"
  if [ "$process_ready" = true ]; then
    return 0
  fi
  return 1
}

listener_is_loopback() {
  local service_process_id="$1"
  lsof -nP -a -p "$service_process_id" -iTCP:"$PORT" -sTCP:LISTEN -Fn 2>/dev/null \
    | awk -v port="$PORT" '
      BEGIN { suffix = ":" port }
      substr($0, 1, 1) == "n" && substr($0, length($0) - length(suffix) + 1) == suffix {
        address = substr($0, 2, length($0) - length(suffix) - 1)
        if (address == "127.0.0.1" || address == "localhost" || address == "::1" || address == "[::1]") {
          found = 1
        } else {
          unsafe = 1
        }
      }
      END { exit(found && !unsafe ? 0 : 1) }
    '
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
  local load_status=0
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    set +e
    service_loaded
    load_status=$?
    set -e
    case "$load_status" in
      0) ;;
      1) return 0 ;;
      *) return 1 ;;
    esac
    if [ "$attempt" -lt "$HEALTH_ATTEMPTS" ]; then
      sleep "$HEALTH_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

bootout_service() {
  local load_status=0
  set +e
  service_loaded
  load_status=$?
  set -e
  case "$load_status" in
    0) ;;
    1) return 0 ;;
    *) return 1 ;;
  esac
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
    echo "Dashboard LaunchAgent rollback could not unload the failed definition" >&2
    rollback_status=1
  fi
  if [ "$HAD_PRIOR_PLIST" -eq 1 ] && [ -n "$PLIST_ROLLBACK" ] && [ -f "$PLIST_ROLLBACK" ]; then
    if "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" replace-regular \
      --source "$PLIST_ROLLBACK" --target "$PLIST"; then
      PLIST_ROLLBACK=""
      fsync_file_and_parent "$PLIST" || rollback_status=1
    else
      echo "Dashboard LaunchAgent rollback could not restore the prior plist" >&2
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
      echo "Dashboard LaunchAgent rollback could not restore the prior service policy" >&2
    fi
  else
    if [ -e "$PLIST" ] && [ ! -L "$PLIST" ]; then
      if ! rm -f -- "$PLIST"; then
        echo "Dashboard LaunchAgent rollback could not remove the failed first-install plist" >&2
        rollback_status=1
      fi
    fi
    if [ "$rollback_status" -eq 0 ] && [ "$PRIOR_DISABLED" -eq 1 ] \
      && ! launchctl disable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1; then
      echo "Dashboard LaunchAgent rollback could not restore the prior disabled policy" >&2
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
  if [ -n "$HEALTH_COOKIE_FILE" ]; then
    rm -f -- "$HEALTH_COOKIE_FILE"
  fi
  if { [ "$INSTALL_HEALTHY" -eq 1 ] || [ "$PLIST_REPLACED" -eq 0 ]; } \
    && [ -n "$PLIST_ROLLBACK" ]; then
    rm -f -- "$PLIST_ROLLBACK"
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$DEFAULT_RESPONSE_MODE" in
  compact|full) ;;
  *)
    echo "Dashboard response mode must be compact or full" >&2
    exit 2
    ;;
esac
case "$MAX_RESPONSE_BYTES" in
  ""|*[!0-9]*)
    echo "Dashboard response budget must be an integer" >&2
    exit 2
    ;;
esac
if [ "$MAX_RESPONSE_BYTES" -lt 1024 ] || [ "$MAX_RESPONSE_BYTES" -gt 1048576 ]; then
  echo "Dashboard response budget is outside its safety bound" >&2
  exit 2
fi

case "$HOST" in
  127.0.0.1|localhost|::1) ;;
  *)
    echo "Dashboard host must be loopback-only: $HOST" >&2
    exit 2
    ;;
esac

if [ "$DASHBOARD_AGENT_ACTION" = status ]; then
  trap - EXIT HUP INT TERM
  if dashboard_status; then
    exit 0
  else
    STATUS_RESULT=$?
    exit "$STATUS_RESULT"
  fi
fi

LOCK_MARKER="dashboard:$LABEL"
INSTALL_LOCK_PATH="$PLIST_DIR/.${LABEL}.install.lock"
if [ "${SYNAPSE_S2_INSTALL_LOCK_HELD:-}" != "$LOCK_MARKER" ]; then
  exec "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" run-locked \
    --lock "$INSTALL_LOCK_PATH" \
    --marker "$LOCK_MARKER" \
    -- /bin/bash "$0" "$@"
fi

"$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" ensure-directory \
  --path "$PLIST_DIR" --shared
"$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" ensure-directory \
  --path "$CANONICAL_DATA_ROOT"
"$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" ensure-directory \
  --path "$(dirname "$DASHBOARD_AUTH_FILE")"
if [ -z "$CORE_BINDING" ]; then
  "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" ensure-directory \
    --path "$EXPORT_DIR"
fi
if ! "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" prepare-log \
  --path "$LOG_PATH"; then
  echo "Dashboard log target must be a regular non-symlink file" >&2
  exit 2
fi

PLIST_TEMP="$(mktemp "$PLIST_DIR/.${LABEL}.plist.XXXXXX")"
plutil -create xml1 "$PLIST_TEMP"
plutil -insert Label -string "$LABEL" "$PLIST_TEMP"
plutil -insert ProgramArguments -xml '<array/>' "$PLIST_TEMP"
plutil -insert ProgramArguments.0 -string "$PYTHON" "$PLIST_TEMP"
plutil -insert ProgramArguments.1 -string "$ROOT/dashboard_server.py" "$PLIST_TEMP"
plutil -insert ProgramArguments.2 -string "--host" "$PLIST_TEMP"
plutil -insert ProgramArguments.3 -string "$HOST" "$PLIST_TEMP"
plutil -insert ProgramArguments.4 -string "--port" "$PLIST_TEMP"
plutil -insert ProgramArguments.5 -string "$PORT" "$PLIST_TEMP"
plutil -insert ProgramArguments.6 -string "--context" "$PLIST_TEMP"
plutil -insert ProgramArguments.7 -string "$CONTEXT" "$PLIST_TEMP"
plutil -insert ProgramArguments.8 -string "--auth-file" "$PLIST_TEMP"
plutil -insert ProgramArguments.9 -string "$DASHBOARD_AUTH_FILE" "$PLIST_TEMP"
plutil -insert EnvironmentVariables -xml '<dict/>' "$PLIST_TEMP"
if [ -n "$CORE_BINDING" ]; then
  plutil -insert EnvironmentVariables.SYNAPSE_S2_CORE_BINDING -string "$CORE_BINDING" "$PLIST_TEMP"
else
  plutil -insert EnvironmentVariables.MLX_DEVICE -string "${MLX_DEVICE:-gpu}" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_EMBEDDING_PROVIDER -string "$EMBEDDING_PROVIDER" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURAL_MODEL -string "$NEURAL_MODEL" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURAL_CACHE_DIR -string "$NEURAL_CACHE_DIR" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY -string "$NEURAL_LOCAL_FILES_ONLY" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_DIMENSION -string "$DIMENSION" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_NEURONS -string "$NEURONS" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_TOP_K -string "$TOP_K" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_RECALL_COUNT -string "$RECALL_COUNT" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_STATE_PATH -string "$STATE_PATH" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_MEMORY_DB -string "$MEMORY_DB" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_EXPORT_DIR -string "$EXPORT_DIR" "$PLIST_TEMP"
  plutil -insert EnvironmentVariables.SYNAPSE_S2_CAPTURE_ROOT -string "$CAPTURE_ROOT" "$PLIST_TEMP"
fi
plutil -insert EnvironmentVariables.SYNAPSE_S2_DEFAULT_RESPONSE_MODE -string "$DEFAULT_RESPONSE_MODE" "$PLIST_TEMP"
plutil -insert EnvironmentVariables.SYNAPSE_S2_MAX_RESPONSE_BYTES -string "$MAX_RESPONSE_BYTES" "$PLIST_TEMP"
plutil -insert RunAtLoad -bool YES "$PLIST_TEMP"
plutil -insert KeepAlive -bool YES "$PLIST_TEMP"
plutil -insert Umask -integer 63 "$PLIST_TEMP"
plutil -insert StandardOutPath -string "$LOG_PATH" "$PLIST_TEMP"
plutil -insert StandardErrorPath -string "$LOG_PATH" "$PLIST_TEMP"
plutil -insert WorkingDirectory -string "$ROOT" "$PLIST_TEMP"

chmod 600 "$PLIST_TEMP"
plutil -lint "$PLIST_TEMP" >/dev/null
fsync_file_and_parent "$PLIST_TEMP"

if ! "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" validate-regular \
  --path "$PLIST" --allow-missing; then
  echo "Refusing to replace an unsafe Dashboard LaunchAgent plist" >&2
  exit 2
fi

set +e
service_loaded
SERVICE_LOAD_STATUS=$?
set -e
if [ "$SERVICE_LOAD_STATUS" -eq 0 ]; then
  PRIOR_LOADED=1
  if service_running; then
    PRIOR_RUNNING=1
    PRIOR_PID="$(service_pid 2>/dev/null || true)"
  fi
elif [ "$SERVICE_LOAD_STATUS" -ne 1 ]; then
  echo "Dashboard LaunchAgent state could not be classified safely" >&2
  exit 2
fi
if service_disabled; then
  PRIOR_DISABLED=1
fi
if [ "$PRIOR_LOADED" -eq 1 ] && [ ! -f "$PLIST" ]; then
  echo "Dashboard LaunchAgent is loaded without a restorable local plist" >&2
  exit 2
fi
if [ -f "$PLIST" ]; then
  HAD_PRIOR_PLIST=1
  PLIST_ROLLBACK="$(mktemp "$PLIST_DIR/.${LABEL}.rollback.XXXXXX")"
  chmod 600 "$PLIST_ROLLBACK"
  "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" backup-regular \
    --source "$PLIST" --target "$PLIST_ROLLBACK"
  fsync_file_and_parent "$PLIST_ROLLBACK"
fi

PLIST_REPLACED=1
if [ "$HAD_PRIOR_PLIST" -eq 1 ]; then
  "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" replace-regular \
    --source "$PLIST_TEMP" --target "$PLIST" \
    --expected-current "$PLIST_ROLLBACK"
else
  "$PYTHON" "$SCRIPT_DIR/secure_installer_support.py" replace-regular \
    --source "$PLIST_TEMP" --target "$PLIST" --expect-absent
fi
PLIST_TEMP=""
fsync_file_and_parent "$PLIST"
if ! bootout_service; then
  echo "Dashboard LaunchAgent could not quiesce its prior launchd definition" >&2
  exit 1
fi
if ! launchctl enable "gui/$UID_VALUE/$LABEL" >/dev/null 2>&1 \
  || ! launchctl bootstrap "gui/$UID_VALUE" "$PLIST" >/dev/null 2>&1; then
  echo "Dashboard LaunchAgent activation failed; restoring the prior definition" >&2
  exit 1
fi

if ! verify_dashboard_health; then
  echo "Dashboard LaunchAgent failed its stabilized process, loopback-listener, or authoritative API health gate; restoring the prior definition" >&2
  exit 1
fi

INSTALL_HEALTHY=1
echo "Dashboard LaunchAgent installed and healthy"
echo "Open it with: $PYTHON $SCRIPT_DIR/open_dashboard.py"
