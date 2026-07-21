#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="${SYNAPSE_S2_CORE_PYTHON:-$ROOT/.venv/bin/python}"

if [ ! -x "$PYTHON" ]; then
  echo "Authoritative-core Python runtime is missing or not executable" >&2
  exit 2
fi

exec "$PYTHON" "$SCRIPT_DIR/core_cutover_preflight.py" "$@"
