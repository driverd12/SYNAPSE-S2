"""Official LongMemEval-V2 harness integration for SYNAPSE-S2.

This package implements the official ``memory_modules.memory.Memory``
contract (memory_type ``synapse_s2``) so the pinned official LongMemEval-V2
checkout can index trajectories into a disposable SYNAPSE-S2 store and query
it for reader context.  Nothing here computes or claims an official score:
scoring belongs to the official harness, reader, and judge.  Until a complete
official run has executed with the external prerequisites (official dataset,
Qwen3.5-9B reader endpoint, Qwen3-Embedding-8B/controller endpoints where
applicable, GPT-5.2 judge key), the only claim this package supports is
"official-harness-adapter-ready".

Import strategy: the package lives inside the SYNAPSE-S2 repository and is
made visible to the pinned official checkout by putting this repository root
on ``sys.path`` for this process only (no file in the official checkout is
ever edited and no PYTHONPATH is persisted).  ``official_longmem.bootstrap``
verifies the exact pinned checkout commit, wires ``sys.path``, and registers
``synapse_s2`` with the pinned official registry before the official harness
builds or loads any memory.
"""

from __future__ import annotations

import sys
from pathlib import Path

ADAPTER_VERSION = "3.0.0"
OFFICIAL_COMMIT_PIN = "2cc8c540bdb87fe6761629b585e727e1c4704520"

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
