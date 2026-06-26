# SYNAPSE-S2 Agent Operating Notes

Use SYNAPSE-S2 as the durable local memory substrate for this repository.

At the start of substantive work, inspect the current memory context:

```bash
.venv/bin/python synapse_cli.py --json pull-context --context default --since-event-id 0 --limit 20
.venv/bin/python synapse_cli.py --json graph --context default --limit 30
```

When a session produces useful project memory, capture a concise factual session note before finishing:

```bash
.venv/bin/python synapse_cli.py --json capture-inbox-drop \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "<factual decisions, implementation details, validation evidence, and follow-up constraints>"
.venv/bin/python synapse_cli.py --json capture-inbox-process
```

If the capture sidecar is not running or you need immediate synchronous capture, use the direct path:

```bash
.venv/bin/python synapse_cli.py --json capture-session \
  --context default \
  --tag codex-session \
  --speaker codex \
  --text "<factual decisions, implementation details, validation evidence, and follow-up constraints>"
```

Capture real decisions, corrections, temporal order, blockers, and validation evidence. Do not capture credentials, tokens, private keys, unnecessary personal data, or speculative claims as memory. The inbox path redacts common secret shapes before ingestion, but do not rely on redaction as permission to capture sensitive material.

If memory is wrong, sensitive, or only partially true, prune it rather than leaving it in the graph:

```bash
.venv/bin/python synapse_cli.py --json prune-memory \
  --context default \
  --target-type event \
  --memory-id "<memory-id>" \
  --reason "<why this is being removed>" \
  --confirm
```

Supported prune targets are `event`, `memory`, `relationship`, `context_event`, `temporal`, and `associative`. Prefer deleting a single node or relationship edge when possible. Use mode-wide `temporal` or `associative` pruning only when the entire relationship class is bad for the selected context.
