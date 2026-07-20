# SYNAPSE-S2 Agent Operating Notes

Use SYNAPSE-S2 as the durable local memory substrate for this repository.

SYNAPSE-S2 MCP clients launched through `/Users/dan.driver/.local/bin/synapse-s2-mcp` hydrate recall and graph state without claiming unseen events at process startup, enter a strict Cortex Governor session, and drop a sanitized session-boundary note plus typed `follow_up` cortical trace on exit. At the start of substantive repo work, run a manual hydrate when you need the briefing visible in the terminal or thread context. It leases events but does not acknowledge them before output; acknowledge the returned `receipt_id` values only after use:

```bash
.venv/bin/python synapse_cli.py --json agent-brief \
  --context default \
  --agent-id codex-desktop \
  --prompt "<current task or user request>" \
  --response-mode compact \
  --max-response-bytes 12288
# After actually consuming each deployment, acknowledge its exact receipt:
.venv/bin/python synapse_cli.py --json ack-context \
  --context default \
  --agent-id codex-desktop \
  --receipt-id '<data.delivery.deployments[].receipt_id from agent-brief>'
```

If you need lower-level diagnostics, inspect the raw context bus and graph:

```bash
.venv/bin/python synapse_cli.py --json observe-context --context default --since-event-id 0 --order asc --limit 20
.venv/bin/python synapse_cli.py --json graph --context default --limit 30 \
  --response-mode compact --max-response-bytes 12288
```

`observe-context` is a raw read-only delivery-ledger diagnostic, not one of the
four compact response-contract surfaces. Keep its limit small and do not paste
the raw output into an agent context unless the individual events are needed.

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

For new topics, threads, or feature work, make the namespace explicit in the capture text when possible. Use short prefixes such as `Thread:`, `Feature:`, `Goal:`, `Objective:`, and `Event:` so SYNAPSE-S2 creates typed namespace nodes and temporal event relationships automatically.

When relevant context lives in another already-running local app, use App Connect instead of inventing a brittle scrape path. Detect, attach, and snapshot only what is locally visible and relevant:

```bash
.venv/bin/python synapse_cli.py --json app-list
.venv/bin/python synapse_cli.py --json app-connect \
  --context default \
  --app-name "<running app name>" \
  --tag app-connect \
  --speaker operator \
  --confirm
.venv/bin/python synapse_cli.py --json app-snapshot \
  --connection-id "<connection-id>" \
  --confirm
```

If an app blocks Accessibility snapshots, select the relevant text in that app and run `scripts/capture_frontmost_selection.sh default frontmost-selection operator`; it performs one selected-text capture and restores the previous clipboard.

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
