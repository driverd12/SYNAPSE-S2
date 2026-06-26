# SYNAPSE-S2 Tomorrow Runbook

This is the fast operator path for using SYNAPSE-S2 from this Mac tomorrow.

## One-command preflight

```bash
cd "/Users/dan.driver/Documents/Neuromorphic Spiking Attention Plugin for Local AI Clients: An Apple Silicon Optimized MCP Architecture"
scripts/prep_tomorrow.sh
```

The script installs or refreshes the local launcher, runs the unit suite, checks bytecode compilation, seeds the `board-demo` memory context, runs CLI preflight, exercises the FastMCP launcher, and writes a SQLite backup into `.synapse_s2`.

## Expected ready signal

The CLI preflight JSON should include:

```json
{
  "ready": true,
  "failed_checks": []
}
```

If `ready` is false, inspect `failed_checks` first. The common checks are:

| Check | Meaning | Fix |
| :--- | :--- | :--- |
| `dependencies_importable` | `mlx.core`, `mlxsnn`, `fastmcp`, or `mcp` is not importable. | Run `uv sync`. |
| `launcher_executable` | `/Users/dan.driver/.local/bin/synapse-s2-mcp` is missing or not executable. | Run `scripts/install_local_launcher.sh`. |
| `memory_minimum_met` | The selected context has fewer persisted memories than requested. | Run `synapse_cli.py --json seed-demo --context board-demo`. |
| `effective_enabled` | The selected context is disabled. | Run `synapse_cli.py --json enable --context board-demo`. |
| `query_returned_context` | Recall did not return a registered context. | Seed or remember a matching trace, then query again. |

## Operator commands

Status:

```bash
.venv/bin/python synapse_cli.py --json status --context board-demo
```

Compact memory list:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context board-demo --limit 10
```

Full vector details, only when needed:

```bash
.venv/bin/python synapse_cli.py --json list-memory --context board-demo --limit 2 --include-vectors
```

Recall smoke:

```bash
.venv/bin/python synapse_cli.py --json query-text \
  --context board-demo \
  --text "durable real memory local SQLite substrate MCP list export backup toggle remember recall context across clients"
```

Backup:

```bash
.venv/bin/python synapse_cli.py --json backup-memory \
  --output .synapse_s2/manual-memory-backup.sqlite3
```

## MCP Inspector

Use the launcher directly:

```bash
npx @anthropic-ai/mcp-inspector /Users/dan.driver/.local/bin/synapse-s2-mcp
```

Useful tool calls:

| Tool | Use |
| :--- | :--- |
| `get_spiking_attention_status` | Proves the runtime is enabled and shows memory counts. |
| `remember_spiking_context` | Stores a new local memory trace. |
| `query_spiking_attention_text` | Recalls local memory from text without external embedding calls. |
| `list_spiking_memory` | Lists compact persisted memory records. |
| `backup_spiking_memory` | Writes a guarded SQLite backup under `.synapse_s2`. |

## Local state

| Path | Purpose |
| :--- | :--- |
| `.synapse_s2/memory.sqlite3` | Durable memory store. |
| `.synapse_s2/runtime_state.json` | Toggle/runtime state. |
| `.synapse_s2/*backup*.sqlite3` | Local backups. |
| `/Users/dan.driver/.local/bin/synapse-s2-mcp` | Launcher used by Codex, FastMCP, and inspector tools. |
