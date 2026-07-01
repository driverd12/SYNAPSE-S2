#!/usr/bin/env python3
"""Render a live operator status report for SYNAPSE-S2."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "CURRENT_STATUS.md"


FEATURE_INVENTORY = (
    ("Saved namespace menu", "Dashboard sidebar lists live `memory_contexts`, keeps `default` first, and preserves manual namespace entry."),
    ("Start Work", "Dashboard and CLI morning brief for current objective, risks, recent traces, next actions, source memories, and goals."),
    ("Wrap Session", "Preview and confirmed handoff capture for decisions, validation evidence, blockers, and next actions."),
    ("Cortex Governor", "Enter, tick, commit typed traces, moderate working memory, close sessions, and expose guardrails."),
    ("Cross-process Cortex closure", "Closed, finished, or orphaned Cortex sessions survive stale dashboard and capture-daemon runtime-state writers."),
    ("App Connect preview", "Detect apps, attach with confirmation, preview capture quality, and write only after operator confirmation."),
    ("Selected-text fallback", "Exact-content capture path for apps that expose only chrome or metadata through Accessibility."),
    ("Memory Hygiene", "Queue low-confidence, duplicate, stale, sensitive-looking, or follow-up memory for operator action."),
    ("Doctor / Repair", "Runtime, config, LaunchAgent, embedding, memory DB, App Connect, and repair-plan diagnostics."),
    ("Recall with evidence", "Recall cards expose score, source, provenance, why-matched detail, moderation, and pin-to-session action."),
    ("Goal Ledger", "Durable goal create/update/list state surfaced in Start Work and Cortex state."),
    ("Context bus", "Durable pull/ack deployments for MCP clients, local IDE adapters, and dashboard writes."),
    ("Operator readiness pack", "Single evidence pack proving client connect, memory write, recall, app preview, wrap, Doctor, and dashboard smoke."),
)


KNOWN_NON_CLAIMS = (
    "App Connect is not guaranteed internal app scraping; it captures locally exposed Accessibility text or exact selected text.",
    "SYNAPSE-S2 does not invisibly intercept arbitrary private transcript stores; clients must expose text through MCP, inbox drops, transcript sources, selected text, or App Connect.",
    "Do not capture credentials, tokens, private keys, or unnecessary personal data; redaction is a guardrail, not permission.",
    "Do not call `test-validated` truth unless concrete command, artifact, output, commit, or report evidence exists.",
    "Do not treat dashboard detection of an app as proof that the app exposed useful internal content.",
    "Do not assume the default CLI provider equals the installed client/dashboard provider; pass `--embedding-provider mlx-neural` when validating the neural path.",
    "Do not claim Apple Instruments or external Metal counter certification; current certification is MLX/topology/runtime evidence.",
    "Do not push or prune memory without explicit confirmation and a focused target.",
)


def number(value: Any, digits: int = 0) -> str:
    if value is None:
        return "--"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    if not numeric.is_integer() or digits > 0:
        return f"{numeric:,.{digits}f}"
    return f"{int(numeric):,}"


def yes_no(value: Any) -> str:
    return "yes" if bool(value) else "no"


def sorted_context_rows(contexts: dict[str, Any]) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    for name, count in contexts.items():
        clean_name = str(name or "").strip()
        if not clean_name:
            continue
        try:
            clean_count = int(count)
        except (TypeError, ValueError):
            clean_count = 0
        rows.append((clean_name, clean_count))
    return sorted(rows, key=lambda item: (item[0] != "default", item[0].lower()))


def provider_label(provider: dict[str, Any]) -> str:
    provider_id = provider.get("provider") or provider.get("provider_type") or "unknown"
    model = provider.get("model_id") or "local provider"
    native = "native MLX" if provider.get("native_mlx") else "non-native/fallback-capable"
    semantic = "semantic" if provider.get("semantic") else "non-semantic"
    return f"{provider_id} / {model} / {native} / {semantic}"


def render_status_markdown(report: dict[str, Any]) -> str:
    status = dict(report.get("status") or {})
    profile = dict(report.get("profile") or {})
    doctor = dict(report.get("doctor") or {})
    health = dict(report.get("context_health") or {})
    hygiene = dict(report.get("memory_hygiene") or {})
    cortex = dict(report.get("cortex_state") or {})
    git = dict(report.get("git") or {})
    provider = dict(status.get("embedding_provider") or {})
    quick_pruning = dict(profile.get("quick_pruning") or {})
    target = dict(profile.get("target_envelope_mb") or {})

    lines = [
        "# SYNAPSE-S2 Current Status",
        "",
        f"Generated: `{report.get('generated_at', '--')}`",
        f"Context: `{report.get('context_id') or status.get('context_id') or 'default'}`",
        f"Agent: `{report.get('agent_id', 'codex-desktop')}`",
        "",
        "## Runtime Snapshot",
        "",
        "| Field | Current value |",
        "| :--- | :--- |",
        f"| Runtime | `{status.get('runtime', 'unknown')}` |",
        f"| Core enabled | `{yes_no(status.get('effective_enabled'))}` |",
        f"| Embedding provider | `{provider_label(provider)}` |",
        f"| Neurons | `{number(status.get('num_neurons'))}` |",
        f"| Dimension / top-k | `{number(status.get('dimension'))}` / `{number(status.get('default_top_k'))}` |",
        f"| Memory entries / relationships | `{number(status.get('memory_context_entry_count'))}` / `{number(status.get('memory_context_relationship_count'))}` |",
        f"| Latest context-bus event | `{number(status.get('context_bus_latest_event_id'))}` |",
        f"| Topology footprint | `{number(profile.get('estimated_total_mb'), 1)} MB` |",
        f"| Target envelope | `{number(target.get('min'), 0)}-{number(target.get('max'), 0)} MB`, within target: `{yes_no(profile.get('within_target_envelope'))}` |",
        f"| Quick prune | `{number(quick_pruning.get('elapsed_ms'), 1)} ms` of `{number(quick_pruning.get('budget_ms'), 0)} ms`, within budget: `{yes_no(quick_pruning.get('within_60ms_budget'))}` |",
        f"| Doctor | `{doctor.get('overall_status') or doctor.get('status') or 'not run'}` |",
        f"| Context health | `{health.get('status', 'not run')}` / score `{number(health.get('score'))}` |",
        f"| Memory hygiene backlog | `{number(hygiene.get('backlog_count'))}` / quality `{number(hygiene.get('memory_quality_score'))}` |",
        f"| Cortex active sessions / goals | `{number(cortex.get('active_session_count'))}` / `{number(cortex.get('goal_count'))}` |",
        f"| Source checkout at generation | branch `{git.get('branch', '--')}`, head `{git.get('head', '--')}`, uncommitted changes `{yes_no(git.get('dirty'))}` |",
        "",
        "## Saved Memory Contexts",
        "",
        "| Namespace | Entries |",
        "| :--- | ---: |",
    ]

    context_rows = sorted_context_rows(dict(status.get("memory_contexts") or {}))
    if context_rows:
        lines.extend(f"| {name} | {number(count)} |" for name, count in context_rows)
    else:
        lines.append("| none returned | 0 |")

    lines.extend(
        [
            "",
            "## Feature Inventory",
            "",
            "| Feature | Real current behavior |",
            "| :--- | :--- |",
            *[f"| {name} | {detail} |" for name, detail in FEATURE_INVENTORY],
            "",
            "## Known Non-Claims And Do-Not-Do Rules",
            "",
            *[f"- {item}" for item in KNOWN_NON_CLAIMS],
            "",
            "## Current Gaps To Watch",
            "",
        ]
    )

    queue_summary = dict(hygiene.get("queue_summary") or {})
    if hygiene.get("backlog_count"):
        lines.append(
            f"- Memory Hygiene currently reports `{number(hygiene.get('backlog_count'))}` review items; top categories: "
            + ", ".join(f"{key}={number(value)}" for key, value in sorted(queue_summary.items()))
            + "."
        )
    else:
        lines.append("- Memory Hygiene did not report a review backlog in this report.")

    repair_plan = doctor.get("repair_plan") or []
    if repair_plan:
        lines.append("- Doctor repair plan: " + " ".join(str(item) for item in repair_plan[:5]))
    else:
        lines.append("- Doctor did not return a repair plan.")

    if int(cortex.get("active_session_count") or 0) > 0:
        lines.append("- Cortex has active sessions; close stale startup or hydration sessions after verified handoff capture.")
    else:
        lines.append("- Cortex has no active sessions in this report.")

    lines.extend(
        [
            "",
            "## Regeneration",
            "",
            "```bash",
            ".venv/bin/python scripts/synapse_status_report.py --context default --embedding-provider mlx-neural",
            "```",
            "",
            "Use this report as a point-in-time status artifact. Re-run it before demos, handoffs, and readiness claims. The source-checkout row records the repository state at generation time; after committing this file, use `git log -1 --oneline` and `git status -sb` for the final commit position.",
            "",
        ]
    )
    return "\n".join(lines)


def run_json(command: list[str]) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def git_snapshot() -> dict[str, Any]:
    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    return {
        "branch": git("branch", "--show-current") or "--",
        "head": git("rev-parse", "--short", "HEAD") or "--",
        "dirty": bool(git("status", "--porcelain")),
        "remotes": sorted(line.split()[0] for line in git("remote", "-v").splitlines() if line),
    }


def collect_live_report(args: argparse.Namespace) -> dict[str, Any]:
    base = [
        sys.executable,
        str(ROOT / "synapse_cli.py"),
        "--json",
        "--embedding-provider",
        args.embedding_provider,
    ]
    return {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "context_id": args.context,
        "agent_id": args.agent_id,
        "status": run_json([*base, "status", "--context", args.context]),
        "profile": run_json([*base, "profile", "--benchmark-quick-prune"]),
        "doctor": run_json([*base, "doctor", "--context", args.context, "--include-apps", "--repair-plan"]),
        "context_health": run_json([*base, "context-health", "--context", args.context]),
        "memory_hygiene": run_json([*base, "memory-hygiene", "--context", args.context, "--limit", str(args.hygiene_limit)]),
        "cortex_state": run_json([*base, "cortex-state", "--context", args.context, "--agent-id", args.agent_id]),
        "git": git_snapshot(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate docs/CURRENT_STATUS.md from live SYNAPSE-S2 state.")
    parser.add_argument("--context", default="default")
    parser.add_argument("--agent-id", default="codex-desktop")
    parser.add_argument("--embedding-provider", default="mlx-neural")
    parser.add_argument("--hygiene-limit", type=int, default=10)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--print", action="store_true", dest="print_report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect_live_report(args)
    markdown = render_status_markdown(report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    if args.print_report:
        print(markdown)
    else:
        print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
