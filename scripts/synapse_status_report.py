#!/usr/bin/env python3
"""Render a live operator status report for SYNAPSE-S2."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redaction import (
    SecretSafeArgumentParser,
    redact_capture_text,
    reject_sensitive_identifier,
)
from backend_router import (
    CORE_SOCKET_ENV,
    LEGACY_CORE_CONFIG_ENV,
    MEMORY_DB_ENV,
    STATE_PATH_ENV,
)
from core_client_binding import (
    BINDING_ENV,
    EXPECTED_CONFIG_ENV,
    binding_from_environment,
)


DEFAULT_OUTPUT = ROOT / "docs" / "CURRENT_STATUS.md"
VISUAL_MANUAL_DIR = ROOT / "output" / "manual"
VISUAL_PDF_DIR = ROOT / "output" / "pdf"
VISUAL_PLATES_DIR = VISUAL_MANUAL_DIR / "plates"
VISUAL_MANUAL_MD = "SYNAPSE-S2_Visual_User_Manual.md"
VISUAL_MANUAL_PDF = "SYNAPSE-S2_Visual_User_Manual.pdf"
VISUAL_QUICK_PDF = "SYNAPSE-S2_Quick_Reference.pdf"
VISUAL_QUICK_PNG = "SYNAPSE-S2_Quick_Reference.png"
VISUAL_PLATE_COUNT = 13


def ensure_private_directory(path: Path) -> None:
    """Create missing private directories without chmodding caller parents."""

    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            if not directory.is_dir():
                raise


def validate_status_output_path(value: Any) -> Path:
    raw = reject_sensitive_identifier(value, field="status report output path")
    if not raw.strip():
        raise ValueError("status report output path must not be empty")
    requested = Path(raw).expanduser()
    canonical = requested.parent.resolve() / requested.name
    reject_sensitive_identifier(
        canonical,
        field="status report output path",
    )
    return canonical


def write_private_status_report(path: Path, text: str) -> None:
    ensure_private_directory(path.parent)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


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
    ("Retrieval associations", "Typed and graph-neighbor relevance cues plus governed Memora bindings improve bounded retrieval without becoming tasks, approvals, or execution authority."),
    ("Private image and media memory", "Explicit local image capture, bounded thumbnails/descriptions, Apple Vision OCR and feature-print cues, read-only similarity, and snapshot-bound recovery derivatives."),
    ("Impact scorecard", "Content-free dashboard yield, routing, latency, resource, and ACK telemetry with an explicitly illustrative cost what-if, never provider billing or proven savings."),
    ("Governed Memora lifecycle", "Read-only shadow plans and separated propose/promote/reject/revoke roles preserve attributable, reversible Retrieval associations."),
    ("Goal Ledger", "Durable goal create/update/list state surfaced in Start Work and Cortex state."),
    ("Exactly-once capture and delivery", "Stable capture identity, bounded deferred processing, leased context delivery, exact ACK/release/dead-letter receipts, and fail-closed uncertain outcomes."),
    ("Verified recovery and replication", "Signed paired recovery with isolated restore proof plus target-bound offline multi-Mac checkpoints and signed ACK evidence; no live promotion or two-way merge."),
    ("Release safety substrate", "Provenance, preservation, compatibility, inactive staging, installed-layout, environment-evidence, and activation-journal primitives fail closed but do not yet compose an executable updater."),
    ("Operator readiness pack", "Single evidence pack proving client connect, memory write, recall, app preview, wrap, Doctor, and dashboard smoke."),
)


KNOWN_NON_CLAIMS = (
    "App Connect is not guaranteed internal app scraping; it captures locally exposed Accessibility text or exact selected text.",
    "SYNAPSE-S2 does not invisibly intercept arbitrary private transcript stores; clients must expose text through MCP, inbox drops, transcript sources, selected text, or App Connect.",
    "Do not capture credentials, tokens, private keys, or unnecessary personal data; redaction is a guardrail, not permission.",
    "Do not call `test-validated` truth unless concrete command, artifact, output, commit, or report evidence exists.",
    "Do not treat dashboard detection of an app as proof that the app exposed useful internal content.",
    "Do not configure a neural provider in a status client; the authoritative core reports the provider it actually owns.",
    "Do not claim Apple Instruments or external Metal counter certification; current certification is MLX/topology/runtime evidence.",
    "Do not describe Retrieval associations or Memora cues as user actions, approvals, goals, follow-ups, or execution authority.",
    "Do not describe Apple Vision OCR or image feature prints as a VLM, identity system, or calibrated text-to-image semantic search.",
    "Do not treat Impact yield, latency, token estimates, or dollar what-if output as relevance, correctness, provider billing, savings, or avoided work.",
    "Do not copy a live SQLite file for recovery; use paired verified recovery or signed target-bound offline replication with one active writer.",
    "Offline replication does not provide live federation, automatic promotion, two-way divergent merge, or unattended adoption.",
    "Release safety primitives are dormant foundations; no signed/notarized installer, composed cutover executor, governed migration, executable rollback, or multi-host canary is currently claimed.",
    "Do not push or prune memory without explicit confirmation and a focused target.",
)


@dataclass(frozen=True)
class VisualSection:
    title: str
    bullets: tuple[str, ...]


@dataclass(frozen=True)
class VisualPage:
    title: str
    subtitle: str
    principle: str
    sections: tuple[VisualSection, VisualSection, VisualSection, VisualSection]
    operator_note: str


def visual_manual_pages() -> tuple[VisualPage, ...]:
    """Single human-readable source for the 13-page visual manual."""

    section = VisualSection
    page = VisualPage
    return (
        page(
            "The operating model",
            "Durable local memory with explicit authority boundaries",
            "SYNAPSE-S2 stores what was deliberately captured. It never claims unseen thoughts, files, or app state.",
            (
                section("Memory anatomy", (
                    "Galaxy: every observed namespace and reviewed connection.",
                    "Cortex: one namespace and its governed work state.",
                    "Ganglion: a derived semantic or type cluster, not a stored object.",
                    "Neuron: one durable memory entry with provenance and relationships.",
                )),
                section("Authoritative core", (
                    "One authenticated local core owns SQLite writes, neural state, capture, recovery, and replication.",
                    "CLI, MCP, and dashboard clients use that authority instead of fallback databases.",
                    "The loopback dashboard is an operator surface, not a second source of truth.",
                )),
                section("What persists", (
                    "Text, events, typed relationships, namespace catalog state, goals, and governed traces.",
                    "Private image derivatives and their exact database references when image memory is used.",
                    "Delivery, capture, recovery, replication, and governance receipts needed for audit.",
                )),
                section("What stays transient", (
                    "Graph layouts, open drawers, browser navigation, and other presentation state.",
                    "Quick Prune and Deep Sleep maintain bounded runtime state; neither silently deletes durable memory.",
                    "Unreviewed suggestions never become execution authority.",
                )),
            ),
            "Inspect first; mutate only through the smallest named governed operation.",
        ),
        page(
            "The Daily Operator Trust Loop",
            "Establish current truth before relying on memory or starting risky work",
            "Choose context -> Start Work -> Health and Doctor -> Enter Cortex -> Capture or Recall -> Wrap and protect.",
            (
                section("Start Work", (
                    "Loads a bounded morning brief for the selected namespace.",
                    "Shows recent evidence, active goals, risks, next actions, and leased delivery receipts.",
                    "Acknowledgement happens only after content is successfully rendered or consumed.",
                )),
                section("Trust checks", (
                    "Context Health explains memory quality and recommendations.",
                    "Doctor checks runtime, SQLite, embeddings, capture, delivery, and App Connect.",
                    "Readiness evidence is stronger than a green dashboard badge alone.",
                )),
                section("Governed work", (
                    "Enter Cortex with agent, mode, and task before substantial mutation.",
                    "Tick before risky actions and declare intended files, tools, mutation intent, and confidence.",
                    "Commit verified traces, then close instead of leaving stale active work.",
                )),
                section("Clean handoff", (
                    "Wrap Session records decisions, validation, blockers, and next action.",
                    "Create a recovery point before broad repair, pruning, or transfer.",
                    "Keep commit, publication, installation, and live readiness as separate claims.",
                )),
            ),
            "Prove which context, core, and evidence are active at the start of each session.",
        ),
        page(
            "Durable memory and capture",
            "Explicit creation paths with exactly-once processing and provenance",
            "Capture is deliberate: bounded source text receives identity, is committed once, and remains attributable.",
            (
                section("Creation paths", (
                    "Remember stores one trace; ingest segments structured events and relationships.",
                    "Conversation capture enters through the exactly-once capture ledger.",
                    "App Connect previews locally exposed text before confirmed snapshot capture.",
                )),
                section("Exactly-once posture", (
                    "Stable request identity and journals fail closed around uncertain outcomes.",
                    "The inbox defers work while the core is unavailable, then resumes bounded batches.",
                    "Credential-shaped material is rejected or redacted before durable ingestion.",
                )),
                section("Typed context", (
                    "Goal, Decision, Risk, Validation, and Follow-up prefixes create typed context where appropriate.",
                    "The active dashboard or CLI context determines the durable namespace target.",
                    "Provenance remains available for recall, correction, and recovery checks.",
                )),
                section("Correction", (
                    "Capture a replacement, then prune only the bad node or relationship.",
                    "Arbitrary stored text is not edited in place.",
                    "Broad relationship-class deletion is reserved for an entirely bad class.",
                )),
            ),
            "Secret redaction is a guardrail, never permission to capture credentials or private keys.",
        ),
        page(
            "Recall and Retrieval associations",
            "Deterministic retrieval with visible evidence and bounded graph assistance",
            "Retrieval associations are relevance cues, not user actions, approvals, tasks, or execution instructions.",
            (
                section("Recall scopes", (
                    "Local searches the active namespace plus explicit global memory.",
                    "Connected adds approved, enabled, one-hop namespace bridges.",
                    "All explicitly searches every saved namespace for that read-only request.",
                )),
                section("Retrieval v2", (
                    "Local neural embeddings and deterministic ranking return bounded evidence.",
                    "Typed and graph-neighbor evidence can improve relevance without mutating memory.",
                    "Recall cards expose provenance and why-matched detail for review.",
                )),
                section("Associations", (
                    "Derived terms can route a query toward related durable evidence.",
                    "They stay subordinate to source memories and can be audited or revoked through Memora.",
                    "Association output must never be described as operator intent.",
                )),
                section("Bounded nonclaims", (
                    "A non-empty result does not prove relevance, truth, completeness, or success.",
                    "Visible degree describes only the returned relationship sample.",
                    "Benchmarks do not prove every real workload or every target Mac.",
                )),
            ),
            "Recall locally first; expand scope only when the question needs broader evidence.",
        ),
        page(
            "Namespace Galaxy and bridges",
            "Read-only navigation plus reviewed cross-namespace recall",
            "Galaxy -> Cortex -> Ganglion -> Neuron is semantic drill-down. Focus never edits, copies, or reconnects memory.",
            (
                section("Navigate", (
                    "Enter namespace changes the active operating scope.",
                    "Scroll changes semantic depth; focus loads bounded neuron detail.",
                    "The accessible list mirrors canvas navigation.",
                )),
                section("Visual meaning", (
                    "Galaxy area combines memory volume, indexed density, and enabled approved bridge weight.",
                    "Ganglion and neuron size summarize bounded structure, not truth or importance.",
                    "Suggestions and phase-delay values are presentation evidence only.",
                )),
                section("Bridge lifecycle", (
                    "Suggestion -> pending proposal -> exact review -> approved enabled bridge.",
                    "Disable, revoke, and expiry close recall authority without copying memory.",
                    "Changed evidence invalidates stale review material.",
                )),
                section("Isolation", (
                    "Connected recall follows approved one-hop paths and remains read-only.",
                    "Suggestions never expand recall scope or affect durable state.",
                    "The namespace catalog is not an ACL or ownership registry.",
                )),
            ),
            "Changing scope does not move, duplicate, synchronize, or merge stored memory.",
        ),
        page(
            "Private image and media memory",
            "Locally derived visual evidence with explicit capture and recovery boundaries",
            "Image memory is opt-in and local: thumbnail, description, and bounded descriptors support inspection and similarity.",
            (
                section("Capture", (
                    "The operator chooses an image and target namespace before creation.",
                    "Transient source handling produces bounded private derivatives, not a hidden cloud upload.",
                    "Explicit descriptions remain source-backed and inspectable.",
                )),
                section("Apple Vision lane", (
                    "Local feature prints support image-to-image similarity.",
                    "Consent-gated OCR contributes imperfect searchable cues.",
                    "Neither lane is a VLM or calibrated text-to-image semantic search.",
                )),
                section("Similarity", (
                    "Find Similar resolves candidates from authoritative references.",
                    "Distance is uncalibrated and carries truncation or exclusion notices.",
                    "Feature bytes, raw OCR, and witness internals stay out of responses.",
                )),
                section("Preservation", (
                    "Recovery and replication seal derivatives referenced by the immutable snapshot.",
                    "Missing or corrupt referenced derivatives block publication.",
                    "Valid orphan files are excluded and reported.",
                )),
            ),
            "Visual recall is evidence with provenance, not an identity or semantic-certainty claim.",
        ),
        page(
            "Memora governance",
            "Compact abstractions and cues remain reviewable, attributable, and reversible",
            "Memora improves relevance routing while source-backed durable memory remains authoritative.",
            (
                section("Shadow planning", (
                    "A read-only plan proposes abstractions and cue anchors for one namespace.",
                    "Planning never changes retrieval or writes an effective binding.",
                    "Raw source text, vectors, supporting IDs, and witness internals stay hidden.",
                )),
                section("Governed lifecycle", (
                    "Proposal records one isolated candidate for exact review.",
                    "Promotion requires separated proposer and reviewer roles.",
                    "Reject and revoke preserve append-only receipts and remove authority.",
                )),
                section("Integrity", (
                    "Bindings, sources, provider identity, and receipts are cross-checked.",
                    "Recovery and replication carry a content-free aggregate that recomputes exactly.",
                    "Invalid source memories cannot stay effective through a stale cue.",
                )),
                section("Authority boundary", (
                    "Cues influence retrieval relevance only.",
                    "They do not create goals, tasks, approvals, follow-ups, bridges, or writes.",
                    "Source memories remain independently inspectable and deletable.",
                )),
            ),
            "Call them Retrieval associations: useful routing, never autonomous intent.",
        ),
        page(
            "Impact and evaluation",
            "Observed behavior stays separate from illustrative estimates",
            "Impact never claims provider billing, savings, relevance, correctness, or avoided work.",
            (
                section("Observed scorecard", (
                    "Counts non-empty dashboard recalls and bridge or graph-neighbor routing.",
                    "Reports backend p50/p95 latency, response-byte token estimates, and warm coverage.",
                    "Delivery ACK ratio is reliability evidence, not a quality score.",
                )),
                section("Cost what-if", (
                    "The operator supplies a token rate and tokens-per-assist assumption.",
                    "The dollar result is illustrative equivalence only.",
                    "Coverage excludes MCP, CLI, and agent hydration traffic.",
                )),
                section("LongMem evaluation", (
                    "Bounded artifacts cover factual, temporal, update, abstention, and visual dimensions.",
                    "The official adapter lane stays isolated from live operator memory.",
                    "A benchmark gate supports comparison, not universal certification.",
                )),
                section("Interpretation", (
                    "Non-empty recall is yield, not proven relevance.",
                    "Latency covers backend retrieval, not complete client experience.",
                    "Resource evidence is not external Instruments or Metal certification.",
                )),
            ),
            "Prefer a small defensible claim with visible coverage over an unclear impressive number.",
        ),
        page(
            "Cortex Governor and Goal Ledger",
            "Typed work state preserves intent, evidence, risk, and next action",
            "The governor disciplines work; it never replaces operator approval or turns relevance into authority.",
            (
                section("Session lifecycle", (
                    "Enter with agent, mode, and task.",
                    "Tick with observation, proposed action, files, tools, mutation intent, and confidence.",
                    "Commit typed evidence and close or wrap when the task ends.",
                )),
                section("Typed traces", (
                    "Goal, decision, constraint, implementation, validation, risk, correction, and follow-up stay distinct.",
                    "Truth posture, confidence, evidence, agent, and session identity remain attached.",
                    "Promote and Demote apply to governed traces, not arbitrary memories.",
                )),
                section("Goal Ledger", (
                    "Goals carry owner, state, evidence, and next action.",
                    "Active goals appear in Start Work and Cortex across CLI, MCP, and dashboard.",
                    "A goal records coordination state; it does not authorize unrelated mutation.",
                )),
                section("Guardrails", (
                    "Undeclared mutations, sensitive paths, and high-impact tools produce warnings.",
                    "Cross-process closure prevents resurrection of ended sessions.",
                    "An idle Cortex is normal before work begins.",
                )),
            ),
            "Store verified outcomes and concrete follow-ups, not speculation that could look factual later.",
        ),
        page(
            "Delivery and operational integrity",
            "Bounded leases and exact receipts protect agent context",
            "Delivery is at-least-once with stable identity; consumers deduplicate and acknowledge exact receipts.",
            (
                section("Hydration", (
                    "Agent Brief combines leased events, recall, graph, Cortex state, and goals.",
                    "Startup hydration does not acknowledge unseen events.",
                    "Compact output retains visible receipts or releases the lease.",
                )),
                section("Receipt lifecycle", (
                    "A receipt is acknowledged only after successful delivery.",
                    "Expired work gets a new fenced receipt with stable delivery identity.",
                    "Release and dead-letter remain explicit operations.",
                )),
                section("Failure semantics", (
                    "Deterministic invalid requests finish terminally and are not replayed.",
                    "Genuinely uncertain commit state stays outcome-unknown and is never auto-replayed.",
                    "Only pre-connect failure may retry the same signed request once.",
                )),
                section("Capacity", (
                    "Response channels and scans are bounded to protect core and client context.",
                    "Terminal rows age out; sustained throughput remains finite until pruning.",
                    "Rich dashboard views stay separate from compact MCP projections.",
                )),
            ),
            "A response without matching receipt and delivery identity is incomplete delivery evidence.",
        ),
        page(
            "Evidence, recovery, and multi-Mac",
            "Preserve database, capture, media, and authority as one verified story",
            "Use paired signed recovery or target-bound replication, never an ad hoc live SQLite copy.",
            (
                section("Recovery point", (
                    "A verified pair seals the immutable database snapshot and capture state.",
                    "Referenced media derivatives are included by exact reference and digest.",
                    "Isolated restore proof runs before the artifact is trusted.",
                )),
                section("Evidence pack", (
                    "A readiness report and pinned recovery bundle preserve one run's proof.",
                    "Certification checks core, embeddings, write, recall, App Preview, wrap, and dashboard smoke.",
                    "Evidence is time-bound and must be refreshed for a new handoff.",
                )),
                section("Offline replication", (
                    "Checkpoints are signed, paired, capability-negotiated, and target-bound.",
                    "The receiver proves an isolated restore before signed acknowledgement.",
                    "Any future live adoption requires a separately governed procedure; promotion is not supported here.",
                )),
                section("Handoff rule", (
                    "Quiesce the writer before final checkpoint creation.",
                    "Current replication stops at isolated stage and signed ACK with promotion_supported false.",
                    "Any later live use or return transfer needs separate governance; never improvise a two-way merge.",
                )),
            ),
            "Signing protects authenticity, not confidentiality; transfer through encryption.",
        ),
        page(
            "Safe release lane",
            "Strong primitives exist; a conventional executable product does not yet",
            "Production-ready local runtime and downloadable executable product are separate milestones.",
            (
                section("Working today", (
                    "A verified checkout runs the core, dashboard, CLI, MCP, capture, recovery, and offline replication.",
                    "Source inspection, preservation, compatibility, and inactive staging exist.",
                    "Readiness and replacement gates prove the installed checkout before launch.",
                )),
                section("Dormant substrate", (
                    "Provenance, layout, environment evidence, staging, and activation journals fail closed.",
                    "They verify authority but do not compose one unattended cutover executor.",
                    "Current evidence profiles do not form complete activation authority.",
                )),
                section("Not yet claimed", (
                    "No signed and notarized macOS app or package is published.",
                    "No offline installer, automatic migration, or executable rollback exists.",
                    "No CI-backed multi-host canary proves unattended adoption.",
                )),
                section("Safe order", (
                    "Verify provenance and compatibility; preserve state; stage immutably.",
                    "Journal cutover, prove environment and equivalence, then commit the floor.",
                    "Reconcile or roll back through evidence, never manual file replacement.",
                )),
            ),
            "Dormant release primitives are safety foundations, not an executable updater.",
        ),
        page(
            "Capability boundaries and checklist",
            "Treat unsupported capabilities as unavailable, never implied",
            "SYNAPSE-S2 is production-usable local memory, not yet an unattended downloadable multi-host product.",
            (
                section("Memory boundaries", (
                    "No in-place text or ganglion editor and no neuron reassignment.",
                    "No namespace rename, archive, or delete lifecycle.",
                    "No freeform relationship topology or weight editor.",
                )),
                section("Intelligence boundaries", (
                    "Associations and Memora cues route relevance only.",
                    "Vision features are not a VLM or identity system.",
                    "Impact and benchmarks do not prove truth or savings.",
                )),
                section("Before host handoff", (
                    "Drain capture and establish one active writer.",
                    "Create a signed target-bound checkpoint and use encryption.",
                    "Prove isolated restore before ACK; treat live adoption as unsupported until separately governed.",
                )),
                section("Before release claims", (
                    "Verify the exact commit independently on every remote.",
                    "Separate publication, installation, launch, and live readiness.",
                    "Name missing installer, migration, rollback, and canary work plainly.",
                )),
            ),
            "If evidence is stale, refresh it. If state may diverge, stop one writer before creating another.",
        ),
    )


def visual_identity(revision: str, source_date: str) -> str:
    return f"Source baseline {revision} | Generated {source_date}"


def visual_artifact_relative_paths() -> tuple[str, ...]:
    return (
        f"output/manual/{VISUAL_MANUAL_MD}",
        f"output/manual/{VISUAL_QUICK_PNG}",
        *(f"output/manual/plates/manual-{page:02d}.png" for page in range(1, VISUAL_PLATE_COUNT + 1)),
        f"output/pdf/{VISUAL_QUICK_PDF}",
        f"output/pdf/{VISUAL_MANUAL_PDF}",
    )


def render_visual_manual_markdown(revision: str, source_date: str) -> str:
    """Render Markdown from the same page source used for the PDFs."""

    lines = [
        "# SYNAPSE-S2 Visual Operator Manual",
        "",
        "Human-readable field guide for the current local memory system, its governed operator surfaces, recovery model, and honest release posture.",
        "",
        f"{visual_identity(revision, source_date)}.",
        "",
        "Companion artifacts:",
        "",
        "- [Annotated visual manual (PDF)](../pdf/SYNAPSE-S2_Visual_User_Manual.pdf)",
        "- [One-page operator reference (PDF)](../pdf/SYNAPSE-S2_Quick_Reference.pdf)",
        "- [One-page operator reference (PNG)](SYNAPSE-S2_Quick_Reference.png)",
        "- `plates/` contains one presentation-ready PNG for each manual page.",
        "",
        "## The one-sentence model",
        "",
        "SYNAPSE-S2 is a durable local memory substrate: one authoritative core stores explicitly captured knowledge, retrieves bounded evidence, governs agent work, and preserves verifiable recovery state without claiming unseen information or unsupported authority.",
        "",
    ]
    for index, page in enumerate(visual_manual_pages(), 1):
        lines.extend((f"## {index}. {page.title}", "", page.subtitle + ".", "", f"> {page.principle}", ""))
        for section in page.sections:
            lines.extend((f"### {section.title}", ""))
            lines.extend(f"- {bullet}" for bullet in section.bullets)
            lines.append("")
        lines.extend((f"Operator note: {page.operator_note}", ""))
    lines.extend((
        "## Source anchors",
        "",
        "- [README](../../README.md) - active CLI, MCP, dashboard, capture, retrieval, media, governance, and recovery behavior.",
        "- [Authoritative Core Operations](../../docs/AUTHORITATIVE_CORE_OPERATIONS.md) - authority, readiness, replacement, and recovery procedures.",
        "- [Bridge Governance](../../docs/BRIDGE_GOVERNANCE.md) - namespace isolation and reviewed one-hop recall.",
        "- [Memora Shadow](../../docs/MEMORA_SHADOW.md) - Retrieval association planning and cue governance.",
        "- [Frontier Enhancements](../../docs/FRONTIER_ENHANCEMENTS.md) - image, evaluation, Impact, and future boundaries.",
        "- [Production Gap Audit](../../docs/PRODUCTION_GAP_AUDIT.md) - implemented controls and productization nonclaims.",
        "- [Multi-Mac Replication](../../docs/MULTI_MAC_REPLICATION.md) - signed target-bound offline handoff.",
        "",
        "## Regeneration",
        "",
        "Use a disposable documentation environment; do not add these rendering tools to the SYNAPSE-S2 runtime environment. The checked-in images were rendered with ReportLab 4.4.9, Python 3.12, and Poppler 26.05.0.",
        "",
        "```bash",
        "PDFTOPPM=\"$(command -v pdftoppm || true)\"",
        "test -x \"$PDFTOPPM\" || { printf '%s\\n' 'Poppler pdftoppm is required' >&2; exit 1; }",
        "\"$PDFTOPPM\" -v 2>&1 | grep -F '26.05.0' >/dev/null || { printf '%s\\n' 'Poppler 26.05.0 is required for byte-stable regeneration' >&2; exit 1; }",
        "uv run --isolated --no-project --python 3.12 --with 'reportlab==4.4.9' \\",
        "  python scripts/synapse_status_report.py --visual-docs \\",
        "  --visual-revision \"$(git rev-parse --short=7 HEAD)\" \\",
        "  --visual-source-date \"$(date +%F)\" \\",
        "  --visual-pdftoppm \"$PDFTOPPM\"",
        "```",
        "",
        "`uv run --isolated --no-project` keeps ReportLab out of the project `.venv`; Poppler remains a separately provisioned executable. Neither tool is a SYNAPSE-S2 runtime dependency.",
        "",
    ))
    return "\n".join(lines)


def _visual_reportlab():
    """Load documentation-only PDF dependencies without changing runtime deps."""

    try:
        from reportlab import rl_config
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfgen import canvas
    except ImportError as exc:  # pragma: no cover - host dependency boundary
        raise RuntimeError(
            "visual documentation needs ReportLab in a separate documentation environment"
        ) from exc
    rl_config.invariant = 1
    return colors, landscape, letter, pdfmetrics, canvas


def _visual_color(colors: Any, value: str) -> Any:
    return colors.HexColor(value)


def _visual_wrap(
    text: str,
    *,
    font: str,
    size: float,
    width: float,
    pdfmetrics: Any,
) -> list[str]:
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = word if not current else f"{current} {word}"
        if pdfmetrics.stringWidth(candidate, font, size) <= width:
            current = candidate
            continue
        if not current:
            raise ValueError(f"unbreakable visual-manual text exceeds width: {word!r}")
        lines.append(current)
        current = word
    if current:
        lines.append(current)
    return lines


def _visual_draw_wrapped(
    canvas_obj: Any,
    text: str,
    *,
    x: float,
    y: float,
    width: float,
    font: str,
    size: float,
    leading: float,
    color: Any,
    pdfmetrics: Any,
    max_lines: int,
) -> float:
    lines = _visual_wrap(text, font=font, size=size, width=width, pdfmetrics=pdfmetrics)
    if len(lines) > max_lines:
        raise ValueError(
            f"visual-manual copy needs {len(lines)} lines, limit {max_lines}: {text}"
        )
    canvas_obj.setFont(font, size)
    canvas_obj.setFillColor(color)
    for line in lines:
        canvas_obj.drawString(x, y, line)
        y -= leading
    return y


def _visual_section_height(section: VisualSection, width: float, pdfmetrics: Any) -> float:
    height = 38.0
    for bullet in section.bullets:
        line_count = len(
            _visual_wrap(
                bullet,
                font="Helvetica",
                size=9.4,
                width=width - 42,
                pdfmetrics=pdfmetrics,
            )
        )
        height += line_count * 12.4 + 5
    return height + 11


def _visual_draw_card(
    canvas_obj: Any,
    section: VisualSection,
    *,
    x: float,
    top: float,
    width: float,
    height: float,
    colors: Any,
    pdfmetrics: Any,
) -> None:
    border = _visual_color(colors, "#2B6F69")
    panel = _visual_color(colors, "#0C211F")
    mint = _visual_color(colors, "#4DE0D0")
    text = _visual_color(colors, "#EAF7F5")
    canvas_obj.setFillColor(panel)
    canvas_obj.setStrokeColor(border)
    canvas_obj.setLineWidth(1)
    canvas_obj.roundRect(x, top - height, width, height, 10, stroke=1, fill=1)
    canvas_obj.setFont("Helvetica-Bold", 12.2)
    canvas_obj.setFillColor(mint)
    canvas_obj.drawString(x + 15, top - 23, section.title.upper())
    y = top - 45
    for bullet in section.bullets:
        lines = _visual_wrap(
            bullet,
            font="Helvetica",
            size=9.4,
            width=width - 42,
            pdfmetrics=pdfmetrics,
        )
        canvas_obj.setFillColor(mint)
        canvas_obj.circle(x + 18, y + 3, 2.1, stroke=0, fill=1)
        canvas_obj.setFillColor(text)
        canvas_obj.setFont("Helvetica", 9.4)
        for line in lines:
            canvas_obj.drawString(x + 28, y, line)
            y -= 12.4
        y -= 5


def _draw_visual_manual_pdf(path: Path, revision: str, source_date: str) -> None:
    colors, _landscape, letter, pdfmetrics, canvas = _visual_reportlab()
    width, height = letter
    pdf = canvas.Canvas(str(path), pagesize=letter, pageCompression=1, invariant=1)
    pdf.setTitle("SYNAPSE-S2 Visual Operator Manual")
    pdf.setAuthor("SYNAPSE-S2 project")
    pdf.setSubject("Current capabilities, safe operation, recovery, and release boundaries")
    background = _visual_color(colors, "#061315")
    text = _visual_color(colors, "#EAF7F5")
    muted = _visual_color(colors, "#A8C1BE")
    mint = _visual_color(colors, "#4DE0D0")
    lime = _visual_color(colors, "#9BFF42")
    amber = _visual_color(colors, "#FFC857")
    identity = visual_identity(revision, source_date)
    pages = visual_manual_pages()
    if len(pages) != VISUAL_PLATE_COUNT:
        raise ValueError("visual manual page count must remain exactly 13")
    for page_number, page in enumerate(pages, 1):
        pdf.setFillColor(background)
        pdf.rect(0, 0, width, height, stroke=0, fill=1)
        pdf.setFillColor(mint)
        pdf.rect(0, height - 10, width, 10, stroke=0, fill=1)
        pdf.setFont("Helvetica-Bold", 8.5)
        pdf.setFillColor(mint)
        pdf.drawString(42, height - 39, f"SYNAPSE-S2 OPERATOR MANUAL  /  {page_number:02d}")
        pdf.setFont("Helvetica-Bold", 24)
        pdf.setFillColor(text)
        pdf.drawString(42, height - 72, page.title)
        _visual_draw_wrapped(
            pdf,
            page.subtitle,
            x=42,
            y=height - 94,
            width=528,
            font="Helvetica",
            size=10.5,
            leading=13,
            color=muted,
            pdfmetrics=pdfmetrics,
            max_lines=2,
        )
        principle_top = height - 126
        pdf.setFillColor(_visual_color(colors, "#102927"))
        pdf.setStrokeColor(lime)
        pdf.roundRect(42, principle_top - 61, 528, 61, 9, stroke=1, fill=1)
        pdf.setFillColor(lime)
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(57, principle_top - 19, "OPERATING PRINCIPLE")
        _visual_draw_wrapped(
            pdf,
            page.principle,
            x=57,
            y=principle_top - 37,
            width=498,
            font="Helvetica",
            size=10.1,
            leading=12.2,
            color=text,
            pdfmetrics=pdfmetrics,
            max_lines=2,
        )
        column_width = 255
        for column, x in enumerate((42, 315)):
            top = principle_top - 79
            for section in page.sections[column * 2:(column + 1) * 2]:
                card_height = _visual_section_height(section, column_width, pdfmetrics)
                _visual_draw_card(
                    pdf,
                    section,
                    x=x,
                    top=top,
                    width=column_width,
                    height=card_height,
                    colors=colors,
                    pdfmetrics=pdfmetrics,
                )
                top -= card_height + 13
                if top < 91:
                    raise ValueError(f"visual manual page {page_number} content overflows")
        pdf.setStrokeColor(_visual_color(colors, "#245B57"))
        pdf.line(42, 66, 570, 66)
        _visual_draw_wrapped(
            pdf,
            page.operator_note,
            x=42,
            y=51,
            width=355,
            font="Helvetica-Bold",
            size=8.2,
            leading=9.5,
            color=amber,
            pdfmetrics=pdfmetrics,
            max_lines=2,
        )
        pdf.setFont("Helvetica", 7.6)
        pdf.setFillColor(muted)
        pdf.drawRightString(570, 51, identity)
        pdf.showPage()
    pdf.save()


def _draw_visual_quick_pdf(path: Path, revision: str, source_date: str) -> None:
    colors, landscape, letter, pdfmetrics, canvas = _visual_reportlab()
    width, height = landscape(letter)
    pdf = canvas.Canvas(str(path), pagesize=(width, height), pageCompression=1, invariant=1)
    pdf.setTitle("SYNAPSE-S2 One-Page Operator Reference")
    pdf.setAuthor("SYNAPSE-S2 project")
    pdf.setSubject("Current capabilities, safe workflow, and release posture")
    background = _visual_color(colors, "#061315")
    panel = _visual_color(colors, "#0C211F")
    text = _visual_color(colors, "#EAF7F5")
    muted = _visual_color(colors, "#AAC4C0")
    mint = _visual_color(colors, "#4DE0D0")
    lime = _visual_color(colors, "#9BFF42")
    amber = _visual_color(colors, "#FFC857")
    violet = _visual_color(colors, "#B388FF")
    rose = _visual_color(colors, "#FF5C93")
    pdf.setFillColor(background)
    pdf.rect(0, 0, width, height, stroke=0, fill=1)
    pdf.setFillColor(mint)
    pdf.rect(0, height - 9, width, 9, stroke=0, fill=1)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.setFillColor(mint)
    pdf.drawString(34, height - 34, "CURRENT OPERATOR FIELD CARD")
    pdf.setFont("Helvetica-Bold", 27)
    pdf.setFillColor(text)
    pdf.drawString(34, height - 66, "SYNAPSE-S2")
    pdf.setFont("Helvetica", 14)
    pdf.setFillColor(muted)
    pdf.drawString(222, height - 64, "durable local memory, governed action, verified continuity")
    pdf.setFillColor(_visual_color(colors, "#102927"))
    pdf.setStrokeColor(lime)
    pdf.roundRect(34, height - 124, width - 68, 39, 8, stroke=1, fill=1)
    pdf.setFont("Helvetica-Bold", 11.2)
    pdf.setFillColor(lime)
    pdf.drawString(48, height - 101, "DAILY TRUST LOOP")
    pdf.setFont("Helvetica", 10.4)
    pdf.setFillColor(text)
    pdf.drawString(180, height - 101, "Choose context -> Start Work -> Health + Doctor -> Enter Cortex -> Capture / Recall -> Wrap + protect")
    cards = (
        ("MEMORY + RETRIEVAL", mint, (
            "Durable text, events, goals, typed graph, and namespaces",
            "Retrieval v2 with Local / Connected / All scopes",
            "Retrieval associations route relevance, never authority",
        )),
        ("CAPTURE + MEDIA", amber, (
            "Exactly-once conversation and App Connect capture",
            "Private image memory, Vision cues, and media similarity",
            "Source-backed provenance and surgical correction",
        )),
        ("GOVERNANCE", violet, (
            "Cortex Governor and Goal Ledger preserve intent and evidence",
            "Memora proposal -> review -> promote / reject / revoke",
            "Suggestions and cues never create tasks or approvals",
        )),
        ("PROOF + CONTINUITY", rose, (
            "Honest Impact metrics and bounded LongMem evaluation",
            "Signed paired recovery with isolated restore proof",
            "Target-bound checkpoints with signed ACK; no promotion",
        )),
    )
    card_top = height - 149
    card_gap = 12
    card_width = (width - 68 - card_gap) / 2
    card_height = 117
    for index, (title, accent, bullets) in enumerate(cards):
        column = index % 2
        row = index // 2
        x = 34 + column * (card_width + card_gap)
        top = card_top - row * (card_height + card_gap)
        pdf.setFillColor(panel)
        pdf.setStrokeColor(accent)
        pdf.roundRect(x, top - card_height, card_width, card_height, 9, stroke=1, fill=1)
        pdf.setFont("Helvetica-Bold", 11.7)
        pdf.setFillColor(accent)
        pdf.drawString(x + 14, top - 22, title)
        y = top - 45
        for bullet in bullets:
            lines = _visual_wrap(
                bullet,
                font="Helvetica",
                size=9.6,
                width=card_width - 43,
                pdfmetrics=pdfmetrics,
            )
            pdf.setFillColor(accent)
            pdf.circle(x + 18, y + 3, 2, stroke=0, fill=1)
            pdf.setFont("Helvetica", 9.6)
            pdf.setFillColor(text)
            for line in lines:
                pdf.drawString(x + 28, y, line)
                y -= 12
            y -= 4
    release_top = card_top - 2 * (card_height + card_gap) - 5
    pdf.setFillColor(_visual_color(colors, "#102927"))
    pdf.setStrokeColor(amber)
    pdf.roundRect(34, release_top - 83, width - 68, 83, 9, stroke=1, fill=1)
    pdf.setFont("Helvetica-Bold", 11.7)
    pdf.setFillColor(amber)
    pdf.drawString(48, release_top - 22, "SAFE RELEASE POSTURE")
    _visual_draw_wrapped(
        pdf,
        "Usable now: verified checkout, authoritative core, dashboard, CLI/MCP, capture, recall, recovery, and offline checkpoint stage/ACK.",
        x=48,
        y=release_top - 43,
        width=326,
        font="Helvetica",
        size=9.7,
        leading=12,
        color=text,
        pdfmetrics=pdfmetrics,
        max_lines=3,
    )
    _visual_draw_wrapped(
        pdf,
        "Not yet claimed: signed/notarized installer, unattended cutover, migrations, executable rollback, or multi-host canary.",
        x=405,
        y=release_top - 43,
        width=338,
        font="Helvetica",
        size=9.7,
        leading=12,
        color=text,
        pdfmetrics=pdfmetrics,
        max_lines=3,
    )
    pdf.setStrokeColor(_visual_color(colors, "#245B57"))
    pdf.line(34, 36, width - 34, 36)
    pdf.setFont("Helvetica-Bold", 8.4)
    pdf.setFillColor(lime)
    pdf.drawString(34, 21, "SAFE RULE: inspect -> preserve -> act once -> verify receipt + Doctor + recall + store identity")
    pdf.setFont("Helvetica", 7.8)
    pdf.setFillColor(muted)
    pdf.drawRightString(width - 34, 21, visual_identity(revision, source_date))
    pdf.showPage()
    pdf.save()


def _visual_resolve_pdftoppm(explicit: str | None) -> str:
    candidate = explicit or os.environ.get("PDFTOPPM") or shutil.which("pdftoppm")
    if not candidate:
        raise RuntimeError(
            "visual documentation needs Poppler pdftoppm; pass --visual-pdftoppm PATH"
        )
    resolved = Path(candidate).expanduser().resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"visual pdftoppm is not executable: {resolved}")
    return str(resolved)


def _visual_render_page(
    renderer: str,
    pdf: Path,
    prefix: Path,
    *,
    dpi: int,
    page: int | None = None,
) -> Path:
    command = [renderer, "-png", "-r", str(dpi)]
    if page is not None:
        command.extend(("-f", str(page), "-l", str(page)))
    command.append("-singlefile")
    command.extend((str(pdf), str(prefix)))
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C"})
    result = subprocess.run(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"visual PDF render failed for page {page or 1}: "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    rendered = prefix.with_suffix(".png")
    if not rendered.is_file() or rendered.stat().st_size == 0:
        raise RuntimeError(f"visual PDF render did not create {rendered}")
    return rendered


def _visual_render_document(
    renderer: str,
    pdf: Path,
    prefix: Path,
    *,
    dpi: int,
    page_count: int,
) -> tuple[Path, ...]:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C"})
    result = subprocess.run(
        [renderer, "-png", "-r", str(dpi), str(pdf), str(prefix)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "visual PDF document render failed: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    width = len(str(page_count))
    rendered = tuple(
        prefix.with_name(f"{prefix.name}-{page:0{width}d}.png")
        for page in range(1, page_count + 1)
    )
    missing = [path for path in rendered if not path.is_file() or path.stat().st_size == 0]
    if missing:
        raise RuntimeError(f"visual PDF document render is missing: {missing}")
    return rendered


def generate_visual_documentation(
    *,
    output_root: Path,
    revision: str,
    source_date: str,
    pdftoppm: str | None = None,
) -> tuple[Path, ...]:
    """Atomically rebuild the exact existing 17-path visual package."""

    if not revision or any(character.isspace() for character in revision):
        raise ValueError("visual revision must be one non-empty token")
    date.fromisoformat(source_date)
    if len(visual_manual_pages()) != VISUAL_PLATE_COUNT:
        raise ValueError("visual manual must define exactly 13 pages")
    markdown = render_visual_manual_markdown(revision, source_date)
    if not markdown.isascii():
        raise ValueError("visual manual text must use portable ASCII punctuation")
    renderer = _visual_resolve_pdftoppm(pdftoppm)
    output_root = output_root.resolve()
    output_parent = output_root / "output"
    output_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".visual-manual-build-",
        dir=output_parent,
    ) as raw_temporary:
        build_root = Path(raw_temporary) / "tree"
        manual_dir = build_root / "output" / "manual"
        pdf_dir = build_root / "output" / "pdf"
        plates_dir = manual_dir / "plates"
        plates_dir.mkdir(parents=True)
        pdf_dir.mkdir(parents=True)
        (manual_dir / VISUAL_MANUAL_MD).write_text(markdown, encoding="utf-8")
        quick_pdf = pdf_dir / VISUAL_QUICK_PDF
        manual_pdf = pdf_dir / VISUAL_MANUAL_PDF
        _draw_visual_quick_pdf(quick_pdf, revision, source_date)
        _draw_visual_manual_pdf(manual_pdf, revision, source_date)
        _visual_render_page(
            renderer,
            quick_pdf,
            manual_dir / VISUAL_QUICK_PNG.removesuffix(".png"),
            dpi=165,
        )
        _visual_render_document(
            renderer,
            manual_pdf,
            plates_dir / "manual",
            dpi=150,
            page_count=VISUAL_PLATE_COUNT,
        )
        relative_paths = visual_artifact_relative_paths()
        if len(relative_paths) != 17 or len(set(relative_paths)) != 17:
            raise ValueError("visual artifact inventory must contain 17 unique paths")
        for relative in relative_paths:
            source = build_root / relative
            if not source.is_file() or source.stat().st_size == 0:
                raise RuntimeError(f"visual build is missing {relative}")
        for relative in relative_paths:
            source = build_root / relative
            destination = output_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.visual.tmp")
            shutil.copyfile(source, temporary)
            os.replace(temporary, destination)
    return tuple(output_root / relative for relative in visual_artifact_relative_paths())


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

    lines.append(
        "- Offline replication is a signed target-bound handoff with isolated restore proof; it does not provide live promotion, federation, or two-way divergent merge."
    )
    lines.append(
        "- Release provenance, compatibility, staging, layout, environment evidence, and activation journals remain an incomplete dormant substrate, not a signed installer or executable updater."
    )

    lines.extend(
        [
            "",
            "## Regeneration",
            "",
            "```bash",
            ".venv/bin/python scripts/synapse_status_report.py --context default",
            "```",
            "",
            "Use this report as a point-in-time status artifact. Re-run it before demos, handoffs, and readiness claims. The source-checkout row records the repository state at generation time; after committing this file, use `git log -1 --oneline` and `git status -sb` for the final commit position.",
            "",
        ]
    )
    return "\n".join(lines)


def run_json(command: list[str], *, env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
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
    env = status_subprocess_environment(args)
    base = [
        sys.executable,
        str(ROOT / "synapse_cli.py"),
        "--json",
    ]
    return {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "context_id": args.context,
        "agent_id": args.agent_id,
        "status": run_json([*base, "status", "--context", args.context], env=env),
        "profile": run_json([*base, "profile", "--benchmark-quick-prune"], env=env),
        "doctor": run_json([*base, "doctor", "--context", args.context, "--include-apps", "--repair-plan"], env=env),
        "context_health": run_json([*base, "context-health", "--context", args.context], env=env),
        "memory_hygiene": run_json([*base, "memory-hygiene", "--context", args.context, "--limit", str(args.hygiene_limit)], env=env),
        "cortex_state": run_json(
            [
                *base,
                "cortex-state",
                "--context",
                args.context,
                "--agent-id",
                args.agent_id,
                "--response-mode",
                "legacy",
            ],
            env=env,
        ),
        "git": git_snapshot(),
    }


def _validated_core_socket(value: Any) -> str:
    socket_path = Path(str(value or "")).expanduser()
    if not socket_path.is_absolute() or ".." in socket_path.parts:
        raise ValueError("core socket must be an absolute normalized path")
    return str(socket_path)


def status_subprocess_environment(
    args: argparse.Namespace,
    *,
    environ: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build one deterministic child environment for every live probe."""

    source = dict(os.environ if environ is None else environ)
    binding = binding_from_environment(source)
    requested_socket = str(getattr(args, "core_socket", "") or "").strip()
    inherited_socket = str(source.get(CORE_SOCKET_ENV, "") or "").strip()
    env = dict(source)
    env.pop("MLX_DEVICE", None)
    env.pop(STATE_PATH_ENV, None)
    env.pop(MEMORY_DB_ENV, None)
    for name in LEGACY_CORE_CONFIG_ENV:
        env.pop(name, None)
    if binding is not None:
        if binding.repo_root != ROOT:
            raise ValueError(
                "core binding repository does not match the status report checkout"
            )
        if requested_socket:
            asserted_socket = _validated_core_socket(requested_socket)
            if (
                binding.authority_mode != "authoritative-core-v6"
                or Path(asserted_socket) != binding.socket_path
            ):
                raise ValueError(
                    "core socket assertion conflicts with the reviewed core binding"
                )
        for name in (
            CORE_SOCKET_ENV,
            EXPECTED_CONFIG_ENV,
            "SYNAPSE_S2_EXPORT_DIR",
            "SYNAPSE_S2_CAPTURE_ROOT",
        ):
            env.pop(name, None)
        env[BINDING_ENV] = str(source[BINDING_ENV]).strip()
        return env

    env.pop(BINDING_ENV, None)
    env.pop(CORE_SOCKET_ENV, None)
    selected_socket = requested_socket or inherited_socket
    if selected_socket:
        env[CORE_SOCKET_ENV] = _validated_core_socket(selected_socket)
    return env


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(description="Generate docs/CURRENT_STATUS.md from live SYNAPSE-S2 state.")
    parser.add_argument(
        "--visual-docs",
        action="store_true",
        help="Rebuild the existing 13-page visual manual and one-page field card instead of querying live state.",
    )
    parser.add_argument("--visual-revision", default="")
    parser.add_argument("--visual-source-date", default=date.today().isoformat())
    parser.add_argument("--visual-pdftoppm", default="")
    parser.add_argument("--context", default="default")
    parser.add_argument("--agent-id", default="codex-desktop")
    parser.add_argument("--embedding-provider", default="mlx-neural")
    parser.add_argument(
        "--core-socket",
        default="",
        help="Optional explicit authoritative-core socket; otherwise use the durable marker.",
    )
    parser.add_argument("--hygiene-limit", type=int, default=10)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--print", action="store_true", dest="print_report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.visual_docs:
        revision = args.visual_revision or git_snapshot()["head"]
        artifacts = generate_visual_documentation(
            output_root=ROOT,
            revision=revision,
            source_date=args.visual_source_date,
            pdftoppm=args.visual_pdftoppm or None,
        )
        for artifact in artifacts:
            print(f"Wrote {artifact}")
        return 0
    output = validate_status_output_path(args.output)
    args.context = reject_sensitive_identifier(
        args.context,
        field="status report context_id",
    )
    args.agent_id = reject_sensitive_identifier(
        args.agent_id,
        field="status report agent_id",
    )
    args.embedding_provider = reject_sensitive_identifier(
        args.embedding_provider,
        field="status report embedding provider",
    )
    report = collect_live_report(args)
    markdown = render_status_markdown(report)
    markdown, _ = redact_capture_text(markdown)
    write_private_status_report(output, markdown)
    if args.print_report:
        print(markdown)
    else:
        print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
