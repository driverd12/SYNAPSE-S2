# SYNAPSE-S2 Reliability Usability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SYNAPSE-S2 dashboard easier to trust by adding an operator self-test matrix and a meaningful App Connect fallback when Accessibility snapshots are low-signal.

**Architecture:** Keep the existing stdlib dashboard server and vanilla JS dashboard. Add focused API endpoints backed by `DashboardRuntime` and `TranscriptCaptureManager`, then wire the existing App Connect panel to the new fallback capture path.

**Tech Stack:** Python stdlib HTTP server, `unittest`, local SQLite-backed SYNAPSE-S2 backend, vanilla HTML/CSS/JS.

---

### Task 1: Dashboard Self-Test

**Files:**
- Modify: `dashboard_server.py`
- Modify: `web/index.html`
- Modify: `web/app.js`
- Modify: `web/styles.css`
- Test: `tests/test_dashboard_server.py`

- [ ] **Step 1: Write failing API/UI wiring tests**
  Add a dashboard runtime test asserting `GET /api/self-test?context_id=demo` returns `action=self-test`, `overall_status`, and component statuses for `runtime`, `memory`, `embedding`, `context_bus`, `capture_inbox`, and `app_connect`. Extend the static asset test to require `selfTestButton`, `selfTestState`, `selfTestGrid`, and `/api/self-test`.

- [ ] **Step 2: Verify tests fail**
  Run: `.venv/bin/python -m unittest tests.test_dashboard_server.DashboardRuntimeTests.test_self_test_endpoint_reports_operator_readiness tests.test_dashboard_server.DashboardRuntimeTests.test_dashboard_assets_do_not_seed_demo_or_auto_recall`
  Expected: failure because `/api/self-test` and self-test DOM ids do not exist.

- [ ] **Step 3: Implement minimal self-test**
  Add `DashboardRuntime.self_test()`, route `GET /api/self-test`, an action button, a compact status grid, and JS rendering.

- [ ] **Step 4: Verify tests pass**
  Run the same targeted command and expect OK.

### Task 2: App Connect Selected-Text Fallback

**Files:**
- Modify: `transcript_capture.py`
- Modify: `dashboard_server.py`
- Modify: `web/index.html`
- Modify: `web/app.js`
- Modify: `web/styles.css`
- Test: `tests/test_transcript_capture.py`
- Test: `tests/test_dashboard_server.py`

- [ ] **Step 1: Write failing capture tests**
  Add a manager test for `capture_app_selected_text()` requiring confirmation, redaction, connection metadata, and `adapter_kind=app-selected-text`. Add a dashboard endpoint test for `POST /api/app-selection-capture` with `confirm=true`.

- [ ] **Step 2: Verify tests fail**
  Run: `.venv/bin/python -m unittest tests.test_transcript_capture.TranscriptCaptureManagerTests.test_app_selected_text_capture_uses_connection_metadata_and_redacts tests.test_dashboard_server.DashboardRuntimeTests.test_app_selection_capture_endpoint_persists_selected_text`
  Expected: failure because the method and route do not exist.

- [ ] **Step 3: Implement minimal fallback**
  Add `TranscriptCaptureManager.capture_app_selected_text()`, route it through the dashboard, add a textarea/button in App Connect, and render low-signal snapshot guidance that points to the fallback.

- [ ] **Step 4: Verify tests pass**
  Run the same targeted command and expect OK.

### Task 3: Verification

**Files:**
- No new source files beyond Tasks 1-2.

- [ ] **Step 1: Run targeted test suite**
  Run: `.venv/bin/python -m unittest tests.test_transcript_capture tests.test_dashboard_server`
  Expected: OK.

- [ ] **Step 2: Run full suite and static checks**
  Run: `.venv/bin/python -m unittest discover -s tests`, `node --check web/app.js`, and `git diff --check`.
  Expected: OK / zero diff whitespace errors.

- [ ] **Step 3: Capture SYNAPSE-S2 evidence**
  Run `synapse_cli.py --json capture-session` with implementation decisions and validation evidence.
