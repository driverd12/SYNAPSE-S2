# Large Neural Embedding Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute this plan.

**Goal:** Add a real local large-neural embedding provider to SYNAPSE-S2 so memory capture and recall can use a downloaded MLX language model instead of only hash-based semantic features.

**Architecture:** Keep the existing provider boundary. Add a lazy-loading MLX neural provider that resolves from `SYNAPSE_S2_EMBEDDING_PROVIDER=mlx-neural`, loads a local or Hugging Face MLX model, pools hidden states into fixed-size vectors, normalizes/projects to the requested SYNAPSE-S2 dimensions, and emits explicit provenance plus benchmark/certification data. Preserve `semantic-hash` as the offline fallback and do not silently claim neural mode when model loading fails.

**Tech Stack:** Python 3.11, MLX, mlx-lm, Hugging Face Hub cache, unittest, existing SYNAPSE-S2 CLI/backend/MCP/dashboard.

---

### Task 1: Add Failing Provider Tests

**Files:**
- `tests/test_embedding_providers.py`

**Steps:**
1. Add a test that `resolve_embedding_provider("mlx-neural")` returns a provider with `provider_id == "mlx-neural-v1"` and does not eagerly load a model.
2. Add a test that a fake injected neural runtime produces a fixed-size normalized vector with provenance fields: `provider`, `provider_type`, `model_id`, `semantic`, `local_only`, `native_mlx`, `pooling`, and `source_dimensions`.
3. Add a test that missing MLX model dependencies fail with `EmbeddingProviderError` carrying an actionable install/configuration message.

**Verification:**
- Run `.venv/bin/python -m unittest tests.test_embedding_providers`.
- Confirm the new tests fail because neural provider support is missing.

### Task 2: Implement MLX Neural Provider

**Files:**
- `embedding_providers.py`

**Steps:**
1. Add `MLXNeuralEmbeddingProvider`.
2. Support provider specs: `mlx-neural`, `mlx-neural:<model-id-or-path>`, `neural`, and `neural:<model-id-or-path>`.
3. Add lazy runtime loading using `mlx_lm.load`, with model selection from `SYNAPSE_S2_NEURAL_MODEL`.
4. Pool hidden states into an embedding vector, normalize it, and deterministically project or pad/truncate to requested dimensions.
5. Add runtime dependency errors that explain how to install dependencies and set `SYNAPSE_S2_NEURAL_MODEL`.
6. Keep hash providers unchanged.

**Verification:**
- Run `.venv/bin/python -m unittest tests.test_embedding_providers`.

### Task 3: Add CLI Diagnostics and Certification Visibility

**Files:**
- `synapse_cli.py`
- `mlx_backend.py`
- `mcp_server.py`
- `dashboard_server.py`
- `web/app.js`

**Steps:**
1. Surface neural provider details in `doctor`, `status`, and `certify-runtime`.
2. Add a CLI command to benchmark the configured embedding provider with a real prompt and return latency, vector dimensions, model id, and provenance.
3. Ensure MCP/dashboard provider provenance shows neural/native status without implying it is the LLM model.

**Verification:**
- Run targeted CLI/backend/dashboard tests.

### Task 4: Install and Lock Model Dependencies

**Files:**
- `pyproject.toml`
- `uv.lock`

**Steps:**
1. Add `mlx-lm`, `huggingface-hub`, and supporting tokenizer/safetensors dependencies through `uv`.
2. Verify dependency importability in the project `.venv`.
3. Prefer a configurable local model default suitable for Apple Silicon, with documentation that operators can override it.

**Verification:**
- Run `.venv/bin/python -c "import mlx_lm, huggingface_hub, tokenizers, safetensors"`.

### Task 5: Real Model Smoke and Performance Evidence

**Files:**
- `docs/TOMORROW_RUNBOOK.md`
- `README.md`

**Steps:**
1. Attempt a real MLX neural model smoke test with a manageable default model.
2. Record latency, vector dimensions, provider provenance, and failure mode if the model cannot be downloaded.
3. Update operator docs with exact commands for neural mode and fallback mode.

**Verification:**
- Run `synapse_cli.py --json --embedding-provider mlx-neural provider-benchmark --text "..."`.
- Run `certify-runtime` with neural provider enabled.

### Task 6: Full Verification, Capture, Commit, Push

**Files:**
- All modified files.

**Steps:**
1. Run the full unittest suite.
2. Run a CLI status/query smoke.
3. Capture a concise SYNAPSE-S2 session note with implementation details and validation evidence.
4. Commit and push `codex/large-neural-embedding-provider`.

**Verification:**
- `git status -sb` is clean after commit.
- Remote push succeeds or failure is documented with exact reason.
