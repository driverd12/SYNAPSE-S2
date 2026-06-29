# Monday Operator Readiness Certification

- Add a real readiness certifier that writes a single evidence pack under `.synapse_s2/evidence_packs/`.
- Prove the required operator path with live commands: client/MCP connect, memory write, recall, App Connect preview, wrap-session persistence, Doctor, and dashboard smoke.
- Record raw stdout/stderr, parsed payloads, pass/fail status, repair guidance, and a summary runbook.
- Add focused tests for manifest/report generation and honest degraded/blocked handling.
- Run the certifier against the local default context and push the implementation to both remotes.
