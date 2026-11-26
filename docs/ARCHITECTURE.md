# AEGIS AI — Architecture Map

Updated for the V3.1 public release. Paths are relative to the repository root.

## 1. Runtime

| Entry | File | Behaviour |
|---|---|---|
| API + static UI | `backend/main.py` | FastAPI app on your configured local address; mounts `frontend/` at `/` |
| Desktop window | `backend/main.py::__main__` | uvicorn in daemon thread + `pywebview` window (WebView2) |
| Desktop launcher | `launch_aegis.ps1` | starts `start_all.ps1` if needed, then opens the UI in a browser |
| Service orchestration | `start_all.ps1`, `START_ALL.cmd` | user-configured local targets and API |
| Telegram | `backend/telegram_bot.py`, `start_telegram_bot.ps1` | long-polling public bot, `/start`, `/help`, `/scan`, `/status`, `/pipeline`, `/stop`, `/report`, `/gates`, `/tools`, `/profile`, `/owner` |
| Demo driver | `demo/run_demo.py` | real SSE agent run, prints trace, writes `reports/demo_last.json` |

## 2. Backend modules (33 files)

| Module | Responsibility |
|---|---|
| `__init__.py` | loads `.env` before other modules read secrets |
| `main.py` | all API routes, CORS, SSE streams, agent/deep state, desktop launcher |
| `security_agent.py` | Ollama/Qwen function-calling loop (Gemini fallback), versioned prompt, 11 declarations, retries/fallback |
| `tool_registry.py` | `DEEP_TOOLS` metadata, availability/version probes, scan-path allowlist |
| `deep_scanner.py` | real runners/parsers for Semgrep, Trivy, Gitleaks, httpx, Katana, API checks, testssl, Burp, Metasploit |
| `deep_correlation.py` | canonical finding normalization, dedup, grouping, correlation stats |
| `deep_pdf.py` | deep-engine PDF export |
| `wsl_scanner.py` | guarded WSL process execution, cancellation, localhost DAST target validation |
| `guardrail.py` | command allowlist, injection token detection, model output review |
| `scan_engine.py` | V1 audit/DAST scan manager, cancel/retry, SSE generators |
| `auditor.py` | local source analysis + V1 patch application |
| `php_audit.py` | PHP/local web static analysis |
| `comparison.py` | BEFORE/AFTER comparison of two persisted scans (numeric/structured only) |
| `verification.py` | remediation before/after verification from backups + ledger |
| `remediation.py` | approval-gated proposals, immutable backups, apply, rollback, ledger |
| `attack_graph.py`, `attack_surface.py` | evidence-based graph/surface builders |
| `correlation.py`, `vulnerability_center.py`, `vuln_analyst.py` | classic audit correlation, CVSS/CVE analysis |
| `ai_intelligence.py`, `dashboard.py`, `insights.py`, `reports_center.py`, `settings_center.py` | dashboard/aggregation payloads |
| `api_security.py`, `copilot.py`, `monitor.py`, `history.py`, `local_http.py`, `serial_beacon.py`, `pdf_report.py` | API checks, Q&A, drift watcher, JSON persistence, localhost fetch, ESP32 beacon, standard PDF |

## 3. API surface

V1 contract (unchanged): `GET /`, `GET /api/audit-stream`, `GET /api/dast-stream`, `POST /api/apply-patch`, `GET /api/download-report`; events `stage | log | error | complete`.

V3 additions (grouped): `agent` (`/api/agent/run`, `/api/agent-stream`, `/api/agent/last`), `deep engine` (`/api/deep-scan-stream`, `/api/deep-results`, `/api/deep-correlate`, `/api/download-deep-report`), `tools` (`/api/tools`, `/api/tools/{name}/guide`, `/api/tools/{name}/check`, `/api/tools/run`), `engine` (`/api/engine/*`), `intelligence` (`/api/overview`, `/api/vulnerability-center`, `/api/ai-intelligence`, `/api/attack-graph`, `/api/attack-surface`, `/api/api-security`), `respond` (`/api/remediation/*`, `/api/verification/*`, `/api/comparison*`, `/api/reports`, `/api/report-file`), `ops` (`/api/monitor/*`, `/api/settings*`, `/api/copilot/ask`, `/api/history*`).

## 4. Frontend

- `frontend/index.html`: hash router shell, nav groups `SCAN / INTELLIGENCE / DEEP ENGINE / RESPOND`, 9-stage pipeline bar, agent hero + task form, comparison panel, attack graph panel. Styles: `styles.css?v=15`, `agent.css?v=1`; script `app.js?v=22`.
- `frontend/app.js`: `PAGE_BUTTON_MAP` / `SLUG_TO_BUTTON` hash router; SSE handlers for audit, DAST, deep and agent streams; `runAgentMode()`, `agentHandleTool()`, `agentUpdateCard()`, `renderAgentResult()`; `paintGraphSvg()` for the attack graph; before/after comparison selectors.
- `frontend/agent.css`: agent timeline, tool cards, severity chips.
- No image diff or Playwright code exists in the frontend.

## 5. Persistence

All state is file-based under `reports/` (no SQLite): `history.json` (capped 100 atomic records), `agent_last.json`, `agent_audit.jsonl`, `deep_tool_audit.jsonl`, `verification*.json`, `monitor.json`, `backups/remediation_ledger.json`, PDF reports. `reports/` and `*.pdf` are gitignored.

## 6. Tests / verification

The in-repo suite lives in `tests/` and runs with `.\.venv\Scripts\python.exe -m pytest -q tests` (99 tests on the reference machine). Mock tests never claim real scanner execution; live checks are driven by `demo/run_demo.py`.

## 7. V3.1 delivery summary

Delivered in V3.1: a versioned system prompt (`prompts/security_agent.v3.1.md`), full tool parameter/permission/output contracts, explicit `decision / tool_result / verified_finding / counters` events with IDs, canonical finding enrichment (CWE, method, parameter, numeric confidence, verification status), screenshot-based BEFORE/AFTER visual diff with slider, explicit-origin CORS/Host hardening plus `/api/version`, an in-repo pytest suite, `DEVELOPMENT_REPORT.md`, and V3.1 desktop branding.
