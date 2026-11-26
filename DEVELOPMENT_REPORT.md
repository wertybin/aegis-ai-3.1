# AEGIS AI V3.1 — Development Report

**Date:** 2026-11-24 · **Version:** 3.1.0 · **Scope:** additive upgrade of the existing V3 project. No V1 route, event name, scanner implementation or UI page was removed or replaced.

**Premium Telegram update (2026-11-24):** the existing bot was rebuilt as a Telegram-native presentation layer (`backend/telegram_ui/`) with verified Premium custom emoji, inline navigation, a validated callback architecture and a real cooperative `/stop`. Existing commands and the backend contract are preserved.

**Release preparation:** the public repository contains only source, docs, demo files, tests and WSL helpers. Runtime state, `.env`, logs, reports and local tool binaries stay untracked.

---

## 1. Summary

V3.1 turns the existing Gemini integration into a genuinely autonomous, evidence-driven agent. The model receives version-controlled instructions and real JSON tool contracts, emits real `function_call`s, receives real `function_response`s, and its decisions are streamed to the UI as distinguishable events. Cross-tool correlation, optional visual BEFORE/AFTER capture, API hardening, an automated test suite, documentation and a real desktop launcher were added on top of the working V3 engine.

The Telegram bot is now a premium, Telegram-only product: a reusable HTML design system, inline keyboard navigation, 61 live-verified Premium custom emoji (one consistent animated pack), honest Unicode fallbacks, a validated `ag:v1` callback codec, per-chat state and a real `/stop` backed by `POST /api/agent/cancel`.

**Status rule used below:** `VERIFIED` = implemented and observed in a real run or test; `PARTIAL` = implemented with a documented constraint; `NOT IMPLEMENTED` = not claimed.

---

## 2. Files changed / added

### Added
| File | Purpose |
|---|---|
| `prompts/security_agent.v3.1.md` | Single source of truth for the system prompt, `version: 3.1.0` |
| `backend/visual_diff.py` | Optional Playwright screenshot capture + Pillow pixel diff, honest `available=false` fallback |
| `backend/desktop_window.py` | Native WebView2 window pointing at the already-running local service (no second uvicorn) |
| `tests/conftest.py`, `test_prompt.py`, `test_registry.py`, `test_agent.py`, `test_scope.py`, `test_correlation.py`, `test_api.py`, `test_pdf.py`, `test_telegram.py` | Automated unit/API/transport tests (mock-based where no binary is needed) |
| `backend/telegram_ui/__init__.py`, `config.py`, `emoji.py`, `emoji_data.py`, `components.py`, `keyboards.py`, `callbacks.py`, `state.py`, `api.py`, `transport.py`, `screens.py`, `handlers.py` | Premium Telegram UI package: brand config, verified emoji registry, HTML components, keyboards, callback codec, per-chat state, API client, fallback transport, screens and router |
| `tests/test_telegram_ui.py` | Mock-only tests for emoji provenance/fallbacks, callbacks, keyboards, screens, state, transport, cross-chat locking and `/stop` flows |
| `docs/ARCHITECTURE.md` | Architecture map and V3.1 delivery summary |
| `docs/V3.1_PLAN.md` | Incremental execution plan |
| `docs/screenshots/agent-v31-ui.png`, `agent-and-pipeline.png`, `dast-findings.png` | Real application screenshots |
| `requirements-visual.txt`, `requirements-dev.txt` | Optional visual capture and test dependencies |
| `install_desktop.ps1`, `launch_aegis_31.ps1`, `assets/aegis_31.ico` | Desktop shortcut installer, idempotent launcher, real icon |

### Modified
| File | Change |
|---|---|
| `backend/security_agent.py` | Prompt loader + version, 11 contracts-driven declarations, canonical IDs, decision/tool_result/verified_finding/counters events, exact-duplicate suppression, enriched findings; cooperative `check_cancelled()` between turns and before every tool call |
| `backend/tool_registry.py` | `description`, `parameters_schema`, `permission_level`, `output_schema` on all 11 tools; exposed through `check_all_tools()` |
| `backend/deep_correlation.py` | `canonical_id`, CWE, method, parameter, numeric confidence, verification status, confirmed/potential split |
| `backend/main.py` | `APP_VERSION=3.1.0`, `GET /api/version`, explicit CORS + Host/Origin guard, snapshot/image routes, V3.1 imports; `POST /api/agent/cancel`, `_agent_cancel_scope`, sync + SSE cancellation handling |
| `backend/wsl_scanner.py` | `ScanCancelled`, `bind_cancel_event`, `clear_cancel_event`, `check_cancelled`; guarded `_run` polls every 500 ms and terminates the WSL child on cancel |
| `backend/telegram_bot.py` | Premium entry point: `getMe` identity, offset priming, message + callback polling, `/stop`, `/menu`, `/gates`, `/tools`, `/profile`, `/owner`; preserves `_tg_opener`, `_request`, `tg`, `allowed`, `api_get`, `api_post`, `parse_scan` |
| `.env.example` | Documented `TELEGRAM_OWNER_CHAT_IDS` and `TELEGRAM_EMOJI_MODE` |
| `backend/guardrail.py` | Unchanged — existing allowlist reused (no regression) |
| `frontend/index.html`, `app.js`, `agent.css` | v3.1 brand, counters bar, decision/result/finding SSE handlers, visual slider; existing pages untouched |
| `README.md` | Project documentation with Mermaid diagrams, exact prompt, tools table, real screenshots, premium Telegram section, "Where I Got Stuck" |
| `docs/DEMO_SCRIPT.md` | V3.1 event names, honest timing guidance |
| `demo/run_demo.py` | Prints decision/evidence/finding/counter frames; stores version and counters in `reports/demo_last.json` |
| `requirements.txt` | Pillow for real image diff |

---

## 3. Features implemented

| # | Feature | Status | Evidence |
|---|---|---|---|
| 1 | Real model function calling with full history | VERIFIED | Live `ollama-function-calling` run with `qwen2.5:14b`; earlier live Gemini fallback run `gemini-function-calling`, model `gemini-3.1-flash-lite`; real `function_call`/`function_response` objects in `security_agent.py` |
| 2 | Model selects tools adaptively (not a fixed sequence) | VERIFIED | Latest run: model chose Semgrep → httpx → Katana → correlate_findings; earlier run chose 6 tools |
| 3 | Unique IDs, timestamps, status, real output per call | VERIFIED | `decision_id`, `tool_call_id` in live SSE trace; `tests/test_agent.py` |
| 4 | Iteration/time limits, retries, free fallback chain, cooperative cancellation | VERIFIED | 8-call cap, per-tool timeouts, 503/429/500 retry, model chain; `/api/agent/cancel` aborted a real sync run in **4.07 s** and the SSE run emitted `error` with `cancelled=true`; cancelled results are not stored |
| 5 | Version-controlled prompt | VERIFIED | `PROMPT_VERSION=3.1.0`, `GET /api/version`, `tests/test_prompt.py` |
| 6 | Tool registry contracts + generated declarations | VERIFIED | `/api/tools` returns all four fields for 11 tools; `tests/test_registry.py` |
| 7 | Live Activity Center events | VERIFIED | `decision`, `tool_result`, `verified_finding`, `counters` observed in real SSE run; browser console 0 errors, 0 failed requests |
| 8 | Cross-tool correlation enrichment | VERIFIED | `tests/test_correlation.py`: two tools on same endpoint merge with both evidence sources and confidence 0.9+; unrelated findings stay separate |
| 9 | Exact-duplicate suppression in agent findings | VERIFIED | `tests/test_agent.py` + code; final real run went from 26 raw to 21 unique findings, all `AF-` IDs distinct |
| 10 | BEFORE/AFTER numeric comparison | VERIFIED (pre-existing V3) | Routes `/api/comparison`, `/api/comparison/scans`; regression harness |
| 11 | BEFORE/AFTER screenshots + slider | PARTIAL | API and slider implemented, pixel diff honest; capture unavailable until optional Playwright/Chromium is installed (`available=false` observed) |
| 12 | API hardening | VERIFIED | Explicit CORS, Host/Origin middleware; mock test rejects `Origin: https://evil.example` with 403 |
| 13 | Automated tests | VERIFIED | 99/99 pass in `.venv` |
| 14 | Desktop V3.1 shortcut | VERIFIED | Shortcut installer created a working shortcut; launcher started `pythonw -m backend.desktop_window`; real window title `AEGIS AI 3.1 // Autonomous Security Intelligence` observed with a non-zero `MainWindowHandle` |
| 15 | Telegram bot | VERIFIED (premium UI) | Token verified via `getMe` (`@aegls_ai_bot`); live bot process starts with clean logs; `/start`, `/menu`, `/help`, `/scan`, `/stop`, `/status`, `/report`, `/pipeline`, `/gates`, `/tools`, `/profile`, `/owner` implemented; callbacks validated; 54 mock-only UI tests pass; 31/31 screens rendered from real backend payloads |
| 16 | PDF generation | VERIFIED | `tests/test_pdf.py` writes a real `%PDF` from correlation data |
| 17 | Verified Premium custom emoji registry | VERIFIED | `getStickerSet` harvested 400 IDs from 4 public packs; `getCustomEmojiStickers` re-verified 400/400; registry ships **61 NewsEmoji IDs / 76 keys**, IDs stored as strings |
| 18 | Premium message design system | VERIFIED | `components.py` + `screens.py`: header/rule/section/footer, blockquotes, severity lines, findings preview, escaping; all screens render under 4096 chars |
| 19 | Inline navigation + callback architecture | VERIFIED | `ag:v1:<action>[:args]`, whitelist, gate/tool validation, 64-byte cap, immediate ACK, debounce, parent-based Back, screen tokens; every button parses. Bot state mirrors the backend's one-run-at-a-time rule so a second chat cannot claim a slot and cancel another chat's scan |
| 20 | Real `/stop` | VERIFIED | `POST /api/agent/cancel` + contextvar event + 500 ms WSL polling; sync 4.07 s, SSE final `error`, last-run unchanged; bot command and Stop button |
| 21 | Telegram DAST → Audit → Agent pipeline | VERIFIED | `/pipeline` with per-gate DAST/Audit/Agent/Full-chain callbacks; real `POST /api/engine/start`, decoded SSE progress, per-chat engine cancellation and one global run slot; live DAST cancel + Audit completion confirmed |

---

## 4. Test results

### Automated (in-repo)
```
.venv\Scripts\python.exe -m pytest -q tests
99 passed, 130 warnings in 32.69s
```
Warnings are upstream FastAPI/Starlette deprecations, not application errors. The suite now includes `tests/test_telegram_ui.py` (54 tests), `tests/test_ollama_browser.py` (5 tests), `tests/test_report_delivery.py` and the original core tests. The two temporary failures after the Ollama integration were test isolation issues (a legacy test assumed Gemini despite `.env` selecting Ollama, and a registry test assumed browser disabled); both tests now set their own provider/browser state.

### Real integration / regression
| Check | Result |
|---|---|
| Real Gemini E2E (`demo/run_demo.py --no-open`) | VERIFIED — final post-dedup run: 4 real tool calls (Semgrep → httpx → Katana → correlate_findings), **21 unique real findings** (HIGH 7 / MEDIUM 12 / LOW 2), `gemini-function-calling`, `gemini-3.1-flash-lite`, 262 s; trace in `logs/demo_final.log`, digest in `reports/demo_last.json` |
| Guardrail harness (`v3_guardrail_check.py`) | **30 blocked / 0 bypass** |
| Browser AGENT page (your configured local UI URL) | Title `AEGIS-AI // v3.1`; 0 console messages at warning+; counters and visual slider present; `app.js?v=23` |
| API `/api/version` | `{"version":"3.1.0","agent_version":"3.1.0","prompt_version":"3.1.0"}` |
| API `/api/tools` | 11 tools; **11 OK, 0 MISSING** at final audit — Metasploit `Framework Version: 6.5.12-dev-` after PATH-aware fix, Burp Suite Community `2026.3.3-47134` |
| API `/api/agent/cancel` (idle) | `{"cancelled": false, "active": false}` — no false positives |
| API `/api/agent/cancel` (real sync run) | **VERIFIED** — `{"cancelled": true, "active": true}`; run returned `status=cancelled`, `cancelled=true`, 0 findings in **4.07 s**; `/api/agent/last` timestamp unchanged, `running=false` |
| API `/api/agent-stream` cancellation | **VERIFIED** — final SSE event `error`; `/api/agent/last` unchanged |
| API `/api/tools/semgrep/check` | **VERIFIED** — `status=OK`, `version=1.186.0`, 0.9 s |
| Telegram `getStickerSet` + `getCustomEmojiStickers` | **400/400 IDs verified** across NewsEmoji, TgAndroidIcons, vector_icons_by_fStikBot, StatusEmoji; registry ships 61 NewsEmoji IDs |
| Telegram bot startup | `getMe` → `@aegls_ai_bot`; log `identity @aegls_ai_bot · callbacks enabled`; no poll errors |
| Local suite | The repository's own `.venv` runs **99/99** tests; `.env`, `.git`, `.venv`, `reports/` and `logs/` remain local and untracked |
| Live services (`start_all.ps1`) | **ALL SERVICES READY** — UI `:8765`, Site 1 `:5000`, Site 2 `:5001`, DNS lab `aegis-lab.local` |
| Live `/api/tools` | **11/11 installed in 7.07 s**; `semgrep` re-check `status=OK`, `version=1.186.0` in 1.06 s |
| Live `/api/agent/cancel` | idle `{"cancelled": false, "active": false}`; real sync run cancelled in **3.08 s**, `cancelled=true`, 0 findings; `/api/agent/last` timestamp unchanged, `running=false` |
| Real-payload screen audit | **31/31 screens OK** rendered from the live `/api/agent/last` and `/api/tools` payloads: every message < 4096 chars, every HTML tag balanced, every keyboard valid, all 11 tool-detail screens included |
| Live bot process | `identity @aegls_ai_bot · callbacks enabled`; transient `WinError 10054` poll errors recover through the poll loop; bot token confirmed absent from the log |
| Live bot launcher | `START_ALL.cmd` now runs `start_all.ps1`, which starts the Telegram bot as a detached process after a 2 s stale-PID guard; the WMI check filters on `python*` so a launcher shell cannot be mistaken for the bot; badge reports `Telegram : OK` and `AI provider : ollama` |
| Live premium chat flow | **VERIFIED** through the real Bot API against a live chat: `/start`, Gates callback (`ag:v1:gates`), `/scan <your-localhost-URL>`, `/stop` (`cancelled=true`, `chat_running=false`) and `/status`; command/callback/scan/stop logs were masked and no token pattern appeared |
| Telegram PDF delivery | **VERIFIED** — `/report` called `sendDocument` with a real `AegisAI_Audit_Report_20261123_200827.pdf` (18,739 bytes); log recorded `pdf sent` with the chat id masked; PDF buttons added to Status and scan-result keyboards |
| Telegram DAST → Audit → Agent | **VERIFIED** — `/pipeline` + `pfull` callback started real `scan_20261124_204958_2a67c2`, decoded live SSE stage/log/status events (Nmap, FFUF) and cooperative `/stop` cancelled it at `20:50:20`; single `paudit` callback completed `scan_20261124_205047_d911af` (score 10, real PDF `AegisAI_Audit_Report_20261124_205145.pdf`); Agent stage reuses the verified `/api/agent/run` Ollama path |
| Gemini `role=tool` regression | Fixed in code by appending tool responses as `role=user` for Gemini while Ollama keeps its native `role=tool`; `grep` confirms no Gemini `role=tool` content remains |
| Legacy services | `:8765`, `:5000`, `:5001`, `:5002` all HTTP 200 |
| Secret scan of candidate tracked files | No token/key patterns found; `.env`, `logs/`, `reports/` confirmed ignored by git |
| V1 SSE regression harness | **TOTAL 36/36 passed** — V1 SSE contract, localhost guards, remediation gating/rollback, verification, comparison, aggregation endpoints |
| Deep-engine smoke harness | **TOTAL 31 PASS / 0 FAIL** — 11-tool registry shape, real runner schemas, SSE names preserved, deep correlation and results endpoints |

**Failed tests:** none in the final in-repo suite. Intermediate failures were found and fixed during development (missing `cache["results"]` in a mock, correlation confidence threshold, README prompt identity string, a stale `state.snapshot` field, an initial keyboard test that omitted tool names, and a cross-chat scan-slot race) — all fixed before the final **99/99** run.

---

## 5. Tools available / unavailable

Live `/api/tools` status at report time:

| Tool | Status | Note |
|---|---|---|
| Semgrep | OK (1.186.0) | Real SAST; produced 24 findings in the live run |
| Trivy | OK (0.76.2) | Real dependency/CVE scanner |
| Gitleaks | OK (8.30.1) | Real secret scanner, values masked |
| testssl.sh | OK (3.2.2) | TLS only for authorized `https://localhost` |
| httpx | OK | Real HTTP fingerprint; 1 finding in live run |
| Katana | OK | Real crawler; 1 finding in live run |
| API Security | OK (`builtin-v3`) | Real built-in checks |
| AI Correlation | OK (`builtin-v3`) | Real dedup/confidence |
| Tool Center | OK (`builtin-v3`) | Real availability/version probe |
| Burp Suite | **OK** (`2026.3.3-47134 Burp Suite Community Edition`) | Real CLI detected via guarded WSL; `validate-only` — no fake proxy traffic |
| Metasploit | **OK** (`Framework Version: 6.5.12-dev-`) | Real read-only validation: version + scanner module inventory via guarded WSL; exploit/payload execution disabled by policy |

Optional: Playwright/Chromium absent → `visual_diff.playwright_status().available == false`; Pillow present.

---

## 6. Real vs mock integrations

**Real (no simulation):** Ollama/Qwen function calling, with optional Gemini function calling via `google-genai`; Semgrep, Trivy, Gitleaks, httpx, Katana, testssl.sh through guarded WSL processes; API security checks; deep correlation; PDF via ReportLab; FastAPI/SSE; pywebview desktop window; Telegram `getMe`, `getStickerSet` and `getCustomEmojiStickers` verification (400/400 IDs); real `/api/tools` and `/api/tools/{name}/check` calls; real gate HTTP probes; real `/api/agent/cancel` runs.

**Mock (clearly labelled in code):** `tests/test_agent.py` replaces the model provider and tool execution with fakes to test loop mechanics, iteration limits and event shape. These tests never write findings to reports and are never presented as scanner output. `tests/test_api.py` uses FastAPI `TestClient`, not a real browser. `tests/test_telegram_ui.py` uses a fake transport and fake API client: it proves routing, validation and fallback logic, not Telegram rendering. Visual capture is explicitly unavailable rather than mocked.

---

## 7. Known limitations

- Scope is intentionally your configured localhost targets only; no address is bundled and remote targets are rejected before execution.
- The local Ollama model can be slow on limited hardware; the optional Gemini fallback can return 503 under load, and retries reduce but do not eliminate this.
- The full real agent run can exceed 120 s: in the final run Semgrep took ~95 s and total wall time was ~262 s because of model latency. The ≤2-minute video must be edited/compressed (or use the pre-recorded timeline); results are never fabricated.
- Playwright screenshots are optional and not bundled; visual proof reports unavailable when absent. A screenshot difference never marks a finding resolved.
- Persistence is file-based JSON/JSONL/PDF, not a multi-user database.
- Agent cancellation is cooperative, not a hard process kill: it aborts between model turns and every 500 ms inside guarded WSL tools, then terminates the child process. A cancelled run is not stored as the last result.
- Telegram custom emoji are capability-gated by Telegram: a bot can send them only if it owns a Fragment-purchased username or its owner has Premium, and only in supported chat types. The bot attempts the verified IDs once, then permanently downgrades to Unicode and retries. Inline buttons cannot use custom emoji or custom colours at all; the UI uses Unicode there and does not simulate either feature.
- A Premium client render cannot be forced from the server; the IDs and fallback logic were verified against the live Bot API and with mock-only tests, and the live command flow was exercised through a real chat.
- Burp and Metasploit integrations are validate-only (no exploit/payload execution). Both are detected on this host at final audit: Burp Suite Community `2026.3.3-47134` and Metasploit `Framework Version: 6.5.12-dev-`; Metasploit reports 3 real read-only findings (version + HTTP/SSL scanner module inventories).

---

## 8. Public release notes

1. Published at `https://github.com/wertybin/aegis-ai-3.1` as a single clean release commit on `main`.
2. No key rotation is required for the repository itself: the public history contains no real secret and `.env` is untracked. Users supply every endpoint and credential in their own `.env`.
3. No localhost address or port is bundled as a default target. Users set `AEGIS_DEFAULT_TARGET`, `AEGIS_GATE_1_URL`, `AEGIS_GATE_2_URL`, `AEGIS_GATE_3_URL`, `AEGIS_OLLAMA_URL` and `AEGIS_API_BASE` themselves.
4. Support for all questions: Telegram [@wertybin](https://t.me/wertybin), shown in the README, the web UI and every Telegram screen footer.
5. Optional next step: record the ≤2-minute video per `docs/DEMO_SCRIPT.md` using the user's own configured target.
