# AEGIS AI V3.1 — 2-minute demo script

Goal: show that the **agent chooses tools itself, works step by step, and reports only real findings**. The video must be ≤ 2:00. Capture at 1440×900 or 1920×1080 and open the AEGIS UI URL you configured in `.env` with `/#/agent` appended.

## Preparation (before recording)

```powershell
START_ALL.cmd                        # UI :8765 + lab + Ollama + Telegram bot (everything)
.\.venv\Scripts\python.exe demo\run_demo.py --no-open
```

- `--no-open` keeps the script from opening a browser; open the page yourself and prepare the layout first.
- Open the `@aegls_ai_bot` chat in Telegram Desktop beforehand. Never show `.env`, the terminal token, or the AI Studio key in any frame.
- Keep the AI key only in `.env`; never show it on camera. The ready provider is `ollama` + `qwen2.5:14b`; Gemini is retained as a fallback.
- The demo runs against the open-source `sample_vulnerable_app`; users may supply their own localhost URL instead.

## Scenario (120 seconds total)

| Time | What is on screen | What to say (short) |
|---|---|---|
| 0:00–0:10 | UI opens on `DEEP ENGINE → AGENT MODE` | “This is AEGIS V3.1 — not a chatbot. The agent receives a task, selects tools, observes the result, and decides the next step itself.” |
| 0:10–0:25 | Hero + `TRIGGER → MODEL → TOOLS → RESULT` diagram; task field visible | “The flow is trigger, local Ollama/Qwen model (Gemini fallback), real tools, evidence-based report. Scope is limited to the localhost targets I configured myself.” |
| 0:25–0:35 | Type the task, enter your own localhost URL, click `[ RUN AGENT ]` | “Task: scan my local application, correlate the findings, and report the most critical risks with evidence.” |
| 0:35–0:55 | Timeline: `Scope validated`, `AI DECISION → semgrep`, `TOOL RESULT semgrep` | “The model chose source analysis itself, explained why, and received the real result. Every decision has a `decision_id`; every execution has a `tool_call_id` — nothing is simulated.” |
| 0:55–1:15 | `AI DECISION → httpx / katana`; tool cards show findings/duration; `STATS` counters | “Based on the evidence it moved to network tools. The counters show iterations, successful/failed calls, and findings from real SSE events.” |
| 1:15–1:25 | `CALL correlate_findings`, severity cards | “Findings are merged, exact duplicates are removed, CWE/CVE and confidence are added, and the severity distribution is computed.” |
| 1:25–1:45 | `VERIFIED FINDING` events + `FINAL` + Markdown report + `VERIFIED TOTALS` | “The report comes from the model, but the numbers are rechecked against raw tool output. `VERIFIED FINDING` comes only from real output; an AI hypothesis is never shown as one.” |
| 1:45–2:00 | Tool Management Center or Deep Lab, PDF / real finding detail; close the screen | “The same tools are also available in the 11-module panel. The repository, README, and system prompt are part of the handover material.” |

## Telegram bonus (10–15 s, recommended)

If it fits inside the 2-minute limit, replace the Tool Center segment at 1:45–2:00 with a short Telegram shot (or a 10-second picture-in-picture). It shows the Telegram integration visually:

1. Open the `@aegls_ai_bot` chat in Telegram Desktop.
2. `/start` → premium welcome and inline menu.
3. `Gates` button → your three configured localhost targets; `Pipeline Target` → detail screen (when your target is running).
4. `/pipeline` → `DAST → Audit → Agent` panel; for your pipeline target, press `Full chain` → real SSE stage progress; stop it with `Stop pipeline`.
5. `/status` → real last run; `/report` → real PDF delivered by Telegram.

Say: “The same agent also runs as a Telegram-native bot: DAST, Audit, and Agent stages use the real backend endpoints, progress comes from SSE events, and inline navigation plus cooperative stop are built in. There is no Mini App — everything is a native Telegram message.”

Note: Telegram inline buttons do not support custom emoji or custom colours; the bot does not simulate them and uses Unicode glyphs instead. If the bot cannot send custom emoji at that moment, the screen automatically falls back to Unicode — that is the honest behaviour.

**Last real test (2026-11-24):** `ollama-function-calling`, model `qwen2.5:14b`, 6 real tool calls (browser, httpx, Katana, api_security, Semgrep), **27 real findings**; `/api/agent/last` reported `mode=ollama-function-calling`, 5 unique tools, 27 findings, and no Gemini role error. An earlier Gemini run used `gemini-function-calling`, `gemini-3.1-flash-lite`, 4 calls (Semgrep → httpx → Katana → correlate_findings), and 21 unique findings in ~262 s. The model chooses tools adaptively, so numbers vary — quote what is on screen; do not memorise them. A cold start can take longer than 120 seconds; cut or speed up the footage and never fake results.

## If something goes wrong

- **Ollama does not respond:** make sure `ollama serve` is running and `qwen2.5:14b` is available; in `.env`, set `AEGIS_MODEL_PROVIDER=ollama` and `AEGIS_OLLAMA_MODEL=qwen2.5:14b`. The agent shows its mode honestly.
- **Gemini fallback returns 503 / high demand:** the agent retries, then switches to another free model. If you see `MODEL UNAVAILABLE — fallback used`, keep going: “As you can see, the agent changes mode itself and reports it honestly.”
- **No model is available:** the badge becomes `DETERMINISTIC FALLBACK`. It still runs the real tools, but show `ollama-function-calling` when possible — check the provider and model before recording.
- **Port 8765 is free:** run `.\start_all.ps1` again.
- **The video runs longer than 2 minutes:** shorten the 1:45–2:00 segment; the core moment is 0:35–1:45.

## After recording

1. Push the repository and share the GitHub link together with the video. No key rotation is required: the full Git history contains no real secret, and `.env` is gitignored.
2. The Telegram bot starts automatically with `START_ALL.cmd`; make sure `TELEGRAM_BOT_TOKEN` is set in `.env`. For the video, the sequence `/start` → `Gates` → `/pipeline` → `Full chain` → `Stop pipeline` → `/status` → `/report` is enough.
