"""AEGIS AI V3 — premium Telegram bot (long-polling, no webhook, no Mini App).

Commands
    /start              premium welcome + main menu
    /menu               command center (live backend, tools, last run)
    /help               commands, scope and honest limitations
    /scan [target] [task]   run the real agent on your own localhost target
    /stop               cooperative cancellation of the active run
    /status             last completed agent run (real numbers only)
    /report             send the latest real PDF report as a Telegram document
    /review [file]      ask local Qwen for a proposed source diff
    /pipeline           DAST -> Audit -> Agent with live streamed progress
    /gates              live status of the three authorized local gates
    /tools              the real 11-tool fleet with details and re-checks
    /profile            chat, cooldown and last-run data
    /owner              read-only deployment status

Environment (never hard-code secrets; see .env.example):
    TELEGRAM_BOT_TOKEN          token from @BotFather (required)
    TELEGRAM_ALLOWED_CHAT_IDS   optional comma list; empty = everyone may use it
    TELEGRAM_OWNER_CHAT_IDS     optional comma list for the owner console
    TELEGRAM_EMOJI_MODE         auto (default) | custom | unicode
    AEGIS_API_BASE              your AEGIS API URL (user-supplied, no default)

The bot keeps the local architecture honest: AEGIS scans ONLY the
localhost targets you configure yourself. It never exposes arbitrary hosts
or exploits. Questions: Telegram @wertybin.
Run with:  python -m backend.telegram_bot
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

# Importing the backend package loads the local .env file.
import backend  # noqa: F401
from backend.telegram_ui import config as ui_config
from backend.telegram_ui import state
from backend.telegram_ui.api import ApiClient
from backend.telegram_ui.handlers import BotHandlers, HandlerDeps
from backend.telegram_ui.transport import Transport

API_BASE = os.getenv("AEGIS_API_BASE", "").strip().rstrip("/")
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ALLOWED = {
    item.strip()
    for item in os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "").split(",")
    if item.strip()
}
TG_BASE = f"https://api.telegram.org/bot{TOKEN}"
RATE_LIMIT_SECONDS = ui_config.RATE_LIMIT_SECONDS
MAX_TASK_CHARS = ui_config.MAX_TASK_CHARS
MAX_MESSAGE_CHARS = ui_config.MAX_MESSAGE_CHARS

_local_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# _request() calls opener.open(...); urllib.request itself only exposes
# urlopen(), so Telegram needs a real opener instance too.
_tg_opener = urllib.request.build_opener()
_last_scan: dict[str, float] = {}
_scan_lock = threading.Lock()
_handlers_lock = threading.Lock()
_handlers: BotHandlers | None = None

_TOKEN_PATTERN = re.compile(r"(?<!\d)\d{6,12}:[A-Za-z0-9_-]{8,}")


def _redact(message: str) -> str:
    text = str(message or "")
    if TOKEN:
        text = text.replace(TOKEN, "<token>")
    return _TOKEN_PATTERN.sub("<token>", text)


def _log(message: str) -> None:
    stamp = datetime.now().isoformat(timespec="seconds")
    print(f"[{stamp}] {_redact(message)}", flush=True)


def _request(opener, url: str, payload: dict | None = None, timeout: int = 30) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    with opener.open(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", "replace")
    return json.loads(raw) if raw else {}


def tg(method: str, payload: dict | None = None, timeout: int = 30) -> dict:
    return _request(_tg_opener, f"{TG_BASE}/{method}", payload, timeout)


def tg_document(chat_id, file_path, caption: str = "", timeout: int = 60) -> dict:
    """Upload a generated report or review through Telegram sendDocument."""
    source = Path(file_path)
    mime = {".pdf": "application/pdf", ".diff": "text/x-diff"}.get(source.suffix.lower())
    if not source.is_file() or mime is None:
        raise ValueError("Document must be an available PDF or diff.")
    if source.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("report file exceeds the Telegram 50 MB limit")
    boundary = "----AegisReport" + uuid.uuid4().hex
    body = bytearray()

    def add_field(name: str, value: str) -> None:
        body.extend(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")
        )

    add_field("chat_id", str(chat_id))
    body.extend(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="document"; '
            f'filename="{source.name}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode("utf-8")
    )
    body.extend(source.read_bytes())
    body.extend(b"\r\n")
    if caption:
        add_field("caption", str(caption)[:1024])
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    request = urllib.request.Request(
        f"{TG_BASE}/sendDocument",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with _tg_opener.open(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", "replace")
    return json.loads(raw) if raw else {}


def send_message(chat_id, text: str) -> None:
    """Legacy plain-text helper; bounded chunks keep Telegram happy."""
    text = str(text or "").strip() or "No output."
    for start in range(0, len(text), MAX_MESSAGE_CHARS):
        chunk = text[start : start + MAX_MESSAGE_CHARS]
        try:
            tg("sendMessage", {
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": True,
            })
        except Exception as exc:  # network hiccups must not kill the poll loop
            _log(f"sendMessage failed for {chat_id}: {type(exc).__name__}")


def allowed(chat_id) -> bool:
    return not ALLOWED or str(chat_id) in ALLOWED


def rate_limited(chat_id) -> bool:
    """Legacy compatibility helper; the premium flow uses telegram_ui.state."""
    now = time.monotonic()
    with _scan_lock:
        last = _last_scan.get(str(chat_id), 0.0)
        if now - last < RATE_LIMIT_SECONDS:
            return True
        _last_scan[str(chat_id)] = now
    return False


def api_get(path: str) -> dict:
    return _request(_local_opener, f"{API_BASE}{path}", timeout=20)


def api_post(path: str, payload: dict) -> dict:
    return _request(_local_opener, f"{API_BASE}{path}", payload, timeout=420)


def _sse_terminal(event: str, payload: dict) -> bool:
    if event != "scan":
        return False
    scan = payload.get("scan") or {}
    return (
        str(scan.get("status") or "").lower() in {"completed", "failed", "cancelled"}
        and bool(scan.get("finished_at"))
    )


def api_stream(path: str, on_event) -> dict:
    """Reads a local SSE endpoint without blocking the Telegram poll loop.

    Only the fixed /api/engine/stream/{scan_id} path is accepted. Every decoded
    event is forwarded to ``on_event``; the loop stops on the final scan frame
    or after a hard deadline so a worker can never hang forever.
    """
    if not re.fullmatch(r"/api/engine/stream/scan_[0-9]{8}_[0-9]{6}_[0-9a-f]{6}", path):
        raise ValueError("unsupported stream path")
    summary = {"events": 0, "complete": None, "error": None, "status": None}
    started = time.monotonic()
    event_name = ""
    data_lines: list[str] = []
    with _local_opener.open(f"{API_BASE}{path}", timeout=60) as response:
        for raw_line in response:
            if time.monotonic() - started > 900:
                summary["error"] = "stream deadline exceeded"
                break
            line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                if event_name and data_lines:
                    try:
                        payload = json.loads("".join(data_lines))
                    except ValueError:
                        payload = {}
                    summary["events"] += 1
                    if event_name == "complete":
                        summary["complete"] = payload
                    elif event_name == "error":
                        summary["error"] = payload.get("msg") or "stream error"
                    elif event_name == "scan":
                        scan = payload.get("scan") or {}
                        summary["status"] = scan.get("status")
                    on_event(event_name, payload)
                    if _sse_terminal(event_name, payload):
                        break
                event_name = ""
                data_lines = []
            elif line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
    return summary


def help_text() -> str:
    return (
        "AEGIS AI V3 — autonomous local security agent\n\n"
        "/start — premium welcome and main menu\n"
        "/menu — live command center\n"
        "/help — this message\n"
        "/scan [your-localhost-URL] [task] — run a real agent audit\n"
        "/stop — cancel the active scan\n"
        "/status — last completed agent run\n"
        "/report — send the latest real PDF report\n"
        "/pipeline — DAST → Audit → Agent with live progress\n"
        "/gates — live local gate status\n"
        "/tools — the real 11-tool fleet\n"
        "/profile — your chat, cooldown and last run\n"
        "/owner — read-only deployment status\n\n"
        "SCOPE: your own localhost / 127.0.0.1 targets only. No bundled addresses.\n"
        "Set gate URLs in .env or pass a URL to /scan. "
        "No exploits, no payloads, no destructive tests. "
        "Every finding comes from a real local tool.\n"
        f"Rate limit: one scan per {RATE_LIMIT_SECONDS}s per chat.\n"
        f"Questions: Telegram {ui_config.SUPPORT_HANDLE} ({ui_config.SUPPORT_URL})."
    )


def status_text() -> str:
    """Legacy plain-text status; the premium screen lives in telegram_ui."""
    try:
        data = api_get("/api/agent/last")
    except Exception as exc:
        return f"Cannot reach AEGIS on {API_BASE}: {type(exc).__name__}: {exc}"
    last = data.get("last")
    if not last:
        return "No agent run recorded yet. Send /scan to start one."
    counts = last.get("severity_counts") or {}
    return "\n".join([
        "LAST AEGIS AGENT RUN",
        f"Mode: {last.get('mode')}",
        f"Model: {last.get('model') or '-'}",
        f"Target: {last.get('target')}",
        f"Tools: {', '.join(last.get('tools_used') or []) or '-'}",
        f"Real findings: {last.get('total_findings', 0)} "
        f"(CRIT {counts.get('CRITICAL', 0)} · HIGH {counts.get('HIGH', 0)} · "
        f"MED {counts.get('MEDIUM', 0)} · LOW {counts.get('LOW', 0)})",
        f"Duration: {(last.get('duration_ms') or 0) / 1000:.1f}s",
        f"At: {last.get('ts')}",
    ])


def parse_scan(text: str) -> tuple[str, str]:
    """Returns (target_or_empty, task). No target is bundled or assumed."""
    parts = text.strip().split(maxsplit=1)
    target = ""
    task = ""
    if parts and parts[0].lower().startswith(("http://", "https://")):
        target = parts[0]
        task = parts[1] if len(parts) > 1 else ""
    else:
        task = text.strip()
    return target, (task or "Audit the authorized local application and report the top risks.")[
        :MAX_TASK_CHARS
    ]


def scan_text(target: str, task: str) -> str:
    """Legacy plain-text scan helper, kept for scripts and older tests."""
    payload = {"task": task, "use_ai": True}
    if target:
        payload["target"] = target
    try:
        result = api_post("/api/agent/run", payload)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        return f"Agent rejected the request (HTTP {exc.code}). Check the scope.\n{detail}"
    except Exception as exc:
        return f"Cannot reach AEGIS on {API_BASE}: {type(exc).__name__}: {exc}"

    counts = result.get("severity_counts") or {}
    findings = result.get("findings") or []
    lines = [
        "AEGIS AGENT COMPLETE",
        f"Mode: {result.get('mode')}",
        f"Tools called: {', '.join(result.get('tools_used') or []) or '-'}",
        f"Target: {result.get('target')}",
        f"Real findings: {result.get('total_findings', 0)} "
        f"(CRIT {counts.get('CRITICAL', 0)} · HIGH {counts.get('HIGH', 0)} · "
        f"MED {counts.get('MEDIUM', 0)} · LOW {counts.get('LOW', 0)})",
        "",
        result.get("verified_summary") or "",
        "",
        "TOP FINDINGS",
    ]
    for index, finding in enumerate(findings[:5], 1):
        location = finding.get("endpoint") or finding.get("file") or "-"
        lines.append(
            f"{index}. [{finding.get('severity')}] {finding.get('title')} "
            f"— {str(location)[:120]}"
        )
    if not findings:
        lines.append("No findings inside the authorized scope.")
    lines.extend(["", (result.get("summary") or "")[:1400]])
    return "\n".join(lines)


def _build_handlers() -> BotHandlers:
    transport = Transport(tg, _log, tg_document)
    client = ApiClient(api_get, api_post, api_stream)
    return BotHandlers(
        HandlerDeps(
            transport=transport,
            client=client,
            authorize=allowed,
            is_owner=lambda chat_id: str(chat_id) in ui_config.OWNER_IDS,
            parse_scan=parse_scan,
            api_base=API_BASE,
            access_mode="restricted" if ALLOWED else "public",
            log=_log,
        )
    )


def get_handlers() -> BotHandlers:
    global _handlers
    with _handlers_lock:
        if _handlers is None:
            _handlers = _build_handlers()
        return _handlers


def handle_message(message: dict) -> None:
    get_handlers().handle_message(message)


def _prime_offset() -> int:
    """Skips updates queued before this process started.

    Telegram redelivers unconfirmed updates; without this a restart could
    replay an old /scan command. ``offset=-1`` returns only the latest update.
    """
    try:
        probe = tg(
            "getUpdates",
            {"offset": -1, "limit": 1, "timeout": 0},
            timeout=15,
        )
    except Exception as exc:
        _log(f"offset probe skipped: {type(exc).__name__}")
        return 0
    offset = 0
    for update in probe.get("result") or []:
        offset = max(offset, int(update.get("update_id", 0)) + 1)
    return offset


def main() -> int:
    if not TOKEN:
        print("TELEGRAM_BOT_TOKEN missing. Add it to .env (see .env.example).")
        return 2
    _log(
        f"AEGIS Telegram bot starting · API {API_BASE} · "
        f"public={not ALLOWED} · emoji={ui_config.EMOJI_MODE}"
    )
    handlers = get_handlers()
    try:
        me = handlers.deps.transport.get_me()
        username = me.get("username") or ""
        state.set_bot_username(username)
        _log(f"identity @{username or 'unknown'} · callbacks enabled")
    except Exception as exc:
        _log(f"getMe failed: {type(exc).__name__}")

    offset = _prime_offset()
    while True:
        try:
            updates = tg(
                "getUpdates",
                {
                    "offset": offset,
                    "timeout": 10,
                    "allowed_updates": ["message", "callback_query"],
                },
                timeout=20,
            )
            for update in updates.get("result") or []:
                offset = max(offset, int(update.get("update_id", 0)) + 1)
                state.set_last_update_id(offset - 1)
                try:
                    handlers.handle_update(update)
                except Exception as exc:
                    _log(f"handler error: {type(exc).__name__}: {exc}")
        except KeyboardInterrupt:
            _log("stopped by user")
            return 0
        except Exception as exc:
            _log(f"poll error: {type(exc).__name__}: {exc}")
            time.sleep(3)


if __name__ == "__main__":
    sys.exit(main())
