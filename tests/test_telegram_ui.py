"""Mock-only tests for the premium Telegram UI layer.

No Telegram call and no AEGIS backend call is made here. Gate probes are
monkeypatched, the transport is faked, and every handler runs against an
in-memory client.
"""

from __future__ import annotations

import io
import json
import threading
import time
import urllib.error

import pytest

from backend.telegram_ui import (
    api as api_module,
    callbacks,
    components,
    config,
    emoji,
    keyboards,
    screens,
    state,
    transport as transport_module,
)
from backend.telegram_ui.handlers import BotHandlers, HandlerDeps
from backend.telegram_ui.transport import Transport


@pytest.fixture(autouse=True)
def clean_state():
    state.reset()
    emoji.reset_runtime_state()
    yield
    state.reset()
    emoji.reset_runtime_state()


# ---------------------------------------------------------------------------
# Fixtures and fakes
# ---------------------------------------------------------------------------

SAMPLE_RESULT = {
    "ok": True,
    "mode": "gemini",
    "model": "gemini-3.1-flash-lite",
    "target": "http://127.0.0.1:5002",
    "tools_used": ["semgrep", "trivy"],
    "total_findings": 3,
    "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0},
    "findings": [
        {"severity": "CRITICAL", "title": "SQL injection", "endpoint": "/login"},
        {"severity": "HIGH", "title": "Missing CSP", "endpoint": "/"},
    ],
    "duration_ms": 42000,
    "ts": "2026-11-24T10:00:00",
    "verified_summary": "3 verified findings from real local tools.",
    "summary": "Real scan complete.",
}

CANCELLED_RESULT = {
    "ok": False,
    "cancelled": True,
    "status": "cancelled",
    "mode": "cancelled",
    "target": "http://127.0.0.1:5002",
    "tools_used": [],
    "total_findings": 0,
    "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "findings": [],
    "duration_ms": 1200,
    "verified_summary": "CANCELLED — no findings were stored.",
}


def tools_payload(count: int = 8) -> dict:
    names = [
        "metasploit", "burp", "semgrep", "trivy", "gitleaks",
        "testssl", "httpx", "katana", "api_security", "ai_correlation",
    ][:count]
    tools = {}
    for index, name in enumerate(names):
        tools[name] = {
            "label": name.replace("_", " ").title(),
            "status": "OK" if index % 3 else "MISSING",
            "version": f"1.{index}",
            "timeout": 120,
            "note": "read-only local probe",
            "last_execution": "2026-11-24T09:00:00" if index % 2 else None,
            "execution_status": "OK" if index % 2 else "NOT RUN",
            "findings_count": index,
            "error_log": None,
            "configuration": {"timeout_seconds": 120, "scope": "localhost", "safe_note": "read-only"},
        }
    return {"tools": tools, "order": names, "total": len(names), "installed": len(names)}


class FakeTransport:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.edits: list[dict] = []
        self.answers: list[dict] = []
        self.documents: list[dict] = []
        self._next_id = 100

    def send(self, chat_id, text, keyboard=None, preview=False, timeout=30):
        message_id = self._next_id
        self._next_id += 1
        self.sent.append(
            {"chat_id": chat_id, "text": text, "keyboard": keyboard, "message_id": message_id}
        )
        return {"ok": True, "result": {"message_id": message_id}}

    def edit(self, chat_id, message_id, text, keyboard=None, preview=False, timeout=30):
        self.edits.append(
            {"chat_id": chat_id, "message_id": message_id, "text": text, "keyboard": keyboard}
        )
        return {"ok": True, "result": {"message_id": message_id}}

    def send_text(self, chat_id, text, timeout=30):
        self.sent.append(
            {"chat_id": chat_id, "text": text, "keyboard": None, "message_id": None}
        )
        return {"ok": True, "result": {"message_id": None}}

    def send_document(self, chat_id, file_path, caption="", timeout=60):
        self.documents.append(
            {
                "chat_id": chat_id,
                "file_path": file_path,
                "caption": caption,
                "message_id": self._next_id,
            }
        )
        self._next_id += 1
        return {"ok": True, "result": {"message_id": self.documents[-1]["message_id"]}}

    def answer(self, callback_id, text="", show_alert=False):
        self.answers.append({"id": callback_id, "text": text, "alert": show_alert})
        return {"ok": True}


class FakeClient:
    def __init__(self, result: dict | None = None, block: bool = False) -> None:
        self.result = dict(result or SAMPLE_RESULT)
        self.block = block
        self.run_calls: list[dict] = []
        self.cancel_calls = 0
        self.tools_calls = 0
        self.tool_check_calls: list[str] = []
        self.engine_starts: list[dict] = []
        self.engine_streams: list[str] = []
        self.engine_cancels: list[str] = []
        self.stream_events: list[tuple[str, dict]] = [
            ("stage", {"step": 1, "label": "Scope check", "state": "running"}),
            ("stage", {"step": 2, "label": "Local HTTP probes", "state": "completed"}),
            ("complete", {"pdf_filename": "pipeline.pdf", "score": 7}),
            ("scan", {"scan": {"status": "completed", "finished_at": "2026-11-24T12:00:00"}}),
        ]
        self.started = threading.Event()
        self.release = threading.Event()

    def health(self):
        return {"online": True, "latency_ms": 3}

    def agent_last(self):
        last = None if self.result.get("cancelled") else self.result
        return {"last": last, "running": False}

    def reports(self):
        return {
            "summary": {"latest_filename": "AegisAI_Audit_Report_20261123_200827.pdf"},
            "reports": [
                {
                    "filename": "AegisAI_Audit_Report_20261123_200827.pdf",
                    "scan": {"mode": "audit", "finding_count": 9, "target": "http://127.0.0.1:5002"},
                }
            ],
        }

    def agent_run(self, task, target=None, use_ai=True):
        self.run_calls.append({"task": task, "target": target, "use_ai": use_ai})
        self.started.set()
        if self.block:
            self.release.wait(3)
        return dict(self.result)

    def agent_cancel(self):
        self.cancel_calls += 1
        if self.block:
            self.release.set()
        return {"cancelled": True, "active": True}

    def tools(self, force=False):
        self.tools_calls += 1
        return tools_payload()

    def tool_check(self, name):
        self.tool_check_calls.append(name)
        return {"tool": name, "status": "OK", "version": "9.9"}

    def engine_start(self, mode, target):
        self.engine_starts.append({"mode": mode, "target": target})
        return {"scanId": f"scan_20261124_120000_{len(self.engine_starts):06x}", "status": "queued"}

    def engine_stream(self, scan_id, on_event):
        self.engine_streams.append(scan_id)
        for event, payload in self.stream_events:
            on_event(event, dict(payload))
        complete = next((payload for event, payload in self.stream_events if event == "complete"), {})
        return {"events": len(self.stream_events), "status": "completed", "complete": dict(complete)}

    def engine_cancel(self, scan_id):
        self.engine_cancels.append(scan_id)
        return {"status": "cancelling"}


def make_handlers(
    client: FakeClient | None = None,
    transport: FakeTransport | None = None,
    authorize=lambda chat_id: True,
    is_owner=lambda chat_id: False,
) -> tuple[BotHandlers, FakeTransport, FakeClient]:
    client = client or FakeClient()
    transport = transport or FakeTransport()
    handlers = BotHandlers(
        HandlerDeps(
            transport=transport,
            client=client,
            authorize=authorize,
            is_owner=is_owner,
            parse_scan=lambda text: (
                (text.split(maxsplit=1)[0], text.split(maxsplit=1)[1] if len(text.split(maxsplit=1)) > 1 else "")
                if text.startswith("http")
                else ("", text or "Audit the authorized local application.")
            ),
            api_base="http://127.0.0.1:8765",
            access_mode="public",
            log=lambda message: None,
        )
    )
    return handlers, transport, client


def wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def http_error(code: int, description: str, retry_after: int | None = None):
    payload = {"ok": False, "error_code": code, "description": description}
    if retry_after is not None:
        payload["parameters"] = {"retry_after": retry_after}
    return urllib.error.HTTPError(
        "https://api.telegram.org/bot123456:SECRET/sendMessage",
        code,
        description,
        {},
        io.BytesIO(json.dumps(payload).encode("utf-8")),
    )


# ---------------------------------------------------------------------------
# Emoji registry
# ---------------------------------------------------------------------------


def test_registry_contains_only_verified_real_ids():
    rows = emoji.REGISTRY.rows()
    assert len(rows) == 76
    assert emoji.REGISTRY.verified_count() == 61
    assert emoji.catalog()["packs"] == ["NewsEmoji"]
    for row in rows:
        assert row["fallback"]
        if row["verified"]:
            assert row["custom_id"].isdigit()
            assert 15 <= len(row["custom_id"]) <= 20
            assert row["pack"] == "NewsEmoji"
        else:
            assert row["custom_id"] is None
    assert len({row["key"] for row in rows}) == len(rows)


def test_render_custom_and_unicode_modes():
    custom = emoji.render("brand")
    assert custom.startswith('<tg-emoji emoji-id="')
    assert "🛡" in custom
    assert emoji.render("brand", mode="unicode") == "🛡"
    assert emoji.render("back") == "◀"  # unverified key -> fallback


def test_strip_custom_keeps_fallback_glyphs():
    text = 'a <tg-emoji emoji-id="5251203410396458957">🛡</tg-emoji> b'
    assert emoji.strip_custom(text) == "a 🛡 b"


def test_disable_custom_switches_to_unicode():
    assert emoji.custom_enabled() is True
    emoji.disable_custom("test rejection")
    assert emoji.custom_enabled() is False
    assert emoji.render("brand") == "🛡"
    assert emoji.downgrade_reason() == "test rejection"


def test_custom_emoji_error_detection():
    assert emoji.looks_like_custom_emoji_error("Bad Request: can't parse entities: Unsupported custom emoji")
    assert not emoji.looks_like_custom_emoji_error("Bad Request: chat not found")


# ---------------------------------------------------------------------------
# Callbacks and keyboards
# ---------------------------------------------------------------------------


def test_callback_roundtrip_for_every_action():
    cases = [
        ("home", ()),
        ("gates", ()),
        ("tools", ("0",)),
        ("trefresh", ("2",)),
        ("gate", ("pipeline",)),
        ("gscan", ("core",)),
        ("tool", ("semgrep", "1")),
        ("tcheck", ("trivy", "0")),
        ("profile", ()),
        ("owner", ()),
        ("help", ()),
        ("status", ()),
        ("scan", ("pipeline",)),
        ("sgo", ("sample",)),
        ("sx", ()),
        ("sr", ()),
        ("noop", ()),
    ]
    for action, args in cases:
        callback = callbacks.c(action, *args)
        assert callbacks.parse(callback.data) == callback
        assert len(callback.data.encode("utf-8")) <= 64


def test_callback_rejects_forged_payloads():
    assert callbacks.parse(f"{callbacks.PREFIX}:{callbacks.VERSION}:quick:bad") is None
    assert callbacks.parse(None) is None
    assert callbacks.parse("") is None
    assert callbacks.parse("xx:v1:home") is None
    assert callbacks.parse("ag:v1:gate:evil") is None
    assert callbacks.parse("ag:v1:tool:../../etc:0") is None
    assert callbacks.parse("ag:v1:tools:999") is None
    assert callbacks.parse("ag:v1:sx:extra") is None
    assert callbacks.parse("ag:v1:home:" + "a" * 70) is None
    with pytest.raises(callbacks.CallbackError):
        callbacks.encode("gate", "pipeline", "extra")
    with pytest.raises(callbacks.CallbackError):
        callbacks.encode("tool", "a" * 40, "0")


def test_every_keyboard_button_has_a_valid_short_callback():
    boards = [
        keyboards.main_menu(True),
        keyboards.main_menu(False),
        keyboards.gates({"core": True, "sample": False, "pipeline": None}),
        keyboards.gate_detail("pipeline"),
        keyboards.scan_confirm("pipeline"),
        keyboards.scan_running(),
        keyboards.stop_pending(),
        keyboards.idle(),
        keyboards.scan_result("pipeline"),
        keyboards.tools_page(
            0,
            [{"name": name, **entry} for name, entry in tools_payload(6)["tools"].items()],
            False,
            True,
        ),
        keyboards.tools_page(
            1,
            [{"name": name, **entry} for name, entry in tools_payload(6)["tools"].items()],
            True,
            False,
        ),
        keyboards.tool_detail("semgrep", 1),
        keyboards.profile(),
        keyboards.owner(),
        keyboards.status(),
        keyboards.help_menu(),
        keyboards.error(callbacks.c("gates")),
        keyboards.noop(),
    ]
    for board in boards:
        keyboards.validate(board)
        for row in board:
            assert row
            for item in row:
                assert item["text"]
                assert item["style"] in {"success", "primary", "danger"}
                assert len(item["callback_data"].encode("utf-8")) <= 64
                assert callbacks.parse(item["callback_data"]) is not None


def test_main_menu_native_colours_and_owner_visibility():
    rows = keyboards.main_menu(owner=True)
    layout = [[(callbacks.parse(b["callback_data"]).action, b["style"]) for b in row] for row in rows]
    assert layout[:3] == [[("gates", "success"), ("tools", "success")],
                          [("profile", "primary")], [("owner", "primary")]]
    assert all(b["callback_data"] != callbacks.c("owner").data for row in keyboards.main_menu(False) for b in row)


# ---------------------------------------------------------------------------
# Message components and screens
# ---------------------------------------------------------------------------


def test_components_escape_html():
    assert components.esc("<b>&") == "&lt;b&gt;&amp;"
    text = components.PremiumError("x", "<script>alert(1)</script>")
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_welcome_and_help_include_brand_and_scope():
    welcome = screens.welcome("Aysel", "aysel", True)
    assert "AEGIS AI" in welcome.text
    assert "Hello" in welcome.text
    assert "Owner console" in welcome.text
    assert welcome.keyboard
    help_screen = screens.help_screen()
    assert "/stop" in help_screen.text
    assert "localhost" in help_screen.text
    assert "Unicode" in help_screen.text
    assert "@wertybin" in welcome.text
    assert "@wertybin" in help_screen.text


def test_gates_screen_uses_live_probe_data(monkeypatch):
    monkeypatch.setattr(
        api_module,
        "probe_gates",
        lambda timeout=1.5: {
            gate["id"]: {"online": True, "status": 200, "latency_ms": 2}
            for gate in config.GATES
        },
    )
    screen = screens.gates(FakeClient())
    assert "3 / 3" in screen.text
    assert "Primary Target" in screen.text
    assert "HTTP 200" in screen.text
    assert screen.keyboard


def test_tools_screen_paginates_real_entries():
    state.cache_tools(tools_payload(8))
    first = screens.tools(FakeClient(), 0)
    second = screens.tools(FakeClient(), 1)
    assert "Page 1 / 2" in first.text
    assert "Page 2 / 2" in second.text
    assert "SEMGREP" in first.text.upper()
    assert any(
        item["callback_data"] == callbacks.c("tools", "1").data
        for row in first.keyboard for item in row
    )
    assert any(
        item["callback_data"] == callbacks.c("tools", "0").data
        for row in second.keyboard for item in row
    )


def test_tool_detail_renders_real_fields():
    state.cache_tools(tools_payload(4))
    screen = screens.tool_detail(FakeClient(), "semgrep", 1)
    assert "SEMGREP" in screen.text.upper()
    assert "1.2" in screen.text  # version from payload index 2
    assert "localhost" in screen.text
    assert callbacks.c("tcheck", "semgrep", "1").data in [
        item["callback_data"] for row in screen.keyboard for item in row
    ]


def test_scan_result_escapes_untrusted_findings():
    result = dict(SAMPLE_RESULT)
    result["findings"] = [
        {"severity": "HIGH", "title": "<script>alert(1)</script>", "endpoint": "<b>x</b>"}
    ]
    screen = screens.scan_result(result, "pipeline")
    assert "<script>" not in screen.text
    assert "&lt;script&gt;" in screen.text
    assert "SCAN COMPLETE" in screen.text


def test_cancelled_result_is_rendered_as_cancelled():
    screen = screens.scan_result(CANCELLED_RESULT, "pipeline")
    assert "SCAN CANCELLED" in screen.text
    assert "No partial findings" in screen.text


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


def test_state_cooldown_running_and_refund():
    assert state.cooldown_remaining(1) == 0
    assert state.begin_scan(1, "http://127.0.0.1:5002") is True
    assert state.is_running(1) is True
    assert state.cooldown_remaining(1) > 50
    assert state.begin_scan(1, "again") is False
    state.end_scan(1, refund=True)
    assert state.is_running(1) is False
    assert state.cooldown_remaining(1) == 0
    assert state.begin_scan(1, "again") is True
    state.end_scan(1)


def test_state_allows_only_one_active_chat_globally():
    assert state.begin_scan(1, "http://127.0.0.1:5002") is True
    assert state.begin_scan(2, "http://127.0.0.1:5002") is False
    assert state.is_running(2) is False
    assert state.active_chat() == "1"
    state.end_scan(1)
    assert state.begin_scan(2, "http://127.0.0.1:5002") is True
    state.end_scan(2)


def test_state_debounce_and_screen_tokens():
    assert state.debounce(1, "a") is True
    assert state.debounce(1, "a") is False
    token = state.bump_screen(1)
    assert state.is_current_screen(1, token) is True
    state.bump_screen(1)
    assert state.is_current_screen(1, token) is False


def test_state_tools_cache_and_update():
    state.cache_tools(tools_payload(3))
    assert state.cached_tools()["total"] == 3
    state.update_cached_tool("semgrep", {"status": "OK", "version": "9.9"})
    assert state.cached_tools()["tools"]["semgrep"]["version"] == "9.9"
    state.invalidate_tools()
    assert state.cached_tools() is None


# ---------------------------------------------------------------------------
# Transport fallbacks
# ---------------------------------------------------------------------------


def test_transport_downgrades_custom_emoji_and_retries():
    calls = []

    def fake_tg(method, payload, timeout=30):
        calls.append({"method": method, "payload": dict(payload)})
        if len(calls) == 1:
            raise http_error(400, "Bad Request: can't parse entities: Unsupported custom emoji")
        return {"ok": True, "result": {"message_id": 7}}

    transport = Transport(fake_tg, log=lambda message: None)
    response = transport.send(1, emoji.render("brand") + " <b>Hi</b>")
    assert response["ok"] is True
    assert len(calls) == 2
    assert "<tg-emoji" not in calls[1]["payload"]["text"]
    assert "🛡" in calls[1]["payload"]["text"]
    assert emoji.custom_enabled() is False


def test_transport_retries_parse_failures_as_plain_text():
    calls = []

    def fake_tg(method, payload, timeout=30):
        calls.append({"method": method, "payload": dict(payload)})
        if len(calls) == 1:
            raise http_error(400, "Bad Request: can't parse entities: Can't find end tag")
        return {"ok": True, "result": {"message_id": 8}}

    transport = Transport(fake_tg, log=lambda message: None)
    transport.send(1, "<b>broken")
    assert len(calls) == 2
    assert "parse_mode" not in calls[1]["payload"]
    assert calls[1]["payload"]["text"] == "broken"


def test_transport_retries_429(monkeypatch):
    monkeypatch.setattr(transport_module.time, "sleep", lambda seconds: None)
    calls = []

    def fake_tg(method, payload, timeout=30):
        calls.append(method)
        if len(calls) == 1:
            raise http_error(429, "Too Many Requests: retry after 0", retry_after=0)
        return {"ok": True, "result": {"message_id": 9}}

    transport = Transport(fake_tg, log=lambda message: None)
    assert transport.send(1, "hello")["ok"] is True
    assert calls == ["sendMessage", "sendMessage"]


def test_transport_retries_transient_network_reset(monkeypatch):
    monkeypatch.setattr(transport_module.time, "sleep", lambda seconds: None)
    calls = []

    def fake_tg(method, payload, timeout=30):
        calls.append(method)
        if len(calls) < 3:
            raise ConnectionResetError(10054, "connection reset")
        return {"ok": True, "result": {"message_id": 12}}

    transport = Transport(fake_tg, log=lambda message: None)
    assert transport.send(1, "hello")["ok"] is True
    assert calls == ["sendMessage", "sendMessage", "sendMessage"]


def test_transport_gives_up_after_persistent_network_resets(monkeypatch):
    monkeypatch.setattr(transport_module.time, "sleep", lambda seconds: None)
    calls = []

    def fake_tg(method, payload, timeout=30):
        calls.append(method)
        raise ConnectionResetError(10054, "connection reset")

    transport = Transport(fake_tg, log=lambda message: None)
    assert transport.send(1, "hello") is None
    assert len(calls) == transport_module.NETWORK_ATTEMPTS


def test_transport_not_modified_and_not_found():
    def not_modified(method, payload, timeout=30):
        raise http_error(400, "Bad Request: message is not modified: specified new message content")

    transport = Transport(not_modified, log=lambda message: None)
    assert transport.edit(1, 5, "same") == {"ok": True, "unchanged": True}

    methods = []

    def not_found(method, payload, timeout=30):
        methods.append(method)
        if method == "editMessageText":
            raise http_error(400, "Bad Request: message to edit not found")
        return {"ok": True, "result": {"message_id": 10}}

    transport = Transport(not_found, log=lambda message: None)
    response = transport.edit(1, 5, "new")
    assert response["result"]["message_id"] == 10
    assert methods == ["editMessageText", "sendMessage"]


def test_transport_truncates_oversized_html():
    captured = {}

    def fake_tg(method, payload, timeout=30):
        captured.update(payload)
        return {"ok": True, "result": {"message_id": 11}}

    transport = Transport(fake_tg, log=lambda message: None)
    transport.send(1, "<b>" + ("x" * 5000) + "</b>")
    assert len(captured["text"]) <= config.MAX_MESSAGE_CHARS
    assert "<b>" not in captured["text"]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def test_start_sends_premium_welcome_menu():
    handlers, transport, _ = make_handlers()
    handlers.handle_message({"chat": {"id": 1}, "from": {"first_name": "Aysel"}, "text": "/start"})
    assert len(transport.sent) == 1
    message = transport.sent[0]
    assert "AEGIS AI" in message["text"]
    assert "Hello, Aysel" in message["text"]
    assert message["keyboard"]


def test_scan_command_runs_agent_and_edits_result():
    handlers, transport, client = make_handlers()
    handlers.handle_message(
        {"chat": {"id": 1}, "from": {"first_name": "A"}, "text": "/scan http://127.0.0.1:5002 audit"}
    )
    assert "AGENT RUNNING" in transport.sent[0]["text"]
    assert wait_for(lambda: any("SCAN COMPLETE" in edit["text"] for edit in transport.edits))
    assert client.run_calls[0]["target"] == "http://127.0.0.1:5002"
    assert state.is_running(1) is False


def test_stop_cancels_active_scan():
    client = FakeClient(result=CANCELLED_RESULT, block=True)
    handlers, transport, _ = make_handlers(client=client)
    handlers.handle_message(
        {"chat": {"id": 1}, "from": {"first_name": "A"}, "text": "/scan http://127.0.0.1:5002 audit"}
    )
    assert client.started.wait(2)
    handlers.handle_message({"chat": {"id": 1}, "text": "/stop"})
    assert client.cancel_calls == 1
    assert wait_for(lambda: any("SCAN CANCELLED" in edit["text"] for edit in transport.edits))


def test_stop_without_active_scan_never_calls_the_api():
    handlers, transport, client = make_handlers()
    handlers.handle_message({"chat": {"id": 1}, "text": "/stop"})
    assert client.cancel_calls == 0
    assert "NOTHING TO STOP" in transport.sent[0]["text"]


def test_scan_cooldown_blocks_a_second_run():
    handlers, transport, client = make_handlers()
    state.begin_scan(1, "http://127.0.0.1:5002")
    state.end_scan(1)
    handlers.handle_message({"chat": {"id": 1}, "text": "/scan http://127.0.0.1:5002 audit"})
    assert "SCAN COOLDOWN" in transport.sent[0]["text"]
    assert client.run_calls == []


def test_second_chat_cannot_scan_or_stop_while_another_runs():
    handlers, transport, client = make_handlers()
    assert state.begin_scan(1, "http://127.0.0.1:5002") is True
    handlers.handle_message(
        {"chat": {"id": 2}, "text": "/scan http://127.0.0.1:5002 audit"}
    )
    assert "SCAN BUSY" in transport.sent[0]["text"]
    assert client.run_calls == []
    handlers.handle_message({"chat": {"id": 2}, "text": "/stop"})
    assert client.cancel_calls == 0
    assert "NOTHING TO STOP" in transport.sent[1]["text"]
    state.end_scan(1)


def test_callback_home_edits_the_same_message():
    handlers, transport, _ = make_handlers()
    query = {
        "id": "q1",
        "data": callbacks.c("home").data,
        "message": {"chat": {"id": 1}, "message_id": 5},
        "from": {"id": 1},
    }
    handlers.handle_callback(query)
    assert transport.answers
    assert wait_for(
        lambda: any(
            edit["message_id"] == 5 and "COMMAND CENTER" in edit["text"]
            for edit in transport.edits
        )
    )


def test_callback_help_edits_immediately():
    handlers, transport, _ = make_handlers()
    query = {
        "id": "q2",
        "data": callbacks.c("help").data,
        "message": {"chat": {"id": 1}, "message_id": 6},
    }
    handlers.handle_callback(query)
    assert transport.answers[-1]["id"] == "q2"
    assert transport.edits[-1]["message_id"] == 6
    assert "HELP" in transport.edits[-1]["text"]


def test_callback_rejects_forged_data():
    handlers, transport, _ = make_handlers()
    handlers.handle_callback(
        {
            "id": "q3",
            "data": "ag:v1:evil",
            "message": {"chat": {"id": 1}, "message_id": 7},
        }
    )
    assert transport.answers[-1]["text"] == "This button is out of date."
    assert transport.answers[-1]["alert"] is True
    assert transport.edits == []


def test_callback_denies_unauthorized_chat():
    handlers, transport, _ = make_handlers(authorize=lambda chat_id: False)
    handlers.handle_callback(
        {
            "id": "q4",
            "data": callbacks.c("home").data,
            "message": {"chat": {"id": 1}, "message_id": 8},
        }
    )
    assert transport.answers[-1]["text"] == "Not authorized."
    assert transport.answers[-1]["alert"] is True
    assert transport.edits == []


def test_duplicate_callback_is_debounced():
    handlers, transport, _ = make_handlers()
    query = {
        "id": "q5",
        "data": callbacks.c("help").data,
        "message": {"chat": {"id": 1}, "message_id": 9},
    }
    handlers.handle_callback(query)
    handlers.handle_callback(query)
    assert len([edit for edit in transport.edits if edit["message_id"] == 9]) == 1


def test_tools_callback_renders_fleet():
    handlers, transport, client = make_handlers()
    handlers.handle_callback(
        {
            "id": "q6",
            "data": callbacks.c("tools", "0").data,
            "message": {"chat": {"id": 1}, "message_id": 10},
        }
    )
    assert wait_for(lambda: any("TOOL FLEET" in edit["text"] for edit in transport.edits))
    assert client.tools_calls == 1


def test_tool_recheck_updates_the_cached_fleet():
    handlers, transport, client = make_handlers()
    state.cache_tools(tools_payload())
    handlers.handle_callback(
        {
            "id": "q7",
            "data": callbacks.c("tcheck", "semgrep", "0").data,
            "message": {"chat": {"id": 1}, "message_id": 11},
        }
    )
    assert wait_for(lambda: client.tool_check_calls == ["semgrep"])
    assert wait_for(lambda: any("9.9" in edit["text"] for edit in transport.edits))
    assert state.cached_tools()["tools"]["semgrep"]["version"] == "9.9"


def test_owner_console_respects_owner_ids(monkeypatch):
    monkeypatch.setattr(config, "OWNER_IDS", {"99"})
    handlers, transport, _ = make_handlers(is_owner=lambda chat_id: str(chat_id) == "99")
    handlers.handle_message({"chat": {"id": 1}, "text": "/owner"})
    assert "OWNER CONSOLE RESTRICTED" in transport.sent[0]["text"]

    handlers, transport, _ = make_handlers(is_owner=lambda chat_id: str(chat_id) == "99")
    handlers.handle_message({"chat": {"id": 99}, "text": "/owner"})
    assert wait_for(lambda: any("OWNER CONSOLE" in edit["text"] for edit in transport.edits))


def test_scan_again_callback_starts_from_the_gate():
    handlers, transport, client = make_handlers()
    handlers.handle_callback(
        {
            "id": "q8",
            "data": callbacks.c("sgo", "pipeline").data,
            "message": {"chat": {"id": 1}, "message_id": 12},
        }
    )
    assert wait_for(lambda: bool(client.run_calls))
    assert client.run_calls[0]["target"] == "http://127.0.0.1:5002"
    assert any(edit["message_id"] == 12 for edit in transport.edits)


def test_bot_log_redacts_tokens():
    import backend.telegram_bot as bot

    redacted = bot._redact("url https://api.telegram.org/bot123456:SECRETTOKENVALUE/sendMessage")
    assert "SECRETTOKENVALUE" not in redacted
    assert "<token>" in redacted


def test_scan_target_log_mask_drops_credentials_and_query():
    masked = api_module.mask_target(
        "http://user:password@127.0.0.1:5002/scan?token=SUPERSECRET"
    )
    assert masked == "http://127.0.0.1:5002"
    assert "password" not in masked
    assert "SUPERSECRET" not in masked


def test_pdf_callback_is_whitelisted_and_present_on_status():
    data = callbacks.c("pdf").data
    assert callbacks.parse(data).action == "pdf"
    rows = keyboards.status()
    assert any(button["callback_data"] == data for row in rows for button in row)


def test_report_command_sends_the_latest_real_pdf(monkeypatch):
    from pathlib import Path

    monkeypatch.setattr(Path, "is_file", lambda self: True)
    handlers, transport, _ = make_handlers()
    handlers.handle_message({"chat": {"id": 1}, "text": "/report"})
    assert len(transport.documents) == 1
    document = transport.documents[0]
    assert document["file_path"].endswith("AegisAI_Audit_Report_20261123_200827.pdf")
    assert "audit" in document["caption"]
    assert "9 findings" in document["caption"]


def test_report_command_rejects_a_traversal_filename(monkeypatch):
    from pathlib import Path

    monkeypatch.setattr(Path, "is_file", lambda self: True)
    handlers, transport, client = make_handlers()
    client.reports = lambda: {"summary": {"latest_filename": "../secret.pdf"}, "reports": []}
    handlers.handle_message({"chat": {"id": 1}, "text": "/report"})
    assert transport.documents == []
    assert "no pdf report" in transport.sent[0]["text"].lower()


def test_transport_send_document_delegates_to_upload_callable():
    captured = {}

    def upload(chat_id, file_path, caption, timeout):
        captured.update(chat_id=chat_id, file_path=file_path, caption=caption, timeout=timeout)
        return {"ok": True, "result": {"message_id": 77}}

    transport = Transport(lambda *args, **kwargs: {}, log=lambda message: None, upload_callable=upload)
    assert transport.send_document(1, "report.pdf", "caption", 45)["ok"] is True
    assert captured == {"chat_id": 1, "file_path": "report.pdf", "caption": "caption", "timeout": 45}


# ---------------------------------------------------------------------------
# DAST -> Audit -> Agent pipeline
# ---------------------------------------------------------------------------


def _tap_pipeline(handlers, action, gate_id="pipeline", message_id=12):
    handlers.handle_callback(
        {
            "id": "pipe-tap",
            "data": callbacks.c(action, gate_id).data,
            "message": {"chat": {"id": 1}, "message_id": message_id},
        }
    )


def test_pipeline_button_is_whitelisted_and_present_on_main_menu():
    assert callbacks.parse(callbacks.c("pfull", "pipeline").data).action == "pfull"
    rows = keyboards.main_menu(True)
    assert any(button["callback_data"] == callbacks.c("pipeline").data for row in rows for button in row)
    menu_rows = keyboards.pipeline_menu()
    assert any(button["callback_data"] == callbacks.c("pdast", "pipeline").data for row in menu_rows for button in row)
    assert any(button["callback_data"] == callbacks.c("paudit", "pipeline").data for row in menu_rows for button in row)
    assert any(button["callback_data"] == callbacks.c("pagent", "pipeline").data for row in menu_rows for button in row)


def test_pipeline_callback_rejects_an_unknown_gate():
    forged = f"{callbacks.PREFIX}:{callbacks.VERSION}:pdast:evil"
    assert callbacks.parse(forged) is None
    with pytest.raises(callbacks.CallbackError):
        callbacks.c("pdast", "evil")


def test_full_pipeline_runs_dast_audit_then_agent_with_real_progress():
    handlers, transport, client = make_handlers()
    handlers.handle_message({"chat": {"id": 1}, "text": "/pipeline"})
    assert "DAST" in transport.sent[-1]["text"].upper()

    _tap_pipeline(handlers, "pfull")
    assert wait_for(
        lambda: len(client.engine_starts) == 2
        and len(client.run_calls) == 1
        and any("PIPELINE COMPLETE" in edit["text"].upper() for edit in transport.edits)
    )

    assert [item["mode"] for item in client.engine_starts] == ["dast", "audit"]
    assert all(item["target"] == "http://127.0.0.1:5002" for item in client.engine_starts)
    assert len(client.engine_streams) == 2
    assert all(call["target"] == "http://127.0.0.1:5002" for call in client.run_calls)
    assert "prior audit score: 7" in client.run_calls[0]["task"].lower()
    assert any("Scope check" in edit["text"] for edit in transport.edits)
    assert not state.is_running(1)

    final = [edit for edit in transport.edits if "PIPELINE COMPLETE" in edit["text"].upper()][-1]
    assert callbacks.c("pdf").data in str(final["keyboard"])


def test_single_audit_stage_does_not_start_the_agent():
    handlers, transport, client = make_handlers()
    _tap_pipeline(handlers, "paudit")
    assert wait_for(lambda: any("AUDIT COMPLETE" in edit["text"].upper() for edit in transport.edits))
    assert [item["mode"] for item in client.engine_starts] == ["audit"]
    assert client.run_calls == []


def test_pipeline_stop_cancels_only_the_current_engine_scan():
    class BlockingStreamClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.stream_started = threading.Event()
            self.stream_release = threading.Event()

        def engine_stream(self, scan_id, on_event):
            self.stream_started.set()
            self.stream_release.wait(3)
            on_event("error", {"msg": "cancelled"})
            return {"status": "cancelled", "error": "cancelled"}

        def engine_cancel(self, scan_id):
            result = super().engine_cancel(scan_id)
            self.stream_release.set()
            return result

    client = BlockingStreamClient()
    handlers, transport, _ = make_handlers(client=client)
    _tap_pipeline(handlers, "pfull")
    assert client.stream_started.wait(3)
    scan_id = state.pipeline_scan_id(1)

    handlers.handle_message({"chat": {"id": 1}, "text": "/stop"})
    assert client.engine_cancels == [scan_id]
    assert client.cancel_calls == 0
    assert wait_for(lambda: any("PIPELINE STOPPED" in edit["text"].upper() for edit in transport.edits))
    assert not state.is_running(1)


def test_pipeline_api_failure_is_reported_and_releases_the_slot():
    handlers, transport, client = make_handlers()

    def fail(mode, target):
        raise RuntimeError("engine offline")

    client.engine_start = fail
    _tap_pipeline(handlers, "pdast")
    assert wait_for(lambda: any("PIPELINE FAILED" in edit["text"].upper() for edit in transport.edits))
    assert any("engine offline" in edit["text"] for edit in transport.edits)
    assert not state.is_running(1)


def test_api_client_validates_engine_inputs():
    client = api_module.ApiClient(lambda path: {}, lambda path, payload: {}, lambda path, cb: {})
    with pytest.raises(ValueError):
        client.engine_start("exploit", "http://127.0.0.1:5002")
    with pytest.raises(ValueError):
        client.engine_cancel("bad-id")
    with pytest.raises(ValueError):
        client.engine_stream("bad-id", lambda event, payload: None)


def test_mixed_pipeline_keeps_code_audit_and_agent_severities():
    from backend.deep_scanner import normalize_severity
    from backend.correlation import _severity_rank

    assert normalize_severity("INFO") == normalize_severity("note") == "INFO"
    assert _severity_rank("LOW") > _severity_rank("INFO")
    audit = {"findings": [
        {"severity": "LOW", "title": "minor"},
        {"severity": "CRITICAL", "title": "code issue"},
    ]}
    agent = {"severity_counts": {"INFO": 4, "LOW": 4}, "findings": [
        {"severity": "INFO", "title": "discovered page"},
    ]}
    result = screens.pipeline_summary({"dast": {"audit": audit}, "audit": audit, "agent": agent}, "local", None)
    assert result.text.count("code issue") == 1
    assert result.text.index("code issue") < result.text.index("minor")
    assert "<b>1</b> CRITICAL" in result.text and "<b>4</b> INFO" in result.text


def test_connection_loss_after_stop_reports_unknown_outcome():
    handlers, transport, client = make_handlers()
    assert state.begin_scan(1, "local")
    assert state.request_cancel(1)
    def interrupted(*args):
        raise ConnectionResetError(10054, "connection reset")
    client.agent_run = interrupted
    handlers._run_scan(1, "local", "task", None, 12)
    body = transport.edits[-1]["text"]
    assert "STOP REQUESTED" in body and "/status" in body
    assert "SCAN FAILED" not in body and "10054" not in body
    assert not state.is_running(1)


def test_timeout_shows_completed_audit_in_pipeline():
    handlers, transport, client = make_handlers()
    client.stream_events = [("complete", {"audit": {"findings": [
        {"severity": "HIGH", "title": "Earlier code finding"}
    ]}})]
    def timeout(*args):
        raise urllib.error.URLError(TimeoutError())
    client.agent_run = timeout
    _tap_pipeline(handlers, "pfull")
    assert wait_for(lambda: any("RESULT UNAVAILABLE" in e["text"] for e in transport.edits))
    body = transport.edits[-1]["text"]
    assert "Earlier code finding" in body and "COMPLETED STAGES" in body
    assert "PIPELINE COMPLETE" not in body


def test_empty_stage_stream_does_not_show_success():
    handlers, transport, client = make_handlers()
    client.engine_stream = lambda scan_id, on_event: {}
    _tap_pipeline(handlers, "pdast")
    assert wait_for(lambda: any("RESULT UNAVAILABLE" in e["text"] for e in transport.edits))
    assert not state.is_running(1)


def test_quick_audit_routes_directly_to_the_local_source(monkeypatch):
    seen = []
    def local_check(gate):
        seen.append(gate)
        return {"source": "app2.py", "findings": [{"severity": "HIGH", "title": "Review this line"}]}
    monkeypatch.setattr(api_module, "quick_source_audit", local_check)
    handlers, transport, client = make_handlers()
    handlers.handle_message({"chat": {"id": 13}, "text": "/quick sample"})
    assert wait_for(lambda: bool(transport.sent))
    assert seen == ["sample"] and len(transport.sent) == 1
    assert "app2.py" in transport.sent[0]["text"] and "Review this line" in transport.sent[0]["text"]
    assert not client.run_calls and not client.engine_starts


def test_completed_audit_is_visible_while_agent_is_running():
    assert state.begin_pipeline(7, "local", ("audit", "agent"))
    state.set_pipeline_audit_counts(7, {"HIGH": 2})
    page = screens.pipeline_running("local", 1, 2, "processing", "running",
                                    stage_key="agent", audit_counts=state.pipeline_audit_counts(7))
    assert "COMPLETED CODE AUDIT" in page.text and "<b>2</b> HIGH" in page.text and "2 / 2 · Agent" in page.text
    state.end_pipeline(7)
    assert state.begin_pipeline(7, "local", ("agent",))
    assert state.pipeline_audit_counts(7) is None

