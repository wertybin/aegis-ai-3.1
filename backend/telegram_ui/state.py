"""Thread-safe per-chat state: cooldowns, active scans, caches, debounce.

The polling loop, worker threads and callback handlers all touch this module,
so every mutation goes through one lock. No Telegram or HTTP calls happen here.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from backend.telegram_ui import config


@dataclass
class ChatState:
    last_scan_at: float = 0.0          # wall clock, for display
    last_scan_mono: float = 0.0        # monotonic, for rate limiting
    last_target: str = ""
    running: bool = False
    scan_started_mono: float = 0.0
    scan_target: str = ""
    scan_message_id: int | None = None
    cancel_requested: bool = False
    pipeline: bool = False
    pipeline_stages: tuple[str, ...] = ()
    pipeline_index: int = 0
    pipeline_scan_id: str = ""
    pipeline_stage_label: str = ""
    pipeline_status: str = ""
    pipeline_last: dict | None = None
    audit_counts: dict | None = None
    last_action: str = ""
    last_action_at: float = 0.0
    screen_seq: int = 0


@dataclass
class _Global:
    chats: dict[str, ChatState] = field(default_factory=dict)
    active_chat: str = ""
    bot_username: str = ""
    started_mono: float = field(default_factory=time.monotonic)
    last_update_id: int = 0
    tools_cache: dict | None = None
    tools_cached_at: float = 0.0
    tools_error: str = ""


_LOCK = threading.RLock()
_STATE = _Global()


def _chat(chat_id) -> ChatState:
    key = str(chat_id)
    state = _STATE.chats.get(key)
    if state is None:
        state = ChatState()
        _STATE.chats[key] = state
    return state


def reset() -> None:
    """Test helper: forget every chat and the cached bot identity."""
    global _STATE
    with _LOCK:
        _STATE = _Global()


def set_bot_username(username: str | None) -> None:
    with _LOCK:
        _STATE.bot_username = str(username or "").lstrip("@")


def bot_username() -> str:
    with _LOCK:
        return _STATE.bot_username


def uptime_seconds() -> int:
    with _LOCK:
        return int(time.monotonic() - _STATE.started_mono)


def set_last_update_id(update_id) -> None:
    try:
        value = int(update_id)
    except (TypeError, ValueError):
        return
    with _LOCK:
        if value > _STATE.last_update_id:
            _STATE.last_update_id = value


def last_update_id() -> int:
    with _LOCK:
        return _STATE.last_update_id


def cooldown_remaining(chat_id, seconds: int = config.RATE_LIMIT_SECONDS) -> int:
    with _LOCK:
        state = _chat(chat_id)
        if not state.last_scan_mono:
            return 0
        elapsed = time.monotonic() - state.last_scan_mono
    return max(0, int(seconds - elapsed))


def rate_limited(chat_id, seconds: int = config.RATE_LIMIT_SECONDS) -> bool:
    return cooldown_remaining(chat_id, seconds) > 0


def begin_scan(chat_id, target: str, message_id: int | None = None) -> bool:
    """Atomically claims the chat's single scan slot and starts the cooldown.

    The backend runs one agent at a time (``_claim_agent_slot`` returns 409
    otherwise), so the bot mirrors that rule globally. Without this check a
    second chat could briefly enter ``running`` and then call ``/stop`` before
    the backend rejected its run, cancelling the first chat's scan.
    """
    with _LOCK:
        state = _chat(chat_id)
        if state.running:
            return False
        if _STATE.active_chat and _STATE.active_chat != str(chat_id):
            other = _STATE.chats.get(_STATE.active_chat)
            if other is not None and other.running:
                return False
        now = time.monotonic()
        state.running = True
        state.cancel_requested = False
        state.scan_started_mono = now
        state.scan_target = str(target or "")
        state.scan_message_id = message_id
        state.last_scan_mono = now
        state.last_scan_at = time.time()
        state.last_target = str(target or "")
        _STATE.active_chat = str(chat_id)
    return True


def end_scan(chat_id, refund: bool = False) -> None:
    with _LOCK:
        state = _chat(chat_id)
        state.running = False
        state.scan_message_id = None
        if refund:
            state.last_scan_mono = 0.0
            state.last_scan_at = 0.0
        if _STATE.active_chat == str(chat_id):
            _STATE.active_chat = ""


def is_running(chat_id) -> bool:
    with _LOCK:
        return _chat(chat_id).running


def begin_pipeline(
    chat_id,
    target: str,
    stages: tuple[str, ...],
    message_id: int | None = None,
) -> bool:
    """Claims the global run slot for a DAST -> Audit -> Agent chain."""
    if not begin_scan(chat_id, target, message_id):
        return False
    with _LOCK:
        state = _chat(chat_id)
        state.pipeline = True
        state.pipeline_stages = tuple(stages)
        state.pipeline_index = 0
        state.pipeline_scan_id = ""
        state.pipeline_stage_label = ""
        state.pipeline_status = "starting"
        state.pipeline_last = None
        state.audit_counts = None
    return True


def end_pipeline(chat_id, refund: bool = False, last: dict | None = None) -> None:
    end_scan(chat_id, refund=refund)
    with _LOCK:
        state = _chat(chat_id)
        state.pipeline = False
        state.pipeline_scan_id = ""
        state.pipeline_status = ""
        if last is not None:
            state.pipeline_last = last


def is_pipeline(chat_id) -> bool:
    with _LOCK:
        return _chat(chat_id).pipeline


def pipeline_scan_id(chat_id) -> str:
    with _LOCK:
        return _chat(chat_id).pipeline_scan_id


def set_pipeline_scan_id(chat_id, scan_id: str) -> None:
    with _LOCK:
        _chat(chat_id).pipeline_scan_id = str(scan_id or "")


def pipeline_status(chat_id) -> str:
    with _LOCK:
        return _chat(chat_id).pipeline_status


def set_pipeline_status(chat_id, status: str) -> None:
    with _LOCK:
        _chat(chat_id).pipeline_status = str(status or "")[:40]


def pipeline_stage(chat_id) -> tuple[int, int, tuple[str, ...], str]:
    with _LOCK:
        state = _chat(chat_id)
        return (
            state.pipeline_index,
            len(state.pipeline_stages),
            state.pipeline_stages,
            state.pipeline_stage_label,
        )


def set_pipeline_stage(chat_id, index: int, label: str = "") -> None:
    with _LOCK:
        state = _chat(chat_id)
        state.pipeline_index = max(0, int(index))
        state.pipeline_stage_label = str(label or "")[:120]


def pipeline_last(chat_id) -> dict | None:
    with _LOCK:
        return _chat(chat_id).pipeline_last


def set_pipeline_audit_counts(chat_id, counts: dict) -> None:
    with _LOCK:
        _chat(chat_id).audit_counts = dict(counts)


def pipeline_audit_counts(chat_id) -> dict | None:
    with _LOCK:
        counts = _chat(chat_id).audit_counts
        return None if counts is None else dict(counts)


def any_running() -> bool:
    with _LOCK:
        return any(state.running for state in _STATE.chats.values())


def active_chat() -> str:
    with _LOCK:
        return _STATE.active_chat


def request_cancel(chat_id) -> bool:
    with _LOCK:
        state = _chat(chat_id)
        if not state.running:
            return False
        state.cancel_requested = True
        return True


def cancel_requested(chat_id) -> bool:
    with _LOCK:
        return _chat(chat_id).cancel_requested


def scan_elapsed(chat_id) -> float:
    with _LOCK:
        state = _chat(chat_id)
        if not state.running or not state.scan_started_mono:
            return 0.0
        return max(0.0, time.monotonic() - state.scan_started_mono)


def scan_message_id(chat_id) -> int | None:
    with _LOCK:
        return _chat(chat_id).scan_message_id


def scan_target(chat_id) -> str:
    with _LOCK:
        return _chat(chat_id).scan_target


def set_scan_message_id(chat_id, message_id: int | None) -> None:
    with _LOCK:
        _chat(chat_id).scan_message_id = message_id


def cache_tools(payload: dict) -> None:
    with _LOCK:
        _STATE.tools_cache = payload
        _STATE.tools_cached_at = time.monotonic()
        _STATE.tools_error = ""


def cache_tools_error(message: str) -> None:
    with _LOCK:
        _STATE.tools_error = str(message or "")[:300]


def cached_tools(max_age: int = config.TOOLS_CACHE_SECONDS) -> dict | None:
    with _LOCK:
        if not _STATE.tools_cache:
            return None
        if time.monotonic() - _STATE.tools_cached_at > max_age:
            return None
        return _STATE.tools_cache


def tools_cache_age() -> int | None:
    with _LOCK:
        if not _STATE.tools_cached_at:
            return None
        return int(time.monotonic() - _STATE.tools_cached_at)


def tools_error() -> str:
    with _LOCK:
        return _STATE.tools_error


def update_cached_tool(name: str, entry: dict) -> None:
    """Merges a fresh /api/tools/{name}/check result into the cached fleet."""
    with _LOCK:
        payload = _STATE.tools_cache
        if not payload:
            return
        tools = payload.get("tools")
        if not isinstance(tools, dict):
            return
        current = dict(tools.get(name) or {})
        current.update({key: value for key, value in (entry or {}).items() if value is not None})
        tools[name] = current
        payload["installed"] = sum(
            1 for item in tools.values() if str(item.get("status") or "").upper() == "OK"
        )
        _STATE.tools_cached_at = time.monotonic()


def invalidate_tools() -> None:
    with _LOCK:
        _STATE.tools_cache = None
        _STATE.tools_cached_at = 0.0


def debounce(chat_id, action_key: str, seconds: float = config.CALLBACK_DEBOUNCE_SECONDS) -> bool:
    """True when the action should run; False for an accidental double tap."""
    with _LOCK:
        state = _chat(chat_id)
        now = time.monotonic()
        if state.last_action == action_key and now - state.last_action_at < seconds:
            return False
        state.last_action = action_key
        state.last_action_at = now
        return True


def bump_screen(chat_id) -> int:
    """Marks a new navigation target so stale workers cannot overwrite it."""
    with _LOCK:
        state = _chat(chat_id)
        state.screen_seq += 1
        return state.screen_seq


def is_current_screen(chat_id, token: int) -> bool:
    with _LOCK:
        return _chat(chat_id).screen_seq == int(token)


def snapshot(chat_id) -> dict:
    """Real values used by the Profile screen."""
    with _LOCK:
        state = _chat(chat_id)
        return {
            "running": state.running,
            "last_scan_at": state.last_scan_at,
            "last_target": state.last_target,
            "scan_elapsed": (
                max(0.0, time.monotonic() - state.scan_started_mono)
                if state.running and state.scan_started_mono
                else 0.0
            ),
            "tools_cache_age": (
                int(time.monotonic() - _STATE.tools_cached_at)
                if _STATE.tools_cached_at
                else None
            ),
        }
