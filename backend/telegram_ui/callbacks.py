"""Callback-data codec, validation and navigation parents.

Wire format (always ASCII, always <= 64 bytes):

    ag:v1:<action>[:arg[:arg]]

Only the actions in :data:`ACTIONS` are accepted. Anything else is rejected
before a handler runs, so a forged callback can never reach an arbitrary code
path. Arguments are validated against the real gate registry and a strict
tool-name pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from backend.telegram_ui import config

PREFIX = config.CALLBACK_PREFIX
VERSION = config.CALLBACK_VERSION
MAX_BYTES = 64

_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PAGE_RE = re.compile(r"^\d{1,2}$")

# action -> number of arguments after the action.
ACTIONS: dict[str, int] = {
    "home": 0,
    "gates": 0,
    "tools": 1,
    "trefresh": 1,
    "gate": 1,
    "gscan": 1,
    "tool": 2,
    "tcheck": 2,
    "profile": 0,
    "owner": 0,
    "help": 0,
    "status": 0,
    "pdf": 0,
    "pipeline": 0,
    "quick": 1,
    "pdast": 1,
    "paudit": 1,
    "pagent": 1,
    "pfull": 1,
    "px": 0,
    "pr": 0,
    "scan": 1,
    "sgo": 1,
    "sx": 0,
    "sr": 0,
    "noop": 0,
}

# Deterministic parent screen for Back buttons (no fragile history stack).
PARENTS: dict[str, str] = {
    "gates": "home",
    "tools": "home",
    "gate": "gates",
    "gscan": "gates",
    "tool": "tools",
    "tcheck": "tools",
    "profile": "home",
    "owner": "home",
    "help": "home",
    "status": "home",
    "pdf": "status",
    "pipeline": "home",
    "quick": "pipeline",
    "pdast": "pipeline",
    "paudit": "pipeline",
    "pagent": "pipeline",
    "pfull": "pipeline",
    "px": "home",
    "pr": "home",
    "scan": "gates",
    "sgo": "gates",
    "sx": "home",
    "sr": "home",
    "noop": "home",
}


class CallbackError(ValueError):
    """Raised when a callback payload is malformed or forged."""


@dataclass(frozen=True)
class Callback:
    action: str
    args: tuple[str, ...] = ()

    @property
    def data(self) -> str:
        return encode(self.action, *self.args)

    @property
    def page(self) -> int:
        for value in reversed(self.args):
            if _PAGE_RE.match(value):
                return int(value)
        return 0

    @property
    def gate_id(self) -> str:
        for value in self.args:
            if value in config.GATE_BY_ID:
                return value
        return ""

    @property
    def tool_name(self) -> str:
        for value in self.args:
            if _TOOL_RE.match(value):
                return value
        return ""

    @property
    def parent(self) -> str:
        return PARENTS.get(self.action, "home")


def _validate_arg(action: str, index: int, value: str) -> str:
    if action in {"tools", "trefresh"}:
        if not _PAGE_RE.match(value):
            raise CallbackError("invalid page")
        page = int(value)
        if page > 99:
            raise CallbackError("page out of range")
        return str(page)
    if action in {"gate", "gscan", "scan", "sgo", "pdast", "paudit", "pagent", "pfull", "quick"}:
        if value not in config.GATE_BY_ID:
            raise CallbackError("unknown gate")
        return value
    if action in {"tool", "tcheck"}:
        if index == 0:
            if not _TOOL_RE.match(value):
                raise CallbackError("invalid tool name")
            return value
        if not _PAGE_RE.match(value):
            raise CallbackError("invalid page")
        page = int(value)
        if page > 99:
            raise CallbackError("page out of range")
        return str(page)
    raise CallbackError("unexpected argument")


def encode(action: str, *args: str) -> str:
    if action not in ACTIONS:
        raise CallbackError(f"unknown action: {action}")
    expected = ACTIONS[action]
    if len(args) != expected:
        raise CallbackError(f"{action} expects {expected} argument(s)")
    safe_args = tuple(
        _validate_arg(action, index, str(value)) for index, value in enumerate(args)
    )
    data = ":".join((PREFIX, VERSION, action, *safe_args))
    if len(data.encode("utf-8")) > MAX_BYTES:
        raise CallbackError("callback data exceeds 64 bytes")
    return data


def parse(data: str | None) -> Callback | None:
    """Returns a validated Callback, or None for anything suspicious."""
    if not isinstance(data, str) or not data:
        return None
    if len(data.encode("utf-8")) > MAX_BYTES:
        return None
    parts = data.split(":")
    if len(parts) < 3 or parts[0] != PREFIX or parts[1] != VERSION:
        return None
    action = parts[2]
    args = tuple(parts[3:])
    if action not in ACTIONS or len(args) != ACTIONS[action]:
        return None
    try:
        for index, value in enumerate(args):
            _validate_arg(action, index, value)
    except CallbackError:
        return None
    return Callback(action, args)


def button(text: str, callback: Callback | str, *, style: str = "primary") -> dict:
    data = callback if isinstance(callback, str) else callback.data
    if len(data.encode("utf-8")) > MAX_BYTES:
        raise CallbackError("button callback exceeds 64 bytes")
    if style not in {"primary", "success", "danger"}:
        raise CallbackError(f"unknown Telegram button style: {style}")
    return {"text": text, "callback_data": data, "style": style}


def c(action: str, *args: str) -> Callback:
    encode(action, *args)  # validate eagerly
    return Callback(action, tuple(str(arg) for arg in args))
