"""Verified Telegram Premium custom-emoji engine.

Only IDs that were returned by a live ``getStickerSet`` call and re-checked
with ``getCustomEmojiStickers`` live in :mod:`emoji_data`. This module never
invents an ID: a key either resolves to a verified custom emoji or to its
Unicode fallback.

Runtime rules
    * ``auto``   try the verified custom emoji, downgrade globally the first
                 time Telegram rejects custom emoji, then retry Unicode.
    * ``custom`` same attempt policy, but a rejection is logged loudly.
    * ``unicode`` never emit ``<tg-emoji>`` at all.

Telegram only accepts ``<tg-emoji>`` inside HTML parse mode, and inline
button labels cannot contain custom emoji at all, so buttons always use the
Unicode fallback from :func:`plain`.
"""

from __future__ import annotations

import html as html_lib
import re
import threading

from backend.telegram_ui import config
from backend.telegram_ui.emoji_data import REGISTRY_ROWS

_TG_EMOJI_RE = re.compile(
    r'<tg-emoji\s+emoji-id="(?P<id>\d+)">(?P<fallback>[^<]*)</tg-emoji>',
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")


class _Registry:
    """Immutable key -> entry map built from the generated verified rows."""

    def __init__(self, rows: list[dict]) -> None:
        self._entries: dict[str, dict] = {}
        for row in rows:
            key = str(row.get("key") or "").strip()
            fallback = str(row.get("fallback") or "").strip()
            if not key or not fallback:
                continue
            custom_id = row.get("custom_id")
            verified = bool(row.get("verified")) and bool(
                isinstance(custom_id, str) and custom_id.isdigit()
            )
            self._entries[key] = {
                "key": key,
                "fallback": fallback,
                "custom_id": custom_id if verified else None,
                "pack": row.get("pack") if verified else None,
                "category": row.get("category") or "general",
                "description": row.get("description") or "",
                "animation": row.get("animation") or "unicode",
                "verified": verified,
            }

    def get(self, key: str) -> dict:
        entry = self._entries.get(key)
        if entry is not None:
            return entry
        return {
            "key": key,
            "fallback": "•",
            "custom_id": None,
            "pack": None,
            "category": "general",
            "description": "Unknown registry key",
            "animation": "unicode",
            "verified": False,
        }

    def keys(self) -> list[str]:
        return list(self._entries)

    def rows(self) -> list[dict]:
        return [dict(entry) for entry in self._entries.values()]

    def verified_count(self) -> int:
        return sum(1 for entry in self._entries.values() if entry["verified"])

    def categories(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for entry in self._entries.values():
            grouped.setdefault(entry["category"], []).append(entry["key"])
        return {name: sorted(keys) for name, keys in sorted(grouped.items())}


REGISTRY = _Registry(REGISTRY_ROWS)

_state_lock = threading.Lock()
_custom_enabled = config.EMOJI_MODE != "unicode"
_downgrade_reason: str | None = None


def custom_enabled() -> bool:
    with _state_lock:
        return _custom_enabled


def downgrade_reason() -> str | None:
    with _state_lock:
        return _downgrade_reason


def disable_custom(reason: str = "Telegram rejected custom emoji") -> None:
    """Permanently switches this process to Unicode fallbacks (idempotent)."""
    global _custom_enabled, _downgrade_reason
    with _state_lock:
        if _custom_enabled:
            _custom_enabled = False
            _downgrade_reason = reason[:240]


def reset_runtime_state() -> None:
    """Test helper: restore the configured emoji mode."""
    global _custom_enabled, _downgrade_reason
    with _state_lock:
        _custom_enabled = config.EMOJI_MODE != "unicode"
        _downgrade_reason = None


def plain(key: str) -> str:
    """Unicode fallback safe for buttons and plain-text retries."""
    return REGISTRY.get(key)["fallback"]


def render(key: str, mode: str | None = None) -> str:
    """Returns an HTML fragment for one emoji key.

    Custom output is only produced when the key is verified and custom emoji
    are enabled for this process. Otherwise the Unicode fallback is returned.
    """
    entry = REGISTRY.get(key)
    selected = (mode or config.EMOJI_MODE).strip().lower()
    if selected == "unicode" or not entry["verified"] or not custom_enabled():
        return entry["fallback"]
    return (
        f'<tg-emoji emoji-id="{entry["custom_id"]}">'
        f"{entry['fallback']}</tg-emoji>"
    )


def has_custom(key: str) -> bool:
    entry = REGISTRY.get(key)
    return bool(entry["verified"] and entry["custom_id"])


def strip_custom(text: str) -> str:
    """Removes ``<tg-emoji>`` wrappers but keeps their fallback glyphs."""
    return _TG_EMOJI_RE.sub(lambda match: match.group("fallback"), text)


def strip_html(text: str) -> str:
    """Best-effort plain-text retry used only after a parse-mode rejection."""
    without_custom = strip_custom(text)
    no_tags = _TAG_RE.sub("", without_custom)
    return html_lib.unescape(no_tags)


def looks_like_custom_emoji_error(message: str) -> bool:
    lowered = (message or "").lower()
    return any(
        marker in lowered
        for marker in (
            "custom emoji",
            "custom_emoji",
            "tg-emoji",
            "unsupported emoji",
        )
    )


def catalog() -> dict:
    """Machine-readable registry summary for docs and the owner console."""
    return {
        "mode": config.EMOJI_MODE,
        "custom_enabled": custom_enabled(),
        "downgrade_reason": downgrade_reason(),
        "keys": len(REGISTRY.keys()),
        "verified": REGISTRY.verified_count(),
        "packs": sorted(
            {row["pack"] for row in REGISTRY.rows() if row["pack"]}
        ),
        "categories": REGISTRY.categories(),
    }
