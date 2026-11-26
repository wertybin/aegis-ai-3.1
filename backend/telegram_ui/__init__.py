"""Premium Telegram-native presentation layer for the AEGIS AI bot.

The package is intentionally independent from the polling/transport primitives
in ``backend.telegram_bot``: the bot injects its own callables, which keeps the
existing transport testable and avoids circular imports.

Modules
    config       brand, limits, authorized gates
    emoji        verified Premium custom-emoji registry + safe fallbacks
    components   HTML typography and reusable premium message blocks
    keyboards    inline keyboard builders
    callbacks    callback-data codec and validation
    state        per-chat cooldowns, active scans, caches
    api          thin client for the local AEGIS backend
    transport    Telegram send/edit/answer with premium fallback
    screens      every screen renderer (welcome, gates, tools, ...)
    handlers     command + callback router
"""

from __future__ import annotations

from backend.telegram_ui.config import VERSION

__all__ = ["VERSION"]
