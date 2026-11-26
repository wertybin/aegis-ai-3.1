"""Central configuration for the premium Telegram presentation layer.

Nothing here talks to Telegram or to the AEGIS API. It only holds brand
constants, limits and the user-configured local gates so every screen and
keyboard agrees on the same values. No target URL is bundled with this
release; users provide their own localhost servers in .env.

Environment (all optional, secrets stay in .env):
    AEGIS_GATE_1_URL           first user-defined localhost target
    AEGIS_GATE_2_URL           second user-defined localhost target
    AEGIS_GATE_3_URL           third user-defined localhost target
    AEGIS_GATE_1_SOURCE        local source file/dir for quick code audit
    AEGIS_GATE_2_SOURCE        local source file/dir for quick code audit
    AEGIS_GATE_3_SOURCE        local source file/dir for quick code audit
    TELEGRAM_EMOJI_MODE        auto (default) | custom | unicode
    TELEGRAM_OWNER_CHAT_IDS    comma list for the read-only owner console
"""

from __future__ import annotations

import os
import urllib.parse
from pathlib import Path

BRAND = "AEGIS AI"
VERSION = "3.1"
CODENAME = "Sentinel"
TAGLINE = "Autonomous local security agent"
SCOPE_NOTE = "User-defined localhost targets only. No exploits, no payloads."
SUPPORT_HANDLE = "@wertybin"
SUPPORT_URL = "https://t.me/wertybin"

# A single box-drawing rule keeps every screen visually aligned.
DIVIDER = "─" * 14
DOT = "·"

# Telegram limits and bot behaviour.
MAX_MESSAGE_CHARS = 3800
MAX_TASK_CHARS = 600
RATE_LIMIT_SECONDS = 60
SCAN_TIMEOUT_SECONDS = 420
CALLBACK_DEBOUNCE_SECONDS = 1.2
TOOLS_CACHE_SECONDS = 60
GATE_PROBE_TIMEOUT = 1.5
TOOLS_PAGE_SIZE = 6
FINDINGS_PREVIEW = 5

BASE_DIR = Path(__file__).resolve().parent.parent


def _gate_port(url: str) -> int | None:
    try:
        return urllib.parse.urlparse(url).port
    except ValueError:
        return None


def _configured_gate(
    gate_id: str,
    number: int,
    name: str,
    role: str,
    accent: str,
) -> dict:
    """Builds one gate entirely from user-supplied .env values.

    No URL or source path is bundled in the public release. The guardrail in
    backend/auditor.py still rejects anything outside localhost/127.0.0.1.
    """
    url = os.getenv(f"AEGIS_GATE_{number}_URL", "").strip().rstrip("/")
    source = os.getenv(f"AEGIS_GATE_{number}_SOURCE", "").strip()
    source_path = ""
    if source:
        candidate = Path(source)
        if not candidate.is_absolute():
            candidate = BASE_DIR / candidate
        source_path = str(candidate.resolve())
    return {
        "id": gate_id,
        "port": _gate_port(url),
        "name": name,
        "role": role,
        "url": url,
        "source": source_path,
        "accent": accent,
        "env_var": f"AEGIS_GATE_{number}_URL",
        "source_env_var": f"AEGIS_GATE_{number}_SOURCE",
    }


# Stable ids keep every existing callback contract unchanged. Only the
# display names and the URLs/source paths are user-defined.
GATES: tuple[dict, ...] = (
    _configured_gate("core", 1, "Primary Target", "Your configured local target", "gates"),
    _configured_gate("sample", 2, "Secondary Target", "Your configured local target", "tools"),
    _configured_gate("pipeline", 3, "Pipeline Target", "Your configured local target", "scan"),
)
GATE_BY_ID = {gate["id"]: gate for gate in GATES}
DEFAULT_GATE_ID = "core"

# Emoji runtime: "auto" tries verified Premium custom emoji first and falls
# back to Unicode if Telegram rejects them; "unicode" never tries custom.
EMOJI_MODE = os.getenv("TELEGRAM_EMOJI_MODE", "auto").strip().lower()
if EMOJI_MODE not in {"auto", "custom", "unicode"}:
    EMOJI_MODE = "auto"

# Read-only owner console. Empty means the console is shown only to chats that
# already passed the normal allow-list check (still read-only, no secrets).
OWNER_IDS = {
    item.strip()
    for item in os.getenv("TELEGRAM_OWNER_CHAT_IDS", "").split(",")
    if item.strip()
}

# Callback namespace. Kept short because Telegram caps callback_data at 64 B.
CALLBACK_PREFIX = "ag"
CALLBACK_VERSION = "1"
