"""AegisAI backend package.

Loads local .env values (if present) before any module reads GEMINI_API_KEY or
AEGIS_SERIAL_PORT. No third-party dependency is required.
"""

import os
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    env_file = _BASE_DIR / ".env"
    if not env_file.exists():
        return
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


_load_dotenv()
