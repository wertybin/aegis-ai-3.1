"""V3.1 — native desktop window for the already-running local AEGIS UI.

This module intentionally does NOT start a second uvicorn server. The launcher
script makes sure the shared local services are up, then this window simply
points at the AEGIS URL you configured in .env. That keeps one source of truth
for agent state and avoids launching backend.main twice.
"""

from __future__ import annotations

import os
import sys
import time
import urllib.request

import webview

_BASE_URL = os.getenv("AEGIS_API_BASE", "").strip().rstrip("/")
URL = f"{_BASE_URL}/" if _BASE_URL else ""
TITLE = "AEGIS AI 3.1 // Autonomous Security Intelligence"


def _wait_for_ui(timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(URL, timeout=2) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> int:
    if not _wait_for_ui():
        # No silent fake window: tell the user what is missing.
        webview.create_window(
            "AEGIS AI 3.1 — service unavailable",
            html=(
                "<div style=\"font-family:Consolas,monospace;background:#07070B;color:#F87171;"
                "padding:24px;height:100%\">"
                "<h2>Local AEGIS service is not running.</h2>"
                "<p>Run <b>start_all.ps1</b> first, or re-run the desktop launcher.</p>"
                "</div>"
            ),
            width=680,
            height=260,
        )
        webview.start()
        return 1

    webview.create_window(
        title=TITLE,
        url=URL,
        width=1360,
        height=860,
        min_size=(1024, 680),
        background_color="#07070B",
    )
    webview.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
