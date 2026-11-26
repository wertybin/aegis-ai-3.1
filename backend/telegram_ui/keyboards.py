"""Telegram inline keyboards with native button styles and validated callbacks."""

from __future__ import annotations

from backend.telegram_ui import callbacks, config, emoji
from backend.telegram_ui.callbacks import Callback, button, c

SHORT_LABELS = {
    "metasploit": "Metasploit",
    "burp": "Burp",
    "semgrep": "Semgrep",
    "trivy": "Trivy",
    "gitleaks": "Gitleaks",
    "testssl": "testSSL",
    "httpx": "httpx",
    "katana": "Katana",
    "api_security": "API Security",
    "ai_correlation": "Correlation",
    "tool_center": "Tool Center",
}

STATUS_GLYPH = {
    "OK": emoji.plain("gate_online"),
    "FAILED": emoji.plain("gate_offline"),
    "MISSING": emoji.plain("warning"),
    "UNKNOWN": emoji.plain("info"),
    "NOT RUN": emoji.plain("timer"),
}


def _row(*buttons: dict) -> list[dict]:
    return [item for item in buttons if item]


def _nav(back: Callback | None = None) -> list[list[dict]]:
    row = []
    if back is not None:
        row.append(button(f"{emoji.plain('back')} Back", back))
    row.append(button(f"{emoji.plain('home')} Home", c("home")))
    return [row]


def short_label(name: str, label: str | None = None) -> str:
    text = SHORT_LABELS.get(name) or (label or name)
    text = str(text).strip()
    return text if len(text) <= 18 else text[:17].rstrip() + "…"


def main_menu(owner: bool = True) -> list[list[dict]]:
    rows = [
        _row(
            button(f"{emoji.plain('gates')} Gates", c("gates"), style="success"),
            button(f"{emoji.plain('tools')} Tools", c("tools", "0"), style="success"),
        ),
        _row(button(f"{emoji.plain('profile')} Profile", c("profile"))),
    ]
    if owner:
        rows.append(_row(button(f"{emoji.plain('owner')} Owner", c("owner"))))
    rows.extend([
        _row(
            button(f"{emoji.plain('rocket')} Pipeline", c("pipeline")),
            button(f"{emoji.plain('stats')} Status", c("status")),
        ),
        _row(
            button(f"{emoji.plain('search')} Quick code audit", c("quick", config.DEFAULT_GATE_ID)),
            button(f"{emoji.plain('question')} Help", c("help")),
        ),
    ])
    return rows


def pipeline_menu() -> list[list[dict]]:
    rows: list[list[dict]] = []
    for gate in config.GATES:
        gid = gate["id"]
        rows.append(
            _row(
                button(f"{emoji.plain('radar')} DAST · {short_label(gate['name'])}", c("pdast", gid)),
                button(f"{emoji.plain('search')} Audit · {short_label(gate['name'])}", c("paudit", gid)),
            )
        )
        rows.append(
            _row(
                button(f"{emoji.plain('bot')} Agent · {short_label(gate['name'])}", c("pagent", gid)),
                button(f"{emoji.plain('rocket')} Full chain · {short_label(gate['name'])}", c("pfull", gid)),
            )
        )
    rows.extend(quick_choices())
    rows.extend(_nav())
    return rows


def quick_choices() -> list[list[dict]]:
    return [_row(*(button("Quick · " + gate["name"], c("quick", gate["id"])) for gate in config.GATES))]


def pipeline_running() -> list[list[dict]]:
    return [
        _row(
            button(f"{emoji.plain('stop')} Stop pipeline", c("px"), style="danger"),
            button(f"{emoji.plain('refresh')} Refresh", c("pr")),
        ),
        *_nav(c("pipeline")),
    ]


def pipeline_result(stage: str, gate_id: str | None = None) -> list[list[dict]]:
    target = gate_id if gate_id in config.GATE_BY_ID else config.DEFAULT_GATE_ID
    if stage == "dast":
        rows = [
            _row(
                button(f"{emoji.plain('next')} Next: Audit", c("paudit", target)),
                button(f"{emoji.plain('rocket')} Full chain", c("pfull", target)),
            )
        ]
    elif stage == "audit":
        rows = [
            _row(
                button(f"{emoji.plain('next')} Next: Agent", c("pagent", target)),
                button(f"{emoji.plain('rocket')} Full chain", c("pfull", target)),
            )
        ]
    else:
        rows = [
            _row(
                button(f"{emoji.plain('gem')} PDF report", c("pdf")),
                button(f"{emoji.plain('stats')} Status", c("status")),
            )
        ]
    rows.append(_row(button(f"{emoji.plain('rocket')} Run again", c("pipeline"))))
    rows.extend(_nav(c("pipeline")))
    return rows


def gates(statuses: dict[str, bool] | None = None) -> list[list[dict]]:
    statuses = statuses or {}
    rows: list[list[dict]] = []
    for gate in config.GATES:
        online = statuses.get(gate["id"])
        glyph = (
            emoji.plain("gate_online")
            if online
            else emoji.plain("gate_offline")
            if online is False
            else emoji.plain("timer")
        )
        rows.append(_row(button(f"{glyph} {gate['name']}", c("gate", gate["id"]))))
    rows.append(_row(button(f"{emoji.plain('refresh')} Re-check", c("gates"))))
    rows.extend(_nav())
    return rows


def gate_detail(gate_id: str) -> list[list[dict]]:
    return [
        _row(button(f"{emoji.plain('search')} Quick code audit", c("quick", gate_id))),
        _row(
            button(f"{emoji.plain('play')} Scan this gate", c("gscan", gate_id)),
            button(f"{emoji.plain('refresh')} Re-check", c("gate", gate_id)),
        ),
        *_nav(c("gates")),
    ]


def scan_confirm(gate_id: str) -> list[list[dict]]:
    return [
        _row(
            button(f"{emoji.plain('play')} Start scan", c("sgo", gate_id), style="success"),
            button(f"{emoji.plain('cross')} Cancel", c("gate", gate_id), style="danger"),
        ),
    ]


def scan_running() -> list[list[dict]]:
    return [
        _row(
            button(f"{emoji.plain('stop')} Stop scan", c("sx"), style="danger"),
            button(f"{emoji.plain('refresh')} Refresh", c("sr")),
        ),
    ]


def stop_pending() -> list[list[dict]]:
    return [
        _row(button(f"{emoji.plain('refresh')} Refresh", c("sr"))),
        *_nav(),
    ]


def idle() -> list[list[dict]]:
    return [
        _row(
            button(f"{emoji.plain('gates')} Gates", c("gates")),
            button(f"{emoji.plain('home')} Home", c("home")),
        ),
    ]


def scan_result(gate_id: str | None = None) -> list[list[dict]]:
    target = gate_id if gate_id in config.GATE_BY_ID else config.DEFAULT_GATE_ID
    return [
        _row(
            button(f"{emoji.plain('scan')} Scan again", c("gscan", target)),
            button(f"{emoji.plain('stats')} Status", c("status")),
        ),
        _row(button(f"{emoji.plain('gem')} PDF report", c("pdf"))),
        *_nav(),
    ]


def tools_page(
    page: int,
    tools: list[dict],
    has_prev: bool,
    has_next: bool,
) -> list[list[dict]]:
    rows: list[list[dict]] = []
    pair: list[dict] = []
    for tool in tools:
        name = str(tool.get("name") or "")
        status = str(tool.get("status") or "UNKNOWN").upper()
        glyph = STATUS_GLYPH.get(status, emoji.plain("info"))
        pair.append(button(f"{glyph} {short_label(name, tool.get('label'))}", c("tool", name, str(page))))
        if len(pair) == 2:
            rows.append(pair)
            pair = []
    if pair:
        rows.append(pair)

    nav_row: list[dict] = []
    if has_prev:
        nav_row.append(button(f"{emoji.plain('prev')} Prev", c("tools", str(page - 1))))
    if has_next:
        nav_row.append(button(f"{emoji.plain('next')} Next", c("tools", str(page + 1))))
    if nav_row:
        rows.append(nav_row)
    rows.append(_row(button(f"{emoji.plain('refresh')} Refresh", c("trefresh", str(page)))))
    rows.extend(_nav())
    return rows


def tool_detail(name: str, page: int) -> list[list[dict]]:
    return [
        _row(button(f"{emoji.plain('refresh')} Re-check", c("tcheck", name, str(page)))),
        *_nav(c("tools", str(page))),
    ]


def profile() -> list[list[dict]]:
    return [
        _row(button(f"{emoji.plain('refresh')} Refresh", c("profile"))),
        *_nav(),
    ]


def owner() -> list[list[dict]]:
    return [
        _row(button(f"{emoji.plain('refresh')} Refresh", c("owner"))),
        *_nav(),
    ]


def status() -> list[list[dict]]:
    return [
        _row(
            button(f"{emoji.plain('refresh')} Refresh", c("status")),
            button(f"{emoji.plain('gates')} Gates", c("gates")),
        ),
        _row(button(f"{emoji.plain('gem')} Send PDF report", c("pdf"))),
        *_nav(),
    ]


def help_menu() -> list[list[dict]]:
    return [*_nav()]


def error(parent: Callback | None = None) -> list[list[dict]]:
    return _nav(parent)


def noop() -> list[list[dict]]:
    """A single acknowledged button used only if a caller needs a placeholder."""
    return [[button(f"{emoji.plain('info')} OK", c("noop"))]]


def validate(keyboard: list[list[dict]] | None) -> list[list[dict]] | None:
    """Development guard: every row is a non-empty list of valid buttons."""
    if keyboard is None:
        return None
    for row in keyboard:
        if not row:
            raise callbacks.CallbackError("empty keyboard row")
        for item in row:
            text = item.get("text")
            data = item.get("callback_data")
            if not text or not data:
                raise callbacks.CallbackError("incomplete button")
            if callbacks.parse(data) is None:
                raise callbacks.CallbackError(f"invalid callback: {data}")
    return keyboard
