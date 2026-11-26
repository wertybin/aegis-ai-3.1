"""Reusable premium message components.

Everything is plain Telegram HTML. Dynamic values are escaped exactly once,
here, so screens never have to think about injection. The visual language is
deliberately restrained: one header, one rule, labelled sections, one footer.
"""

from __future__ import annotations

import html
import re
from datetime import datetime

from backend.telegram_ui import config
from backend.telegram_ui import emoji

MAX_DYNAMIC = 600


def esc(value, limit: int = MAX_DYNAMIC) -> str:
    """Escapes Telegram HTML and bounds untrusted text."""
    text = "" if value is None else str(value)
    text = text.replace("\x00", "").strip()
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return html.escape(text, quote=False)


def icon(key: str) -> str:
    return emoji.render(key)


def rule() -> str:
    return f"<i>{config.DIVIDER}</i>"


def divider() -> str:
    return rule()


def header(title: str, subtitle: str | None = None, icon_key: str = "brand") -> str:
    lines = [f"{icon(icon_key)} <b>{esc(title.upper(), 80)}</b>"]
    if subtitle:
        lines.append(f"<i>{esc(subtitle, 140)}</i>")
    lines.append(rule())
    return "\n".join(lines)


def footer(note: str | None = None) -> str:
    lines = [rule()]
    if note:
        lines.append(f"<i>{esc(note, 220)}</i>")
    else:
        lines.append(f"<i>{esc(config.TAGLINE)}</i>")
    lines.append(
        f'<i>Questions · <a href="{config.SUPPORT_URL}">{esc(config.SUPPORT_HANDLE, 40)}</a></i>'
    )
    return "\n".join(lines)


def section(title: str, icon_key: str | None = None) -> str:
    prefix = f"{icon(icon_key)} " if icon_key else ""
    return f"\n{prefix}<b>{esc(title.upper(), 60)}</b>"


def kv(label: str, value, icon_key: str | None = None) -> str:
    prefix = f"{icon(icon_key)} " if icon_key else ""
    return f"{prefix}<b>{esc(label, 40)}</b> · {esc(value, 240)}"


def quote(text: str) -> str:
    return f"<blockquote>{esc(text, 420)}</blockquote>"


def code(text: str) -> str:
    return f"<code>{esc(text, 180)}</code>"


def bar(ratio: float, width: int = 10) -> str:
    try:
        value = max(0.0, min(1.0, float(ratio)))
    except (TypeError, ValueError):
        value = 0.0
    filled = int(round(value * width))
    return "▰" * filled + "▱" * (width - filled)


def fmt_duration(ms) -> str:
    try:
        seconds = max(0.0, float(ms) / 1000.0)
    except (TypeError, ValueError):
        return "—"
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes}m {rest:02d}s"


def fmt_ts(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    text = text.replace("T", " ")
    return text[:19]


def fmt_age(seconds) -> str:
    try:
        value = max(0, int(seconds))
    except (TypeError, ValueError):
        return "—"
    if value < 60:
        return f"{value}s"
    minutes, rest = divmod(value, 60)
    if minutes < 60:
        return f"{minutes}m {rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def severity_counts(counts: dict | None) -> dict[str, int]:
    source = counts or {}
    result: dict[str, int] = {}
    for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        try:
            result[key] = int(source.get(key, 0) or 0)
        except (TypeError, ValueError):
            result[key] = 0
    return result


def severity_line(counts: dict | None) -> str:
    values = severity_counts(counts)
    return " · ".join(f"<b>{n}</b> {level}" for level, n in values.items() if n) or "0 findings"


def findings_block(findings: list[dict] | None, limit: int = config.FINDINGS_PREVIEW) -> str:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    def rank(item):
        severity = str(item.get("severity", "")).upper()
        return order.index(severity) if severity in order else len(order)

    rows = sorted((f for f in findings or [] if isinstance(f, dict)), key=rank)[:max(0, limit)]
    if not rows:
        return f"{icon('success')} <i>No findings inside the authorized scope.</i>"
    lines = []
    for index, finding in enumerate(rows, 1):
        severity = str(finding.get("severity") or "INFO").upper()
        title = esc(finding.get("title") or "Untitled finding", 160)
        location = finding.get("endpoint") or finding.get("file") or "—"
        lines.append(
            f"<b>{index}.</b> [{esc(severity, 12)}] {title}\n"
            f"    <i>{esc(location, 140)}</i>"
        )
    return "\n".join(lines)


def welcome_name(first_name: str | None, username: str | None) -> str:
    if first_name:
        return esc(first_name, 40)
    if username:
        return esc("@" + str(username).lstrip("@"), 40)
    return "operator"


# ---------------------------------------------------------------------------
# Named premium components (used by screens and by the test-suite).
# ---------------------------------------------------------------------------


def PremiumHeader(title: str, subtitle: str | None = None, icon_key: str = "brand") -> str:
    return header(title, subtitle, icon_key)


def PremiumFooter(note: str | None = None) -> str:
    return footer(note)


def owner_contact() -> str:
    return (
        f'{icon("owner")} <b>Owner</b> · '
        f'<a href="{config.SUPPORT_URL}">{esc(config.SUPPORT_HANDLE, 40)}</a>'
    )


def PremiumWelcome(first_name: str | None, username: str | None, owner: bool = False) -> str:
    name = welcome_name(first_name, username)
    owner_line = (
        f"\n{icon('owner')} <b>Owner console</b> · read-only deployment status"
        if owner
        else ""
    )
    return "\n".join(
        [
            header(f"{config.BRAND} {config.VERSION}", config.TAGLINE, "brand"),
            "",
            f"{icon('welcome')} <b>Hello, {name}.</b>",
            "",
            "Real local tools. Real evidence. A model-driven agent that audits "
            "your authorized lab and reports only what it can prove.",
            section("What you can do"),
            f"{icon('gates')} <b>Gates</b> · live lab targets",
            f"{icon('tools')} <b>Tools</b> · 11-tool fleet status",
            f"{icon('profile')} <b>Profile</b> · scan limits and history",
            owner_contact(),
            owner_line,
            "",
            quote(config.SCOPE_NOTE),
            footer(f"One scan every {config.RATE_LIMIT_SECONDS}s per chat"),
        ]
    )


def PremiumDashboard(snapshot: dict) -> str:
    backend = snapshot.get("backend") or {}
    online = bool(backend.get("online"))
    latency = backend.get("latency_ms")
    backend_value = "online" if online else "unreachable"
    if online and latency is not None:
        backend_value += f" · {int(latency)}ms"
    tools_installed = snapshot.get("tools_installed")
    tools_total = snapshot.get("tools_total")
    if tools_installed is None:
        tools_value = "not checked"
    else:
        tools_value = f"{tools_installed} / {tools_total} installed"
    agent_running = bool(snapshot.get("agent_running"))
    last = snapshot.get("last") or {}
    if last:
        last_value = (
            f"{int(last.get('total_findings') or 0)} findings · "
            f"{fmt_duration(last.get('duration_ms'))}"
        )
    else:
        last_value = "no run yet"
    return "\n".join(
        [
            header(f"{config.BRAND} command center", config.CODENAME, "brand"),
            "",
            kv("Backend", backend_value, "internet"),
            kv("Tools", tools_value, "tools"),
            kv("Agent", "running" if agent_running else "idle", "scan"),
            kv("Last run", last_value, "calendar"),
            "",
            quote("Every number on this screen comes from the live local backend."),
            footer(),
        ]
    )


def PremiumStatus(last: dict | None, running: bool = False) -> str:
    if not last:
        return "\n".join(
            [
                header("agent status", "no completed run", "stats"),
                "",
                f"{icon('info')} No agent run has been recorded yet.",
                f"{icon('play')} Use /scan or open Gates to start a real audit.",
                "",
                footer(),
            ]
        )
    counts = severity_counts(last.get("severity_counts"))
    tools = last.get("tools_used") or []
    return "\n".join(
        [
            header("last agent run", "verified local evidence", "stats"),
            "",
            kv("Mode", last.get("mode") or "—", "settings"),
            kv("Model", last.get("model") or "deterministic", "bot"),
            kv("Target", last.get("target") or "—", "target"),
            kv("Duration", fmt_duration(last.get("duration_ms")), "timer"),
            kv("When", fmt_ts(last.get("ts")), "calendar"),
            "",
            f"{icon('fire')} <b>Findings</b> · <b>{int(last.get('total_findings') or 0)}</b>",
            severity_line(counts),
            "",
            kv("Tools", ", ".join(str(t) for t in tools) or "—", "tools"),
            "",
            f"<i>{esc(last.get('verified_summary') or 'No verified summary stored.', 500)}</i>",
            "",
            footer(f"Agent {'running' if running else 'idle'}"),
        ]
    )


def PremiumError(title: str, detail: str = "", hint: str = "") -> str:
    lines = [header(title, "request failed", "error"), ""]
    if detail:
        lines.append(f"{icon('cross')} {esc(detail, 700)}")
    if hint:
        lines.extend(["", f"{icon('info')} <i>{esc(hint, 300)}</i>"])
    lines.extend(["", footer()])
    return "\n".join(lines)


def PremiumSuccess(title: str, detail: str = "") -> str:
    lines = [header(title, "completed", "success"), ""]
    if detail:
        lines.append(f"{icon('check')} {esc(detail, 700)}")
    lines.extend(["", footer()])
    return "\n".join(lines)


def PremiumWarning(title: str, detail: str = "") -> str:
    lines = [header(title, "attention", "warning"), ""]
    if detail:
        lines.append(f"{icon('warning')} {esc(detail, 700)}")
    lines.extend(["", footer()])
    return "\n".join(lines)


def PremiumLoading(title: str, detail: str = "") -> str:
    lines = [
        header(title, "working", "loading"),
        "",
        f"{icon('loading')} {esc(detail or 'Contacting the local backend…', 500)}",
        "",
        footer("This message updates automatically"),
    ]
    return "\n".join(lines)


def PremiumProfile(snapshot: dict) -> str:
    return "\n".join(
        [
            header("profile", "operator and limits", "profile"),
            "",
            kv("Name", snapshot.get("name") or "—", "user"),
            kv("Chat", snapshot.get("chat_id") or "—", "chat"),
            kv("Access", snapshot.get("access") or "—", "lock"),
            "",
            section("Scan budget"),
            kv("Cooldown", snapshot.get("cooldown") or "ready", "timer"),
            kv("Agent", "running" if snapshot.get("agent_running") else "idle", "scan"),
            kv("Last scan", snapshot.get("last_scan") or "never", "calendar"),
            "",
            section("This deployment"),
            kv("Backend", snapshot.get("backend") or "—", "internet"),
            kv("Version", f"{config.BRAND} {config.VERSION}", "star"),
            "",
            footer("Profiles are derived from your real chat and the live backend"),
        ]
    )


def PremiumScanResult(result: dict, note: str | None = None) -> str:
    counts = severity_counts(result.get("severity_counts"))
    findings = result.get("findings") or []
    tools = result.get("tools_used") or []
    lines = [
        header("scan complete", "evidence-backed result", "success"),
        "",
        kv("Target", result.get("target") or "—", "target"),
        kv("Mode", result.get("mode") or "—", "settings"),
        kv("Duration", fmt_duration(result.get("duration_ms")), "timer"),
        kv("Tools", ", ".join(str(t) for t in tools) or "—", "tools"),
        "",
        f"{icon('stats')} <b>Findings</b> · <b>{int(result.get('total_findings') or 0)}</b>",
        severity_line(counts),
        section("Top findings"),
        findings_block(findings),
        "",
        f"<i>{esc(result.get('verified_summary') or '', 500)}</i>",
    ]
    if note:
        lines.extend(["", quote(note)])
    lines.extend(["", footer("Run again from Gates · /stop cancels an active run")])
    return "\n".join(lines)


def strip_preview(text: str, limit: int = 180) -> str:
    """Plain, tag-free preview for callback toasts."""
    cleaned = re.sub(r"<[^>]+>", "", text or "")
    cleaned = html.unescape(cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]
