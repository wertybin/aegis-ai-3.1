"""Every screen the bot can render.

Screens are pure: they receive live data (or an API client) and return a
:class:`Screen` with Telegram HTML and a validated inline keyboard. Handlers
own transport, loading states and threading.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.telegram_ui import api as api_module
from backend.telegram_ui import callbacks, components, config, emoji, keyboards, state


@dataclass
class Screen:
    text: str
    keyboard: list[list[dict]] | None = None


def _clock(epoch: float | None) -> str:
    if not epoch:
        return "never"
    try:
        return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError, OverflowError):
        return "—"


def _status_glyph(online: bool | None) -> str:
    if online is True:
        return emoji.plain("gate_online")
    if online is False:
        return emoji.plain("gate_offline")
    return emoji.plain("timer")


def _gate_line(gate: dict, probe: dict) -> str:
    online = bool(probe.get("online"))
    parts = ["online" if online else "offline"]
    if probe.get("status"):
        parts.append(f"HTTP {probe['status']}")
    if probe.get("latency_ms") is not None:
        parts.append(f"{int(probe['latency_ms'])}ms")
    return (
        f"{_status_glyph(online)} <b>{components.esc(gate['name'])}</b> · "
        f"{components.esc(' · '.join(parts))}\n"
        f"    <i>{components.esc(gate['role'])}</i>"
    )


def _ordered_tools(payload: dict) -> list[dict]:
    tools = payload.get("tools") or {}
    order = payload.get("order") or list(tools)
    result = []
    for name in order:
        entry = tools.get(name)
        if isinstance(entry, dict):
            result.append({"name": name, **entry})
    for name, entry in tools.items():
        if name not in order and isinstance(entry, dict):
            result.append({"name": name, **entry})
    return result


def welcome(first_name: str | None, username: str | None, owner: bool) -> Screen:
    return Screen(
        components.PremiumWelcome(first_name, username, owner),
        keyboards.main_menu(owner),
    )


def home(client: api_module.ApiClient, owner: bool) -> Screen:
    health = client.health()
    running = state.any_running()
    last = None
    try:
        data = client.agent_last() or {}
        last = data.get("last")
        running = running or bool(data.get("running"))
    except Exception:
        pass
    cached = state.cached_tools(config.TOOLS_CACHE_SECONDS)
    tools_installed = cached.get("installed") if cached else None
    tools_total = cached.get("total") if cached else None
    snapshot = {
        "backend": health,
        "tools_installed": tools_installed,
        "tools_total": tools_total,
        "agent_running": running,
        "last": last,
    }
    keyboard = [
        *keyboards.main_menu(owner),
        [keyboards.button(f"{emoji.plain('refresh')} Refresh", callbacks.c("home"))],
    ]
    return Screen(components.PremiumDashboard(snapshot), keyboard)


def gates(client: api_module.ApiClient) -> Screen:
    probes = api_module.probe_gates()
    lines = [
        components.header("gates", "live local targets", "gates"),
        "",
    ]
    for gate in config.GATES:
        lines.append(_gate_line(gate, probes.get(gate["id"]) or {}))
        lines.append(f"    {components.code(gate['url'] or 'not configured')}")
        lines.append("")
    online = sum(1 for probe in probes.values() if probe.get("online"))
    lines.extend(
        [
            components.rule(),
            f"{emoji.plain('stats')} <b>{online} / {len(config.GATES)}</b> gates responding",
            "",
            components.quote(
                "Only your configured localhost targets are authorized. Set each URL "
                "in .env; a gate is online when its port answers a real HTTP request."
            ),
            components.footer("Tap a gate to inspect or scan it"),
        ]
    )
    statuses = {gate_id: bool(probe.get("online")) for gate_id, probe in probes.items()}
    return Screen("\n".join(lines), keyboards.gates(statuses))


def gate_detail(client: api_module.ApiClient, gate_id: str) -> Screen:
    gate = config.GATE_BY_ID.get(gate_id)
    if gate is None:
        return error("unknown gate", "That gate id is not in the authorized registry.", parent="gates")
    probe = api_module.probe_gate(gate)
    online = bool(probe.get("online"))
    lines = [
        components.header(gate["name"], gate["role"], gate.get("accent") or "gates"),
        "",
        components.kv("Status", "online" if online else "offline", "gate_online" if online else "gate_offline"),
        components.kv("HTTP", probe.get("status") or "—", "internet"),
        components.kv("Latency", f"{probe.get('latency_ms')}ms" if probe.get("latency_ms") is not None else "—", "timer"),
        components.kv("Port", gate["port"] or "not configured", "settings"),
        components.kv("URL", gate["url"] or "not configured", "link"),
        "",
    ]
    if not online:
        lines.extend(
            [
                f"{emoji.plain('warning')} <i>This gate is not responding right now; "
                "a scan will report that honestly.</i>",
                "",
            ]
        )
    lines.extend(
        [
            components.quote(
                "A scan runs the real agent against this local target only. "
                "No external host, exploit or payload is ever used."
            ),
            "",
            components.footer("Choose Scan this gate to review the task first"),
        ]
    )
    return Screen("\n".join(lines), keyboards.gate_detail(gate["id"]))


def scan_confirm(gate_id: str, task: str | None = None) -> Screen:
    gate = config.GATE_BY_ID.get(gate_id) or config.GATE_BY_ID[config.DEFAULT_GATE_ID]
    chosen_task = (task or "Audit the authorized local application and report the top risks.")[
        : config.MAX_TASK_CHARS
    ]
    lines = [
        components.header("confirm scan", gate["name"], "scan"),
        "",
        components.kv("Target", gate["url"] or "not configured", "target"),
        components.kv("Mode", "Qwen/Gemini agent + real tools", "bot"),
        components.kv("Fallback", "deterministic playbook", "settings"),
        "",
        components.section("Task", "search"),
        f"<i>{components.esc(chosen_task, 600)}</i>",
        "",
        components.quote(
            "The agent plans, calls real local tools and returns evidence-backed "
            "findings. It can take 1–3 minutes. /stop cancels safely."
        ),
        "",
        components.footer("Nothing runs until you press Start scan"),
    ]
    return Screen("\n".join(lines), keyboards.scan_confirm(gate["id"]))


def scan_running(target: str, elapsed: float = 0.0) -> Screen:
    minutes = int(elapsed) // 60
    seconds = int(elapsed) % 60
    lines = [
        components.header("agent running", "real tools · real evidence", "loading"),
        "",
        components.kv("Target", target or "default local lab", "target"),
        components.kv("Elapsed", f"{minutes}m {seconds:02d}s", "timer"),
        "",
        f"{emoji.plain('loading')} <b>Planning → tool call → observation</b>",
        "",
        components.quote(
            "You can stop at any time. A cancelled run is never stored as the "
            "last result and no partial findings are reported."
        ),
        "",
        components.footer("This message updates when the run finishes"),
    ]
    return Screen("\n".join(lines), keyboards.scan_running())


_PIPELINE_STAGES = (
    ("dast", "DAST", "radar", "9 real stages · local HTTP tools"),
    ("audit", "Audit", "search", "5 real stages · source review + PDF"),
    ("agent", "Agent", "bot", "Qwen/Gemini function-calling over real tools"),
)


def _pipeline_stage(stage: str) -> tuple[str, str, str]:
    for key, label, icon_key, detail in _PIPELINE_STAGES:
        if key == stage:
            return label, icon_key, detail
    return str(stage or "stage").upper(), "info", ""


def quick_audit(gate_id: str) -> Screen:
    gate = config.GATE_BY_ID[gate_id]
    report = api_module.quick_source_audit(gate_id)
    rows = report["findings"]
    counts = {}
    for row in rows:
        level = row["severity"]
        counts[level] = counts.get(level, 0) + 1
    lines = [
        components.header("quick code audit", gate["name"], "search"),
        components.kv("Source", report["source"], "document"),
        components.severity_line(counts),
        "",
    ]
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    ranked = sorted(rows, key=lambda row: order.index(row["severity"]) if row["severity"] in order else len(order))
    lines.extend(f"[{components.esc(r['severity'])}] {components.esc(r['title'], 160)}" for r in ranked[:5])
    lines.append(components.footer("Fresh local source check · static rules"))
    return Screen("\n".join(lines), [*keyboards.quick_choices(), *keyboards.error(callbacks.c("pipeline"))])


def pipeline_menu() -> Screen:
    lines = [
        components.header("pipeline", "DAST → Audit → Agent", "rocket"),
        "",
    ]
    for index, (key, label, icon_key, detail) in enumerate(_PIPELINE_STAGES, 1):
        lines.append(
            f"{emoji.plain(icon_key)} <b>{index}. {components.esc(label)}</b> · "
            f"<i>{components.esc(detail)}</i>"
        )
    lines.extend(
        [
            "",
            components.quote(
                "Choose a real local gate. A stage starts only when you press its "
                "button; Full chain runs all three in order and streams live progress."
            ),
            "",
            components.footer("One active run at a time · /pipeline to reopen"),
        ]
    )
    return Screen("\n".join(lines), keyboards.pipeline_menu())


def pipeline_running(
    target: str,
    stage_index: int = 0,
    total: int = 3,
    stage_label: str = "",
    status: str = "starting",
    elapsed: float = 0.0,
    scan_id: str = "",
    *,
    stage_key: str | None = None,
    audit_counts: dict | None = None,
) -> Screen:
    label, icon_key, _ = _pipeline_stage(
        stage_key or _PIPELINE_STAGES[min(max(stage_index, 0), 2)][0]
    )
    done = max(0, min(int(stage_index), max(0, int(total) - 1)))
    ratio = (done + 0.5) / max(1, int(total)) if status != "starting" else 0.0
    lines = [
        components.header("pipeline running", "live engine stream", "loading"),
        "",
        components.kv("Stage", f"{done + 1} / {max(1, int(total))} · {label}", icon_key),
        components.kv("State", status or "running", "loading"),
        components.kv("Target", target, "target"),
        components.kv("Elapsed", components.fmt_age(int(elapsed)), "timer"),
        f"{emoji.plain('loading')} <code>{components.bar(ratio)}</code>",
        "",
    ]
    if audit_counts is not None:
        lines.append(components.section("Completed code audit", "stats"))
        lines.append(components.severity_line(audit_counts))
    if stage_label:
        lines.append(f"{emoji.plain('search')} <i>{components.esc(stage_label)}</i>")
        lines.append("")
    if scan_id:
        lines.append(f"{emoji.plain('document')} <code>{components.esc(scan_id[-14:], 20)}</code>")
        lines.append("")
    lines.extend(
        [
            components.quote(
                "Progress comes from real SSE stage events. Stop pipeline cancels "
                "this run only; no partial findings are stored."
            ),
            "",
            components.footer("This message updates on each stage change"),
        ]
    )
    return Screen("\n".join(lines), keyboards.pipeline_running())


def pipeline_summary(results: dict, target: str, gate_id: str | None, *, complete: bool = True) -> Screen:
    heading = "pipeline complete" if complete else "completed stages"
    lines = [components.header(heading, target, "shield")]
    audit_result = results.get("audit") or {}
    audit = audit_result.get("audit") or audit_result
    for stage, payload in results.items():
        label, icon_key, _ = _pipeline_stage(stage)
        source = payload.get("audit") or payload
        rows = [f for f in source.get("findings") or [] if isinstance(f, dict)]
        counts = source.get("severity_counts")
        if counts is None and "findings" in source:
            counts = {}
            for finding in rows:
                severity = str(finding.get("severity") or "INFO").upper()
                counts[severity] = counts.get(severity, 0) + 1
        if stage == "dast" and payload.get("audit"):
            if (rows and rows == audit.get("findings")
                    and source.get("file_path") == audit.get("file_path")):
                lines.append(components.section(label, icon_key))
                lines.append("<i>Completed. The same code findings are listed under Audit.</i>")
                continue
            label += " · embedded code audit"
        lines.append(components.section(label, icon_key))
        if stage == "agent" and payload.get("mode"):
            lines.append(components.kv("Mode", payload["mode"], "bot"))
        if counts is not None:
            lines.append(components.severity_line(counts))
        else:
            lines.append("<i>Completed · no severity breakdown supplied.</i>")
        if rows:
            lines.append(components.findings_block(rows, 3 if stage == "audit" else 2))
    lines.extend(["", components.footer("Counts are per stage and can overlap")])
    return Screen("\n".join(lines), keyboards.pipeline_result(next(reversed(results)), gate_id))


def pipeline_result(
    stage: str,
    result: dict | None,
    target: str,
    gate_id: str | None = None,
) -> Screen:
    label, icon_key, _ = _pipeline_stage(stage)
    payload = result or {}
    if payload.get("cancelled") or str(payload.get("status") or "").lower() == "cancelled":
        return Screen(
            components.PremiumWarning(
                "pipeline cancelled",
                "No partial findings were stored for this run.",
            ),
            keyboards.pipeline_result(stage, gate_id),
        )
    lines = [
        components.header(f"{label} complete", f"stage of the local pipeline · {target}", icon_key),
        "",
    ]
    audit = payload.get("audit") or {}
    findings = audit.get("findings") or payload.get("findings") or []
    score = payload.get("score") if payload.get("score") is not None else audit.get("score")
    if stage == "dast":
        lines.append(
            components.kv("Score", score if score is not None else "—", "stats")
        )
        surface = audit.get("attack_surface") or {}
        endpoints = surface.get("endpoints") if isinstance(surface, dict) else None
        lines.append(
            components.kv("Attack surface", len(endpoints) if isinstance(endpoints, list) else "—", "radar")
        )
    elif stage == "audit":
        lines.append(components.kv("Score", score if score is not None else "—", "stats"))
        lines.append(components.kv("Findings", len(findings), "stats"))
    else:
        lines.append(
            components.kv("Mode", payload.get("mode") or "agent", "bot")
        )
        tools = payload.get("tools_used") or []
        lines.append(components.kv("Real tools", len(tools), "tools"))
        lines.append(components.kv("Findings", payload.get("total_findings", 0), "stats"))
        if tools:
            lines.append(
                f"{emoji.plain('verified')} <i>{components.esc(', '.join(map(str, tools)), 220)}</i>"
            )
    pdf_name = payload.get("pdf_filename") or ""
    if pdf_name:
        lines.append(components.kv("PDF", pdf_name, "document"))
    lines.extend(["", components.section("Evidence", "shield")])
    if "findings" in audit or "findings" in payload:
        lines.append(components.findings_block(findings))
    else:
        lines.append("<i>No finding details supplied for this stage.</i>")
    lines.extend(
        [
            "",
            components.quote(
                "Every value above comes from the completed backend run. "
                "Continue with the next stage or restart the full chain."
            ),
            components.footer("DAST → Audit → Agent"),
        ]
    )
    return Screen("\n".join(lines), keyboards.pipeline_result(stage, gate_id))


def scan_result(result: dict, gate_id: str | None = None) -> Screen:
    if result.get("cancelled") or str(result.get("status") or "").lower() == "cancelled":
        return cancelled("Run cancelled. No partial findings were stored.")
    note = None
    if str(result.get("mode") or "").startswith("deterministic"):
        note = (
            "The AI provider was unavailable, so the deterministic playbook "
            "executed the same real local tools. The mode is reported honestly."
        )
    return Screen(
        components.PremiumScanResult(result, note),
        keyboards.scan_result(gate_id),
    )


def tools(
    client: api_module.ApiClient,
    page: int = 0,
    force: bool = False,
) -> Screen:
    payload = None if force else state.cached_tools()
    if payload is None:
        try:
            payload = client.tools(force=force)
            state.cache_tools(payload)
        except Exception as exc:
            detail = api_module.describe_error(exc)
            state.cache_tools_error(detail)
            return error(
                "tool fleet unavailable",
                detail,
                "The backend may still be starting. Try Refresh in a moment.",
                parent="home",
            )
    entries = _ordered_tools(payload)
    page_size = config.TOOLS_PAGE_SIZE
    pages = max(1, (len(entries) + page_size - 1) // page_size)
    page = max(0, min(page, pages - 1))
    chunk = entries[page * page_size : (page + 1) * page_size]
    installed = int(payload.get("installed") or 0)
    total = int(payload.get("total") or len(entries))
    lines = [
        components.header("tool fleet", f"{installed} / {total} installed", "tools"),
        "",
    ]
    if not chunk:
        lines.append(f"{emoji.plain('warning')} <i>No tools reported by the backend.</i>")
    for tool in chunk:
        status = str(tool.get("status") or "UNKNOWN").upper()
        glyph = keyboards.STATUS_GLYPH.get(status, emoji.plain("info"))
        version = tool.get("version")
        suffix = f" · {components.esc(version, 40)}" if version else ""
        lines.append(
            f"{glyph} <b>{components.esc(keyboards.short_label(tool['name'], tool.get('label')), 40)}</b>"
            f" · {components.esc(status, 16)}{suffix}"
        )
        note = tool.get("note") or tool.get("error") or ""
        if note:
            lines.append(f"    <i>{components.esc(note, 110)}</i>")
    lines.extend(
        [
            "",
            components.rule(),
            f"{emoji.plain('bookmark')} <b>Page {page + 1} / {pages}</b> · "
            f"{len(entries)} tools · live WSL2 availability",
            components.footer("Tap a tool for details or a live re-check"),
        ]
    )
    return Screen(
        "\n".join(lines),
        keyboards.tools_page(page, chunk, page > 0, page < pages - 1),
    )


def tool_detail(client: api_module.ApiClient, name: str, page: int = 0) -> Screen:
    payload = state.cached_tools()
    if payload is None:
        try:
            payload = client.tools()
            state.cache_tools(payload)
        except Exception as exc:
            return error(
                "tool unavailable",
                api_module.describe_error(exc),
                "Try again from the tool fleet.",
                parent="tools",
            )
    entries = {tool["name"]: tool for tool in _ordered_tools(payload)}
    tool = entries.get(name)
    if tool is None:
        return error("unknown tool", f"{name} is not part of the current fleet.", parent="tools")
    status = str(tool.get("status") or "UNKNOWN").upper()
    glyph = keyboards.STATUS_GLYPH.get(status, emoji.plain("info"))
    config_info = tool.get("configuration") or {}
    lines = [
        components.header(tool.get("label") or name, f"tool · {name}", "tool"),
        "",
        f"{glyph} <b>Status</b> · {components.esc(status, 20)}",
        components.kv("Version", tool.get("version") or "—", "settings"),
        components.kv("Timeout", f"{config_info.get('timeout_seconds', tool.get('timeout', '—'))}s", "timer"),
        components.kv("Last run", components.fmt_ts(tool.get("last_execution")), "calendar"),
        components.kv("Execution", tool.get("execution_status") or "NOT RUN", "play"),
        components.kv("Findings", tool.get("findings_count") or 0, "stats"),
        "",
        components.section("Configuration", "settings"),
        f"<i>{components.esc(config_info.get('scope') or 'localhost / allowlisted local lab paths', 200)}</i>",
        f"<i>{components.esc(config_info.get('safe_note') or tool.get('note') or '', 300)}</i>",
        "",
    ]
    error_log = tool.get("error_log") or tool.get("error")
    if error_log:
        lines.extend(
            [
                f"{emoji.plain('warning')} <b>Last error</b>",
                f"<i>{components.esc(error_log, 300)}</i>",
                "",
            ]
        )
    lines.extend(
        [
            components.quote("Re-check runs the real WSL2 availability probe, not a fake status."),
            components.footer("Read-only tool control"),
        ]
    )
    return Screen("\n".join(lines), keyboards.tool_detail(name, page))


def profile(
    client: api_module.ApiClient,
    chat: dict,
    owner: bool,
    access: str,
) -> Screen:
    snap = state.snapshot(chat.get("id"))
    health = client.health()
    remaining = state.cooldown_remaining(chat.get("id"))
    cooldown = "ready" if remaining <= 0 else f"wait {remaining}s"
    name = chat.get("first_name") or chat.get("username") or "operator"
    snapshot = {
        "name": name,
        "chat_id": chat.get("id"),
        "access": access,
        "cooldown": cooldown,
        "agent_running": snap.get("running"),
        "last_scan": _clock(snap.get("last_scan_at")),
        "backend": (
            f"online · {health.get('latency_ms')}ms"
            if health.get("online")
            else "unreachable"
        ),
    }
    return Screen(components.PremiumProfile(snapshot), keyboards.profile())


def owner(
    client: api_module.ApiClient,
    api_base: str,
    access_mode: str,
    owner_ids_configured: bool,
) -> Screen:
    health = client.health()
    cached = state.cached_tools(config.TOOLS_CACHE_SECONDS)
    catalog = emoji.catalog()
    username = state.bot_username() or "unknown"
    downgrade = catalog.get("downgrade_reason") or "none"
    lines = [
        components.header("owner console", "read-only deployment status", "owner"),
        "",
        components.owner_contact(),
        components.kv("Bot", f"@{username}", "bot"),
        components.kv("Backend", api_base, "internet"),
        components.kv("Health", "online" if health.get("online") else "unreachable", "verified"),
        components.kv("Access", access_mode, "lock"),
        components.kv("Owner IDs", "configured" if owner_ids_configured else "not configured", "key"),
        components.kv("Uptime", components.fmt_age(state.uptime_seconds()), "timer"),
        components.kv("Agent", "running" if state.any_running() else "idle", "scan"),
        "",
        components.section("Premium emoji", "gem"),
        components.kv("Mode", catalog.get("mode") or "auto", "settings"),
        components.kv("Verified IDs", f"{catalog.get('verified')} / {catalog.get('keys')}", "verified"),
        components.kv("Packs", ", ".join(catalog.get("packs") or []) or "none", "star"),
        components.kv("Fallback", downgrade, "warning"),
        "",
        components.section("Fleet", "tools"),
        components.kv(
            "Installed",
            f"{cached.get('installed')} / {cached.get('total')}"
            if cached
            else "open Tools to check",
            "tools",
        ),
        "",
        components.quote(
            "This console is read-only on purpose: it exposes no token, no secret "
            "and no mutating operation."
        ),
        components.footer("AEGIS owner console"),
    ]
    return Screen("\n".join(lines), keyboards.owner())


def status(client: api_module.ApiClient) -> Screen:
    try:
        data = client.agent_last() or {}
    except Exception as exc:
        return error("backend unreachable", api_module.describe_error(exc), parent="home")
    return Screen(
        components.PremiumStatus(data.get("last"), bool(data.get("running"))),
        keyboards.status(),
    )


def help_screen() -> Screen:
    lines = [
        components.header("help", "commands, scope, limits", "question"),
        "",
        components.section("Commands", "menu"),
        f"{emoji.plain('home')} /start · welcome and main menu",
        f"{emoji.plain('home')} /menu · command center",
        f"{emoji.plain('scan')} /scan [target] [task] · run the agent",
        f"{emoji.plain('search')} /quick [core | sample | pipeline] · quick local code audit",
        f"{emoji.plain('stop')} /stop · cancel the active scan",
        f"{emoji.plain('stats')} /status · last completed run",
        f"{emoji.plain('gem')} /report · latest PDF report in chat",
        f"{emoji.plain('tools')} /review [app.py | app2.py] · Qwen suggests a code diff",
        f"{emoji.plain('rocket')} /pipeline · DAST → Audit → Agent",
        f"{emoji.plain('gates')} /gates · live local targets",
        f"{emoji.plain('tools')} /tools · 11-tool fleet",
        f"{emoji.plain('profile')} /profile · limits and history",
        f"{emoji.plain('owner')} /owner · deployment status",
        f"{emoji.plain('question')} /help · this message",
        "",
        components.section("Scope", "lock"),
        "<i>Your own localhost / 127.0.0.1 targets only; set them in .env or "
        "pass a URL to /scan. No bundled addresses, exploits, payloads, or "
        "destructive tests. Every finding comes from a real local tool.</i>",
        "",
        components.section("Support", "question"),
        f'{emoji.plain("question")} Questions · '
        f'<a href="{config.SUPPORT_URL}">{components.esc(config.SUPPORT_HANDLE, 40)}</a>',
        "",
        components.section("Premium emoji", "gem"),
        "<i>Verified Telegram Premium icons are attempted first. If Telegram "
        "rejects them for this bot, the identical layout uses Unicode "
        "fallbacks. Menu buttons use Telegram’s native green and blue styles.</i>",
        "",
        components.section("Limits", "timer"),
        f"<i>One scan per {config.RATE_LIMIT_SECONDS}s per chat. The agent runs "
        "one at a time. A cancelled run is not stored.</i>",
        "",
        components.footer("AEGIS AI · defensive by design"),
    ]
    return Screen("\n".join(lines), keyboards.help_menu())


def cancelled(detail: str = "No partial findings were stored.") -> Screen:
    return Screen(
        components.PremiumWarning("scan cancelled", detail),
        keyboards.scan_result(),
    )


def nothing_to_stop() -> Screen:
    return Screen(
        "\n".join(
            [
                components.header("nothing to stop", "agent idle", "info"),
                "",
                f"{emoji.plain('success')} No scan is currently running.",
                "",
                components.footer("Start one from Gates"),
            ]
        ),
        keyboards.idle(),
    )


def stop_confirmed() -> Screen:
    return Screen(
        "\n".join(
            [
                components.header("stop requested", "cooperative cancellation", "stop"),
                "",
                f"{emoji.plain('loading')} <i>The agent is stopping at the next safe checkpoint.</i>",
                "",
                components.footer("The running message will update when it stops"),
            ]
        ),
        keyboards.stop_pending(),
    )


def run_error(title: str, exc: Exception, stop_requested: bool, parent: str) -> Screen:
    notice = api_module.connection_notice(exc)
    if notice:
        heading = "stop requested" if stop_requested else "result unavailable"
        detail = ("The stop request was recorded. " if stop_requested else "") + notice
        detail += " Use /status to check the time of the last completed agent report."
        return Screen(components.PremiumWarning(heading, detail), keyboards.status())
    return error(title, api_module.describe_error(exc), parent=parent)


def error(
    title: str,
    detail: str = "",
    hint: str = "",
    parent: str = "home",
) -> Screen:
    back = None
    if parent == "gates":
        back = callbacks.c("gates")
    elif parent == "tools":
        back = callbacks.c("tools", "0")
    elif parent == "pipeline":
        back = callbacks.c("pipeline")
    return Screen(
        components.PremiumError(title, detail, hint),
        keyboards.error(back),
    )


def loading(title: str = "working", detail: str = "") -> Screen:
    return Screen(components.PremiumLoading(title, detail), None)
