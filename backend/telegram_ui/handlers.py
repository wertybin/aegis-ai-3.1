"""Command and callback routing for the premium bot.

The poll loop calls :meth:`BotHandlers.handle_update` for every update. All
Telegram and backend access goes through injected dependencies, which keeps
this module mockable and keeps the bot token out of the UI package.

Long operations (tool fleet checks, gate probes, agent runs) always run on a
daemon worker; the poll loop is never blocked.
"""

from __future__ import annotations

import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from backend import code_review

from backend.telegram_ui import api as api_module
from backend.telegram_ui import callbacks, config, screens, state
from backend.telegram_ui.transport import Transport

_REPORT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.pdf$", re.IGNORECASE)
_PIPELINE_STAGES = {"dast", "audit", "agent"}


class _PipelineCancelled(RuntimeError):
    """The chat requested cooperative cancellation of its own pipeline."""


@dataclass
class HandlerDeps:
    transport: Transport
    client: api_module.ApiClient
    authorize: Callable[[object], bool]
    is_owner: Callable[[object], bool]
    parse_scan: Callable[[str], tuple[str, str]]
    api_base: str
    access_mode: str = "public"
    log: Callable[[str], None] = field(default=lambda message: None)


class BotHandlers:
    def __init__(self, deps: HandlerDeps) -> None:
        self.deps = deps
        self._review_lock = threading.Lock()

    def _gate_is_configured(self, chat_id, message_id, gate, parent: str) -> bool:
        """Blocks gate actions until the user supplies their own target URL."""
        if gate and gate.get("url"):
            return True
        env_var = (gate or {}).get("env_var", "AEGIS_GATE_1_URL")
        self._nav_now(
            chat_id,
            message_id,
            screens.error(
                "target not configured",
                f"Set {env_var} in .env to your own localhost URL.",
                parent=parent,
            ),
        )
        return False

    # -- entry points ------------------------------------------------------
    def handle_update(self, update: dict) -> None:
        if not isinstance(update, dict):
            return
        if update.get("message"):
            self.handle_message(update["message"])
        elif update.get("callback_query"):
            self.handle_callback(update["callback_query"])

    def handle_message(self, message: dict) -> None:
        chat_id = (message.get("chat") or {}).get("id")
        if chat_id is None:
            return
        if not self.deps.authorize(chat_id):
            self.deps.transport.send_text(
                chat_id, "This bot is restricted to authorized chat IDs."
            )
            return

        text = (message.get("text") or "").strip()
        if not text.startswith("/"):
            self._send(chat_id, screens.help_screen())
            return

        token = text.split()[0]
        command = token.split("@")[0].lower()
        argument = text[len(token) :].strip()
        self.deps.log(
            f"message chat={api_module.mask_chat(chat_id)} command={command}"
        )

        if command == "/start":
            sender = message.get("from") or {}
            self._send(
                chat_id,
                screens.welcome(
                    sender.get("first_name"),
                    sender.get("username"),
                    self._owner_allowed(chat_id),
                ),
            )
        elif command == "/menu":
            self._send_async(
                chat_id,
                "Loading command center…",
                lambda: screens.home(self.deps.client, self._owner_allowed(chat_id)),
            )
        elif command == "/help":
            self._send(chat_id, screens.help_screen())
        elif command == "/status":
            self._send_async(
                chat_id,
                "Loading the last run…",
                lambda: screens.status(self.deps.client),
            )
        elif command == "/report":
            self._send_pdf(chat_id)
        elif command == "/quick":
            gate_id = argument.strip().lower() or config.DEFAULT_GATE_ID
            if gate_id in config.GATE_BY_ID:
                self._nav_async(chat_id, None, None, lambda: screens.quick_audit(gate_id))
            else:
                self._send(chat_id, screens.error("unknown gate", "Use /quick core, /quick sample or /quick pipeline."))
        elif command == "/review":
            self._command_review(chat_id, argument or "app.py")
        elif command == "/pipeline":
            self._send(chat_id, screens.pipeline_menu())
        elif command == "/gates":
            self._send_async(
                chat_id,
                "Probing local gates…",
                lambda: screens.gates(self.deps.client),
            )
        elif command == "/tools":
            self._send_async(
                chat_id,
                "Checking the 11-tool fleet…",
                lambda: screens.tools(self.deps.client, 0),
            )
        elif command == "/profile":
            self._send_async(
                chat_id,
                "Loading profile…",
                lambda: self._profile_screen(chat_id, message.get("from") or {}),
            )
        elif command == "/owner":
            self._owner_command(chat_id)
        elif command == "/scan":
            self._command_scan(chat_id, argument)
        elif command == "/stop":
            self._command_stop(chat_id)
        else:
            self._send(
                chat_id,
                screens.error(
                    "unknown command",
                    f"/{command} is not a command.",
                    "Use /help for the command list.",
                ),
            )

    def handle_callback(self, query: dict) -> None:
        query_id = query.get("id") or ""
        message = query.get("message") or {}
        chat_id = (message.get("chat") or {}).get("id")
        if chat_id is None:
            self.deps.transport.answer(query_id)
            return
        if not self.deps.authorize(chat_id):
            self.deps.transport.answer(query_id, "Not authorized.", True)
            return
        callback = callbacks.parse(query.get("data"))
        if callback is None:
            self.deps.transport.answer(query_id, "This button is out of date.", True)
            return
        self.deps.log(
            f"callback chat={api_module.mask_chat(chat_id)} action={callback.action}"
        )
        if not state.debounce(chat_id, callback.data):
            # Telegram can deliver the same tap twice; acknowledge silently.
            self.deps.transport.answer(query_id)
            return
        self.deps.transport.answer(query_id)
        self._dispatch(chat_id, callback, message.get("message_id"), query.get("from") or {})

    # -- command helpers ---------------------------------------------------
    def _command_review(self, chat_id, filename: str) -> None:
        if filename not in code_review.DEMO_FILES:
            self._send(chat_id, screens.error("code review", "Choose /review app.py or /review app2.py."))
            return
        if not self._review_lock.acquire(blocking=False):
            self._send(chat_id, screens.error("review in progress", "Try again after the current review finishes."))
            return

        def worker() -> None:
            try:
                self._send(chat_id, screens.loading("code review", f"Qwen is reading {filename}…"))
                source = code_review.LAB / filename
                if source.resolve() != source:
                    raise ValueError("The demo file is not at its expected path.")
                patch = code_review.propose_diff(source)
                if not patch:
                    self.deps.transport.send_text(chat_id, f"Qwen proposed no changes to {filename}.")
                    return
                reports = code_review.PROJECT / "reports"
                reports.mkdir(exist_ok=True)
                with tempfile.TemporaryDirectory(prefix="review-", dir=reports) as tmp:
                    document = Path(tmp) / (filename + ".diff")
                    document.write_bytes(patch.encode("utf-8"))
                    response = self.deps.transport.send_document(
                        chat_id, str(document), f"Qwen · {filename} · proposed change for review"
                    )
                if response is None:
                    self._send(chat_id, screens.error("diff delivery failed", "Telegram could not deliver the document."))
            except Exception as exc:
                self.deps.log(f"code review failed: {type(exc).__name__}")
                reason = ("The local Ollama connection failed." if isinstance(exc, OSError)
                          else "Qwen could not produce a valid patch for this file.")
                self._send(chat_id, screens.error("code review failed", reason))
            finally:
                self._review_lock.release()

        threading.Thread(target=worker, daemon=True).start()

    def _command_scan(self, chat_id, argument: str) -> None:
        remaining = state.cooldown_remaining(chat_id)
        if remaining > 0:
            self._send(
                chat_id,
                screens.error(
                    "scan cooldown",
                    f"Please wait {remaining}s before the next scan.",
                    f"One scan per {config.RATE_LIMIT_SECONDS}s per chat.",
                    parent="gates",
                ),
            )
            return
        target, task = self.deps.parse_scan(argument)
        self._start_scan(chat_id, target, task)

    def _command_stop(self, chat_id) -> None:
        if state.is_pipeline(chat_id):
            self._pipeline_cancel(chat_id)
            return
        if not state.is_running(chat_id) and not self._foreign_cancel_allowed(chat_id):
            self._send(chat_id, screens.nothing_to_stop())
            return
        try:
            response = self._cancel_backend()
        except Exception as exc:
            self._send(
                chat_id,
                screens.error("stop failed", api_module.describe_error(exc)),
            )
            return
        if response.get("cancelled"):
            self.deps.log(
                f"stop accepted chat={api_module.mask_chat(chat_id)}"
            )
            state.request_cancel(chat_id)
            screen = screens.stop_confirmed()
            message_id = state.scan_message_id(chat_id)
            if message_id:
                self.deps.transport.edit(
                    chat_id, message_id, screen.text, screen.keyboard
                )
            else:
                self._send(chat_id, screen)
        else:
            self.deps.log(
                f"stop ignored chat={api_module.mask_chat(chat_id)}"
            )
            self._send(chat_id, screens.nothing_to_stop())

    def _send_pdf(self, chat_id) -> None:
        try:
            payload = self.deps.client.reports() or {}
        except Exception as exc:
            self._send(
                chat_id,
                screens.error(
                    "report unavailable",
                    api_module.describe_error(exc),
                    "The backend may still be starting. Try again shortly.",
                    parent="status",
                ),
            )
            return

        reports = payload.get("reports") or []
        summary = payload.get("summary") or {}
        filename = str(summary.get("latest_filename") or "")
        if not filename and reports:
            filename = str((reports[0] or {}).get("filename") or "")
        if not _REPORT_NAME_RE.match(filename) or Path(filename).name != filename:
            self._send(
                chat_id,
                screens.error(
                    "no PDF report yet",
                    "No completed local PDF report was found.",
                    "Run a scan first, then try /report again.",
                    parent="status",
                ),
            )
            return

        path = Path(__file__).resolve().parents[2] / "reports" / filename
        if not path.is_file():
            self._send(
                chat_id,
                screens.error(
                    "report missing",
                    "The backend listed this report, but the file is not present.",
                    "Refresh the report list or run a new scan.",
                    parent="status",
                ),
            )
            return

        selected = next((item for item in reports if item.get("filename") == filename), {})
        scan = selected.get("scan") or {}
        caption = (
            f"AEGIS AI PDF · {filename}\n"
            f"{scan.get('mode', 'report')} · {scan.get('finding_count', 0)} findings · "
            f"{scan.get('target', 'local lab')}"
        )[:1024]
        response = self.deps.transport.send_document(chat_id, str(path), caption)
        if response is None:
            self._send(
                chat_id,
                screens.error(
                    "PDF send failed",
                    "Telegram did not accept the document.",
                    "Try again in a moment; the report is still on disk.",
                    parent="status",
                ),
            )
            return
        self.deps.log(
            f"pdf sent chat={api_module.mask_chat(chat_id)} file={filename}"
        )

    def _owner_command(self, chat_id) -> None:
        if not self._owner_allowed(chat_id):
            self._send(
                chat_id,
                screens.error(
                    "owner console restricted",
                    "This chat is not in TELEGRAM_OWNER_CHAT_IDS.",
                    "The normal menu remains available.",
                ),
            )
            return
        self._send_async(
            chat_id,
            "Loading deployment status…",
            self._owner_screen,
        )

    # -- scan flow ---------------------------------------------------------
    def _start_scan(
        self,
        chat_id,
        target: str,
        task: str,
        message_id: int | None = None,
        gate_id: str | None = None,
    ) -> None:
        label = target or "default local lab"
        if not state.begin_scan(chat_id, label):
            if state.is_running(chat_id):
                title = "scan already running"
                detail = "This chat already has an active scan."
                hint = "Use /stop to cancel it first."
            elif state.any_running():
                title = "scan busy"
                detail = (
                    "Another chat is running the agent. The backend allows one "
                    "real run at a time."
                )
                hint = "Wait for it to finish; /stop only cancels your own run."
            else:
                title = "scan unavailable"
                detail = "The scan slot could not be claimed."
                hint = "Try again in a moment."
            self._send(
                chat_id,
                screens.error(title, detail, hint, parent="gates"),
            )
            return
        self.deps.log(
            f"scan start chat={api_module.mask_chat(chat_id)} "
            f"target={api_module.mask_target(label)}"
        )
        screen = screens.scan_running(label)
        if message_id:
            response = self.deps.transport.edit(
                chat_id, message_id, screen.text, screen.keyboard
            )
        else:
            response = self.deps.transport.send(chat_id, screen.text, screen.keyboard)
        active_message = self._message_id(response) or message_id
        state.set_scan_message_id(chat_id, active_message)
        threading.Thread(
            target=self._run_scan,
            args=(chat_id, target, task, gate_id, active_message),
            daemon=True,
        ).start()

    def _run_scan(
        self,
        chat_id,
        target: str,
        task: str,
        gate_id: str | None,
        message_id: int | None,
    ) -> None:
        try:
            result = self.deps.client.agent_run(task, target or None)
            if not isinstance(result, dict) or not result:
                raise EOFError("Empty agent response")
        except Exception as exc:
            stopped = state.cancel_requested(chat_id)
            state.end_scan(chat_id, refund=True)
            self.deps.log(
                f"scan failed chat={api_module.mask_chat(chat_id)} "
                f"error={type(exc).__name__}"
            )
            screen = screens.run_error("scan failed", exc, stopped, "gates")
            self._edit_scan_message(chat_id, message_id, screen)
            return
        state.end_scan(chat_id)
        self.deps.log(
            f"scan finish chat={api_module.mask_chat(chat_id)} "
            f"cancelled={bool(result.get('cancelled'))}"
        )
        resolved_gate = api_module.gate_for_target(result.get("target") or target)
        final_gate = gate_id or (resolved_gate or {}).get("id")
        self._edit_scan_message(chat_id, message_id, screens.scan_result(result, final_gate))

    # -- DAST -> Audit -> Agent pipeline ------------------------------------
    def _start_pipeline(
        self,
        chat_id,
        target: str,
        gate_id: str | None,
        stages: tuple[str, ...],
        message_id: int | None = None,
    ) -> None:
        stages = tuple(stage for stage in stages if stage in _PIPELINE_STAGES)
        if not stages:
            self._send(chat_id, screens.error("pipeline unavailable", "No valid stage was selected.", parent="pipeline"))
            return
        if not state.begin_pipeline(chat_id, target, stages, message_id):
            if state.is_running(chat_id):
                title = "pipeline already running"
                detail = "This chat already has an active run."
                hint = "Use /stop or Stop pipeline first."
            elif state.any_running():
                title = "pipeline busy"
                detail = "Another chat is running the one allowed local agent."
                hint = "Wait for it to finish; /stop only cancels your own run."
            else:
                title = "pipeline unavailable"
                detail = "The run slot could not be claimed."
                hint = "Try again in a moment."
            self._send(chat_id, screens.error(title, detail, hint, parent="pipeline"))
            return
        self.deps.log(
            f"pipeline start chat={api_module.mask_chat(chat_id)} "
            f"target={api_module.mask_target(target)} stages={','.join(stages)}"
        )
        screen = screens.pipeline_running(target, 0, len(stages), "queued", "starting", 0.0, "", stage_key=stages[0])
        if message_id:
            response = self.deps.transport.edit(chat_id, message_id, screen.text, screen.keyboard)
        else:
            response = self.deps.transport.send(chat_id, screen.text, screen.keyboard)
        active_message = self._message_id(response) or message_id
        state.set_scan_message_id(chat_id, active_message)
        threading.Thread(
            target=self._run_pipeline,
            args=(chat_id, target, gate_id, stages, active_message),
            daemon=True,
        ).start()

    def _run_pipeline(
        self,
        chat_id,
        target: str,
        gate_id: str | None,
        stages: tuple[str, ...],
        message_id: int | None,
    ) -> None:
        results: dict[str, dict] = {}
        stage_reports: dict[str, dict] = {}
        completed = 0
        try:
            for index, stage in enumerate(stages):
                if state.cancel_requested(chat_id):
                    raise _PipelineCancelled()
                state.set_pipeline_stage(chat_id, index, f"{stage} starting")
                state.set_pipeline_status(chat_id, "starting")
                self._pipeline_edit(chat_id, message_id, target, index, len(stages), "starting", "starting", "")

                if stage in {"dast", "audit"}:
                    started = self.deps.client.engine_start(stage, target) or {}
                    scan_id = str(started.get("scanId") or "")
                    if not scan_id:
                        raise RuntimeError("engine did not return a scanId")
                    state.set_pipeline_scan_id(chat_id, scan_id)
                    if state.cancel_requested(chat_id):
                        try:
                            self.deps.client.engine_cancel(scan_id)
                        except Exception:
                            pass
                        raise _PipelineCancelled()
                    progress: dict = {"label": "", "last_edit": 0.0}
                    on_event = (
                        lambda event, payload, index=index, scan_id=scan_id, progress=progress:
                        self._pipeline_event(
                            chat_id, message_id, target, index, len(stages),
                            scan_id, event, payload, progress,
                        )
                    )
                    stream = self.deps.client.engine_stream(scan_id, on_event) or {}
                    final_status = str(stream.get("status") or "").lower()
                    if state.cancel_requested(chat_id) or final_status == "cancelled":
                        raise _PipelineCancelled()
                    if stream.get("error") and final_status != "completed":
                        raise RuntimeError(str(stream["error"])[:300])
                    if final_status in {"failed", "error"}:
                        raise RuntimeError(f"engine scan {final_status}")
                    if final_status != "completed" and not stream.get("complete"):
                        raise EOFError("Stage stream ended without a final result")
                    snapshot = (progress.get("scan") or {}).get("result") or {}
                    result = stream.get("complete") or snapshot
                    stage_reports[stage] = {**snapshot, **result}
                    report = stage_reports[stage].get("audit") or stage_reports[stage]
                    if isinstance(report.get("severity_counts"), dict):
                        state.set_pipeline_audit_counts(chat_id, report["severity_counts"])
                else:
                    state.set_pipeline_status(chat_id, "agent tools")
                    result = self.deps.client.agent_run(self._agent_task(target, results), target) or {}
                    if not isinstance(result, dict) or not result:
                        raise EOFError("Empty agent response")
                    stage_reports[stage] = result

                if result.get("cancelled"):
                    raise _PipelineCancelled()
                results[stage] = result
                completed = index + 1

            final_stage = stages[completed - 1] if completed else stages[0]
            final_result = results.get(final_stage) or {}
            state.end_pipeline(chat_id, last=final_result)
            self.deps.log(
                f"pipeline finish chat={api_module.mask_chat(chat_id)} stage={final_stage} "
                f"cancelled=False"
            )
            self._edit_scan_message(
                chat_id,
                message_id,
                screens.pipeline_summary(stage_reports, target, gate_id) if completed > 1
                else screens.pipeline_result(final_stage, stage_reports[final_stage], target, gate_id),
            )
        except _PipelineCancelled:
            state.end_pipeline(chat_id)
            self.deps.log(f"pipeline cancelled chat={api_module.mask_chat(chat_id)}")
            self._edit_scan_message(
                chat_id,
                message_id,
                screens.cancelled(
                    "Pipeline stopped at a safe checkpoint. No partial findings were stored."
                ),
            )
        except Exception as exc:
            stopped = state.cancel_requested(chat_id)
            state.end_pipeline(chat_id)
            self.deps.log(
                f"pipeline failed chat={api_module.mask_chat(chat_id)} "
                f"error={type(exc).__name__}"
            )
            screen = screens.run_error("pipeline failed", exc, stopped, "pipeline")
            if completed:
                saved = {name: stage_reports[name] for name in results}
                summary = screens.pipeline_summary(saved, target, gate_id, complete=False)
                screen = screens.Screen(screen.text + "\n\n" + summary.text, screen.keyboard)
            self._edit_scan_message(chat_id, message_id, screen)

    def _pipeline_event(
        self,
        chat_id,
        message_id,
        target: str,
        index: int,
        total: int,
        scan_id: str,
        event: str,
        payload: dict,
        progress: dict,
    ) -> None:
        if state.cancel_requested(chat_id):
            return
        label = str(progress.get("label") or "")
        status = state.pipeline_status(chat_id) or "running"
        if event == "stage":
            label = f"{payload.get('label') or 'stage'} · {payload.get('state') or 'running'}"
            status = str(payload.get("state") or "running")
            state.set_pipeline_stage(chat_id, index, label)
        elif event == "status":
            status = str(payload.get("status") or "running")
        elif event == "log":
            message = str(payload.get("msg") or "")[:120]
            if message:
                label = message
        elif event == "complete":
            progress["complete"] = payload
            status, label = "completed", "complete"
        elif event == "error":
            progress["error"] = payload.get("msg")
            status, label = "error", "error"
        elif event == "scan":
            scan = payload.get("scan") or {}
            progress["scan"] = scan
            status = str(scan.get("status") or status)
        state.set_pipeline_status(chat_id, status)
        progress["label"] = label
        terminal = event in {"complete", "error"} or (
            event == "scan" and status in {"completed", "cancelled", "failed"}
        )
        now = time.monotonic()
        if terminal or now - float(progress.get("last_edit", 0.0)) > 2.0:
            progress["last_edit"] = now
            self._pipeline_edit(
                chat_id, message_id, target, index, total, label, status, scan_id
            )

    def _pipeline_edit(
        self,
        chat_id,
        message_id,
        target: str,
        index: int,
        total: int,
        label: str,
        status: str,
        scan_id: str,
    ) -> None:
        _, _, stages, _ = state.pipeline_stage(chat_id)
        screen = screens.pipeline_running(
            target,
            index,
            total,
            label,
            status,
            state.scan_elapsed(chat_id),
            scan_id,
            stage_key=stages[index] if index < len(stages) else None,
            audit_counts=state.pipeline_audit_counts(chat_id),
        )
        self._edit_scan_message(chat_id, message_id, screen)

    def _agent_task(self, target: str, results: dict[str, dict]) -> str:
        parts = [f"Target {target}."]
        audit = results.get("audit") or {}
        score = audit.get("score")
        if score is not None:
            parts.append(f"Prior audit score: {score}.")
        findings = audit.get("findings") or []
        if findings:
            titles = [str(item.get("title") or "finding")[:80] for item in findings[:3]]
            parts.append("Prior findings: " + ", ".join(titles) + ".")
        if results.get("dast"):
            parts.append("DAST already completed with real local tools.")
        parts.append("Use at least two different real tools and report evidence-backed risks.")
        return " ".join(parts)[: config.MAX_TASK_CHARS]

    def _pipeline_cancel(self, chat_id, message_id: int | None = None) -> None:
        if not state.is_pipeline(chat_id):
            if message_id:
                self._nav_now(chat_id, message_id, screens.nothing_to_stop())
            else:
                self._send(chat_id, screens.nothing_to_stop())
            return
        state.request_cancel(chat_id)
        scan_id = state.pipeline_scan_id(chat_id)
        detail = ""
        if scan_id:
            for attempt in range(3):
                try:
                    response = self.deps.client.engine_cancel(scan_id) or {}
                    if response.get("status") in {"cancelling", "cancelled"} or response.get("cancelled"):
                        break
                    detail = str(response.get("detail") or "scan is not running")
                except Exception as exc:
                    detail = api_module.describe_error(exc)
                if attempt < 2:
                    time.sleep(0.2)
        self.deps.log(
            f"pipeline stop requested chat={api_module.mask_chat(chat_id)} "
            f"scan={scan_id[-12:] if scan_id else 'not-started'}"
        )
        screen = screens.stop_confirmed()
        if message_id:
            self._nav_now(chat_id, message_id, screen)
        else:
            self._send(chat_id, screen)

    def _pipeline_refresh(self, chat_id, message_id) -> None:
        if not state.is_pipeline(chat_id):
            self._nav_now(chat_id, message_id, screens.pipeline_menu())
            return
        index, total, stages, label = state.pipeline_stage(chat_id)
        screen = screens.pipeline_running(
            state.scan_target(chat_id),
            index,
            total,
            label,
            state.pipeline_status(chat_id),
            state.scan_elapsed(chat_id),
            state.pipeline_scan_id(chat_id),
            stage_key=stages[index] if index < len(stages) else None,
            audit_counts=state.pipeline_audit_counts(chat_id),
        )
        self._nav_now(chat_id, message_id, screen)

    def _edit_scan_message(self, chat_id, message_id: int | None, screen: screens.Screen) -> None:
        if message_id:
            response = self.deps.transport.edit(
                chat_id, message_id, screen.text, screen.keyboard
            )
            if response is not None:
                return
        self.deps.transport.send(chat_id, screen.text, screen.keyboard)

    # -- callback dispatch -------------------------------------------------
    def _dispatch(
        self,
        chat_id,
        callback: callbacks.Callback,
        message_id,
        sender: dict | None = None,
    ) -> None:
        action = callback.action
        if action == "home":
            self._nav_async(
                chat_id,
                message_id,
                "Loading command center…",
                lambda: screens.home(self.deps.client, self._owner_allowed(chat_id)),
            )
        elif action == "quick":
            self._nav_async(chat_id, message_id, None, lambda: screens.quick_audit(callback.gate_id))
        elif action == "gates":
            self._nav_async(
                chat_id, message_id, "Probing local gates…", lambda: screens.gates(self.deps.client)
            )
        elif action == "gate":
            self._nav_async(
                chat_id,
                message_id,
                "Checking the gate…",
                lambda: screens.gate_detail(self.deps.client, callback.gate_id),
            )
        elif action == "gscan":
            self._nav_now(chat_id, message_id, screens.scan_confirm(callback.gate_id))
        elif action == "scan":
            self._nav_now(chat_id, message_id, screens.scan_confirm(callback.gate_id))
        elif action == "tools":
            self._nav_async(
                chat_id,
                message_id,
                "Checking the 11-tool fleet…",
                lambda: screens.tools(self.deps.client, callback.page),
            )
        elif action == "trefresh":
            self._nav_async(
                chat_id,
                message_id,
                "Re-checking the 11-tool fleet…",
                lambda: screens.tools(self.deps.client, callback.page, force=True),
            )
        elif action == "tool":
            self._nav_async(
                chat_id,
                message_id,
                "Loading tool detail…",
                lambda: screens.tool_detail(self.deps.client, callback.tool_name, callback.page),
            )
        elif action == "tcheck":
            self._nav_async(
                chat_id,
                message_id,
                "Running the real availability probe…",
                lambda: self._check_tool(callback.tool_name, callback.page),
            )
        elif action == "profile":
            self._nav_async(
                chat_id,
                message_id,
                "Loading profile…",
                lambda: self._profile_screen(chat_id, sender),
            )
        elif action == "owner":
            self._owner_callback(chat_id, message_id)
        elif action == "help":
            self._nav_now(chat_id, message_id, screens.help_screen())
        elif action == "status":
            self._nav_async(
                chat_id, message_id, "Loading the last run…", lambda: screens.status(self.deps.client)
            )
        elif action == "pdf":
            self._send_pdf(chat_id)
        elif action == "pipeline":
            self._nav_now(chat_id, message_id, screens.pipeline_menu())
        elif action in {"pdast", "paudit", "pagent"}:
            gate = config.GATE_BY_ID.get(callback.gate_id)
            if gate is None:
                self._nav_now(
                    chat_id,
                    message_id,
                    screens.error("unknown gate", "That gate is not authorized.", parent="pipeline"),
                )
                return
            stage = {"pdast": "dast", "paudit": "audit", "pagent": "agent"}[action]
            if not self._gate_is_configured(chat_id, message_id, gate, "pipeline"):
                return
            self._start_pipeline(chat_id, gate["url"], gate["id"], (stage,), message_id)
        elif action == "pfull":
            gate = config.GATE_BY_ID.get(callback.gate_id)
            if gate is None:
                self._nav_now(
                    chat_id,
                    message_id,
                    screens.error("unknown gate", "That gate is not authorized.", parent="pipeline"),
                )
                return
            if not self._gate_is_configured(chat_id, message_id, gate, "pipeline"):
                return
            self._start_pipeline(
                chat_id,
                gate["url"],
                gate["id"],
                ("dast", "audit", "agent"),
                message_id,
            )
        elif action == "px":
            self._pipeline_cancel(chat_id, message_id)
        elif action == "pr":
            self._pipeline_refresh(chat_id, message_id)
        elif action == "sgo":
            gate = config.GATE_BY_ID.get(callback.gate_id)
            if gate is None:
                self._nav_now(
                    chat_id,
                    message_id,
                    screens.error("unknown gate", "That gate is not authorized.", parent="gates"),
                )
                return
            if not self._gate_is_configured(chat_id, message_id, gate, "gates"):
                return
            self._start_scan(
                chat_id,
                gate["url"],
                "Audit the authorized local application and report the top risks.",
                message_id=message_id,
                gate_id=gate["id"],
            )
        elif action == "sx":
            self._callback_stop(chat_id, message_id)
        elif action == "sr":
            self._refresh_running(chat_id, message_id)
        elif action == "noop":
            return

    def _owner_callback(self, chat_id, message_id) -> None:
        if not self._owner_allowed(chat_id):
            self._nav_now(
                chat_id,
                message_id,
                screens.error(
                    "owner console restricted",
                    "This chat is not in TELEGRAM_OWNER_CHAT_IDS.",
                    "The normal menu remains available.",
                ),
            )
            return
        self._nav_async(
            chat_id, message_id, "Loading deployment status…", self._owner_screen
        )

    def _callback_stop(self, chat_id, message_id) -> None:
        if state.is_pipeline(chat_id):
            self._pipeline_cancel(chat_id, message_id)
            return
        if not state.is_running(chat_id) and not self._foreign_cancel_allowed(chat_id):
            self._nav_now(chat_id, message_id, screens.nothing_to_stop())
            return
        try:
            response = self._cancel_backend()
        except Exception as exc:
            self._nav_now(
                chat_id,
                message_id,
                screens.error("stop failed", api_module.describe_error(exc)),
            )
            return
        if response.get("cancelled"):
            self.deps.log(
                f"stop accepted chat={api_module.mask_chat(chat_id)} via=button"
            )
            state.request_cancel(chat_id)
            self._nav_now(chat_id, message_id, screens.stop_confirmed())
        else:
            self.deps.log(
                f"stop ignored chat={api_module.mask_chat(chat_id)} via=button"
            )
            self._nav_now(chat_id, message_id, screens.nothing_to_stop())

    def _refresh_running(self, chat_id, message_id) -> None:
        if state.is_running(chat_id):
            screen = screens.scan_running(
                state.scan_target(chat_id), state.scan_elapsed(chat_id)
            )
            self._nav_now(chat_id, message_id, screen)
            return
        self._nav_async(
            chat_id, message_id, "Loading the last run…", lambda: screens.status(self.deps.client)
        )

    # -- producers ---------------------------------------------------------
    def _check_tool(self, name: str, page: int) -> screens.Screen:
        fresh = self.deps.client.tool_check(name)
        state.update_cached_tool(name, fresh)
        return screens.tool_detail(self.deps.client, name, page)

    def _cancel_backend(self, attempts: int = 3) -> dict:
        """Retries briefly so a /stop sent right after /scan still lands."""
        response: dict = {}
        for index in range(max(1, attempts)):
            response = self.deps.client.agent_cancel() or {}
            if response.get("cancelled"):
                return response
            if index < attempts - 1:
                time.sleep(0.3)
        return response

    def _profile_screen(self, chat_id, sender: dict | None) -> screens.Screen:
        if not sender:
            sender = {"id": chat_id}
        chat = {
            "id": chat_id,
            "first_name": sender.get("first_name"),
            "username": sender.get("username"),
        }
        return screens.profile(
            self.deps.client,
            chat,
            self._owner_allowed(chat_id),
            self._access_label(chat_id),
        )

    def _owner_screen(self) -> screens.Screen:
        return screens.owner(
            self.deps.client,
            self.deps.api_base,
            self.deps.access_mode,
            bool(config.OWNER_IDS),
        )

    # -- navigation primitives --------------------------------------------
    def _nav_now(self, chat_id, message_id, screen: screens.Screen) -> None:
        state.bump_screen(chat_id)
        if message_id:
            response = self.deps.transport.edit(
                chat_id, message_id, screen.text, screen.keyboard
            )
            if response is not None:
                return
        self.deps.transport.send(chat_id, screen.text, screen.keyboard)

    def _nav_async(self, chat_id, message_id, loading_text: str | None, producer) -> None:
        token = state.bump_screen(chat_id)
        active_message = message_id
        if loading_text:
            loading = screens.loading("working", loading_text)
            if message_id:
                response = self.deps.transport.edit(chat_id, message_id, loading.text, None)
            else:
                response = self.deps.transport.send(chat_id, loading.text, None)
            active_message = self._message_id(response) or message_id

        def worker() -> None:
            try:
                screen = producer()
            except Exception as exc:
                self.deps.log(
                    f"screen worker failed: {type(exc).__name__}"
                )
                screen = screens.error(
                    "request failed",
                    api_module.describe_error(exc),
                    "Try Refresh or return Home.",
                )
            if not state.is_current_screen(chat_id, token):
                return
            if active_message:
                edited = self.deps.transport.edit(
                    chat_id, active_message, screen.text, screen.keyboard
                )
                if edited is not None:
                    return
            self.deps.transport.send(chat_id, screen.text, screen.keyboard)

        threading.Thread(target=worker, daemon=True).start()

    def _send_async(self, chat_id, loading_text: str, producer) -> None:
        response = self.deps.transport.send(
            chat_id, screens.loading("working", loading_text).text, None
        )
        message_id = self._message_id(response)
        token = state.bump_screen(chat_id)

        def worker() -> None:
            try:
                screen = producer()
            except Exception as exc:
                self.deps.log(f"screen worker failed: {type(exc).__name__}")
                screen = screens.error(
                    "request failed",
                    api_module.describe_error(exc),
                    "Try /menu or /help.",
                )
            if not state.is_current_screen(chat_id, token):
                return
            if message_id:
                edited = self.deps.transport.edit(
                    chat_id, message_id, screen.text, screen.keyboard
                )
                if edited is not None:
                    return
            self.deps.transport.send(chat_id, screen.text, screen.keyboard)

        threading.Thread(target=worker, daemon=True).start()

    # -- small helpers -----------------------------------------------------
    def _send(self, chat_id, screen: screens.Screen) -> None:
        self.deps.transport.send(chat_id, screen.text, screen.keyboard)

    def _owner_allowed(self, chat_id) -> bool:
        if config.OWNER_IDS:
            return bool(self.deps.is_owner(chat_id))
        return bool(self.deps.authorize(chat_id))

    def _foreign_cancel_allowed(self, chat_id) -> bool:
        """Only a configured owner may cancel a run this chat did not start."""
        return bool(config.OWNER_IDS) and bool(self.deps.is_owner(chat_id))

    def _access_label(self, chat_id) -> str:
        if self.deps.is_owner(chat_id):
            return "owner"
        return "authorized" if self.deps.access_mode == "restricted" else "public"

    @staticmethod
    def _message_id(response) -> int | None:
        if not isinstance(response, dict):
            return None
        result = response.get("result")
        if isinstance(result, dict):
            value = result.get("message_id")
            if isinstance(value, int):
                return value
        return None
