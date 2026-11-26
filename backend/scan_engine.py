"""AegisAI V2 scanning engine.

This module keeps the exact V1 SSE contract (``stage`` / ``log`` / ``error`` /
``complete``) while adding the Phase 2 execution guarantees:

* explicit stage states (pending / running / completed / failed / skipped)
* per-stage timing and separated logs
* cooperative cancellation of WSL subprocesses
* retry from a failed stage
* persistent scan history
* background scans with a live SSE replay stream
"""

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator

from backend import history
from backend.attack_graph import build_attack_graph
from backend.attack_surface import build_attack_surface
from backend.correlation import correlate
from backend.local_http import fetch_target_snapshot
from backend.vuln_analyst import analyze as analyze_vulnerabilities
from backend.auditor import (
    analyze_source_file,
    gemini_guardrail_check,
    resolve_source_for_target,
    validate_local_scope,
)
from backend.guardrail import gemini_output_review, sanitize_tool_output
from backend.pdf_report import generate_pdf_report
from backend.wsl_scanner import (
    DastError,
    ScanCancelled,
    bind_cancel_event,
    clear_cancel_event,
    dast_tool_status,
    run_dnsrecon,
    run_ffuf,
    run_gofile,
    run_nmap,
    run_nuclei,
    run_sqlmap,
    run_zap,
    validate_dast_target,
)

REPORTS_DIR = history.REPORTS_DIR

STAGE_KEYS = {
    1: "tools",
    2: "dnsrecon",
    3: "nmap",
    4: "ffuf",
    5: "gofile",
    6: "sqlmap",
    7: "zap",
    8: "nuclei",
    9: "guardrail",
}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _scan_id() -> str:
    return f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"


@dataclass
class StageState:
    step: int
    label: str
    state: str = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int | None = None
    logs: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "label": self.label,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "logs": self.logs[-40:],
            "error": self.error,
        }


@dataclass
class ScanRecord:
    id: str
    mode: str
    target: str
    total_stages: int
    status: str = "queued"
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    finished_at: str | None = None
    stages: dict[int, StageState] = field(default_factory=dict)
    result: dict | None = None
    pdf_filename: str | None = None
    score: int | None = None
    error: str | None = None
    resume_from: int | None = None
    retried_from: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mode": self.mode,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": _duration_between(self.started_at, self.finished_at),
            "total_stages": self.total_stages,
            "stages": [self.stages[k].to_dict() for k in sorted(self.stages)],
            "result": self.result,
            "pdf_filename": self.pdf_filename,
            "score": self.score,
            "error": self.error,
            "resume_from": self.resume_from,
            "retried_from": self.retried_from,
        }


def _duration_between(start: str | None, end: str | None) -> int | None:
    if not start or not end:
        return None
    try:
        return int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() * 1000)
    except ValueError:
        return None


class ScanManager:
    """In-memory registry plus JSON history and SSE fan-out."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scans: dict[str, ScanRecord] = {}
        self._queues: dict[str, list[asyncio.Queue]] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def create(
        self,
        mode: str,
        target: str,
        total_stages: int,
        resume_from: int | None = None,
        retried_from: str | None = None,
    ) -> ScanRecord:
        record = ScanRecord(
            id=_scan_id(),
            mode=mode,
            target=target,
            total_stages=total_stages,
            resume_from=resume_from,
            retried_from=retried_from,
        )
        record.status = "queued"
        with self._lock:
            self._scans[record.id] = record
            self._queues[record.id] = []
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            return self._scans.get(scan_id)

    def list(self, limit: int = 100) -> list[dict]:
        with self._lock:
            records = sorted(self._scans.values(), key=lambda r: r.created_at, reverse=True)[:limit]
            return [r.to_dict() for r in records]

    def cancel(self, scan_id: str) -> bool:
        record = self.get(scan_id)
        if not record or record.status in {"completed", "failed", "cancelled"}:
            return False
        record.cancel_event.set()
        record.status = "cancelling"
        self.publish(scan_id, "status", {"scanId": scan_id, "status": "cancelling"})
        return True

    def mark_running(self, record: ScanRecord) -> None:
        record.status = "running"
        record.started_at = record.started_at or _now()
        self.publish(record.id, "status", {"scanId": record.id, "status": "running"})

    def finish(
        self,
        record: ScanRecord,
        status: str,
        error: str | None = None,
        result: dict | None = None,
        pdf_filename: str | None = None,
        score: int | None = None,
    ) -> None:
        record.status = status
        record.finished_at = _now()
        record.error = error
        if result is not None:
            record.result = result
        if pdf_filename is not None:
            record.pdf_filename = pdf_filename
        if score is not None:
            record.score = score
        self.publish(record.id, "status", {"scanId": record.id, "status": status})
        history.append_scan(record.to_dict())
        self._close_stream(record.id)

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        with self._lock:
            self._queues.setdefault(scan_id, []).append(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        with self._lock:
            queues = self._queues.get(scan_id, [])
            if queue in queues:
                queues.remove(queue)

    def publish(self, scan_id: str, event: str, payload: dict) -> None:
        with self._lock:
            queues = list(self._queues.get(scan_id, []))
        for queue in queues:
            try:
                queue.put_nowait((event, payload))
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                queue.put_nowait((event, payload))

    def _close_stream(self, scan_id: str) -> None:
        with self._lock:
            queues = list(self._queues.get(scan_id, []))
        for queue in queues:
            queue.put_nowait(("__done__", {}))

    def track_task(self, scan_id: str, task: asyncio.Task) -> None:
        with self._lock:
            self._tasks[scan_id] = task

    def discard_task(self, scan_id: str) -> None:
        with self._lock:
            self._tasks.pop(scan_id, None)


manager = ScanManager()


class EventBuilder:
    """Builds V1-compatible SSE tuples while recording stage state."""

    def __init__(self, record: ScanRecord) -> None:
        self.record = record
        self.current_step = 0
        self._started: dict[int, float] = {}

    def stage_start(self, step: int, label: str) -> tuple[str, dict]:
        self.current_step = step
        stage = self.record.stages.get(step) or StageState(step=step, label=label)
        stage.state = "running"
        stage.started_at = _now()
        stage.error = None
        self.record.stages[step] = stage
        self._started[step] = time.perf_counter()
        manager.mark_running(self.record)
        return "stage", {
            "step": step,
            "label": label,
            "state": "running",
            "scanId": self.record.id,
            "mode": self.record.mode,
        }

    def stage_end(
        self,
        step: int,
        label: str,
        state: str = "completed",
        error: str | None = None,
        reason: str | None = None,
    ) -> tuple[str, dict]:
        stage = self.record.stages.get(step) or StageState(step=step, label=label)
        stage.state = state
        stage.finished_at = _now()
        stage.error = error
        started = self._started.pop(step, None)
        stage.duration_ms = int((time.perf_counter() - started) * 1000) if started else 0
        if reason:
            stage.logs.append(f"[SKIP] {reason}")
        self.record.stages[step] = stage
        payload = {
            "step": step,
            "label": label,
            "state": state,
            "scanId": self.record.id,
            "durationMs": stage.duration_ms,
        }
        if error:
            payload["error"] = error
        if reason:
            payload["reason"] = reason
        return "stage", payload

    def log(self, msg: str, level: str = "normal") -> tuple[str, dict]:
        stage = self.record.stages.get(self.current_step)
        if stage:
            stage.logs.append(msg)
        return "log", {
            "msg": msg,
            "scanId": self.record.id,
            "stage": self.current_step,
            "level": level,
        }

    def error(self, msg: str) -> tuple[str, dict]:
        self.record.error = msg
        return "error", {"msg": msg, "scanId": self.record.id, "stage": self.current_step}


async def checkpoint(record: ScanRecord) -> None:
    """Cooperative cancellation point between long-running tool calls."""
    if record.cancel_event.is_set():
        raise ScanCancelled("The user cancelled the scan.")
    await asyncio.sleep(0)


async def _run_stage(record: ScanRecord, func, *args):
    await checkpoint(record)
    return await asyncio.to_thread(func, *args)


async def _audit_impl(
    target: str,
    record: ScanRecord,
    beacon: Any | None = None,
) -> AsyncIterator[tuple[str, dict]]:
    ev = EventBuilder(record)

    yield ev.stage_start(1, "Scope & Guardrail Check")
    yield ev.log(f"[INIT] Validating target: {target}")
    if beacon:
        yield ev.log(f"[HW] {beacon.send_state('SCANNING')}")
    guard_ok, guard_msg = await _run_stage(record, gemini_guardrail_check, target)
    yield ev.log(f"[GUARDRAIL] {guard_msg}")
    if not guard_ok:
        yield ev.stage_end(1, "Scope & Guardrail Check", "failed", guard_msg)
        yield ev.error(guard_msg)
        manager.finish(record, "failed", guard_msg)
        return

    scope_ok, scope_msg, resolved_file = validate_local_scope(target)
    yield ev.log(f"[SCOPE] {scope_msg}")
    if not scope_ok:
        yield ev.stage_end(1, "Scope & Guardrail Check", "failed", scope_msg)
        yield ev.error(scope_msg)
        manager.finish(record, "failed", scope_msg)
        return
    yield ev.stage_end(1, "Scope & Guardrail Check")

    yield ev.stage_start(2, "Endpoint & JS Discovery")
    yield ev.log(f"[DISCOVERY] Parsing routes & configurations in {resolved_file.name}...")
    audit_result = await _run_stage(record, analyze_source_file, resolved_file)
    for endpoint in audit_result["endpoints"]:
        yield ev.log(f"[ROUTE FOUND] {endpoint['path']} (line {endpoint['line']})")
        await checkpoint(record)
    if target.startswith(("http://", "https://")):
        try:
            snapshot = await _run_stage(record, fetch_target_snapshot, target)
            audit_result["target_snapshot"] = snapshot
            yield ev.log(
                f"[SURFACE] HTTP {snapshot.get('status_code')} · "
                f"{len(snapshot.get('endpoints', []))} HTML endpoint(s) · "
                f"{len(snapshot.get('technologies', []))} technology marker(s)"
            )
        except Exception as exc:
            audit_result["target_snapshot"] = {"error": str(exc)}
            yield ev.log(f"[SURFACE] Snapshot unavailable: {exc}", "error")
    yield ev.stage_end(2, "Endpoint & JS Discovery")

    yield ev.stage_start(3, "Static & Config Audit")
    yield ev.log("[AUDIT] Running OWASP Top 10 static pattern checks...")
    await checkpoint(record)
    for finding in audit_result["findings"]:
        yield ev.log(f"[{finding['severity']}] {finding['title']} @ {finding['endpoint']}")
        await checkpoint(record)
    yield ev.stage_end(3, "Static & Config Audit")

    yield ev.stage_start(4, "AI Remediation Synthesis")
    yield ev.log("[REMEDIATION] Correlating evidence and preparing secure remediation context...")
    await checkpoint(record)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in audit_result["findings"]:
        severity = str(finding.get("severity", "LOW")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    audit_result["severity_counts"] = counts
    audit_result["correlations"] = correlate(audit_result)
    corr_summary = audit_result["correlations"]["summary"]
    yield ev.log(
        f"[CORRELATION] {corr_summary['total']} group(s): "
        f"{corr_summary['confirmed']} confirmed, {corr_summary['potential']} potential, "
        f"{corr_summary['informational']} informational (mode={corr_summary['ai_mode']})"
    )
    audit_result["attack_surface"] = build_attack_surface(audit_result)
    audit_result["attack_graph"] = build_attack_graph(audit_result)
    yield ev.log(
        f"[SURFACE] {len(audit_result['attack_surface']['nodes'])} asset node(s), "
        f"{len(audit_result['attack_surface']['edges'])} relation(s)"
    )
    yield ev.log(f"[REMEDIATION] Evidence summary: {counts}")
    audit_result["vulnerability_analysis"] = analyze_vulnerabilities(audit_result)
    va = audit_result["vulnerability_analysis"]["summary"]
    yield ev.log(
        f"[VULN-ANALYST] {va['scored_groups']} group(s) scored · "
        f"max CVSS {va['max_cvss']} · NVD lookups {va['cve_sources_queried']} · "
        f"{va['total_cves']} CVE(s)"
    )
    yield ev.stage_end(4, "AI Remediation Synthesis")

    yield ev.stage_start(5, "PDF Report & Patch")
    pdf_path = generate_pdf_report(audit_result, REPORTS_DIR)
    yield ev.log(f"[REPORT] Exported PDF report -> {pdf_path.name}")
    if beacon:
        hw_state = "CRITICAL" if audit_result["findings"] else "SAFE"
        yield ev.log(f"[HW] {beacon.send_state(hw_state)}")
    yield ev.stage_end(5, "PDF Report & Patch")

    record.result = audit_result
    record.pdf_filename = pdf_path.name
    record.score = int(audit_result.get("score", 0))
    manager.finish(
        record,
        "completed",
        result=audit_result,
        pdf_filename=pdf_path.name,
        score=record.score,
    )
    yield "complete", {
        "audit": audit_result,
        "pdf_filename": pdf_path.name,
        "scanId": record.id,
    }


async def _dast_impl(
    target: str,
    record: ScanRecord,
    seed: dict | None = None,
) -> AsyncIterator[tuple[str, dict]]:
    ev = EventBuilder(record)
    seed = seed or {}
    resume_from = record.resume_from

    try:
        clean_target = validate_dast_target(target)
    except DastError as exc:
        yield ev.stage_end(1, "WSL2 Tool Check", "failed", str(exc))
        yield ev.error(str(exc))
        manager.finish(record, "failed", str(exc))
        return

    yield ev.log(f"[DAST] WSL2 dynamic scan -> {clean_target}")
    guard_ok, guard_msg = gemini_guardrail_check(clean_target)
    yield ev.log(f"[GUARDRAIL-IN] {guard_msg}")
    if not guard_ok:
        yield ev.error(guard_msg)
        manager.finish(record, "failed", guard_msg)
        return

    results: dict[str, Any] = dict(seed.get("dast") or {})
    results.setdefault("target", clean_target)
    results.setdefault("tools", {})
    for key in ("dnsrecon", "nmap", "ffuf", "gofile", "sqlmap", "zap", "nuclei"):
        results.setdefault(key, None)

    def remember() -> None:
        """Persists partial evidence so retry can reuse completed stages."""
        record.result = {"dast": dict(results)}

    def reused(step: int) -> bool:
        return resume_from is not None and step < resume_from and STAGE_KEYS[step] in seed.get("dast", {})

    # Stage 1 — tool check
    yield ev.stage_start(1, "WSL2 Tool Check")
    if reused(1):
        tools = results.get("tools") or {}
        yield ev.log("[TOOL] Reused verified tool state from previous scan.")
        yield ev.stage_end(1, "WSL2 Tool Check", "skipped", reason="Reused from previous scan")
    else:
        tools = await _run_stage(record, dast_tool_status)
        for name, info in tools.items():
            yield ev.log(f"[TOOL] {name}: {info['status']}")
        if all(info["status"] != "OK" for info in tools.values()):
            msg = "No DAST tool was found inside WSL2."
            yield ev.stage_end(1, "WSL2 Tool Check", "failed", msg)
            yield ev.error(msg)
            manager.finish(record, "failed", msg)
            return
        results["tools"] = tools
        remember()
        yield ev.stage_end(1, "WSL2 Tool Check")
    await checkpoint(record)

    # Stage 2 — DNS recon
    label = "DNS Recon (dnsrecon)"
    yield ev.stage_start(2, label)
    if reused(2):
        yield ev.log("[DNS] Reused dnsrecon evidence from previous scan.")
        yield ev.stage_end(2, label, "skipped", reason="Reused from previous scan")
    elif tools.get("dnsrecon", {}).get("status") == "OK":
        yield ev.log("[DNS] Enumerating records/subdomains through the offline lab resolver...")
        try:
            dns = await _run_stage(record, run_dnsrecon, clean_target)
            results["dnsrecon"] = dns
            remember()
            for item in dns.get("subdomains", []):
                yield ev.log(f"[DNS] A {item['host']} -> {item['ip']}")
            for item in dns.get("ptr", []):
                yield ev.log(f"[DNS] PTR {item['ip']} -> {item['host']}")
            if dns.get("offline"):
                yield ev.log("[DNS] Local DNS lab server is not running; skipped.")
                yield ev.stage_end(2, label, "skipped", reason=dns.get("error"))
            else:
                yield ev.stage_end(2, label)
        except DastError as exc:
            results["dnsrecon"] = {
                "tool": "dnsrecon",
                "ok": False,
                "error": str(exc),
                "records": [],
                "subdomains": [],
                "ptr": [],
            }
            yield ev.log(f"[DNS] ERROR: {exc}", "error")
            yield ev.stage_end(2, label, "failed", str(exc))
    else:
        yield ev.stage_end(2, label, "skipped", reason="dnsrecon missing or disabled")
    await checkpoint(record)

    # Stage 3 — Nmap
    label = "Nmap Port & Service Scan"
    yield ev.stage_start(3, label)
    if reused(3):
        yield ev.log("[NMAP] Reused nmap evidence from previous scan.")
        yield ev.stage_end(3, label, "skipped", reason="Reused from previous scan")
    elif tools.get("nmap", {}).get("status") == "OK":
        yield ev.log("[NMAP] TCP connect + service/version scan...")
        try:
            nmap = await _run_stage(record, run_nmap, clean_target)
            results["nmap"] = nmap
            remember()
            for item in nmap.get("ports", []):
                yield ev.log(f"[NMAP] {item['port']} {item['state']} {item['service']} {item['version']}")
            yield ev.stage_end(3, label)
        except DastError as exc:
            results["nmap"] = {"tool": "nmap", "ok": False, "error": str(exc), "ports": []}
            yield ev.log(f"[NMAP] ERROR: {exc}", "error")
            yield ev.stage_end(3, label, "failed", str(exc))
    else:
        yield ev.stage_end(3, label, "skipped", reason="nmap missing or disabled")
    await checkpoint(record)

    # Stage 4 — ffuf
    label = "ffuf Route Discovery"
    yield ev.stage_start(4, label)
    if reused(4):
        yield ev.log("[FFUF] Reused route evidence from previous scan.")
        yield ev.stage_end(4, label, "skipped", reason="Reused from previous scan")
    elif tools.get("ffuf", {}).get("status") == "OK":
        yield ev.log("[FFUF] Common path fuzzing...")
        try:
            ffuf = await _run_stage(record, run_ffuf, clean_target)
            results["ffuf"] = ffuf
            remember()
            for item in ffuf.get("results", []):
                yield ev.log(f"[FFUF] {item['status']} {item['path']}")
            if not ffuf.get("results"):
                yield ev.log("[FFUF] No additional routes found.")
            yield ev.stage_end(4, label)
        except DastError as exc:
            results["ffuf"] = {"tool": "ffuf", "ok": False, "error": str(exc), "results": []}
            yield ev.log(f"[FFUF] ERROR: {exc}", "error")
            yield ev.stage_end(4, label, "failed", str(exc))
    else:
        yield ev.stage_end(4, label, "skipped", reason="ffuf missing or disabled")
    await checkpoint(record)

    # Stage 5 — GoFile
    label = "GoFile Hidden Files"
    yield ev.stage_start(5, label)
    if reused(5):
        yield ev.log("[GOFILE] Reused hidden-file evidence from previous scan.")
        yield ev.stage_end(5, label, "skipped", reason="Reused from previous scan")
    elif tools.get("gofile", {}).get("status") == "OK":
        yield ev.log("[GOFILE] Gobuster: hidden file/directory and backup hunt...")
        try:
            gofile = await _run_stage(record, run_gofile, clean_target)
            results["gofile"] = gofile
            remember()
            for item in gofile.get("findings", []):
                tag = "HIDDEN" if item["hidden"] else "FOUND"
                yield ev.log(f"[GOFILE] [{tag}] {item['path']} (HTTP {item['status']})")
            if not gofile.get("findings"):
                yield ev.log("[GOFILE] No hidden files found.")
            yield ev.stage_end(5, label)
        except DastError as exc:
            results["gofile"] = {"tool": "gofile", "ok": False, "error": str(exc), "findings": []}
            yield ev.log(f"[GOFILE] ERROR: {exc}", "error")
            yield ev.stage_end(5, label, "failed", str(exc))
    else:
        yield ev.stage_end(5, label, "skipped", reason="gobuster missing or disabled")
    await checkpoint(record)

    # Stage 6 — sqlmap
    label = "sqlmap Injection Test"
    yield ev.stage_start(6, label)
    if reused(6):
        yield ev.log("[SQLMAP] Reused injection evidence from previous scan.")
        yield ev.stage_end(6, label, "skipped", reason="Reused from previous scan")
    elif tools.get("sqlmap", {}).get("status") == "OK":
        yield ev.log("[SQLMAP] Crawl + boolean/union test...")
        try:
            sqlmap = await _run_stage(record, run_sqlmap, clean_target)
            results["sqlmap"] = sqlmap
            remember()
            if sqlmap.get("injectable"):
                yield ev.log(f"[SQLMAP] VULNERABLE: {', '.join(sqlmap['parameters'])}")
            else:
                yield ev.log("[SQLMAP] No injection found.")
            yield ev.stage_end(6, label)
        except DastError as exc:
            results["sqlmap"] = {
                "tool": "sqlmap",
                "ok": False,
                "injectable": False,
                "parameters": [],
                "types": [],
                "payloads": [],
                "dbms": None,
                "error": str(exc),
            }
            yield ev.log(f"[SQLMAP] ERROR: {exc}", "error")
            yield ev.stage_end(6, label, "failed", str(exc))
    else:
        yield ev.stage_end(6, label, "skipped", reason="sqlmap missing or disabled")
    await checkpoint(record)

    # Stage 7 — OWASP ZAP
    label = "OWASP ZAP Quick Scan"
    yield ev.stage_start(7, label)
    if reused(7):
        yield ev.log("[ZAP] Reused alert evidence from previous scan.")
        yield ev.stage_end(7, label, "skipped", reason="Reused from previous scan")
    elif tools.get("zap", {}).get("status") == "OK":
        yield ev.log("[ZAP] Spider + active scan (a few minutes)...")
        try:
            zap = await _run_stage(record, run_zap, clean_target)
            results["zap"] = zap
            remember()
            for alert in zap.get("alerts", []):
                yield ev.log(f"[ZAP] [{alert['risk']}] {alert['title']}")
            if not zap.get("alerts"):
                yield ev.log("[ZAP] No high/medium alerts.")
            yield ev.stage_end(7, label)
        except DastError as exc:
            results["zap"] = {"tool": "zap", "ok": False, "error": str(exc), "alerts": [], "alert_count": 0}
            yield ev.log(f"[ZAP] ERROR: {exc}", "error")
            yield ev.stage_end(7, label, "failed", str(exc))
    else:
        yield ev.stage_end(7, label, "skipped", reason="ZAP missing or disabled")
    await checkpoint(record)

    # Stage 8 — Nuclei
    label = "Nuclei Template Scan"
    yield ev.stage_start(8, label)
    if reused(8):
        yield ev.log("[NUCLEI] Reused template evidence from previous scan.")
        yield ev.stage_end(8, label, "skipped", reason="Reused from previous scan")
    elif tools.get("nuclei", {}).get("status") == "OK":
        yield ev.log("[NUCLEI] Checking for known issues with YAML templates...")
        try:
            nuclei = await _run_stage(record, run_nuclei, clean_target)
            results["nuclei"] = nuclei
            remember()
            for finding in nuclei.get("findings", []):
                yield ev.log(f"[NUCLEI] [{finding['severity']}] {finding['id']} @ {finding['endpoint']}")
            if not nuclei.get("findings"):
                yield ev.log("[NUCLEI] No template findings.")
            yield ev.stage_end(8, label)
        except DastError as exc:
            results["nuclei"] = {"tool": "nuclei", "ok": False, "error": str(exc), "findings": []}
            yield ev.log(f"[NUCLEI] ERROR: {exc}", "error")
            yield ev.stage_end(8, label, "failed", str(exc))
    else:
        yield ev.stage_end(8, label, "skipped", reason="nuclei missing or disabled")
    await checkpoint(record)

    # Stage 9 — guardrail, source audit, score and PDF
    label = "Guardrail Review & PDF Report"
    yield ev.stage_start(9, label)
    sanitized = sanitize_tool_output(results)
    out_ok, out_msg, out_mode = await _run_stage(record, gemini_output_review, sanitized)
    results["guardrail"] = {"ok": out_ok, "mode": out_mode, "message": out_msg}
    remember()
    yield ev.log(f"[GUARDRAIL-OUT] {out_msg}")
    if not out_ok:
        yield ev.stage_end(9, label, "failed", out_msg)
        yield ev.error(out_msg)
        manager.finish(record, "failed", out_msg, result=results)
        return

    try:
        source_file = resolve_source_for_target(clean_target)
        yield ev.log(f"[REMEDIATION] Source analysis: {source_file.name}")
        audit = analyze_source_file(source_file)
        audit["dast"] = results
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in audit["findings"]:
            severity = str(finding.get("severity", "LOW")).upper()
            counts[severity] = counts.get(severity, 0) + 1
        audit["severity_counts"] = counts
        audit["correlations"] = correlate(audit)
        corr_summary = audit["correlations"]["summary"]
        yield ev.log(
            f"[CORRELATION] {corr_summary['total']} group(s): "
            f"{corr_summary['confirmed']} confirmed, {corr_summary['potential']} potential "
            f"(mode={corr_summary['ai_mode']})"
        )
        if not audit.get("target_snapshot") and clean_target.startswith(("http://", "https://")):
            try:
                audit["target_snapshot"] = await _run_stage(record, fetch_target_snapshot, clean_target)
                yield ev.log(f"[SURFACE] HTTP {audit['target_snapshot'].get('status_code')} snapshot captured")
            except Exception as exc:
                audit["target_snapshot"] = {"error": str(exc)}
                yield ev.log(f"[SURFACE] Snapshot unavailable: {exc}", "error")
        audit["attack_surface"] = build_attack_surface(audit)
        audit["attack_graph"] = build_attack_graph(audit)
        yield ev.log(
            f"[GRAPH] {audit['attack_graph']['stats']['nodes']} node(s), "
            f"{audit['attack_graph']['stats']['evidence_edges']} evidence edge(s), "
            f"{audit['attack_graph']['stats']['theoretical_edges']} theoretical edge(s)"
        )
        audit["vulnerability_analysis"] = analyze_vulnerabilities(audit)
        va = audit["vulnerability_analysis"]["summary"]
        yield ev.log(
            f"[VULN-ANALYST] {va['scored_groups']} group(s) scored · "
            f"max CVSS {va['max_cvss']} · NVD lookups {va['cve_sources_queried']} · "
            f"{va['total_cves']} CVE(s)"
        )
        score = int(audit.get("score", 0))
        yield ev.log(f"[SCORE] Security Score: {score}/100 ({source_file.name})")
        pdf_path = generate_pdf_report(audit, REPORTS_DIR)
        yield ev.log(f"[REPORT] {pdf_path.name}")
    except Exception as exc:  # keeps V1 graceful PDF error branch
        msg = str(exc)
        yield ev.log(f"[REPORT] ERROR: {msg}", "error")
        yield ev.stage_end(9, label, "failed", msg)
        manager.finish(record, "failed", msg, result=results)
        yield "complete", {"dast": results, "pdf_filename": None, "score": None, "scanId": record.id}
        return

    yield ev.stage_end(9, label)
    record.result = {"dast": results, "audit": audit}
    manager.finish(
        record,
        "completed",
        result=record.result,
        pdf_filename=pdf_path.name,
        score=score,
    )
    yield "complete", {
        "dast": results,
        "pdf_filename": pdf_path.name,
        "score": score,
        "file_name": source_file.name,
        "correlations": audit.get("correlations"),
        "attack_surface": audit.get("attack_surface"),
        "attack_graph": audit.get("attack_graph"),
        "vulnerability_analysis": audit.get("vulnerability_analysis"),
        "scanId": record.id,
    }


async def audit_events(
    target: str,
    record: ScanRecord,
    beacon: Any | None = None,
) -> AsyncIterator[tuple[str, dict]]:
    """Public async generator used by both legacy SSE and background scans."""
    token = bind_cancel_event(record.cancel_event)
    try:
        async for event in _audit_impl(target, record, beacon):
            yield event
    except ScanCancelled as exc:
        msg = str(exc)
        for stage in record.stages.values():
            if stage.state == "running":
                stage.state = "failed"
                stage.error = msg
                stage.finished_at = _now()
        yield EventBuilder(record).error(msg)
        manager.finish(record, "cancelled", msg)
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        yield EventBuilder(record).error(msg)
        manager.finish(record, "failed", msg)
    finally:
        clear_cancel_event(token)


async def dast_events(
    target: str,
    record: ScanRecord,
    seed: dict | None = None,
) -> AsyncIterator[tuple[str, dict]]:
    """Public async generator used by both legacy SSE and background scans."""
    token = bind_cancel_event(record.cancel_event)
    try:
        async for event in _dast_impl(target, record, seed=seed):
            yield event
    except ScanCancelled as exc:
        msg = str(exc)
        for stage in record.stages.values():
            if stage.state == "running":
                stage.state = "failed"
                stage.error = msg
                stage.finished_at = _now()
        yield EventBuilder(record).error(msg)
        manager.finish(record, "cancelled", msg)
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        yield EventBuilder(record).error(msg)
        manager.finish(record, "failed", msg)
    finally:
        clear_cancel_event(token)
