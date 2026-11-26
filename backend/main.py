import asyncio
import json
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
import webview
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, UUID4

from backend import history
from backend.attack_graph import build_attack_graph
from backend.attack_surface import build_attack_surface
from backend.auditor import analyze_source_file, apply_remediation_patch
from backend.pdf_report import generate_pdf_report
from backend.scan_engine import (
    audit_events,
    dast_events,
    manager,
)
from backend.deep_correlation import correlate as deep_correlate
from backend.deep_pdf import generate_deep_report
from backend.deep_scanner import empty_result, run_tool
from backend.security_agent import AGENT_VERSION, PROMPT_VERSION, run_agent
from backend.serial_beacon import SerialBeacon
from backend.tool_registry import DEEP_TOOLS, check_all_tools, check_tool, install_guide
from backend.wsl_scanner import ScanCancelled, bind_cancel_event, clear_cancel_event

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
REPORTS_DIR = BASE_DIR / "reports"

APP_VERSION = "3.1.0"
# Local-only API hardening: no wildcard CORS, and state-changing requests must
# come from the local UI origin (or the embedded WebView/TestClient).
_CONFIGURED_API_BASE = os.getenv("AEGIS_API_BASE", "").strip().rstrip("/")
_CONFIGURED_ORIGIN = _CONFIGURED_API_BASE
_CONFIGURED_HOST = urlsplit(_CONFIGURED_API_BASE).netloc if _CONFIGURED_API_BASE else ""
ALLOWED_ORIGINS = {
    "http://testserver",
    "null",  # WebView2 / embedded desktop origin
}
if _CONFIGURED_ORIGIN:
    ALLOWED_ORIGINS.add(_CONFIGURED_ORIGIN)
ALLOWED_HOSTS = {"testserver"}
if _CONFIGURED_HOST:
    ALLOWED_HOSTS.add(_CONFIGURED_HOST)

app = FastAPI(title=f"AegisAI Defensive Audit Engine v{APP_VERSION}")
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED_ORIGINS),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)


@app.middleware("http")
async def local_api_guard(request, call_next):
    """Reject cross-origin browser requests to the local API (CSRF-style defense)."""
    if request.url.path.startswith("/api"):
        host = request.headers.get("host", "").lower()
        origin = request.headers.get("origin")
        if host and host not in ALLOWED_HOSTS:
            return JSONResponse(status_code=403, content={"detail": "Local API host not allowed"})
        if origin and origin not in ALLOWED_ORIGINS:
            return JSONResponse(status_code=403, content={"detail": "Local API origin not allowed"})
    return await call_next(request)


@app.get("/api/version")
def api_version():
    return {
        "app": "AEGIS AI",
        "version": APP_VERSION,
        "agent_version": AGENT_VERSION,
        "prompt_version": PROMPT_VERSION,
        "scope": "localhost / authorized local lab only",
    }

beacon = SerialBeacon()

# V1 contract: these keys and types are unchanged. V2 simply restores the PDF
# path from history after a restart instead of losing it.
LATEST_STATE = {
    "audit": None,
    "pdf_path": history.latest_pdf_path(),
}


class AuditRequest(BaseModel):
    target: str


class PatchRequest(BaseModel):
    file_path: str


class ScanStartRequest(BaseModel):
    mode: str
    target: str = ""
    background: bool = True
    retry_of: str | None = None
    resume_from: int | None = None


class StageRetryRequest(BaseModel):
    step: int | None = None


class DeepToolRequest(BaseModel):
    name: str
    target: str = ""
    path: str | None = None
    image: str | None = None


class DeepScanRequest(BaseModel):
    tools: list[str] | None = None
    target: str = ""
    path: str | None = None


class DeepCorrelateRequest(BaseModel):
    audit: dict | None = None
    dast: dict | None = None
    use_stored: bool = True


class AgentRequest(BaseModel):
    task: str = "Audit the authorized local application and report the risks."
    target: str | None = None
    path: str | None = None
    use_ai: bool = True
    receipt_id: UUID4 | None = None


class SnapshotRequest(BaseModel):
    target: str = ""
    label: str = ""


class ApprovalRequest(BaseModel):
    proposal_ids: list[str]
    note: str = ""


class RemediationApplyRequest(BaseModel):
    approval_id: str
    file_path: str
    proposal_id: str | None = None


class RollbackRequest(BaseModel):
    backup_id: str


class VerificationRequest(BaseModel):
    apply_id: str | None = None
    backup_id: str | None = None


class MonitorStartRequest(BaseModel):
    interval_seconds: int = 60
    target: str | None = None


class CopilotRequest(BaseModel):
    question: str
    scan_id: str | None = None


def sse(event: str, payload: dict) -> str:
    """Exact V1 SSE frame format; new fields are additive only."""
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def _update_latest_state(payload: dict) -> None:
    pdf_name = payload.get("pdf_filename")
    if not pdf_name:
        return
    pdf_path = REPORTS_DIR / pdf_name
    if pdf_path.exists():
        LATEST_STATE["pdf_path"] = str(pdf_path)
    if "audit" in payload and payload["audit"] is not None:
        LATEST_STATE["audit"] = payload["audit"]


def _audit_for_request(scan_id: str | None = None) -> dict | None:
    """Returns the most relevant real audit result for a V2 intelligence view."""
    if scan_id:
        stored = history.get_scan(scan_id)
        if stored and stored.get("result"):
            result = stored["result"]
            return result.get("audit") or (result if "findings" in result else None)
        current = manager.get(scan_id)
        if current and current.result:
            return current.result.get("audit") or (
                current.result if "findings" in current.result else None
            )
        return None

    for stored in history.read_scans():
        result = stored.get("result") or {}
        audit = result.get("audit") or (result if "findings" in result else None)
        if audit and (audit.get("attack_surface") or audit.get("dast")):
            return audit
    return LATEST_STATE.get("audit")


async def forwarded(record, generator):
    """Fan-out engine events to the client, live stream subscribers and history."""
    try:
        async for event, payload in generator:
            manager.publish(record.id, event, payload)
            if event == "complete":
                _update_latest_state(payload)
            yield sse(event, payload)
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        manager.finish(record, "failed", msg)
        yield sse("error", {"msg": msg, "scanId": record.id})


def _resolve_retry(req: ScanStartRequest) -> tuple[str, int | None, dict | None, str | None]:
    """Resolves retry metadata so failed stages can be re-run from real evidence."""
    seed = None
    resume_from = req.resume_from
    retried_from = None
    target = req.target

    if req.retry_of:
        previous = manager.get(req.retry_of)
        if previous is None:
            stored = history.get_scan(req.retry_of)
            if stored is None:
                raise HTTPException(status_code=404, detail="Scan not found.")
            seed = stored.get("result") or {}
            target = stored.get("target", target)
            failed = [
                stage["step"]
                for stage in stored.get("stages", [])
                if stage.get("state") == "failed"
            ]
            resume_from = resume_from or (min(failed) if failed else None)
            retried_from = req.retry_of
        else:
            seed = previous.result or {}
            target = previous.target
            failed = [
                stage.step
                for stage in previous.stages.values()
                if stage.state == "failed"
            ]
            resume_from = resume_from or (min(failed) if failed else None)
            retried_from = previous.id

    if req.mode.lower() == "dast" and resume_from is not None:
        if not 1 <= resume_from <= 9:
            raise HTTPException(status_code=400, detail="resume_from must be between 1 and 9.")
    if req.mode.lower() == "audit" and resume_from is not None:
        if not 1 <= resume_from <= 5:
            raise HTTPException(status_code=400, detail="resume_from must be between 1 and 5.")
    return target, resume_from, seed, retried_from


async def _launch_scan(req: ScanStartRequest) -> dict:
    """Starts a scan in the background and returns its live-stream endpoint."""
    mode = req.mode.lower()
    if mode not in {"audit", "dast"}:
        raise HTTPException(status_code=400, detail="mode must be 'audit' or 'dast'.")

    target, resume_from, seed, retried_from = _resolve_retry(req)
    record = manager.create(
        mode=mode,
        target=target,
        total_stages=5 if mode == "audit" else 9,
        resume_from=resume_from,
        retried_from=retried_from,
    )

    generator = (
        audit_events(target, record, beacon)
        if mode == "audit"
        else dast_events(target, record, seed=seed)
    )

    async def consume() -> None:
        async for _frame in forwarded(record, generator):
            pass

    task = asyncio.create_task(consume())
    manager.track_task(record.id, task)
    task.add_done_callback(lambda _task, sid=record.id: manager.discard_task(sid))

    return {
        "scanId": record.id,
        "status": "queued",
        "mode": mode,
        "target": target,
        "stream_url": f"/api/engine/stream/{record.id}",
    }


# ---------------------------------------------------------------------------
# V1 endpoints — paths, query names and SSE payloads are preserved.
# ---------------------------------------------------------------------------


@app.get("/api/audit-stream")
async def audit_stream(target: str = ""):
    record = manager.create("audit", target, total_stages=5)
    generator = audit_events(target, record, beacon)
    return StreamingResponse(forwarded(record, generator), media_type="text/event-stream")


@app.get("/api/dast-stream")
async def dast_stream(target: str = ""):
    record = manager.create("dast", target, total_stages=9)
    generator = dast_events(target, record)
    return StreamingResponse(forwarded(record, generator), media_type="text/event-stream")


@app.post("/api/apply-patch")
def api_apply_patch(req: PatchRequest):
    target_path = Path(req.file_path).resolve()
    if BASE_DIR not in target_path.parents:
        raise HTTPException(status_code=403, detail="Unauthorized file path.")

    record = manager.create("patch", str(target_path), total_stages=1)
    manager.mark_running(record)

    ok, msg = apply_remediation_patch(target_path)
    if not ok:
        manager.finish(record, "failed", msg)
        raise HTTPException(status_code=400, detail=msg)

    updated_audit = analyze_source_file(target_path)
    pdf_path = generate_pdf_report(updated_audit, REPORTS_DIR)
    LATEST_STATE["audit"] = updated_audit
    LATEST_STATE["pdf_path"] = str(pdf_path)

    hw_state = "CRITICAL" if updated_audit["findings"] else "SAFE"
    hw_msg = beacon.send_state(hw_state)

    manager.finish(
        record,
        "completed",
        result=updated_audit,
        pdf_filename=pdf_path.name,
        score=int(updated_audit.get("score", 0)),
    )

    return {
        "message": msg,
        "hw_status": hw_msg,
        "audit": updated_audit,
        "pdf_filename": pdf_path.name,
    }


@app.get("/api/download-report")
def download_report():
    pdf_str = LATEST_STATE.get("pdf_path")
    if not pdf_str or not Path(pdf_str).exists():
        raise HTTPException(status_code=404, detail="No PDF report generated yet.")
    return FileResponse(pdf_str, media_type="application/pdf", filename=Path(pdf_str).name)


# ---------------------------------------------------------------------------
# V2 Phase 2 endpoints — additive; V1 clients are unaffected.
# ---------------------------------------------------------------------------


@app.get("/api/engine/scans")
def engine_scans(limit: int = 100):
    return {"scans": manager.list(limit), "history": history.read_scans(limit)}


@app.get("/api/history")
def api_history(limit: int = 100):
    return {"scans": history.read_scans(limit)}


@app.get("/api/history/{scan_id}")
def api_history_detail(scan_id: str):
    record = history.get_scan(scan_id)
    if record is None:
        current = manager.get(scan_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return current.to_dict()
    return record


@app.get("/api/attack-surface")
def attack_surface(scan_id: str | None = None):
    audit = _audit_for_request(scan_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="No completed scan available.")
    return audit.get("attack_surface") or build_attack_surface(audit)


@app.get("/api/attack-graph")
def attack_graph(scan_id: str | None = None):
    audit = _audit_for_request(scan_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="No completed scan available.")
    stored = audit.get("attack_graph")
    # Older persisted scans carry a graph without the enriched V2 fields.
    # Rebuild so every response exposes stats/top_risk/node evidence data.
    if (
        isinstance(stored, dict)
        and isinstance(stored.get("stats"), dict)
        and "top_risk" in stored
        and "findings" in stored["stats"]
    ):
        return stored
    return build_attack_graph(audit)


@app.get("/api/vulnerability-analysis")
def vulnerability_analysis(scan_id: str | None = None):
    audit = _audit_for_request(scan_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="No completed scan available.")
    analysis = audit.get("vulnerability_analysis")
    if analysis is None:
        from backend.vuln_analyst import analyze

        analysis = analyze(audit)
    return analysis


# ---------------------------------------------------------------------------
# V2 Phase 6 — approval-gated remediation with backup + rollback.
# ---------------------------------------------------------------------------


@app.get("/api/remediation/proposals")
def remediation_proposals(scan_id: str | None = None):
    from backend.remediation import list_proposals

    return {
        "proposals": list_proposals(scan_id),
        "policy": "A patch is applied only after explicit user approval; every operation is backed up and can be rolled back.",
    }


@app.post("/api/remediation/approve")
def remediation_approve(req: ApprovalRequest):
    from backend.remediation import create_approval

    try:
        return create_approval(req.proposal_ids, req.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/remediation/apply")
def remediation_apply(req: RemediationApplyRequest):
    from backend.remediation import apply_approved

    try:
        result = apply_approved(req.approval_id, req.file_path, req.proposal_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    updated_audit = analyze_source_file(Path(req.file_path))
    pdf_path = generate_pdf_report(updated_audit, REPORTS_DIR)
    LATEST_STATE["audit"] = updated_audit
    LATEST_STATE["pdf_path"] = str(pdf_path)
    return {
        **result,
        "audit": updated_audit,
        "pdf_filename": pdf_path.name,
        "hw_status": beacon.send_state("CRITICAL" if updated_audit["findings"] else "SAFE"),
    }


@app.get("/api/remediation/backups")
def remediation_backups():
    from backend.remediation import list_backups

    return {"backups": list_backups()}


@app.get("/api/remediation/ledger")
def remediation_ledger():
    from backend.remediation import list_ledger

    return {"entries": list_ledger()}


@app.post("/api/remediation/rollback")
def remediation_rollback(req: RollbackRequest):
    from backend.remediation import rollback

    try:
        return rollback(req.backup_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# V2 Phase 7 — fix verification against the immutable backup.
# ---------------------------------------------------------------------------


@app.get("/api/verification")
def verification_latest(limit: int = 10):
    from backend.verification import latest_verification, list_verifications

    return {
        "latest": latest_verification(),
        "history": list_verifications(limit),
        "policy": "Remediation verification rescans the current source file against the real patch backup.",
    }


@app.post("/api/verification/run")
def verification_run(req: VerificationRequest):
    from backend.verification import verify_apply

    try:
        return verify_apply(req.apply_id, req.backup_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# V2 Phase 8 — before/after comparison of two real persisted scans.
# ---------------------------------------------------------------------------


@app.get("/api/comparison/scans")
def comparison_scans(limit: int = 40):
    from backend.comparison import list_comparable

    return {"scans": list_comparable(limit)}


@app.get("/api/comparison")
def comparison(before: str | None = None, after: str | None = None):
    from backend.comparison import compare

    try:
        return compare(before, after)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/comparison/snapshots")
def comparison_snapshots():
    """V3.1: real screenshot metadata; honest availability when Playwright is absent."""
    from backend import visual_diff

    return visual_diff.list_snapshots()


@app.post("/api/comparison/capture")
def comparison_capture(req: SnapshotRequest):
    """Captures a real localhost screenshot when Playwright is installed."""
    from backend import visual_diff

    return visual_diff.capture_snapshot(req.target, req.label)


@app.get("/api/comparison/image/{name}")
def comparison_image(name: str):
    """Serves only generated PNG snapshots from the protected reports folder."""
    from backend.visual_diff import SCREENSHOT_DIR

    root = SCREENSHOT_DIR.resolve()
    candidate = (root / Path(name).name).resolve()
    if candidate.suffix.lower() != ".png" or root not in candidate.parents:
        raise HTTPException(status_code=400, detail="Invalid snapshot image")
    if not candidate.exists():
        raise HTTPException(status_code=404, detail="Snapshot image not found")
    return FileResponse(candidate, media_type="image/png")


@app.get("/api/comparison/image-diff")
def comparison_image_diff(before: str, after: str):
    """Real pixel diff of two captured snapshots; never a resolver by itself."""
    from backend import visual_diff

    return visual_diff.image_diff(before, after)


# ---------------------------------------------------------------------------
# V2 Phase 9 — API security view and localhost-only continuous monitoring.
# ---------------------------------------------------------------------------


@app.get("/api/api-security")
def api_security(scan_id: str | None = None):
    from backend.api_security import analyze_api_security

    return analyze_api_security(scan_id)


@app.get("/api/monitor/status")
def monitor_status():
    from backend.monitor import status

    return status()


@app.post("/api/monitor/start")
def monitor_start(req: MonitorStartRequest):
    from backend.local_http import SnapshotError, validate_snapshot_target
    from backend.monitor import start

    if req.target:
        try:
            validate_snapshot_target(req.target)
        except SnapshotError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return start(req.interval_seconds, req.target)


@app.post("/api/monitor/stop")
def monitor_stop():
    from backend.monitor import stop

    return stop()


@app.get("/api/monitor/history")
def monitor_history(limit: int = 30):
    from backend.monitor import history

    return {"events": history(limit)}


# ---------------------------------------------------------------------------
# V2 Phase 10 — Overview, Vulnerability Center, AI Intelligence, Reports,
# AI Copilot and Settings. All views are read-only aggregations of real data;
# the V1 endpoints above are untouched.
# ---------------------------------------------------------------------------


@app.get("/api/overview")
def api_overview():
    from backend.dashboard import build_overview

    return build_overview()


@app.get("/api/vulnerability-center")
def api_vulnerability_center(scan_id: str | None = None):
    from backend.vulnerability_center import build_vulnerability_center

    return build_vulnerability_center(scan_id)


@app.get("/api/ai-intelligence")
def api_ai_intelligence(scan_id: str | None = None):
    from backend.ai_intelligence import build_ai_intelligence

    return build_ai_intelligence(scan_id)


@app.get("/api/reports")
def api_reports():
    from backend.reports_center import build_reports_center

    return build_reports_center()


@app.get("/api/report-file")
def api_report_file(file: str):
    """Additive, path-validated download of one real generated PDF."""
    report = (REPORTS_DIR / Path(file).name).resolve()
    if REPORTS_DIR not in report.parents or report.suffix.lower() != ".pdf" or not report.exists():
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(report, media_type="application/pdf", filename=report.name)


@app.get('/api/browser-screenshot/{image_id}')
def browser_screenshot(image_id: str):
    if len(image_id) != 32 or any(c not in '0123456789abcdef' for c in image_id):
        raise HTTPException(status_code=404, detail='Screenshot not found.')
    path = REPORTS_DIR / 'browser' / f'{image_id}.png'
    if not path.exists():
        raise HTTPException(status_code=404, detail='Screenshot not found.')
    return FileResponse(path, media_type='image/png')


@app.post("/api/copilot/ask")
def api_copilot_ask(req: CopilotRequest):
    from backend.copilot import CopilotBlocked, ask_copilot

    try:
        return ask_copilot(req.question, req.scan_id)
    except CopilotBlocked as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/settings")
def api_settings():
    from backend.settings_center import build_settings

    return build_settings()


@app.post("/api/settings/tools")
def api_settings_recheck_tools():
    from backend.settings_center import recheck_tools

    return recheck_tools()


@app.post("/api/engine/start")
async def engine_start(req: ScanStartRequest):
    return await _launch_scan(req)


@app.get("/api/engine/stream/{scan_id}")
async def engine_stream(scan_id: str):
    record = manager.get(scan_id)
    if record is None:
        stored = history.get_scan(scan_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return StreamingResponse(
            iter([sse("scan", {"scan": stored, "finished": True})]),
            media_type="text/event-stream",
        )

    async def event_generator():
        queue = manager.subscribe(scan_id)
        yield sse("scan", {"scan": record.to_dict()})
        try:
            while True:
                try:
                    event, payload = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield sse("heartbeat", {"scanId": scan_id, "ts": datetime.now().isoformat()})
                    continue
                if event == "__done__":
                    final = manager.get(scan_id)
                    yield sse("scan", {"scan": final.to_dict() if final else {"id": scan_id}})
                    break
                yield sse(event, payload)
        finally:
            manager.unsubscribe(scan_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/engine/scans/{scan_id}/cancel")
def engine_cancel(scan_id: str):
    if not manager.cancel(scan_id):
        raise HTTPException(status_code=409, detail="Scan is not running or was not found.")
    return {"scanId": scan_id, "status": "cancelling"}


@app.post("/api/engine/scans/{scan_id}/retry")
async def engine_retry(scan_id: str, req: StageRetryRequest | None = None):
    previous = manager.get(scan_id) or history.get_scan(scan_id)
    if previous is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    if isinstance(previous, dict):
        mode = previous.get("mode", "dast")
        failed = [
            stage["step"]
            for stage in previous.get("stages", [])
            if stage.get("state") == "failed"
        ]
        resume_from = (req.step if req and req.step else None) or (min(failed) if failed else None)
    else:
        mode = previous.mode
        failed = [stage.step for stage in previous.stages.values() if stage.state == "failed"]
        resume_from = (req.step if req and req.step else None) or (min(failed) if failed else None)

    if not resume_from:
        raise HTTPException(status_code=400, detail="No failed stage to retry.")

    return await _launch_scan(
        ScanStartRequest(
            mode=mode,
            target=previous.target if isinstance(previous, dict) else previous.target,
            retry_of=scan_id,
            resume_from=resume_from,
        )
    )


# ---------------------------------------------------------------------------
# AEGIS AI V3 — deep security scanning engine.
# Additive endpoints only: the V1 audit/DAST/SSE/remediation contract above is
# untouched. The fixed 9-stage pipeline is not modified by these modules.
# ---------------------------------------------------------------------------
_DEEP_STATE = {
    "results": {},       # tool name -> last real execution result
    "history": [],       # bounded audit trail of executions
    "correlation": None, # last unified correlation result
}
_DEEP_LOCK = threading.Lock()


def _deep_audit(event: str, payload: dict) -> None:
    """Immutable-on-append audit log for every deep tool action."""
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        record = {"ts": datetime.now().isoformat(), "event": event, "payload": payload}
        with (REPORTS_DIR / "deep_tool_audit.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False)[:2500] + "\n")
    except OSError:
        pass  # auditing must never break a scan


def _remember_deep_result(name: str, result: dict) -> dict:
    with _DEEP_LOCK:
        _DEEP_STATE["results"][name] = result
        _DEEP_STATE["history"] = ([
            {
                "tool": name,
                "ts": datetime.now().isoformat(),
                "ok": result.get("ok"),
                "available": result.get("available"),
                "findings": len(result.get("findings") or []),
                "error": result.get("error"),
            }
        ] + _DEEP_STATE["history"])[:100]
    _deep_audit("tool_run", {
        "tool": name,
        "ok": result.get("ok"),
        "available": result.get("available"),
        "findings": len(result.get("findings") or []),
        "error": result.get("error"),
        "duration_ms": result.get("duration_ms"),
    })
    return result


@app.get("/api/tools")
def api_tools(force: bool = False):
    """Live status of all 11 deep tools, merged with last execution metadata."""
    with _DEEP_LOCK:
        results = dict(_DEEP_STATE["results"])
        history = list(_DEEP_STATE["history"])
    tools = check_all_tools()
    for name, entry in tools.items():
        last = results.get(name)
        entry["last_execution"] = None
        for item in history:
            if item.get("tool") == name:
                entry["last_execution"] = item.get("ts")
                break
        entry["execution_status"] = (
            ("OK" if last.get("ok") else "FAILED") if last else "NOT RUN"
        )
        entry["findings_count"] = len(last.get("findings") or []) if last else 0
        entry["error_log"] = (last or {}).get("error")
        entry["configuration"] = {
            "timeout_seconds": entry["timeout"],
            "scope": "localhost / allowlisted local lab paths",
            "destructive_actions": False,
            "safe_note": entry["note"],
        }
    return {
        "tools": tools,
        "order": list(DEEP_TOOLS),
        "total": len(tools),
        "installed": sum(1 for e in tools.values() if e["status"] == "OK"),
        "source": "live WSL2 availability check",
    }


@app.get("/api/tools/{name}/guide")
def api_tool_guide(name: str):
    guide = install_guide(name)
    if not guide["found"]:
        raise HTTPException(status_code=404, detail=guide["guide"])
    return guide


@app.post("/api/tools/{name}/check")
def api_tool_check(name: str):
    entry = check_tool(name)
    _deep_audit("tool_check", {"tool": name, "status": entry["status"]})
    return entry


@app.post("/api/tools/run")
def api_tools_run(req: DeepToolRequest):
    if req.name not in DEEP_TOOLS:
        raise HTTPException(status_code=404, detail="Unknown tool.")
    result = run_tool(req.name, target=req.target, path=req.path, image=req.image)
    return _remember_deep_result(req.name, result)


@app.get("/api/deep-results")
def api_deep_results():
    with _DEEP_LOCK:
        return {
            "results": dict(_DEEP_STATE["results"]),
            "history": list(_DEEP_STATE["history"]),
            "correlation": _DEEP_STATE["correlation"],
        }


@app.post("/api/deep-correlate")
def api_deep_correlate(req: DeepCorrelateRequest | None = None):
    req = req or DeepCorrelateRequest()
    with _DEEP_LOCK:
        stored = dict(_DEEP_STATE["results"]) if req.use_stored else {}
    audit = req.audit
    dast = req.dast
    if audit is None and LATEST_STATE.get("audit"):
        audit = LATEST_STATE["audit"]
    if dast is None:
        for stored_scan in history.read_scans():
            result = stored_scan.get("result") or {}
            if result.get("dast"):
                dast = result["dast"]
                break
    result = deep_correlate(deep_results=stored, audit=audit, dast=dast)
    with _DEEP_LOCK:
        _DEEP_STATE["correlation"] = result
    _deep_audit("correlation", result["stats"])
    return result


@app.get("/api/download-deep-report")
def download_deep_report():
    """Additive export of the real unified deep findings.

    The V1 /api/download-report endpoint and payload contract are untouched.
    """
    with _DEEP_LOCK:
        correlation = _DEEP_STATE.get("correlation")
        results = dict(_DEEP_STATE.get("results") or {})
        audit = LATEST_STATE.get("audit")
    if correlation is None and (results or audit):
        correlation = deep_correlate(deep_results=results, audit=audit)
        with _DEEP_LOCK:
            _DEEP_STATE["correlation"] = correlation
    if not correlation or not (correlation.get("stats") or {}).get("raw_findings"):
        raise HTTPException(status_code=404, detail="No real deep-scan findings yet.")

    path = generate_deep_report(correlation, REPORTS_DIR)
    _deep_audit("deep_report_download", {
        "file": path.name,
        "raw_findings": (correlation.get("stats") or {}).get("raw_findings"),
        "unified_groups": (correlation.get("stats") or {}).get("unified_groups"),
    })
    return FileResponse(
        path, media_type="application/pdf", filename=path.name,
    )


@app.get("/api/deep-scan-stream")
async def api_deep_scan_stream(
    tools: str = "",
    target: str = "",
    path: str | None = None,
):
    """SSE stream using the exact V1 event names (stage|log|error|complete)."""
    names = [item.strip() for item in tools.split(",") if item.strip()]
    if not names:
        names = ["semgrep", "trivy", "gitleaks", "burp", "httpx", "katana", "api_security"]
    unknown = [name for name in names if name not in DEEP_TOOLS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown tool: {', '.join(unknown)}")

    file_tools = {"semgrep", "trivy", "gitleaks"}
    if any(name in file_tools for name in names):
        if not path:
            raise HTTPException(status_code=400, detail="A path is required for source analysis.")
        from backend.tool_registry import is_allowed_scan_path
        ok, message = is_allowed_scan_path(path)
        if not ok:
            raise HTTPException(status_code=400, detail=message)

    net_tools = {"metasploit", "burp", "testssl", "httpx", "katana", "api_security"}
    if any(name in net_tools for name in names):
        from backend.wsl_scanner import DastError, validate_dast_target
        try:
            target = validate_dast_target(target)
        except DastError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    async def event_generator():
        started = datetime.now().isoformat()
        _deep_audit("scan_start", {"tools": names, "target": target, "path": path})
        yield sse("stage", {
            "step": 1, "name": "Deep Security Engine", "status": "running",
            "tools": names, "ts": started,
        })
        completed = 0
        total_findings = 0
        for name in names:
            yield sse("log", {"message": f"[{name}] starting real tool execution", "tool": name})
            try:
                result = await asyncio.to_thread(
                    run_tool, name, target=target, path=path
                )
            except Exception as exc:
                result = empty_result(name, f"{type(exc).__name__}: {str(exc)[:200]}")
            _remember_deep_result(name, result)
            count = len(result.get("findings") or [])
            total_findings += count
            completed += 1
            if result.get("ok"):
                yield sse("log", {
                    "message": f"[{name}] complete — {count} real finding(s)",
                    "tool": name, "findings": count,
                    "available": result.get("available"),
                })
            else:
                yield sse("error", {
                    "message": result.get("error") or f"[{name}] execution failed",
                    "tool": name, "available": result.get("available"),
                })
            yield sse("stage", {
                "step": 1, "name": name, "status": "done" if result.get("ok") else "failed",
                "progress": f"{completed}/{len(names)}", "findings": count,
            })

        try:
            with _DEEP_LOCK:
                stored = dict(_DEEP_STATE["results"])
            correlation = await asyncio.to_thread(deep_correlate, deep_results=stored)
            with _DEEP_LOCK:
                _DEEP_STATE["correlation"] = correlation
            yield sse("log", {
                "message": f"Unified correlation: {correlation['stats']['unified_groups']} "
                           f"group(s) from {correlation['stats']['raw_findings']} raw findings",
            })
        except Exception as exc:
            yield sse("error", {"message": f"Correlation failed: {exc}"})

        payload = {
            "ok": True,
            "tools_run": completed,
            "total_findings": total_findings,
            "results": stored,
            "correlation": correlation if "correlation" in locals() else None,
            "ts": datetime.now().isoformat(),
        }
        _deep_audit("scan_complete", {"tools_run": completed, "total_findings": total_findings})
        yield sse("complete", payload)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# AEGIS AI V3 — model-driven AGENT MODE.
# Additive only: the V1 audit/DAST/remediation contract above is untouched.
# The agent reuses the same real tools and localhost-only guardrails, but the
# plan and tool order come from Gemini function calling (or an honest
# deterministic fallback when the model is unavailable).
# ---------------------------------------------------------------------------
_AGENT_STATE = {
    "last": None,
    "history": [],
    "running": False,
}
_AGENT_LOCK = threading.Lock()
_AGENT_LAST_FILE = REPORTS_DIR / "agent_last.json"
# Bounded delivery cache for clients whose original HTTP response was lost.
_AGENT_RECEIPTS: dict[str, dict] = {}

# Cooperative cancellation for the model-driven agent. Additive: when no
# cancel request arrives the event is never set and behaviour is unchanged.
_AGENT_CANCEL = {"event": None}


@contextmanager
def _agent_cancel_scope():
    """Binds a fresh cancellation event to the current worker thread."""
    event = threading.Event()
    with _AGENT_LOCK:
        _AGENT_CANCEL["event"] = event
    token = bind_cancel_event(event)
    try:
        yield event
    finally:
        clear_cancel_event(token)
        with _AGENT_LOCK:
            if _AGENT_CANCEL.get("event") is event:
                _AGENT_CANCEL["event"] = None


def _agent_audit(event: str, payload: dict) -> None:
    """Append-only audit trail for every agent run; must never break the run."""
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        record = {"ts": datetime.now().isoformat(), "event": event, "payload": payload}
        with (REPORTS_DIR / "agent_audit.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False)[:3000] + "\n")
    except OSError:
        pass


def _agent_digest(result: dict) -> dict:
    return {
        "ts": result.get("ts"),
        "ok": result.get("ok"),
        "mode": result.get("mode"),
        "task": result.get("task"),
        "target": result.get("target"),
        "path": result.get("path"),
        "tools_used": result.get("tools_used") or [],
        "total_findings": result.get("total_findings"),
        "severity_counts": result.get("severity_counts"),
        "duration_ms": result.get("duration_ms"),
        "summary": (result.get("summary") or "")[:600],
    }


def _store_agent_result(result: dict) -> None:
    with _AGENT_LOCK:
        _AGENT_STATE["last"] = result
        _AGENT_STATE["history"] = ([_agent_digest(result)] + _AGENT_STATE["history"])[:20]
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        _AGENT_LAST_FILE.write_text(
            json.dumps(result, ensure_ascii=False)[:2_000_000], encoding="utf-8"
        )
    except OSError:
        pass
    _agent_audit("agent_run", _agent_digest(result))


def _load_last_agent_result() -> None:
    try:
        if _AGENT_LAST_FILE.exists():
            _AGENT_STATE["last"] = json.loads(
                _AGENT_LAST_FILE.read_text(encoding="utf-8")
            )
    except (OSError, json.JSONDecodeError):
        pass  # a corrupt cache must never break startup


_load_last_agent_result()


def _validated_agent_scope(target: str | None, path: str | None) -> tuple[str | None, str | None]:
    """Fail fast on out-of-scope input before any SSE stream opens."""
    if target:
        from backend.wsl_scanner import DastError, validate_dast_target

        try:
            target = validate_dast_target(target)
        except DastError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if path:
        from backend.tool_registry import is_allowed_scan_path

        ok, message = is_allowed_scan_path(path)
        if not ok:
            raise HTTPException(status_code=400, detail=message)
        path = message
    return target, path


def _claim_agent_slot() -> None:
    with _AGENT_LOCK:
        if _AGENT_STATE["running"]:
            raise HTTPException(status_code=409, detail="The agent is already running.")
        _AGENT_STATE["running"] = True


def _release_agent_slot() -> None:
    with _AGENT_LOCK:
        _AGENT_STATE["running"] = False


@app.get("/api/agent/last")
def api_agent_last():
    with _AGENT_LOCK:
        return {
            "last": _AGENT_STATE["last"],
            "history": list(_AGENT_STATE["history"]),
            "running": _AGENT_STATE["running"],
        }


@app.post("/api/agent/run")
def api_agent_run(req: AgentRequest):
    """Synchronous run, used by tests, the demo script and the Telegram bot."""
    target, path = _validated_agent_scope(req.target, req.path)
    _claim_agent_slot()
    key = str(req.receipt_id) if req.receipt_id else None
    try:
        if key:
            with _AGENT_LOCK:
                last = _AGENT_STATE.get("last") or {}
                if key in _AGENT_RECEIPTS or last.get("receipt_id") == key:
                    raise HTTPException(status_code=409, detail="Report ID already used.")
                if len(_AGENT_RECEIPTS) >= 8:
                    del _AGENT_RECEIPTS[next(iter(_AGENT_RECEIPTS))]
                _AGENT_RECEIPTS[key] = {"state": "pending"}
        try:
            result = _sync_agent_result(req, target, path)
            if key:
                result["receipt_id"] = key
            if not result.get("cancelled"):
                _store_agent_result(result)
        except Exception:
            if key:
                with _AGENT_LOCK:
                    _AGENT_RECEIPTS[key] = {"state": "failed"}
            raise
        if key:
            with _AGENT_LOCK:
                _AGENT_RECEIPTS[key] = {"state": "ready", "result": result}
        return result
    finally:
        _release_agent_slot()


@app.get("/api/agent/receipts/{receipt_id}")
def agent_report_receipt(receipt_id: UUID4):
    key = str(receipt_id)
    with _AGENT_LOCK:
        receipt = _AGENT_RECEIPTS.get(key)
        if receipt:
            return {"receipt_id": key, **receipt}
        last = _AGENT_STATE.get("last") or {}
        if last.get("receipt_id") == key:
            return {"receipt_id": key, "state": "ready", "result": last}
    return {"receipt_id": key, "state": "unknown"}


def _sync_agent_result(req: AgentRequest, target: str | None, path: str | None) -> dict:
    started = time.monotonic()
    _agent_audit("agent_start", {
        "task": req.task[:400], "target": target, "path": path,
        "use_ai": req.use_ai, "via": "sync",
    })
    try:
        with _agent_cancel_scope():
            result = run_agent(
                req.task, target=target, path=path, use_ai=req.use_ai,
            )
    except ScanCancelled:
        duration_ms = int((time.monotonic() - started) * 1000)
        _agent_audit("agent_cancelled", {
            "target": target, "path": path, "via": "sync", "duration_ms": duration_ms,
        })
        return {
            "ok": False,
            "status": "cancelled",
            "cancelled": True,
            "mode": "cancelled",
            "task": req.task[:1200],
            "target": target,
            "path": path,
            "tools_used": [],
            "total_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [],
            "duration_ms": duration_ms,
            "summary": "Run cancelled by the user. No partial findings were stored.",
            "verified_summary": "CANCELLED — no findings were stored.",
            "ts": datetime.now().isoformat(),
        }
    return result


@app.post("/api/agent/cancel")
def api_agent_cancel():
    """Requests cooperative cancellation of the active agent run (sync or SSE)."""
    with _AGENT_LOCK:
        event = _AGENT_CANCEL.get("event")
        running = bool(_AGENT_STATE["running"])
    if event is None or not running:
        return {"cancelled": False, "active": running}
    event.set()
    _agent_audit("agent_cancel_requested", {"via": "api"})
    return {"cancelled": True, "active": True}


@app.get("/api/agent-stream")
async def api_agent_stream(
    task: str = "Audit the authorized local application and report the risks.",
    target: str | None = None,
    path: str | None = None,
    use_ai: bool = True,
):
    """Live SSE trace of the agent loop.

    Standard V1 event names (stage|log|error|complete) are preserved; the
    additive `tool` and `final` events carry structured agent steps.
    """
    target, path = _validated_agent_scope(target, path)
    _claim_agent_slot()

    async def event_generator():
        loop = asyncio.get_running_loop()
        events: asyncio.Queue = asyncio.Queue()

        def forward(event: str, payload: dict) -> None:
            loop.call_soon_threadsafe(events.put_nowait, (event, payload))

        _agent_audit("agent_start", {
            "task": task[:400], "target": target, "path": path,
            "use_ai": use_ai, "via": "stream",
        })
        yield sse("stage", {
            "step": 0, "name": "Agent Mode", "status": "running",
            "task": task, "ts": datetime.now().isoformat(),
        })
        def run_bound():
            # contextvars are per-thread: bind the cancel event inside the
            # worker thread that actually executes the tools.
            with _agent_cancel_scope():
                return run_agent(
                    task, target=target, path=path,
                    on_event=forward, use_ai=use_ai,
                )

        try:
            agent_task = asyncio.create_task(asyncio.to_thread(run_bound))
            while True:
                if agent_task.done() and events.empty():
                    await asyncio.sleep(0)  # let thread-scheduled events land
                    if events.empty():
                        break
                try:
                    event, payload = await asyncio.wait_for(events.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                yield sse(event, payload)

            result = agent_task.result()
            _store_agent_result(result)
            yield sse("complete", result)
        except ScanCancelled:
            _agent_audit("agent_cancelled", {"via": "stream", "target": target})
            yield sse("error", {"message": "Run cancelled by the user.", "cancelled": True})
        except Exception as exc:
            message = f"{type(exc).__name__}: {str(exc)[:300]}"
            _agent_audit("agent_error", {"message": message})
            yield sse("error", {"message": message})
        finally:
            _release_agent_slot()

    return StreamingResponse(event_generator(), media_type="text/event-stream")


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


def _local_server_config() -> tuple[str, int, str]:
    base = os.getenv("AEGIS_API_BASE", "").strip().rstrip("/")
    parsed = urlsplit(base)
    if not parsed.scheme or not parsed.hostname:
        raise RuntimeError("Set AEGIS_API_BASE in .env to your local AEGIS URL.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname, port, base


def start_server(host: str, port: int):
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    api_host, api_port, api_url = _local_server_config()
    server_thread = threading.Thread(
        target=start_server, args=(api_host, api_port), daemon=True
    )
    server_thread.start()
    webview.create_window(
        title="AegisAI // Defensive Security & Remediation Dashboard",
        url=api_url,
        width=1360,
        height=860,
        background_color="#07070B",
    )
    webview.start()
