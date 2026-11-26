"""AegisAI V2 Settings / diagnostics (PHASE 10).

Reports the ACTUAL runtime configuration: key presence (never the key value),
model, guardrail mode from a real scan, localhost scope constants, storage
paths and counts, and real DAST tool status from the latest scan. A live tool
recheck is available through ``recheck_tools()``.
"""

import os
from datetime import datetime

from backend import history, insights
from backend.local_http import ALLOWED_HOSTS, MAX_BYTES, TIMEOUT_SECONDS
from backend.monitor import MAX_EVENTS as MONITOR_MAX_EVENTS
from backend.monitor import MAX_INTERVAL as MONITOR_MAX_INTERVAL
from backend.monitor import MIN_INTERVAL as MONITOR_MIN_INTERVAL


def build_settings() -> dict:
    from backend.remediation import BACKUP_DIR
    from backend.verification import VERIFICATIONS_FILE
    from backend.monitor import MONITOR_FILE

    _, audit, _ = insights.scan_context()
    dast_record = insights.latest_completed_dast()
    dast = insights.dast_of(dast_record)
    guardrail = dast.get("guardrail") or {}
    tools = dast.get("tools") or {}

    key_present = bool(os.getenv("GEMINI_API_KEY"))
    completed = [r for r in history.read_scans() if r.get("status") == "completed"]

    return {
        "engine": "aegis-settings-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "policy": "This screen shows real runtime settings; API key values are never displayed.",
        "ai": {
            "provider": os.getenv('AEGIS_MODEL_PROVIDER', 'gemini'),
            "active_model": os.getenv('AEGIS_OLLAMA_MODEL', 'qwen2.5:14b') if os.getenv('AEGIS_MODEL_PROVIDER') == 'ollama' else os.getenv('AEGIS_GEMINI_MODEL', 'gemini-3.1-flash-lite'),
            "browser_enabled": os.getenv('AEGIS_BROWSER_ENABLED', '0') == '1',
            "gemini_key_present": key_present,
            "gemini_model": os.getenv("AEGIS_GEMINI_MODEL", "gemini-3.1-flash-lite"),
            "guardrail_mode": guardrail.get("mode"),
            "guardrail_ok": guardrail.get("ok"),
            "correlation_ai_mode": (((audit or {}).get("correlations") or {}).get("summary") or {}).get("ai_mode"),
        },
        "scope": {
            "localhost_only": True,
            "allowed_snapshot_hosts": sorted(ALLOWED_HOSTS),
            "snapshot_timeout_seconds": TIMEOUT_SECONDS,
            "snapshot_max_bytes": MAX_BYTES,
            "dast_target": os.getenv("AEGIS_DEFAULT_TARGET", "").strip() or "not configured",
            "monitor_target": os.getenv("AEGIS_GATE_1_URL", "").strip() or "not configured",
            "monitor_interval_range": [MONITOR_MIN_INTERVAL, MONITOR_MAX_INTERVAL],
            "monitor_max_events": MONITOR_MAX_EVENTS,
        },
        "storage": {
            "history_file": str(history.HISTORY_FILE),
            "history_records": len(history.read_scans()),
            "completed_scans": len(completed),
            "backup_dir": str(BACKUP_DIR),
            "backup_files": len(list(BACKUP_DIR.glob("*.backup"))) if BACKUP_DIR.exists() else 0,
            "verification_file": str(VERIFICATIONS_FILE),
            "verifications_present": VERIFICATIONS_FILE.exists(),
            "monitor_file": str(MONITOR_FILE),
            "monitor_events_present": MONITOR_FILE.exists(),
        },
        "pipeline": list(insights.PIPELINE_STAGES),
        "tools": {name: (payload or {}).get("status") for name, payload in tools.items()},
        "tools_source": "latest completed DAST scan" if tools else "no DAST scan recorded yet",
        "preserved_v1_contract": [
            "/api/audit-stream",
            "/api/dast-stream",
            "/api/apply-patch",
            "/api/download-report",
            "/",
        ],
    }


def recheck_tools() -> dict:
    """Runs the real WSL2 tool check. Slow but honest."""
    from backend.wsl_scanner import dast_tool_status

    tools = dast_tool_status()
    return {
        "engine": "aegis-settings-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": "live WSL2 executable check",
        "tools": {name: (payload or {}).get("status") for name, payload in tools.items()},
        "ok_count": sum(1 for p in tools.values() if p.get("status") == "OK"),
        "total": len(tools),
    }
