"""AegisAI V2 Continuous Monitoring (PHASE 9).

A bounded, localhost-only background watcher. Each tick re-audits the real lab
source files and (optionally) takes a guarded HTTP snapshot of the authorized
local target, then records sha256/score/finding drift in reports/monitor.json.
No outbound targets and no invented events.
"""

import hashlib
import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from backend.auditor import analyze_source_file
from backend.local_http import SnapshotError, fetch_target_snapshot
from backend.remediation import LAB_DIR

BASE_DIR = Path(__file__).resolve().parent.parent
MONITOR_FILE = BASE_DIR / "reports" / "monitor.json"
MAX_EVENTS = 120
MIN_INTERVAL = 10
MAX_INTERVAL = 3600

_lock = threading.RLock()
_state = {
    "running": False,
    "interval_seconds": 60,
    "target": None,
    "started_at": None,
    "last_tick_at": None,
    "ticks": 0,
    "thread": None,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_events() -> list[dict]:
    if not MONITOR_FILE.exists():
        return []
    try:
        data = json.loads(MONITOR_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _append_event(event: dict) -> None:
    with _lock:
        events = _read_events()
        events.insert(0, event)
        MONITOR_FILE.parent.mkdir(parents=True, exist_ok=True)
        MONITOR_FILE.write_text(
            json.dumps(events[:MAX_EVENTS], ensure_ascii=False, indent=2), encoding="utf-8"
        )


def _source_snapshot() -> list[dict]:
    items = []
    for path in sorted(LAB_DIR.glob("app*.py")):
        audit = analyze_source_file(path)
        items.append(
            {
                "file": path.name,
                "sha256": _sha256(path),
                "score": int(audit.get("score", 0)),
                "finding_count": len(audit.get("findings") or []),
                "finding_ids": [f.get("id") for f in audit.get("findings") or []],
            }
        )
    return items


def _http_snapshot(target: str | None) -> dict:
    if not target:
        return {"enabled": False, "reason": "no target provided"}
    try:
        snapshot = fetch_target_snapshot(target)
        return {
            "enabled": True,
            "status_code": snapshot.get("status_code"),
            "html_sha256": snapshot.get("html_sha256"),
            "security_headers_missing": snapshot.get("security_headers_missing"),
            "endpoint_count": len(snapshot.get("endpoints") or []),
        }
    except SnapshotError as exc:
        return {"enabled": True, "error": str(exc)}


def _compute_drift(current: list[dict], previous: list[dict] | None) -> list[dict]:
    if not previous:
        return []
    old = {item["file"]: item for item in previous}
    drift = []
    for item in current:
        before = old.get(item["file"])
        if not before:
            drift.append({"file": item["file"], "change": "new_file", "score_delta": None})
            continue
        changes = []
        if before.get("sha256") != item.get("sha256"):
            changes.append("source_hash_changed")
        score_delta = int(item.get("score", 0)) - int(before.get("score", 0))
        if score_delta:
            changes.append("score_changed")
        old_ids = set(before.get("finding_ids") or [])
        new_ids = set(item.get("finding_ids") or [])
        added = sorted(new_ids - old_ids)
        removed = sorted(old_ids - new_ids)
        if added:
            changes.append("findings_added")
        if removed:
            changes.append("findings_removed")
        if changes:
            drift.append(
                {
                    "file": item["file"],
                    "change": changes,
                    "score_delta": score_delta,
                    "findings_added": added,
                    "findings_removed": removed,
                }
            )
    return drift


def _tick() -> dict:
    events = _read_events()
    previous = (events[0].get("sources") if events else None)
    sources = _source_snapshot()
    event = {
        "id": f"MON-{uuid.uuid4().hex[:8]}",
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "sources": sources,
        "http": _http_snapshot(_state.get("target")),
        "drift": _compute_drift(sources, previous),
    }
    _append_event(event)
    with _lock:
        _state["ticks"] += 1
        _state["last_tick_at"] = event["captured_at"]
    return event


def _loop(interval: int) -> None:
    # First observation happens immediately so the UI never shows fake data.
    try:
        _tick()
    except Exception:
        pass
    while True:
        with _lock:
            if not _state["running"]:
                return
        for _ in range(interval):
            if not _state["running"]:
                return
            time.sleep(1)
        try:
            _tick()
        except Exception:
            pass


def status() -> dict:
    with _lock:
        return {
            "running": bool(_state["running"]),
            "interval_seconds": int(_state["interval_seconds"]),
            "target": _state.get("target"),
            "started_at": _state.get("started_at"),
            "last_tick_at": _state.get("last_tick_at"),
            "ticks": int(_state.get("ticks", 0)),
            "recorded_events": len(_read_events()),
            "policy": (
                "Only your configured localhost target and local source files are monitored; each tick records real "
                "SHA-256 values, scores and finding sets."
            ),
        }


def start(interval_seconds: int = 60, target: str | None = None) -> dict:
    interval = max(MIN_INTERVAL, min(int(interval_seconds), MAX_INTERVAL))
    with _lock:
        if _state["running"]:
            return status()
        _state.update(
            {
                "running": True,
                "interval_seconds": interval,
                "target": target,
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "ticks": 0,
            }
        )
        thread = threading.Thread(target=_loop, args=(interval,), daemon=True, name="aegis-monitor")
        _state["thread"] = thread
        thread.start()
    return status()


def stop() -> dict:
    with _lock:
        _state["running"] = False
        _state["target"] = None
    return status()


def history(limit: int = 30) -> list[dict]:
    return _read_events()[: max(1, min(int(limit), MAX_EVENTS))]
