"""Persistent scan history for AegisAI V2.

The V1 engine kept only ``LATEST_STATE`` in memory, so history disappeared on
restart and the PDF download link returned 404. This module adds a small,
atomic JSON store under ``reports/history.json`` without changing the V1
``LATEST_STATE`` contract used by the existing endpoints.
"""

import json
import os
import tempfile
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
HISTORY_FILE = REPORTS_DIR / "history.json"
MAX_RECORDS = 100

_lock = threading.RLock()


def _ensure_store() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def read_scans(limit: int = MAX_RECORDS) -> list[dict]:
    """Returns newest-first scan summaries."""
    _ensure_store()
    with _lock:
        if not HISTORY_FILE.exists():
            return []
        try:
            data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        return data[: max(0, min(limit, MAX_RECORDS))]


def get_scan(scan_id: str) -> dict | None:
    _ensure_store()
    with _lock:
        for item in read_scans(MAX_RECORDS):
            if item.get("id") == scan_id:
                return item
    return None


def latest_pdf_path() -> str | None:
    """Restores the V1 download link after a backend restart."""
    for item in read_scans(MAX_RECORDS):
        pdf_name = item.get("pdf_filename")
        if pdf_name:
            candidate = REPORTS_DIR / pdf_name
            if candidate.exists():
                return str(candidate)
    return None


def append_scan(record: dict) -> None:
    """Inserts a completed/updated scan record, keeping the store bounded."""
    _ensure_store()
    with _lock:
        items = read_scans(MAX_RECORDS)
        scan_id = record.get("id")
        items = [item for item in items if item.get("id") != scan_id]
        items.insert(0, record)
        items = items[:MAX_RECORDS]

        fd, tmp_name = tempfile.mkstemp(prefix="history_", suffix=".json", dir=str(REPORTS_DIR))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(items, handle, ensure_ascii=False, indent=2)
            os.replace(tmp_name, HISTORY_FILE)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
