"""AegisAI V2 Reports center (PHASE 10).

Lists the real PDF files produced by real scans and links each one back to the
persisted scan record. No report entry exists without a corresponding file.
"""

from datetime import datetime
from pathlib import Path

from backend import history, insights

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


def build_reports_center() -> dict:
    pdfs = sorted(
        [p for p in REPORTS_DIR.glob("*.pdf") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    by_filename = {}
    for record in history.read_scans(history.MAX_RECORDS):
        name = record.get("pdf_filename")
        if name and name not in by_filename:
            by_filename[name] = record

    items = []
    for path in pdfs:
        record = by_filename.get(path.name)
        stat = path.stat()
        items.append(
            {
                "filename": path.name,
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "scan": insights.scan_summary(record) if record else None,
                "download_url": f"/api/report-file?file={path.name}",
            }
        )

    return {
        "engine": "aegis-reports-center-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "policy": "Each record is based on a real PDF file in the reports/ directory and a history entry.",
        "summary": {
            "total_reports": len(items),
            "total_bytes": sum(item["size_bytes"] for item in items),
            "latest_filename": items[0]["filename"] if items else None,
            "linked_to_scan": sum(1 for item in items if item.get("scan")),
        },
        "reports": items[:60],
    }
