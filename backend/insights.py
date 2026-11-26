"""Shared read-only helpers for the AegisAI V2 intelligence views (PHASE 10).

All helpers read the persisted real scan history. They never fabricate findings,
scores, or evidence. History records keep the V1 ``LATEST_STATE`` contract intact.
"""

from backend import history

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CLASSIFICATIONS = ("Confirmed", "Potential", "Unverified", "Informational")
PIPELINE_STAGES = [
    "Tool Check",
    "DNS Recon",
    "Nmap",
    "ffuf",
    "GoFile",
    "sqlmap",
    "OWASP ZAP",
    "Nuclei",
    "Guardrail & PDF",
]


def records(limit: int = 100) -> list[dict]:
    return history.read_scans(limit)


def latest_completed(limit: int = 100) -> dict | None:
    for record in history.read_scans(limit):
        if record.get("status") == "completed":
            return record
    return None


def latest_completed_dast(limit: int = 100) -> dict | None:
    for record in history.read_scans(limit):
        if record.get("status") == "completed" and record.get("mode") == "dast":
            return record
    return None


def audit_of(record: dict | None) -> dict | None:
    if not record:
        return None
    result = record.get("result") or {}
    return result.get("audit") or (result if "findings" in result else None)


def dast_of(record: dict | None) -> dict:
    if not record:
        return {}
    return (record.get("result") or {}).get("dast") or {}


def scan_context(scan_id: str | None = None) -> tuple[dict | None, dict | None, dict]:
    if scan_id:
        record = history.get_scan(scan_id)
    else:
        record = latest_completed()
    return record, audit_of(record), dast_of(record)


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings or []:
        severity = str(finding.get("severity", "LOW")).upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def scan_summary(record: dict) -> dict:
    audit = audit_of(record)
    dast = dast_of(record)
    correlation_summary = ((audit or {}).get("correlations") or {}).get("summary") or {}
    cvss_summary = ((audit or {}).get("vulnerability_analysis") or {}).get("summary") or {}
    return {
        "id": record.get("id"),
        "mode": record.get("mode"),
        "status": record.get("status"),
        "target": record.get("target"),
        "created_at": record.get("created_at") or record.get("started_at"),
        "finished_at": record.get("finished_at"),
        "duration_ms": record.get("duration_ms"),
        "score": record.get("score") if record.get("score") is not None else (audit or {}).get("score"),
        "pdf_filename": record.get("pdf_filename"),
        "file_name": (audit or {}).get("file_name"),
        "finding_count": len((audit or {}).get("findings") or []),
        "endpoint_count": len((audit or {}).get("endpoints") or []),
        "correlation_groups": correlation_summary.get("total", 0),
        "max_cvss": cvss_summary.get("max_cvss"),
        "guardrail_mode": (dast.get("guardrail") or {}).get("mode"),
        "error": record.get("error"),
    }
