"""AegisAI V2 Before & After (PHASE 8).

Compares two real scans persisted in history. Every number comes from the
stored scan result; the module never invents a vulnerability or a score.
"""

from datetime import datetime

from backend import history

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CLASSIFICATIONS = ("Confirmed", "Potential", "Unverified", "Informational")


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def _finding_key(finding: dict) -> tuple[str, str, str]:
    return (
        str(finding.get("id", "")),
        str(finding.get("title", "")),
        str(finding.get("endpoint", "")),
    )


def _detail(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "endpoint": finding.get("endpoint"),
    }


def summarize(record: dict) -> dict:
    """Normalizes one history record into a comparable, real-data summary."""
    result = record.get("result") or {}
    # Audit and patch scans store the audit at the top level; DAST scans nest it.
    audit = result.get("audit") or (result if "findings" in result else {})
    dast = result.get("dast") or {}
    findings = audit.get("findings") or []
    correlations = audit.get("correlations") or {}
    correlation_summary = correlations.get("summary") or {}
    vuln_summary = (audit.get("vulnerability_analysis") or {}).get("summary") or {}
    surface_stats = (audit.get("attack_surface") or {}).get("stats") or {}
    graph_stats = (audit.get("attack_graph") or {}).get("stats") or {}
    tools = dast.get("tools") or {}

    return {
        "id": record.get("id"),
        "mode": record.get("mode"),
        "status": record.get("status"),
        "target": record.get("target"),
        "created_at": record.get("created_at") or record.get("started_at"),
        "file_name": audit.get("file_name") or result.get("file_name"),
        "pdf_filename": record.get("pdf_filename"),
        "score": record.get("score") if record.get("score") is not None else audit.get("score"),
        "finding_count": len(findings),
        "severity_counts": _severity_counts(findings),
        "endpoint_count": len(audit.get("endpoints") or []),
        "findings": [_detail(f) for f in findings],
        "correlations": {
            name: correlation_summary.get(name, 0) for name in CLASSIFICATIONS
        },
        "correlation_groups": correlation_summary.get("total", 0),
        "cvss": {
            "max": vuln_summary.get("max_cvss"),
            "average": vuln_summary.get("average_cvss"),
            "critical": vuln_summary.get("critical_cvss", 0),
            "high": vuln_summary.get("high_cvss", 0),
        },
        "total_cves": vuln_summary.get("total_cves", 0),
        "surface": {
            "services": surface_stats.get("services", 0),
            "endpoints": surface_stats.get("endpoints", 0),
            "resources": surface_stats.get("resources", 0),
        },
        "graph": {
            "nodes": graph_stats.get("nodes", 0),
            "evidence_edges": graph_stats.get("evidence_edges", 0),
            "theoretical_edges": graph_stats.get("theoretical_edges", 0),
        },
        "tools": {str(name): (value or {}).get("status") for name, value in tools.items()},
    }


def list_comparable(limit: int = 40) -> list[dict]:
    records = history.read_scans(limit)
    return [summarize(record) for record in records if record.get("status") == "completed"]


def default_pair(limit: int = 40) -> tuple[str | None, str | None]:
    """Picks a real before/after pair from history (newest improvement first).

    History is newest-first, so ``after`` is always the newer scan. When a real
    post-remediation improvement exists it is preferred; otherwise any real
    score change is used. The user can still select any two scans explicitly.
    """
    scans = list_comparable(limit)
    if not scans:
        return None, None
    for index, after in enumerate(scans):
        for before in scans[index + 1 :]:
            if (before.get("score") or 0) < (after.get("score") or 0):
                return before.get("id"), after.get("id")
    for index, after in enumerate(scans):
        for before in scans[index + 1 :]:
            if after.get("score") != before.get("score"):
                return before.get("id"), after.get("id")
    if len(scans) >= 2:
        return scans[1].get("id"), scans[0].get("id")
    return None, None


def compare(before_id: str | None = None, after_id: str | None = None) -> dict:
    explicit_selection = bool(before_id and after_id)
    if not before_id or not after_id:
        before_id, after_id = default_pair()
    records = history.read_scans(history.MAX_RECORDS)
    before_record = next((r for r in records if r.get("id") == before_id), None)
    after_record = next((r for r in records if r.get("id") == after_id), None)
    if before_record is None or after_record is None:
        raise ValueError("One of the selected scans was not found in history.")

    before = summarize(before_record)
    after = summarize(after_record)

    before_map = {_finding_key(f): f for f in before["findings"]}
    after_map = {_finding_key(f): f for f in after["findings"]}
    fixed = [_detail(before_map[key]) for key in sorted(set(before_map) - set(after_map), key=str)]
    introduced = [_detail(after_map[key]) for key in sorted(set(after_map) - set(before_map), key=str)]
    persisting = [_detail(after_map[key]) for key in sorted(set(after_map) & set(before_map), key=str)]

    score_delta = (after["score"] or 0) - (before["score"] or 0)
    new_high = sum(1 for f in introduced if f.get("severity") in {"CRITICAL", "HIGH"})
    if new_high or score_delta < 0:
        verdict = "REGRESSED"
    elif score_delta > 0 and fixed:
        verdict = "IMPROVED"
    else:
        verdict = "UNCHANGED"

    return {
        "engine": "aegis-before-after-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "selection": (
            "explicit" if explicit_selection else "default: newest real improvement in history"
        ),
        "policy": (
            "All values are read from real scan records in reports/history.json. "
            "Before/After is a comparison; no simulator or sample data is used."
        ),
        "verdict": verdict,
        "before": before,
        "after": after,
        "deltas": {
            "score": score_delta,
            "finding_count": after["finding_count"] - before["finding_count"],
            "endpoint_count": after["endpoint_count"] - before["endpoint_count"],
            "correlation_groups": after["correlation_groups"] - before["correlation_groups"],
            "severity": {
                name: after["severity_counts"][name] - before["severity_counts"][name]
                for name in SEVERITIES
            },
            "classification": {
                name: after["correlations"][name] - before["correlations"][name]
                for name in CLASSIFICATIONS
            },
            "surface_endpoints": after["surface"]["endpoints"] - before["surface"]["endpoints"],
            "graph_nodes": after["graph"]["nodes"] - before["graph"]["nodes"],
        },
        "fixed": fixed,
        "introduced": introduced,
        "persisting": persisting,
    }
