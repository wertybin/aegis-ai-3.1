"""AegisAI V2 Overview / Dashboard (PHASE 10).

A single consolidated view of the newest real scan plus scan-history health.
Every value is read from persisted history; there are no placeholder metrics.
"""

from datetime import datetime

from backend import insights


def build_overview() -> dict:
    all_records = insights.records()
    completed = [r for r in all_records if r.get("status") == "completed"]
    failed = [r for r in all_records if r.get("status") == "failed"]
    latest = insights.latest_completed()

    record = latest
    audit = insights.audit_of(record)
    # Engine health (guardrail + DAST tools) only exists on DAST scans. When the
    # newest scan is a static audit, read it from the newest real DAST scan and
    # label the source so nothing is implied to belong to the audit.
    dast_record = insights.latest_completed_dast()
    dast = insights.dast_of(dast_record)

    findings = (audit or {}).get("findings") or []
    correlations = (audit or {}).get("correlations") or {}
    correlation_summary = correlations.get("summary") or {}
    vuln = (audit or {}).get("vulnerability_analysis") or {}
    vuln_summary = vuln.get("summary") or {}
    surface_stats = ((audit or {}).get("attack_surface") or {}).get("stats") or {}
    graph_stats = ((audit or {}).get("attack_graph") or {}).get("stats") or {}

    guardrail = dast.get("guardrail") or {}
    tools = dast.get("tools") or {}
    tool_status = {name: (payload or {}).get("status") for name, payload in tools.items()}

    return {
        "engine": "aegis-overview-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "policy": "All metrics are read from real scan records; no projected or sample data is used.",
        "history": {
            "total_scans": len(all_records),
            "completed_scans": len(completed),
            "failed_scans": len(failed),
            "modes": {
                mode: sum(1 for r in completed if r.get("mode") == mode)
                for mode in ("audit", "dast", "patch")
            },
        },
        "latest": insights.scan_summary(latest) if latest else None,
        "security": {
            "score": record.get("score") if record else None,
            "finding_count": len(findings),
            "severity_counts": insights.severity_counts(findings),
            "endpoint_count": len((audit or {}).get("endpoints") or []),
            "correlation_groups": correlation_summary.get("total", 0),
            "confirmed": correlation_summary.get("confirmed", 0),
            "potential": correlation_summary.get("potential", 0),
            "unverified": correlation_summary.get("unverified", 0),
            "max_cvss": vuln_summary.get("max_cvss"),
            "average_cvss": vuln_summary.get("average_cvss"),
            "total_cves": vuln_summary.get("total_cves", 0),
        },
        "surface": {
            "services": surface_stats.get("services", 0),
            "endpoints": surface_stats.get("endpoints", 0),
            "resources": surface_stats.get("resources", 0),
            "graph_nodes": graph_stats.get("nodes", 0),
            "evidence_edges": graph_stats.get("evidence_edges", 0),
            "theoretical_edges": graph_stats.get("theoretical_edges", 0),
        },
        "engine_health": {
            "source_scan": (dast_record or {}).get("id"),
            "guardrail_ok": guardrail.get("ok"),
            "guardrail_mode": guardrail.get("mode"),
            "guardrail_message": guardrail.get("message"),
            "tool_status": tool_status,
            "tools_ok": sum(1 for value in tool_status.values() if value == "OK"),
            "tools_total": len(tool_status),
        },
        "pipeline": list(insights.PIPELINE_STAGES),
        "recent_scans": [insights.scan_summary(r) for r in completed[:8]],
    }
