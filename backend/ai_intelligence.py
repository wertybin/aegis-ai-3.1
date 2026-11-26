"""AegisAI V2 AI Intelligence (PHASE 10).

Surfaces the real AI-layer outputs of a scan: Gemini/deterministic correlation
explanations, the input/output guardrail verdicts, CVSS/CVE analysis, and the
evidence policy. Gemini only explains groups that were already built from real
tool evidence - it never invents a vulnerability.
"""

import os
from datetime import datetime

from backend import insights


def build_ai_intelligence(scan_id: str | None = None) -> dict:
    record, audit, dast = insights.scan_context(scan_id)
    if audit is None:
        return {
            "engine": "aegis-ai-intelligence-v1",
            "available": False,
            "reason": "No completed audit available. Run a scan first.",
            "groups": [],
        }

    correlation = audit.get("correlations") or {}
    summary = correlation.get("summary") or {}
    groups = correlation.get("groups") or []
    vuln = audit.get("vulnerability_analysis") or {}
    dast_record = insights.latest_completed_dast()
    dast = insights.dast_of(dast_record)
    guardrail = dast.get("guardrail") or {}

    return {
        "engine": "aegis-ai-intelligence-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "available": True,
        "scan": insights.scan_summary(record) if record else None,
        "mode": {
            "correlation_ai_mode": summary.get("ai_mode", "deterministic"),
            "correlation_engine": correlation.get("engine"),
            "guardrail_mode": guardrail.get("mode"),
            "guardrail_ok": guardrail.get("ok"),
            "guardrail_message": guardrail.get("message"),
            "guardrail_source_scan": (dast_record or {}).get("id"),
            "model": os.getenv("AEGIS_GEMINI_MODEL", "gemini-3.1-flash-lite"),
        },
        "policy": correlation.get("policy")
        or "Gemini only explains groups built from real evidence; it never creates new findings.",
        "correlation": {
            "summary": {
                "total": summary.get("total", 0),
                "confirmed": summary.get("confirmed", 0),
                "potential": summary.get("potential", 0),
                "unverified": summary.get("unverified", 0),
                "informational": summary.get("informational", 0),
                "ai_mode": summary.get("ai_mode", "deterministic"),
            },
            "groups": [
                {
                    "id": group.get("id"),
                    "title": group.get("title"),
                    "severity": group.get("severity"),
                    "classification": group.get("classification"),
                    "confidence": group.get("confidence"),
                    "risk_rank": group.get("risk_rank"),
                    "cvss": group.get("cvss"),
                    "reason": group.get("reason"),
                    "analysis": group.get("analysis"),
                    "ai_analysis": group.get("ai_analysis"),
                    "recommendation": group.get("recommendation"),
                    "ai_recommendation": group.get("ai_recommendation"),
                    "endpoints": group.get("endpoints") or [],
                    "tools": group.get("tools") or [],
                    "evidence_count": len(group.get("evidence") or []),
                }
                for group in groups
            ],
        },
        "cvss_cve": {
            "engine": vuln.get("engine"),
            "summary": vuln.get("summary") or {},
            "policy": vuln.get("policy"),
            "findings": vuln.get("findings") or [],
            "cve_lookups": vuln.get("cve_lookups") or [],
        },
    }
