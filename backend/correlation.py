"""AI Correlation Engine for AegisAI V2.

The engine never invents findings. It builds a normalized evidence list from
real scanner output, groups evidence that points at the same weakness, and
classifies each group using deterministic rules. Gemini is used only to
explain already-established groups; its text is validated and cannot change
severity, classification or evidence.
"""

import json
import os
import re
import time
from datetime import datetime

from backend.guardrail import local_pattern_check

MAX_GROUPS = 40
MAX_EXPLANATION_CHARS = 700


def _text(value) -> str:
    return str(value if value is not None else "")[:200]


def _canonical_key(text: str) -> str:
    value = _text(text).lower()
    if "sql" in value or "sqli" in value:
        return "SQL_INJECTION"
    if "xss" in value or "cross site script" in value or "script injection" in value:
        return "XSS"
    if "ssti" in value or ("template" in value and "inject" in value):
        return "TEMPLATE_INJECTION"
    if "hardcoded" in value or "api_secret" in value or "secret key" in value:
        return "HARDCODED_SECRET"
    if "debug token" in value or "admin password" in value or "credential" in value:
        return "EXPOSED_CREDENTIALS"
    if "idor" in value or "direct object" in value:
        return "BROKEN_AUTHORIZATION"
    if "traversal" in value:
        return "PATH_TRAVERSAL"
    if "cookie" in value:
        return "INSECURE_COOKIE"
    if "content-security-policy" in value or " csp" in value or ("header" in value and "missing" in value):
        return "MISSING_SECURITY_HEADER"
    if "debug endpoint" in value or "hidden" in value or "backup" in value or ".env" in value:
        return "SENSITIVE_EXPOSURE"
    if "server version" in value or "version disclosure" in value:
        return "TECHNOLOGY_DISCLOSURE"
    if "port" in value and "open" in value:
        return "OPEN_PORT"
    if "subdomain" in value or "ptr" in value or "dns" in value:
        return "DNS_EXPOSURE"
    return "OTHER"


def _severity_rank(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(str(severity).upper(), 1)


def _evidence(source: str, tool: str, title: str, endpoint: str, detail: str, severity="INFO") -> dict:
    return {
        "source": source,
        "tool": tool,
        "title": _text(title),
        "endpoint": _text(endpoint),
        "detail": _text(detail),
        "severity": str(severity).upper(),
        "key": _canonical_key(f"{title} {detail}"),
    }


def build_evidence(audit: dict) -> list[dict]:
    """Converts actual tool output into normalized, bounded evidence items."""
    items: list[dict] = []

    for finding in audit.get("findings", []) or []:
        items.append(
            _evidence(
                source="static",
                tool="auditor",
                title=finding.get("title", ""),
                endpoint=finding.get("endpoint", ""),
                detail=f"{finding.get('id', '')} :: {finding.get('explanation', '')}",
                severity=finding.get("severity", "LOW"),
            )
        )

    dast = audit.get("dast") or {}
    sqlmap = dast.get("sqlmap") or {}
    if sqlmap.get("injectable"):
        items.append(
            _evidence(
                source="dynamic",
                tool="sqlmap",
                title="SQL injection confirmed by sqlmap",
                endpoint=dast.get("target", ""),
                detail=(
                    f"parameters={', '.join(sqlmap.get('parameters', []))}; "
                    f"types={', '.join(sqlmap.get('types', []))}; "
                    f"dbms={sqlmap.get('dbms') or 'unknown'}; "
                    f"payloads={len(sqlmap.get('payloads', []))}"
                ),
                severity="CRITICAL",
            )
        )

    for alert in (dast.get("zap") or {}).get("alerts", []) or []:
        items.append(
            _evidence(
                source="dynamic",
                tool="zap",
                title=alert.get("title", ""),
                endpoint=alert.get("endpoint", ""),
                detail=f"risk={alert.get('risk', '')}; instances={alert.get('instances', 0)}",
                severity="HIGH" if "high" in str(alert.get("risk", "")).lower() else "MEDIUM",
            )
        )

    for finding in (dast.get("nuclei") or {}).get("findings", []) or []:
        items.append(
            _evidence(
                source="dynamic",
                tool="nuclei",
                title=finding.get("name") or finding.get("id", ""),
                endpoint=finding.get("endpoint", ""),
                detail=f"template={finding.get('id', '')}",
                severity=finding.get("severity", "INFO"),
            )
        )

    for entry in (dast.get("gofile") or {}).get("findings", []) or []:
        if not entry.get("hidden"):
            continue
        items.append(
            _evidence(
                source="dynamic",
                tool="gofile",
                title="Hidden or sensitive resource exposed",
                endpoint=entry.get("path", ""),
                detail=f"http_status={entry.get('status', '')}; size={entry.get('size', '')}",
                severity="HIGH",
            )
        )

    for port in (dast.get("nmap") or {}).get("ports", []) or []:
        items.append(
            _evidence(
                source="asset",
                tool="nmap",
                title=f"Open port {port.get('port', '')}",
                endpoint=str(port.get("port", "")),
                detail=f"service={port.get('service', '')}; version={port.get('version', '')}",
                severity="INFO",
            )
        )

    dns = dast.get("dnsrecon") or {}
    for subdomain in dns.get("subdomains", []) or []:
        items.append(
            _evidence(
                source="asset",
                tool="dnsrecon",
                title="Local lab subdomain resolved",
                endpoint=subdomain.get("host", ""),
                detail=f"ip={subdomain.get('ip', '')}",
                severity="INFO",
            )
        )

    # Real negative tool results are retained as context, never as findings.
    if sqlmap and not sqlmap.get("injectable") and sqlmap.get("error"):
        items.append(
            _evidence(
                source="negative",
                tool="sqlmap",
                title="Dynamic SQL injection probe negative",
                endpoint=dast.get("target", ""),
                detail=str(sqlmap.get("error")),
                severity="INFO",
            )
        )
    return items[:120]


def _classify(items: list[dict]) -> tuple[str, float, str]:
    sources = {item["source"] for item in items}
    tools = {item["tool"] for item in items}
    key = items[0]["key"] if items else "OTHER"

    if items and all(item["source"] == "negative" for item in items):
        return "Unverified", 0.25, "Only a negative dynamic result exists; the vulnerability could not be confirmed."
    if items and all(item["source"] == "asset" for item in items):
        return "Informational", 0.9, "Asset/inventory data; not interpreted as a vulnerability."
    if "dynamic" in sources and tools & {"sqlmap", "nuclei", "zap", "gofile"}:
        return "Confirmed", 0.95, "At least one dynamic scanner confirmed this finding."
    if "static" in sources and "negative" not in sources:
        return "Potential", 0.6, "It is based on a real source-code pattern; there is no dynamic confirmation."
    if "static" in sources and "negative" in sources:
        return "Potential", 0.45, "Static evidence exists, but the dynamic probe did not reproduce it; it remains potential."
    if sources:
        return "Unverified", 0.35, "Insufficient evidence; not counted as a confirmed vulnerability."
    return "Informational", 0.1, "No evidence."


def _recommendation(key: str) -> str:
    return {
        "SQL_INJECTION": "Convert all SQL queries to parameterized queries and validate user-supplied values.",
        "XSS": "Escape user input in the HTML context before rendering, and add a CSP.",
        "TEMPLATE_INJECTION": "Do not concatenate user input into template source; use a Jinja2 context variable.",
        "HARDCODED_SECRET": "Move secrets to environment variables or a secure secret store, and revoke the old value.",
        "EXPOSED_CREDENTIALS": "Disable the debug endpoint, move credentials to environment variables, and require authorization.",
        "BROKEN_AUTHORIZATION": "Check user authorization on the server for every object access.",
        "PATH_TRAVERSAL": "Canonicalize the filename and verify that it stays inside the allowed directory.",
        "INSECURE_COOKIE": "Add HttpOnly, Secure and SameSite attributes to cookies.",
        "MISSING_SECURITY_HEADER": "Add CSP and other security headers to server responses.",
        "SENSITIVE_EXPOSURE": "Move sensitive files, backups and debug endpoints outside the web root, or block access.",
        "TECHNOLOGY_DISCLOSURE": "Do not expose server or technology version information unnecessarily.",
        "OPEN_PORT": "Close unnecessary ports; restrict the remaining services to localhost and a firewall.",
        "DNS_EXPOSURE": "Keep lab DNS records only in the authorized test environment.",
    }.get(key, "Apply the relevant code or configuration change for the confirmed finding, then rescan.")


def _ai_enrich(groups: list[dict]) -> dict[str, dict]:
    """Adds explanations only for existing groups; never adds new findings."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or not groups:
        return {}

    lines = []
    for group in groups:
        evidence = "; ".join(f"{e['tool']}:{e['title']}" for e in group["evidence"][:4])
        lines.append(
            f"{group['id']} | {group['classification']} | {group['title']} | evidence={evidence[:300]}"
        )
    summary = "\n".join(lines)[:3000]
    safe, _ = local_pattern_check(summary)
    if not safe:
        return {}

    try:
        from google import genai
        from google.genai import types

        model = os.getenv("AEGIS_GEMINI_MODEL", "gemini-3.1-flash-lite")
        client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=15000))
        prompt = (
            "You are AegisAI correlation analyst. The evidence below comes from real scanner output. "
            "For each existing group id, return ONLY a JSON array of objects with keys id, analysis, "
            "recommendation. Do not invent new ids, CVEs, findings, or evidence. Keep each value under "
            "80 words. If evidence is insufficient, say so.\n\n" + summary
        )
        response = client.models.generate_content(model=model, contents=prompt)
        raw = (response.text or "").strip()
        raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return {}
        result: dict[str, dict] = {}
        valid_ids = {g["id"] for g in groups}
        for item in parsed:
            if not isinstance(item, dict) or item.get("id") not in valid_ids:
                continue
            result[item["id"]] = {
                "analysis": _text(item.get("analysis", ""))[:MAX_EXPLANATION_CHARS],
                "recommendation": _text(item.get("recommendation", ""))[:MAX_EXPLANATION_CHARS],
            }
        return result
    except Exception:
        return {}


def correlate(audit: dict) -> dict:
    """Correlates real evidence from all tools into ranked, classified groups."""
    evidence = build_evidence(audit)
    buckets: dict[str, list[dict]] = {}
    for item in evidence:
        if item["key"] == "OTHER":
            key = f"OTHER::{item['tool']}::{item['title']}"[:80]
            item["key"] = key
        buckets.setdefault(item["key"], []).append(item)

    groups = []
    for index, (key, items) in enumerate(sorted(buckets.items()), start=1):
        classification, confidence, reason = _classify(items)
        severity = max((item["severity"] for item in items), key=_severity_rank, default="INFO")
        title = items[0]["title"] or key.replace("_", " ").title()
        groups.append(
            {
                "id": f"CORR-{index:03d}",
                "key": key,
                "title": title,
                "classification": classification,
                "confidence": confidence,
                "reason": reason,
                "severity": severity,
                "risk_rank": 0,
                "endpoints": sorted({item["endpoint"] for item in items if item["endpoint"]}),
                "tools": sorted({item["tool"] for item in items}),
                "evidence": items,
                "analysis": reason,
                "recommendation": _recommendation(key),
            }
        )

    order = {"Confirmed": 0, "Potential": 1, "Unverified": 2, "Informational": 3, "False Positive": 4}
    groups.sort(
        key=lambda g: (
            order.get(g["classification"], 5),
            -_severity_rank(g["severity"]),
            -g["confidence"],
        )
    )
    for rank, group in enumerate(groups[:MAX_GROUPS], start=1):
        group["risk_rank"] = rank

    groups = groups[:MAX_GROUPS]
    ai = _ai_enrich(groups)
    for group in groups:
        enrichment = ai.get(group["id"], {})
        if enrichment.get("analysis"):
            group["ai_analysis"] = enrichment["analysis"]
        if enrichment.get("recommendation"):
            group["ai_recommendation"] = enrichment["recommendation"]

    summary = {
        "total": len(groups),
        "confirmed": sum(1 for g in groups if g["classification"] == "Confirmed"),
        "potential": sum(1 for g in groups if g["classification"] == "Potential"),
        "unverified": sum(1 for g in groups if g["classification"] == "Unverified"),
        "false_positive": sum(1 for g in groups if g["classification"] == "False Positive"),
        "informational": sum(1 for g in groups if g["classification"] == "Informational"),
        "evidence_items": len(evidence),
        "ai_mode": "gemini" if ai else "deterministic",
    }

    return {
        "engine": "aegis-correlation-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "groups": groups,
        "policy": (
            "A finding is marked Confirmed only with real dynamic tool evidence. "
            "Source-pattern findings are Potential, insufficient evidence is Unverified, "
            "and asset/inventory data is Informational."
        ),
    }
