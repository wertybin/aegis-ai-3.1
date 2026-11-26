"""AegisAI V2 API Security (PHASE 9).

Builds an endpoint-level API risk view from real scan evidence: static routes,
real findings, correlation groups and, when available, the localhost HTTP
snapshot. Security controls are reported as "observed in source" or "not
observed in source" - never as a claim that an endpoint is safe.
"""

import re
from pathlib import Path

from backend import history
from backend.remediation import LAB_DIR

API_PREFIXES = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/")
AUTH_MARKERS = (
    "current_user_can_access",
    "authorization",
    "auth_required",
    "@login_required",
    "check_auth",
    "verify_token",
    "x-api-key",
)
VALIDATION_MARKERS = ("isinstance(", "validate", "schema", "int(", "re.fullmatch", "escape(")
RATE_MARKERS = ("rate_limit", "ratelimit", "throttle", "limiter")


def _audit_for(scan_id: str | None = None) -> dict | None:
    if scan_id:
        record = history.get_scan(scan_id)
        if not record:
            return None
        result = record.get("result") or {}
        return result.get("audit") or (result if "findings" in result else None)
    for record in history.read_scans():
        result = record.get("result") or {}
        audit = result.get("audit") or (result if "findings" in result else None)
        if audit and audit.get("endpoints"):
            return audit
    return None


def _route_body(code: str, line_number: int, max_lines: int = 18) -> str:
    lines = code.splitlines()
    start = max(0, line_number - 1)
    block = lines[start : start + max_lines]
    for index, text in enumerate(block[1:], start=1):
        if text.strip().startswith("@app.route("):
            return "\n".join(block[:index])
    return "\n".join(block)


def _risk(findings: list[dict], groups: list[dict]) -> tuple[str, list[dict]]:
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    level = 0
    evidence = []
    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        level = max(level, rank.get(severity, 1))
        evidence.append({"source": "static_audit", "title": finding.get("title"), "detail": severity})
    for group in groups:
        classification = str(group.get("classification", ""))
        group_rank = {"Confirmed": 4, "Potential": 3, "Unverified": 2, "Informational": 1}.get(classification, 1)
        level = max(level, group_rank)
        for item in (group.get("evidence") or [])[:3]:
            evidence.append(
                {
                    "source": f"correlation:{classification}",
                    "title": item.get("title"),
                    "detail": item.get("tool"),
                }
            )
    names = {0: "NONE", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    return names[level], evidence[:8]


def analyze_api_security(scan_id: str | None = None) -> dict:
    audit = _audit_for(scan_id)
    if audit is None:
        return {
            "engine": "aegis-api-security-v1",
            "available": False,
            "reason": "No completed static audit available.",
            "endpoints": [],
            "summary": {},
        }

    findings = audit.get("findings") or []
    groups = (audit.get("correlations") or {}).get("groups") or []
    surface = audit.get("attack_surface") or {}
    snapshot = surface.get("snapshot") or {}

    source_path = Path(str(audit.get("file_path") or ""))
    code = ""
    if source_path.exists() and LAB_DIR in source_path.resolve().parents:
        code = source_path.read_text(encoding="utf-8", errors="replace")

    api_paths: list[str] = []
    for endpoint in audit.get("endpoints") or []:
        path = str(endpoint.get("path") or "")
        if path.startswith(API_PREFIXES) and path not in api_paths:
            api_paths.append(path)
    for node in surface.get("nodes") or []:
        if node.get("kind") == "endpoint":
            label = str(node.get("label") or "")
            if label.startswith(API_PREFIXES) and label not in api_paths:
                api_paths.append(label)
    for path in snapshot.get("endpoints") or []:
        if str(path).startswith(API_PREFIXES) and str(path) not in api_paths:
            api_paths.append(str(path))

    results = []
    for path in api_paths[:40]:
        linked_findings = [f for f in findings if f.get("endpoint") == path]
        linked_groups = [
            g for g in groups if path in (g.get("endpoints") or [])
        ]
        risk, evidence = _risk(linked_findings, linked_groups)

        line = next(
            (e.get("line") for e in audit.get("endpoints") or [] if e.get("path") == path),
            None,
        )
        body = _route_body(code, int(line)) if line and code else ""
        lowered = body.lower()

        def observed(markers: tuple[str, ...]) -> bool:
            return any(marker.lower() in lowered for marker in markers)

        controls = {
            "authorization_in_source": observed(AUTH_MARKERS),
            "input_validation_in_source": observed(VALIDATION_MARKERS),
            "rate_limit_in_source": observed(RATE_MARKERS),
        }
        results.append(
            {
                "path": path,
                "line": line,
                "risk": risk,
                "finding_count": len(linked_findings),
                "correlation_count": len(linked_groups),
                "controls": controls,
                "evidence": evidence,
                "evidence_sources": sorted({item["source"] for item in evidence}),
            }
        )

    results.sort(key=lambda item: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}[item["risk"]], item["path"]))
    risky = [item for item in results if item["risk"] in {"CRITICAL", "HIGH"}]
    summary = {
        "api_endpoints": len(results),
        "critical_or_high": len(risky),
        "with_auth_observed": sum(1 for item in results if item["controls"]["authorization_in_source"]),
        "without_auth_observed": sum(1 for item in results if not item["controls"]["authorization_in_source"]),
        "with_rate_limit_observed": sum(1 for item in results if item["controls"]["rate_limit_in_source"]),
        "linked_findings": sum(item["finding_count"] for item in results),
        "local_snapshot_status": snapshot.get("status_code"),
        "source_file": audit.get("file_name"),
    }

    return {
        "engine": "aegis-api-security-v1",
        "available": True,
        "scan_id": scan_id or "latest",
        "generated_from": "real persisted audit + correlation + local HTTP snapshot",
        "policy": (
            "API risk is derived only from real scan evidence. Controls are reported as observed "
            "or not observed in source; AEGIS never claims they are secure."
        ),
        "summary": summary,
        "endpoints": results,
    }
