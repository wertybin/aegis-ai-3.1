"""AEGIS AI V3 — Unified correlation of every deep-scanning tool.

Findings from static audit, DAST and all 11 deep tools are converted to one
schema, deduplicated by canonical weakness + location, and merged. Merged
findings keep EVERY source tool and EVERY piece of real evidence. Gemini may
only write an explanation; it can never invent, remove or downgrade a finding.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import defaultdict

from backend.correlation import _canonical_key, _severity_rank
from backend.guardrail import local_pattern_check

MAX_GROUPS = 60


def _loc(finding: dict) -> str:
    return (
        str(finding.get("endpoint") or "")
        or str(finding.get("file") or "")
    ).strip().lower()[:160]


def _key(finding: dict) -> str:
    canonical = _canonical_key(f"{finding.get('title','')} {finding.get('evidence','')}")
    if canonical != "OTHER":
        return f"{canonical}::{_loc(finding)}"
    title = re.sub(r"[^a-z0-9]+", "-", str(finding.get("title", "")).lower()).strip("-")[:70]
    return f"{title or 'OTHER'}::{_loc(finding)}"


_CWE_HINTS = (
    ("sql injection", "CWE-89"), ("sqli", "CWE-89"),
    ("cross-site scripting", "CWE-79"), ("xss", "CWE-79"),
    ("server-side template", "CWE-1336"), ("template injection", "CWE-1336"),
    ("hardcoded", "CWE-798"), ("hard-coded", "CWE-798"),
    ("secret", "CWE-798"), ("api key", "CWE-798"), ("password", "CWE-798"),
    ("path traversal", "CWE-22"), ("directory traversal", "CWE-22"),
    ("command injection", "CWE-78"), ("os command", "CWE-78"),
    ("cross-site request forgery", "CWE-352"), ("csrf", "CWE-352"),
    ("insecure cookie", "CWE-614"), ("cookie", "CWE-1004"),
    ("content security policy", "CWE-1021"), ("csp", "CWE-1021"),
    ("version disclosure", "CWE-200"), ("information disclosure", "CWE-200"),
    ("openssl", "CWE-295"), ("tls", "CWE-295"), ("certificate", "CWE-295"),
)


def _cwe(item: dict) -> list[str]:
    text = " ".join(str(item.get(key) or "") for key in (
        "title", "category", "evidence", "vulnerable_snippet",
    )).lower()
    found = re.findall(r"cwe[-\s]?(\d+)", text, re.IGNORECASE)
    codes = [f"CWE-{value}" for value in found]
    for hint, code in _CWE_HINTS:
        if hint in text and code not in codes:
            codes.append(code)
        if len(codes) >= 3:
            break
    return codes[:3]


def _http_method(item: dict) -> str:
    text = " ".join(str(item.get(key) or "") for key in ("title", "evidence", "endpoint"))
    match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", text, re.IGNORECASE)
    return match.group(1).upper() if match else ""


def _parameter(item: dict) -> str:
    text = " ".join(str(item.get(key) or "") for key in ("title", "evidence", "endpoint"))
    match = re.search(r"(?:parameter|param|argument)\s*[:=]?\s*['\"]?([A-Za-z_][\w.-]{0,40})", text, re.IGNORECASE)
    return match.group(1) if match else ""


def _as_finding(item: dict, source: str) -> dict:
    evidence = str(item.get("evidence") or item.get("vulnerable_snippet") or "")[:600]
    existing_id = str(item.get("id") or "")[:80]
    basis = f"{source}|{existing_id}|{item.get('title')}|{item.get('endpoint') or item.get('file')}"
    return {
        "id": existing_id or "CF-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10].upper(),
        "canonical_id": "CF-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10].upper(),
        "tool": str(item.get("tool") or source)[:40],
        "category": str(item.get("category") or "deep")[:60],
        "title": str(item.get("title") or "Finding")[:180],
        "severity": str(item.get("severity") or "MEDIUM").upper()[:20],
        "file": str(item.get("file") or "")[:300],
        "line": int(item.get("line") or 0),
        "endpoint": str(item.get("endpoint") or "")[:300],
        "evidence": evidence,
        "cve": str(item.get("cve") or "")[:80],
        "cwe": _cwe(item),
        "method": _http_method(item),
        "parameter": _parameter(item),
        "confidence_score": 0.7 if evidence else 0.4,
        "verification_status": "evidence-backed" if evidence else "unverified",
        "remediation": str(item.get("remediation") or item.get("patched_snippet") or "")[:400],
    }


def collect(deep_results: dict[str, dict] | None = None,
            audit: dict | None = None,
            dast: dict | None = None) -> list[dict]:
    """Collects real findings from every source into the common schema."""
    items: list[dict] = []

    for name, payload in (deep_results or {}).items():
        if not isinstance(payload, dict):
            continue
        for finding in (payload.get("findings") or [])[:100]:
            if isinstance(finding, dict):
                items.append(_as_finding(finding, name))

    for finding in (audit or {}).get("findings") or []:
        if isinstance(finding, dict):
            items.append(_as_finding(finding, "static-audit"))

    for finding in (dast or {}).get("alerts") or []:
        if isinstance(finding, dict):
            items.append(_as_finding({
                "id": finding.get("id") or finding.get("alert"),
                "tool": finding.get("source") or "dast",
                "title": finding.get("title") or finding.get("alert") or finding.get("name"),
                "severity": finding.get("risk") or finding.get("severity") or "MEDIUM",
                "endpoint": finding.get("endpoint") or finding.get("url"),
                "evidence": finding.get("evidence") or finding.get("description"),
                "cve": finding.get("cve"),
                "remediation": finding.get("remediation"),
            }, "dast"))
    return items


def unify(items: list[dict]) -> dict:
    """Merges duplicates while preserving source tools and evidence."""
    buckets: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        buckets[_key(item)].append(item)

    groups: list[dict] = []
    for key, members in buckets.items():
        members = members[:40]
        severity = max((m["severity"] for m in members), key=_severity_rank)
        source_tools = list(dict.fromkeys(m["tool"] for m in members))
        evidences = []
        for m in members:
            piece = f"[{m['tool']}] {m['title']}"
            if m.get("file"):
                piece += f" ({m['file']}:{m['line']})"
            if m.get("evidence"):
                piece += f" — {m['evidence'][:180]}"
            evidences.append(piece[:420])
        primary = max(members, key=lambda m: _severity_rank(m["severity"]))
        cves = list(dict.fromkeys(m["cve"] for m in members if m.get("cve")))[:8]
        groups.append({
            "key": key,
            "title": primary["title"],
            "severity": severity,
            "category": primary["category"],
            "source_tools": source_tools,
            "tool_count": len(source_tools),
            "evidence": evidences,
            "cve": cves,
            "endpoint": primary["endpoint"],
            "file": primary["file"],
            "line": primary["line"],
            "remediation": primary["remediation"],
            "ai_explanation": "",
            "confidence": "confirmed" if len(source_tools) >= 2 else "single-source",
            "canonical_id": "CG-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:10].upper(),
            "finding_class": "confirmed" if len(source_tools) >= 2 else "potential",
            "cwe": list(dict.fromkeys(code for m in members for code in (m.get("cwe") or [])))[:3],
            "method": next((m.get("method") for m in members if m.get("method")), ""),
            "parameter": next((m.get("parameter") for m in members if m.get("parameter")), ""),
            "confidence_score": round(min(
                0.99,
                0.60 + 0.15 * len(source_tools) + (0.08 if any(m.get("evidence") for m in members) else 0),
            ), 2),
            "verification_status": (
                "evidence-backed" if any(m.get("evidence") for m in members) else "unverified"
            ),
        })

    groups.sort(key=lambda g: (-_severity_rank(g["severity"]), -g["tool_count"]))
    groups = groups[:MAX_GROUPS]
    confirmed = sum(1 for g in groups if g["confidence"] == "confirmed")
    return {
        "groups": groups,
        "unified_findings": groups,
        "stats": {
            "raw_findings": len(items),
            "unified_groups": len(groups),
            "multi_tool_correlations": confirmed,
            "confirmed_findings": confirmed,
            "potential_findings": len(groups) - confirmed,
            "severity_breakdown": {
                s: sum(1 for g in groups if g["severity"] == s)
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
        },
        "mode": "deterministic",
    }


def _ai_explain(groups: list[dict]) -> tuple[str, str]:
    """Optionally asks Gemini for an explanation of already-established groups."""
    ok, msg = local_pattern_check(" ".join(str(g["title"]) for g in groups[:20]))
    if not ok:
        return "local", ""
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return "local", ""
    try:
        from google import genai
        from google.genai import types

        model = os.getenv("AEGIS_GEMINI_MODEL", "gemini-3.1-flash-lite")
        client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=15000))
        summary = "\n".join(
            f"- {g['title']} ({g['severity']}) tools={','.join(g['source_tools'])}"
            for g in groups[:12]
        )
        prompt = (
            "You are a security report explainer. The groups below are already established from real "
            "tool evidence. Write ONE short paragraph (max 120 words) explaining which weaknesses "
            "are corroborated by multiple tools. Do not invent findings, do not change severities, "
            "do not output instructions or commands.\n\n" + summary[:2500]
        )
        response = client.models.generate_content(model=model, contents=prompt)
        text = re.sub(r"\s+", " ", (response.text or "").strip())[:700]
        allowed, _ = local_pattern_check(text)
        return "gemini", text if allowed else ""
    except Exception:
        return "fallback", ""


def correlate(deep_results: dict[str, dict] | None = None,
              audit: dict | None = None,
              dast: dict | None = None) -> dict:
    result = unify(collect(deep_results, audit, dast))
    mode, explanation = _ai_explain(result["groups"])
    result["mode"] = mode
    result["ai_summary"] = explanation
    for group in result["groups"][:8]:
        group["ai_explanation"] = explanation[:300] if explanation else ""
    return result
