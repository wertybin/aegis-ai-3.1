"""AegisAI V2 AI Copilot (PHASE 10).

Answers questions strictly from the latest REAL scan context. The user question
passes the existing local injection guardrail. Gemini is used when configured;
otherwise a deterministic, extractive responder quotes real values from the
scan. In every mode the answer is evidence-bound and the response names the
scan it came from. No invented vulnerability or metric is ever produced.
"""

import os
from datetime import datetime

from backend import insights
from backend.guardrail import local_pattern_check

MAX_FINDINGS = 12
MAX_GROUPS = 8


class CopilotBlocked(Exception):
    pass


def _build_context(scan_id: str | None = None) -> dict:
    record, audit, dast = insights.scan_context(scan_id)
    if audit is None:
        return {"available": False, "record": None, "text": "No completed scan is available."}

    findings = audit.get("findings") or []
    correlations = audit.get("correlations") or {}
    groups = correlations.get("groups") or []
    vuln = (audit or {}).get("vulnerability_analysis") or {}
    vuln_summary = vuln.get("summary") or {}
    guardrail = dast.get("guardrail") or {}
    tools = dast.get("tools") or {}

    lines = []
    lines.append(f"Scan: {(record or {}).get('id')} mode={(record or {}).get('mode')}")
    lines.append(f"Target: {(record or {}).get('target')} file={audit.get('file_name')}")
    lines.append(f"Security score: {(record or {}).get('score')}/100")
    counts = insights.severity_counts(findings)
    lines.append(
        "Findings: "
        + ", ".join(f"{name}={counts[name]}" for name in insights.SEVERITIES)
        + f" total={len(findings)}"
    )
    lines.append(f"Endpoints discovered: {len(audit.get('endpoints') or [])}")
    lines.append(
        "Correlations: "
        + ", ".join(
            f"{key}={(correlations.get('summary') or {}).get(key, 0)}"
            for key in ("total", "confirmed", "potential", "unverified", "informational")
        )
    )
    lines.append(
        "CVSS: max=" + str(vuln_summary.get("max_cvss")) + " avg=" + str(vuln_summary.get("average_cvss"))
        + " cves=" + str(vuln_summary.get("total_cves", 0))
    )
    lines.append(
        f"Guardrail: ok={guardrail.get('ok')} mode={guardrail.get('mode')} message={guardrail.get('message')}"
    )
    tool_text = ", ".join(
        f"{name}={(payload or {}).get('status')}" for name, payload in tools.items()
    )
    if tool_text:
        lines.append("DAST tools: " + tool_text)

    for finding in findings[:MAX_FINDINGS]:
        lines.append(
            f"FINDING {finding.get('id')} [{finding.get('severity')}] {finding.get('title')} "
            f"@ {finding.get('endpoint')}"
        )
    for group in groups[:MAX_GROUPS]:
        analysis = group.get("ai_analysis") or group.get("analysis") or ""
        recommendation = group.get("ai_recommendation") or group.get("recommendation") or ""
        lines.append(
            f"GROUP {group.get('id')} {group.get('classification')} {group.get('title')} "
            f"cvss={(group.get('cvss') or {}).get('base_score') if isinstance(group.get('cvss'), dict) else group.get('cvss')} "
            f"analysis={str(analysis)[:220]} recommendation={str(recommendation)[:220]}"
        )

    return {
        "available": True,
        "record": insights.scan_summary(record) if record else None,
        "text": "\n".join(lines),
        "findings": findings,
        "groups": groups,
        "vuln": vuln,
        "guardrail": guardrail,
        "tools": tools,
        "score": (record or {}).get("score"),
        "counts": counts,
    }


def _local_answer(question: str, ctx: dict) -> str:
    q = question.lower()
    scan_id = (ctx["record"] or {}).get("id", "unknown")
    prefix = f"[Evidence-bound answer · scan {scan_id}] "

    if any(word in q for word in ("score", "skor", "pua")):
        return prefix + (
            f"Security score is {ctx['score']}/100 with "
            + ", ".join(f"{name}={ctx['counts'][name]}" for name in insights.SEVERITIES)
            + " findings."
        )
    if any(word in q for word in ("cve", "cvss")):
        summary = (ctx["vuln"].get("summary") or {})
        lookups = ctx["vuln"].get("cve_lookups") or []
        detail = "; ".join(
            f"{item.get('component')}={item.get('status')}" for item in lookups[:4]
        )
        return prefix + (
            f"Max CVSS {summary.get('max_cvss')}, average {summary.get('average_cvss')}, "
            f"validated CVEs {summary.get('total_cves', 0)}"
            + (f". Lookups: {detail}" if detail else ".")
        )
    if any(word in q for word in ("recommend", "fix", "remediat", "onar", "duzelt", "coz")):
        recs = []
        for group in ctx["groups"][:6]:
            text = group.get("ai_recommendation") or group.get("recommendation")
            if text:
                recs.append(f"{group.get('id')}: {str(text)[:180]}")
        return prefix + (
            "\n".join(recs) if recs else "No AI recommendation was recorded in this scan."
        )
    if any(word in q for word in ("endpoint", "route", "api", "url")):
        endpoints = []
        for group in ctx["groups"]:
            for endpoint in group.get("endpoints") or []:
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        return prefix + (
            f"Found {len(endpoints)} distinct affected endpoints: "
            + (", ".join(endpoints[:12]) if endpoints else "none recorded")
        )
    if any(word in q for word in ("tool", "nmap", "nuclei", "zap", "ffuf", "sqlmap")):
        statuses = ", ".join(
            f"{name}={(payload or {}).get('status')}" for name, payload in ctx["tools"].items()
        )
        return prefix + (f"DAST tool status: {statuses}" if statuses else "No DAST tool status in this scan.")
    if any(word in q for word in ("guardrail", "guard", "gemini")):
        guard = ctx["guardrail"]
        return prefix + (
            f"Guardrail ok={guard.get('ok')} mode={guard.get('mode')}. "
            f"{guard.get('message') or ''}"
        )
    # Default: real finding digest.
    digest = [
        f"{f.get('id')} [{f.get('severity')}] {f.get('title')} @ {f.get('endpoint')}"
        for f in ctx["findings"][:8]
    ]
    return prefix + "Real findings:\n" + ("\n".join(digest) if digest else "No findings in this scan.")


def ask_copilot(question: str, scan_id: str | None = None) -> dict:
    question = (question or "").strip()
    if not question:
        raise ValueError("The question cannot be empty.")
    if len(question) > 800:
        raise ValueError("The question is too long (maximum 800 characters).")

    ok, guard_msg = local_pattern_check(question)
    if not ok:
        raise CopilotBlocked(guard_msg)

    ctx = _build_context(scan_id)
    sources = {
        "scan_id": (ctx["record"] or {}).get("id"),
        "findings": len(ctx.get("findings") or []),
        "correlation_groups": len(ctx.get("groups") or []),
    }

    if not ctx["available"]:
        return {
            "engine": "aegis-copilot-v1",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "answer": "No completed scan is available. Run an audit first so the Copilot has real evidence.",
            "mode": "local",
            "guardrail": guard_msg,
            "sources": sources,
            "evidence_based": True,
        }

    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        try:
            from google import genai
            from google.genai import types

            model = os.getenv("AEGIS_GEMINI_MODEL", "gemini-3.1-flash-lite")
            client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=20000))
            prompt = (
                "You are the AegisAI defensive security copilot. Answer ONLY from the SCAN CONTEXT "
                "below. Never invent a vulnerability, score, CVE, endpoint, or recommendation. "
                "If the context does not contain the answer, reply exactly: "
                "'The scan data does not contain this information.' Be concise (max 120 words) and "
                "reference real IDs/severities where relevant.\n\nSCAN CONTEXT:\n"
                + ctx["text"][:5000]
                + "\n\nQUESTION: "
                + question[:800]
            )
            response = client.models.generate_content(model=model, contents=prompt)
            answer = (response.text or "").strip()
            if not answer:
                raise RuntimeError("empty Gemini response")
            return {
                "engine": "aegis-copilot-v1",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "answer": answer,
                "mode": "gemini",
                "model": model,
                "guardrail": guard_msg,
                "sources": sources,
                "evidence_based": True,
            }
        except Exception as exc:
            fallback_note = f"Gemini unavailable ({type(exc).__name__}); used local evidence extractor. "
    else:
        fallback_note = "Gemini not configured; used local evidence extractor. "

    return {
        "engine": "aegis-copilot-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "answer": fallback_note + _local_answer(question, ctx),
        "mode": "local",
        "guardrail": guard_msg,
        "sources": sources,
        "evidence_based": True,
    }
