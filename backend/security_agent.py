"""AEGIS AI V3 — Autonomous defensive security agent.

The agent is a real model-driven loop:

    trigger (task) -> Gemini plan -> tool call -> observation -> next step
                   -> unified correlation -> evidence-based report

Only safe, read-only, localhost/local-lab tools are exposed. The model can
never run exploits, payloads or destructive tests: the tool layer rejects
anything outside the explicit scope before execution.

If Gemini is unavailable (missing key, quota, network) the same loop falls
back to a deterministic playbook so the product still performs a real scan —
the mode is reported honestly as ``deterministic-fallback``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime
from pathlib import Path

from backend.deep_correlation import (
    _cwe,
    _http_method,
    _parameter,
    correlate as deep_correlate,
)
from backend.deep_scanner import run_tool
from backend.tool_registry import (
    BASE_DIR,
    DEEP_TOOLS,
    LAB_DIR,
    TOOL_CONTRACTS,
    check_tool,
    is_allowed_scan_path,
)
from backend.wsl_scanner import DastError, ScanCancelled, check_cancelled, validate_dast_target

AGENT_VERSION = "3.1.0"
PROMPT_PATH = BASE_DIR / "prompts" / "security_agent.v3.1.md"
PROMPT_VERSION = AGENT_VERSION


def load_system_prompt() -> tuple[str, str]:
    """Loads the version-controlled prompt. Never silently substitutes a mock."""
    global PROMPT_VERSION
    try:
        raw = PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        return (
            "You are AEGIS AI, a defensive security auditor. Stay inside the "
            "authorized localhost scope. Use only provided tools. Never invent "
            "findings. Call at least two real tools and finish with an "
            "evidence-based report.",
            "embedded-fallback",
        )
    version_match = re.search(r"^#\s*version:\s*(.+)$", raw, re.MULTILINE)
    if version_match:
        PROMPT_VERSION = version_match.group(1).strip()
    body = "\n".join(
        line for line in raw.splitlines() if not line.startswith("#")
    ).strip()
    return body, PROMPT_VERSION


SYSTEM_PROMPT, PROMPT_VERSION = load_system_prompt()

MAX_TOOL_CALLS = 8
MAX_FINDINGS_TO_MODEL = 8
MODEL_RETRIES = 3

_SOURCE_TOOLS = {"semgrep", "trivy", "gitleaks"}
_NETWORK_TOOLS = {"httpx", "katana", "api_security", "testssl", "burp", "metasploit", "browser"}


def _now() -> str:
    return datetime.now().isoformat()


def _emit(on_event, event: str, payload: dict) -> None:
    if on_event is None:
        return
    try:
        on_event(event, payload)
    except Exception:
        pass  # streaming must never break the agent


def _scope_defaults(target: str | None, path: str | None) -> tuple[str, str]:
    """Resolves and validates the run scope before any model call."""
    resolved_path = ""
    if path:
        ok, message = is_allowed_scan_path(path)
        if not ok:
            raise ValueError(message)
        resolved_path = message
    else:
        resolved_path = str(LAB_DIR.resolve())

    if target:
        resolved_target = validate_dast_target(target)
    else:
        configured = os.getenv("AEGIS_DEFAULT_TARGET", "").strip()
        if not configured:
            raise ValueError("Set AEGIS_DEFAULT_TARGET in .env or pass a target to /scan.")
        resolved_target = validate_dast_target(configured)
    return resolved_target, resolved_path


def _canonical_tool(name: str) -> str:
    """The model sees run_* declarations; execution uses bare tool names."""
    name = str(name or "").strip()
    if name.startswith("run_") and name[4:] in (_SOURCE_TOOLS | _NETWORK_TOOLS | {"api_security"}):
        return name[4:]
    return name


def _tool_summary(name: str, result: dict) -> dict:
    findings = result.get("findings") or []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    compact = []
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        severity_counts[severity if severity in severity_counts else "INFO"] += 1
    for finding in findings[:MAX_FINDINGS_TO_MODEL]:
        location = finding.get("endpoint") or (
            f"{finding.get('file')}:{finding.get('line')}" if finding.get("file") else ""
        )
        compact.append({
            "title": str(finding.get("title") or "")[:140],
            "severity": str(finding.get("severity") or "")[:20],
            "location": str(location)[:220],
            "evidence": str(finding.get("evidence") or "")[:180],
            "cve": str(finding.get("cve") or "")[:60],
        })
    return {
        "ok": bool(result.get("ok")),
        "available": bool(result.get("available")),
        "findings_count": len(findings),
        "severity_counts": severity_counts,
        "duration_ms": int(result.get("duration_ms") or 0),
        "findings": compact,
        "error": (result.get("error") or None),
    }


def _execute(name: str, args: dict, target: str, path: str, cache: dict) -> dict:
    """Executes one allowlisted tool with scope validation and deduplication."""
    name = _canonical_tool(name)
    if name == "list_tools":
        return {
            "ok": True,
            "available": True,
            "tools": {
                key: {
                    "status": entry.get("status"),
                    "version": entry.get("version"),
                    "category": entry.get("category"),
                    "note": entry.get("note"),
                }
                for key, entry in cache["status"].items()
                if key in (_SOURCE_TOOLS | _NETWORK_TOOLS)
            },
        }

    if name == "correlate_findings":
        result = deep_correlate(deep_results=cache["results"])
        cache["correlation"] = result
        return {
            "ok": True,
            "available": True,
            "stats": result.get("stats"),
            "top_groups": [
                {
                    "title": group.get("title"),
                    "severity": group.get("severity"),
                    "source_tools": group.get("source_tools"),
                    "confidence": group.get("confidence"),
                }
                for group in (result.get("groups") or [])[:10]
            ],
        }

    if name == 'browser':
        session = cache.get('browser_session')
        if session is None:
            return {'ok': False, 'available': False, 'error': 'Browser mode is not enabled for this run.'}
        result = session.execute(args)
        cache['results']['browser'] = result
        return {**_tool_summary(name, result), 'observation': result.get('observation')}

    if name not in (_SOURCE_TOOLS | _NETWORK_TOOLS):
        return {"ok": False, "available": False, "error": f"Unknown tool: {name}"}

    if name in _SOURCE_TOOLS:
        requested = str(args.get("path") or path).strip()
        ok, message = is_allowed_scan_path(requested)
        if not ok:
            return {"ok": False, "available": False, "error": message}
        call_target, call_path = target, message
    else:
        requested = str(args.get("target") or args.get("url") or target).strip()
        try:
            call_target = validate_dast_target(requested)
        except DastError as exc:
            return {"ok": False, "available": False, "error": f"SCOPE BLOCKED: {exc}"}
        call_path = path

    key = f"{name}|{call_target}|{call_path}"
    if key in cache["executed"]:
        return {**cache["executed"][key], "cached": True}

    status = cache["status"].get(name) or {}
    if status.get("status") != "OK":
        result = {
            "tool": name,
            "ok": False,
            "available": False,
            "findings": [],
            "error": (
                f"{DEEP_TOOLS.get(name, {}).get('label', name)} is not installed. "
                f"{DEEP_TOOLS.get(name, {}).get('install', '')}"
            )[:300],
            "duration_ms": 0,
        }
    else:
        result = run_tool(name, target=call_target, path=call_path)

    cache["results"][name] = result
    summary = _tool_summary(name, result)
    cache["executed"][key] = summary
    return summary


def _aggregate_findings(results: dict[str, dict]) -> tuple[list[dict], dict]:
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    raw: list[dict] = []
    fields = (
        "source_tool", "title", "endpoint", "file", "line",
        "rule_id", "check_id", "evidence",
    )
    for tool_name, result in results.items():
        for finding in result.get("findings") or []:
            enriched = {**finding, "source_tool": tool_name}
            enriched["cwe"] = enriched.get("cwe") or _cwe(enriched)
            enriched["method"] = enriched.get("method") or _http_method(enriched)
            enriched["parameter"] = enriched.get("parameter") or _parameter(enriched)
            raw.append(enriched)

    # Suppress only exact repeats from the same tool. Different evidence at the
    # same location stays separate; nothing is merged on title similarity alone.
    seen: dict[str, dict] = {}
    findings: list[dict] = []
    for item in raw:
        basis = "|".join(str(item.get(key) or "")[:600] for key in fields)
        existing = seen.get(basis)
        if existing is not None:
            existing["duplicate_count"] = int(existing.get("duplicate_count") or 1) + 1
            continue
        item["id"] = "AF-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10].upper()
        seen[basis] = item
        findings.append(item)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in findings:
        severity = str(item.get("severity") or "INFO").upper()
        counts[severity if severity in counts else "INFO"] += 1
    findings.sort(key=lambda item: -rank.get(str(item.get("severity") or "INFO").upper(), 0))
    return findings[:80], counts


def _deterministic_plan(target: str, path: str) -> list[str]:
    plan = []
    if path:
        plan.extend(["semgrep", "trivy", "gitleaks"])
    if target:
        plan.extend(["httpx", "katana", "api_security"])
    return plan


def _fallback_report(tools_used: list[str], counts: dict, findings: list[dict]) -> str:
    total = sum(counts.values())
    if not total:
        return (
            f"Executed {len(tools_used)} real tool(s) ({', '.join(tools_used) or 'none'}). "
            "No findings were reported in the authorized scope."
        )
    top = findings[0] if findings else {}
    return (
        f"Executed {len(tools_used)} real tool(s) ({', '.join(tools_used)}). "
        f"Found {total} finding(s): CRITICAL {counts.get('CRITICAL', 0)}, "
        f"HIGH {counts.get('HIGH', 0)}, MEDIUM {counts.get('MEDIUM', 0)}, "
        f"LOW {counts.get('LOW', 0)}. "
        f"Top finding: {top.get('title', 'n/a')} [{top.get('severity', 'n/a')}]."
    )


_DECLARATION_TO_CONTRACT = {
    "list_tools": "tool_center",
    "correlate_findings": "ai_correlation",
    **{
        f"run_{name}": name
        for name in TOOL_CONTRACTS
        if name not in ("tool_center", "ai_correlation")
    },
}


def _contracts():
    from backend.browser_agent import BROWSER_CONTRACT
    return {**TOOL_CONTRACTS, 'browser': BROWSER_CONTRACT}


def _declaration_mapping():
    mapping = dict(_DECLARATION_TO_CONTRACT)
    if os.getenv('AEGIS_BROWSER_ENABLED', '0') == '1':
        mapping['run_browser'] = 'browser'
    return mapping


def _schema(node: dict, types) -> object:
    """Converts a registry JSON schema node into a Gemini Schema object."""
    node = node if isinstance(node, dict) else {"type": "OBJECT"}
    properties = {
        key: _schema(value, types)
        for key, value in (node.get("properties") or {}).items()
    }
    return types.Schema(
        type=str(node.get("type", "OBJECT")),
        description=str(node.get("description", ""))[:400],
        properties=properties,
    )


def _tool_declarations() -> list:
    """Declarations are generated from the centralized, versioned tool contracts."""
    from google.genai import types

    declarations = []
    for model_name, contract_name in _declaration_mapping().items():
        contract = _contracts().get(contract_name)
        if not contract:
            continue
        declarations.append(types.FunctionDeclaration(
            name=model_name,
            description=contract["description"][:500],
            parameters=_schema(contract["parameters_schema"], types),
        ))
    return declarations


def _model_chain() -> list[str]:
    """Primary free Gemini model plus explicit fallbacks for demand spikes."""
    primary = os.getenv("AEGIS_GEMINI_MODEL", "gemini-3.1-flash-lite").strip()
    fallbacks = [
        item.strip()
        for item in os.getenv(
            "AEGIS_GEMINI_FALLBACK_MODELS",
            "gemini-3.5-flash-lite,gemini-2.5-flash-lite,gemini-3.5-flash",
        ).split(",")
        if item.strip()
    ]
    chain: list[str] = []
    for name in [primary] + fallbacks:
        if name and name not in chain:
            chain.append(name)
    return chain


def _call_gemini(contents: list, api_key: str, models: list[str], state: dict):
    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(timeout=60000),
    )
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=[types.Tool(function_declarations=_tool_declarations())],
        temperature=0.2,
        max_output_tokens=2048,
    )
    last_error = None
    for model in models:
        for attempt in range(1, MODEL_RETRIES + 1):
            try:
                response = client.models.generate_content(
                    model=model, contents=contents, config=config,
                )
                state["model"] = model
                return response
            except Exception as exc:
                last_error = exc
                message = str(exc)
                transient = any(token in message for token in (
                    "503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED",
                    "500", "INTERNAL", "Deadline", "deadline", "timeout", "Timeout",
                ))
                if not transient:
                    raise
                if attempt < MODEL_RETRIES:
                    time.sleep(2 * attempt)  # 2s, 4s — transient demand spikes
        # this model stayed unavailable; try the next free model
    raise last_error  # pragma: no cover - loop always returns or raises


def run_agent(task: str, *, target=None, path=None, max_steps=8, on_event=None, use_ai=True) -> dict:
    from backend.browser_agent import BrowserSession
    session = BrowserSession(_scope_defaults(target, path)[0]) if os.getenv('AEGIS_BROWSER_ENABLED', '0') == '1' else None
    try:
        return _run_agent_impl(task, target=target, path=path, max_steps=max_steps,
                               on_event=on_event, use_ai=use_ai, browser_session=session)
    finally:
        if session:
            session.close()


def _run_agent_impl(
    task: str,
    *,
    target: str | None = None,
    path: str | None = None,
    max_steps: int = 8,
    on_event=None,
    use_ai: bool = True,
    browser_session=None,
) -> dict:
    """Runs the real agent loop and returns a fully traceable result.

    A cancellation event bound by the caller (``bind_cancel_event``) is honoured
    cooperatively between model turns and inside every guarded WSL tool call.
    """
    check_cancelled()
    started = time.monotonic()
    task = (task or "Audit the authorized local application and report the risks.").strip()[:1200]
    target, path = _scope_defaults(target, path)

    _emit(on_event, "stage", {
        "step": 0,
        "name": "Scope validated",
        "status": "running",
        "target": target,
        "path": path,
        "ts": _now(),
    })

    status = {name: check_tool(name) for name in (_SOURCE_TOOLS | _NETWORK_TOOLS)}
    if browser_session:
        from backend.browser_agent import status as browser_status
        status['browser'] = browser_status()
    else:
        status.pop('browser', None)
    cache = {"status": status, "results": {}, "executed": {}, "correlation": None}
    cache['browser_session'] = browser_session
    available = [name for name, entry in status.items() if entry.get("status") == "OK"]
    _emit(on_event, "log", {
        "message": f"Live tools available: {', '.join(sorted(available)) or 'none'}",
    })

    api_key = os.getenv("GEMINI_API_KEY")
    model_chain = _model_chain()
    model_state = {"model": model_chain[0]}
    provider = os.getenv('AEGIS_MODEL_PROVIDER', 'gemini').lower()
    use_ai = bool(use_ai and (api_key or provider == 'ollama'))
    mode = "gemini-function-calling" if use_ai else "deterministic-fallback"
    ai_error = None
    steps: list[dict] = []
    tools_used: list[str] = []
    final_text = ""
    total_calls = 0
    model_switched = False
    decisions: list[dict] = []
    counters = {
        "iterations": 0,
        "tool_calls": 0,
        "tool_success": 0,
        "tool_failed": 0,
        "findings_total": 0,
        "findings_verified": 0,
        "progress": 0,
    }

    if use_ai:
        from google.genai import types

        contents = [types.Content(
            role="user",
            parts=[types.Part(text=(
                f"TASK: {task}\n"
                f"AUTHORIZED TARGET: {target}\n"
                f"AUTHORIZED SOURCE PATH: {path}\n"
                f"LIVE TOOL STATUS: "
                + ", ".join(f"{name}={entry.get('status')}" for name, entry in sorted(status.items()))
                + "\nExecute the audit now. Stay inside the authorized scope."
                + ("\nStart with run_browser(action=inspect), choose follow-up clicks/fills from its observed elements. Also use at least two different scanning tools. Budget all calls within 8." if browser_session else "")
            ))],
        )]

        try:
            for step_index in range(1, max_steps + 1):
                check_cancelled()
                counters["iterations"] += 1
                if provider == 'ollama':
                    from backend.ollama_provider import call_ollama
                    try:
                        response = call_ollama(contents, SYSTEM_PROMPT, _contracts(), _declaration_mapping(), model_state)
                    except ScanCancelled:
                        raise
                    except Exception as local_error:
                        if not api_key:
                            raise
                        provider = 'gemini'
                        _emit(on_event, 'log', {'message': f'Ollama unavailable ({type(local_error).__name__}); switching to Gemini.'})
                        response = _call_gemini(contents, api_key, model_chain, model_state)
                        model_state['provider'] = 'gemini'
                else:
                    response = _call_gemini(contents, api_key, model_chain, model_state)
                    model_state['provider'] = 'gemini'
                mode = f"{model_state.get('provider', 'gemini')}-function-calling"
                if provider == 'gemini' and model_state["model"] != model_chain[0] and not model_switched:
                    model_switched = True
                    _emit(on_event, "log", {
                        "message": (
                            f"Primary model {model_chain[0]} unavailable; "
                            f"continuing with {model_state['model']}."
                        ),
                    })
                candidate = (response.candidates or [None])[0]
                if candidate is None or candidate.content is None:
                    raise RuntimeError("Gemini returned an empty candidate.")
                contents.append(candidate.content)

                text = getattr(response, "text", "") or ""
                calls = list(response.function_calls or [])
                if text.strip():
                    steps.append({
                        "step": step_index, "type": "plan", "text": text.strip()[:800],
                        "ts": _now(),
                    })
                    _emit(on_event, "log", {"message": text.strip()[:500]})

                if not calls:
                    executed_scans = {s.get('tool') for s in steps if s.get('type') == 'tool' and s.get('ok') and s.get('tool') not in ('browser', 'list_tools', 'correlate_findings')}
                    pending_scans = [n for n in available if n != 'browser' and n not in executed_scans]
                    if len(executed_scans) < 2 and pending_scans and total_calls < MAX_TOOL_CALLS and step_index < max_steps:
                        contents.append(types.Content(role='user', parts=[types.Part(text='Before your final report, use at least two different available real scanners in total. Remaining candidates: ' + ', '.join(sorted(pending_scans)))]))
                        continue
                    final_text = text.strip()
                    break

                tool_parts = []
                for call in calls:
                    name = _canonical_tool(str(call.name or ""))
                    is_scan_tool = name not in ("list_tools", "correlate_findings")
                    if is_scan_tool and total_calls >= MAX_TOOL_CALLS:
                        tool_parts.append(types.Part.from_function_response(
                            name=call.name,
                            response={"ok": False, "error": "Tool budget exhausted (8 calls)."},
                        ))
                        continue
                    if is_scan_tool:
                        total_calls += 1
                    args = dict(call.args or {})
                    decision_id = "D-" + uuid.uuid4().hex[:8].upper()
                    call_id = "TC-" + uuid.uuid4().hex[:8].upper()
                    reason = (
                        " ".join(text.strip().splitlines())[:240]
                        if text.strip()
                        else f"Model selected {name} from live tool status and the current evidence."
                    )
                    decision = {
                        "decision_id": decision_id,
                        "tool_call_id": call_id,
                        "step": step_index,
                        "tool": name,
                        "reason": reason,
                        "source": model_state.get('provider', 'gemini'),
                        "ts": _now(),
                    }
                    decisions.append(decision)
                    _emit(on_event, "decision", decision)
                    _emit(on_event, "tool", {
                        "step": step_index,
                        "decision_id": decision_id,
                        "tool_call_id": call_id,
                        "tool": name,
                        "status": "running",
                        "arguments": args,
                        "ts": _now(),
                    })
                    call_started = time.monotonic()
                    check_cancelled()
                    try:
                        summary = _execute(name, args, target, path, cache)
                    except ScanCancelled:
                        raise
                    except Exception as exc:
                        summary = {"ok": False, "available": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
                    elapsed = int((time.monotonic() - call_started) * 1000)
                    if name not in ("list_tools", "correlate_findings") and summary.get("available"):
                        tools_used.append(name)
                    record = {
                        "step": step_index,
                        "type": "tool",
                        "tool": name,
                        "arguments": args,
                        "ok": bool(summary.get("ok")),
                        "available": bool(summary.get("available")),
                        "findings_count": int(summary.get("findings_count") or 0),
                        "duration_ms": int(summary.get("duration_ms") or elapsed),
                        "error": summary.get("error"),
                        "observation": (
                            summary.get("stats") if name == "correlate_findings"
                            else summary.get("error") or f"{summary.get('findings_count', 0)} finding(s)"
                        ),
                        "ts": _now(),
                    }
                    steps.append(record)
                    counters["tool_calls"] += 1
                    counters["tool_success" if summary.get("ok") else "tool_failed"] += 1
                    counters["progress"] = min(90, 10 + counters["tool_calls"] * 12)
                    tool_status = "done" if summary.get("ok") else "failed"
                    _emit(on_event, "tool", {
                        **record,
                        "decision_id": decision_id,
                        "tool_call_id": call_id,
                        "status": tool_status,
                    })
                    _emit(on_event, "tool_result", {
                        "decision_id": decision_id,
                        "tool_call_id": call_id,
                        "step": step_index,
                        "tool": name,
                        "status": tool_status,
                        "ok": bool(summary.get("ok")),
                        "findings_count": int(summary.get("findings_count") or 0),
                        "duration_ms": int(summary.get("duration_ms") or elapsed),
                        "observation": record["observation"],
                        "ts": _now(),
                    })
                    _emit(on_event, "counters", dict(counters))
                    tool_parts.append(types.Part.from_function_response(
                        name=call.name, response=summary,
                    ))
                contents.append(types.Content(role="user", parts=tool_parts))

            if not final_text:
                final_text = "Tool budget reached. Review the collected evidence below."
        except ScanCancelled:
            raise
        except Exception as exc:
            ai_error = f"{type(exc).__name__}: {str(exc)[:300]}"
            mode = "deterministic-fallback"
            _emit(on_event, "error", {
                "message": f"Models unavailable, switching to deterministic fallback: {ai_error}",
            })

    if mode == "deterministic-fallback":
        plan = [
            name for name in _deterministic_plan(target, path)
            if name in status and status[name].get("status") == "OK"
        ]
        if cache["results"]:
            plan = [name for name in plan if name not in cache["results"]]
        for name in plan:
            check_cancelled()
            if total_calls >= MAX_TOOL_CALLS:
                break
            total_calls += 1
            counters["iterations"] += 1
            decision_id = "D-" + uuid.uuid4().hex[:8].upper()
            call_id = "TC-" + uuid.uuid4().hex[:8].upper()
            decision = {
                "decision_id": decision_id,
                "tool_call_id": call_id,
                "step": len(steps) + 1,
                "tool": name,
                "reason": "Deterministic fallback: Gemini was unavailable; real tools still execute in the authorized scope.",
                "source": "deterministic-fallback",
                "ts": _now(),
            }
            decisions.append(decision)
            _emit(on_event, "decision", decision)
            _emit(on_event, "tool", {
                "tool": name, "status": "running", "tool_call_id": call_id, "ts": _now(),
            })
            call_started = time.monotonic()
            summary = _execute(name, {}, target, path, cache)
            elapsed = int((time.monotonic() - call_started) * 1000)
            tools_used.append(name)
            record = {
                "step": len(steps) + 1,
                "type": "tool",
                "tool": name,
                "arguments": {},
                "ok": bool(summary.get("ok")),
                "available": bool(summary.get("available")),
                "findings_count": int(summary.get("findings_count") or 0),
                "duration_ms": int(summary.get("duration_ms") or elapsed),
                "error": summary.get("error"),
                "observation": summary.get("error") or f"{summary.get('findings_count', 0)} finding(s)",
                "ts": _now(),
            }
            steps.append(record)
            counters["tool_calls"] += 1
            counters["tool_success" if summary.get("ok") else "tool_failed"] += 1
            counters["progress"] = min(90, 10 + counters["tool_calls"] * 12)
            tool_status = "done" if summary.get("ok") else "failed"
            _emit(on_event, "tool", {
                **record, "decision_id": decision_id, "tool_call_id": call_id, "status": tool_status,
            })
            _emit(on_event, "tool_result", {
                "decision_id": decision_id,
                "tool_call_id": call_id,
                "step": len(steps),
                "tool": name,
                "status": tool_status,
                "ok": bool(summary.get("ok")),
                "findings_count": int(summary.get("findings_count") or 0),
                "duration_ms": int(summary.get("duration_ms") or elapsed),
                "observation": record["observation"],
                "ts": _now(),
            })
            _emit(on_event, "counters", dict(counters))

    correlation = cache["correlation"] or deep_correlate(deep_results=cache["results"])
    findings, counts = _aggregate_findings(cache["results"])
    unique_tools = list(dict.fromkeys(tools_used))
    verified_summary = (
        f"VERIFIED TOTALS — {sum(counts.values())} real finding(s) from "
        f"{len(unique_tools)} tool(s): CRITICAL {counts['CRITICAL']} · "
        f"HIGH {counts['HIGH']} · MEDIUM {counts['MEDIUM']} · "
        f"LOW {counts['LOW']} · INFO {counts['INFO']}."
    )
    if not final_text:
        final_text = _fallback_report(unique_tools, counts, findings)
    elif mode in ("gemini-function-calling", "ollama-function-calling"):
        # The model sees a bounded sample per tool; append the exact totals
        # computed from raw tool output so the report can never over/undercount.
        final_text = f"{final_text.strip()}\n\n---\n{verified_summary}"

    counters["findings_total"] = sum(counts.values())
    counters["findings_verified"] = len(findings)
    counters["progress"] = 100
    for finding in findings[:10]:
        location = finding.get("endpoint") or (
            f"{finding.get('file')}:{finding.get('line')}" if finding.get("file") else "-"
        )
        _emit(on_event, "verified_finding", {
            "finding_id": finding.get("id"),
            "title": str(finding.get("title") or "")[:160],
            "severity": finding.get("severity"),
            "source_tool": finding.get("source_tool"),
            "location": str(location)[:220],
            "verification_status": "evidence-backed (raw tool output)",
            "ai_hypothesis": False,
            "ts": _now(),
        })
    _emit(on_event, "counters", dict(counters))

    result = {
        "ok": bool(unique_tools),
        "mode": mode,
        "task": task,
        "target": target,
        "path": path,
        "model": model_state["model"] if use_ai else None,
        "provider": model_state.get('provider'),
        "browser_trace": browser_session.trace if browser_session else [],
        "ai_error": ai_error,
        "summary": final_text[:4000],
        "verified_summary": verified_summary,
        "steps": steps,
        "tools_used": unique_tools,
        "tool_results": {
            name: {
                "ok": payload.get("ok"),
                "available": payload.get("available"),
                "findings_count": len(payload.get("findings") or []),
                "duration_ms": payload.get("duration_ms"),
                "error": payload.get("error"),
            }
            for name, payload in cache["results"].items()
        },
        "total_findings": sum(counts.values()),
        "severity_counts": counts,
        "findings": findings,
        "correlation": correlation,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "ts": _now(),
        "agent_version": AGENT_VERSION,
        "prompt_version": PROMPT_VERSION,
        "decisions": decisions,
        "counters": counters,
    }
    _emit(on_event, "final", {
        "summary": result["summary"],
        "tools_used": result["tools_used"],
        "total_findings": result["total_findings"],
        "severity_counts": result["severity_counts"],
        "mode": result["mode"],
    })
    return result
