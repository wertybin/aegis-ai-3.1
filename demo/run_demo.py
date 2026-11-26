"""AEGIS AI V3 — repeatable live demo driver (≤2 minutes on screen).

Start the UI first (start_all.ps1 or uvicorn :8765), then run:

    .venv\\Scripts\\python.exe demo\\run_demo.py

The script opens the AGENT MODE page, triggers a REAL agent run through the
SSE endpoint, and prints every model/tool step to the console. Nothing is
faked: findings are produced by the same local tools used in production.

Useful flags:
    --target your-localhost-URL   your own authorized localhost target
    --task "..."                     custom task for the model
    --no-ai                          force the honest deterministic fallback
    --no-open                        do not open a browser tab
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import backend  # noqa: F401  (loads .env)

API = os.getenv("AEGIS_API_BASE", "").strip().rstrip("/")
UI = f"{API}/#/agent" if API else ""
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def check(label: str, url: str, timeout: int = 5) -> bool:
    try:
        with OPENER.open(url, timeout=timeout) as response:
            ok = response.status == 200
    except Exception as exc:
        print(f"[PREFLIGHT] {label}: FAIL ({type(exc).__name__})")
        return False
    print(f"[PREFLIGHT] {label}: {'OK' if ok else 'FAIL'} ({response.status})")
    return ok


def print_frame(event: str, data: dict, started: float) -> dict | None:
    elapsed = f"{time.monotonic() - started:6.1f}s"
    if event == "stage" and data.get("name"):
        print(f"[{elapsed}] STAGE  {data['name']}")
    elif event == "log" and data.get("message"):
        message = " ".join(str(data["message"]).split())[:180]
        print(f"[{elapsed}] MODEL  {message}")
    elif event == "tool":
        name = data.get("tool", "?")
        status = data.get("status", "")
        if status == "running":
            print(f"[{elapsed}] CALL   {name} {json.dumps(data.get('arguments') or {})[:100]}")
        else:
            flag = "OK" if data.get("ok") else "FAILED"
            print(
                f"[{elapsed}] OBS    {name} [{flag}] "
                f"findings={data.get('findings_count', '-')} "
                f"duration={data.get('duration_ms', '-')}ms"
            )
    elif event == "decision":
        print(
            f"[{elapsed}] THINK  {data.get('tool', '?')} "
            f"[{data.get('decision_id', '-')}] "
            f"{' '.join(str(data.get('reason') or '').split())[:150]}"
        )
    elif event == "tool_result":
        print(
            f"[{elapsed}] EVID   {data.get('tool', '?')} "
            f"ok={data.get('ok')} findings={data.get('findings_count', '-')} "
            f"call={data.get('tool_call_id', '-')}"
        )
    elif event == "verified_finding":
        print(
            f"[{elapsed}] FIND   [{data.get('severity', '-')}] "
            f"{str(data.get('title') or '')[:90]} @ {str(data.get('location') or '')[:90]} "
            f"[{data.get('finding_id', '-')}]"
        )
    elif event == "counters":
        print(
            f"[{elapsed}] STATS  iter={data.get('iterations', 0)} "
            f"calls={data.get('tool_calls', 0)} ok={data.get('tool_success', 0)} "
            f"failed={data.get('tool_failed', 0)} "
            f"findings={data.get('findings_total', 0)} "
            f"progress={data.get('progress', 0)}%"
        )
    elif event == "error" and data.get("message"):
        print(f"[{elapsed}] ERROR  {str(data['message'])[:180]}")
    elif event == "final":
        print(
            f"[{elapsed}] FINAL  mode={data.get('mode')} "
            f"tools={len(data.get('tools_used') or [])} "
            f"findings={data.get('total_findings')}"
        )
    elif event == "complete":
        return data
    return None


def run_agent_stream(target: str, task: str, use_ai: bool, started: float) -> dict:
    params = urllib.parse.urlencode({
        "task": task,
        "target": target,
        "use_ai": "true" if use_ai else "false",
    })
    result = None
    with OPENER.open(f"{API}/api/agent-stream?{params}", timeout=420) as response:
        event = ""
        for raw in response:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                try:
                    payload = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                if event == "complete":
                    result = payload
                else:
                    print_frame(event, payload, started)
            elif not line:
                event = ""
    if not result:
        raise RuntimeError("SSE stream closed without a complete event.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS AI V3 live demo driver")
    parser.add_argument("--target", default=os.getenv("AEGIS_DEFAULT_TARGET", "").strip())
    parser.add_argument(
        "--task",
        default=(
            "Audit the authorized local lab application, correlate the findings, "
            "and report the top risks with evidence."
        ),
    )
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args()

    print("AEGIS AI V3 — LIVE AGENT DEMO")
    print(f"Target: {args.target}")
    if not check("AEGIS API", f"{API}/api/agent/last"):
        print("Start the UI first: .\\start_all.ps1  (or uvicorn backend.main:app --port 8765)")
        return 2
    if not check("Local lab", args.target + "/"):
        print("Start the demo sites: .\\start_all.ps1")
        return 2

    if not args.no_open:
        try:
            webbrowser.open(UI)
            print(f"[UI] opened {UI}")
        except Exception as exc:
            print(f"[UI] could not open browser: {exc}")

    started = time.monotonic()
    try:
        result = run_agent_stream(args.target, args.task, not args.no_ai, started)
    except Exception as exc:
        print(f"[DEMO FAILED] {type(exc).__name__}: {exc}")
        return 1

    digest = {
        "ts": result.get("ts"),
        "mode": result.get("mode"),
        "model": result.get("model"),
        "target": result.get("target"),
        "path": result.get("path"),
        "tools_used": result.get("tools_used"),
        "total_findings": result.get("total_findings"),
        "severity_counts": result.get("severity_counts"),
        "verified_summary": result.get("verified_summary"),
        "duration_ms": result.get("duration_ms"),
        "agent_version": result.get("agent_version"),
        "prompt_version": result.get("prompt_version"),
        "counters": result.get("counters"),
        "decision_count": len(result.get("decisions") or []),
        "steps": [
            {
                "type": step.get("type"),
                "tool": step.get("tool"),
                "ok": step.get("ok"),
                "findings_count": step.get("findings_count"),
            }
            for step in result.get("steps") or []
        ],
    }
    out = ROOT / "reports" / "demo_last.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(digest, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n=== DEMO RESULT ===")
    print(json.dumps(digest, indent=2, ensure_ascii=False))
    print(f"\nSaved: {out.relative_to(ROOT)}")
    print("The browser page now shows the same real timeline, tool cards and report.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
