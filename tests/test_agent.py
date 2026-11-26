"""V3.1 Parts 2 & 4: Gemini loop mechanics with the model fully mocked.

These are MOCK unit tests. They never claim a real scanner or real Gemini call.
Real end-to-end verification is in demo/run_demo.py and docs/DEMO_SCRIPT.md.
"""

from types import SimpleNamespace

from backend import security_agent as sa


class FakeResponse:
    def __init__(self, calls, text=""):
        self.function_calls = [SimpleNamespace(name=name, args=args) for name, args in calls]
        self.text = text
        # The loop only reads candidates[0].content and appends it to history.
        self.candidates = [SimpleNamespace(content=SimpleNamespace(role="model", parts=[]))]


def _patch_tools(monkeypatch, calls=None):
    # These legacy loop tests specifically exercise the Gemini path. The live
    # .env may select Ollama, so isolate the provider and browser tool here.
    monkeypatch.setenv("AEGIS_MODEL_PROVIDER", "gemini")
    monkeypatch.setenv("AEGIS_BROWSER_ENABLED", "0")
    monkeypatch.setattr(sa, "check_tool", lambda name: {
        "tool": name, "status": "OK", "version": "mock", "category": "mock",
        "note": "", "install": "", "destructive": False, "timeout": 60,
    })
    monkeypatch.setattr(sa, "deep_correlate", lambda **kwargs: {"stats": {}, "groups": []})
    def fake_execute(name, args, target, path, cache):
        raw = {
            "tool": name,
            "ok": True,
            "available": True,
            "findings_count": 1,
            "findings": [{
                "title": "SQL Injection", "severity": "HIGH",
                "evidence": "manual string concatenation with request input",
                "endpoint": "http://127.0.0.1:5000/api/user", "tool": name,
            }],
            "duration_ms": 5,
            "error": None,
        }
        cache["results"][name] = raw
        return raw

    monkeypatch.setattr(sa, "_execute", fake_execute)
    if calls is not None:
        monkeypatch.setattr(sa, "_call_gemini", lambda *a, **k: FakeResponse(calls))


def test_canonical_tool_names():
    assert sa._canonical_tool("run_semgrep") == "semgrep"
    assert sa._canonical_tool("run_api_security") == "api_security"
    assert sa._canonical_tool("correlate_findings") == "correlate_findings"


def test_agent_emits_trace_events_and_respects_iteration_limit(monkeypatch):
    _patch_tools(monkeypatch, calls=[("run_semgrep", {})])
    events = []
    result = sa.run_agent(
        "mock audit", use_ai=True, max_steps=3,
        on_event=lambda event, payload: events.append((event, payload)),
    )

    kinds = [event for event, _ in events]
    for required in ("stage", "decision", "tool", "tool_result", "counters", "verified_finding", "final"):
        assert required in kinds, required
    assert result["counters"]["iterations"] == 3
    assert result["counters"]["tool_calls"] == 3
    assert result["mode"] == "gemini-function-calling"
    assert "ID-" in result["findings"][0]["id"] or "AF-" in result["findings"][0]["id"]

    decisions = [payload for event, payload in events if event == "decision"]
    assert len({item["decision_id"] for item in decisions}) == 3
    assert all(item["source"] == "gemini" for item in decisions)
    verified = [payload for event, payload in events if event == "verified_finding"]
    assert verified and verified[0]["ai_hypothesis"] is False


def test_deterministic_fallback_uses_real_tool_plan_without_a_model(monkeypatch):
    _patch_tools(monkeypatch)
    monkeypatch.setattr(sa.os, "getenv", lambda key, default=None: None if key == "GEMINI_API_KEY" else default)
    result = sa.run_agent(
        "mock audit", target="http://127.0.0.1:5002", use_ai=True, max_steps=3
    )
    assert result["mode"] == "deterministic-fallback"
    assert len(result["tools_used"]) >= 2
    assert all(item["source"] == "deterministic-fallback" for item in result["decisions"])
