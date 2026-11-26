"""Offline receipt tests. The agent result producer and report storage are stubbed."""
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.telegram_ui import api, screens


@pytest.fixture
def backend(monkeypatch):
    monkeypatch.setattr(main, "_AGENT_STATE", {"last": None, "history": [], "running": False})
    monkeypatch.setattr(main, "_AGENT_RECEIPTS", {})
    monkeypatch.setattr(main, "_store_agent_result", lambda result: main._AGENT_STATE.update(last=result))
    return TestClient(main.app)


def test_timeout_recovers_only_the_same_report(backend, monkeypatch):
    posts = []
    polls = []
    def produce(req, *args):
        assert main.agent_report_receipt(req.receipt_id)["state"] == "pending"
        return {"ok": True, "total_findings": 28}
    monkeypatch.setattr(main, "_sync_agent_result", produce)
    monkeypatch.setattr(api.time, "sleep", lambda _: None)

    def post(path, payload):
        posts.append(payload)
        assert backend.post(path, json=payload).status_code == 200
        raise TimeoutError("Original response lost")

    def get(path):
        polls.append(path)
        if len(polls) == 1:
            return {"state": "pending", "receipt_id": posts[0]["receipt_id"]}
        return backend.get(path).json()

    result = api.ApiClient(get, post).agent_run("fixture")
    assert result["total_findings"] == 28 and len(posts) == 1 and len(polls) == 2
    assert result["receipt_id"] == posts[0]["receipt_id"]
    assert backend.get(f"/api/agent/receipts/{uuid4()}").json()["state"] == "unknown"
    assert backend.post("/api/agent/run", json=posts[0]).status_code == 409
    main._AGENT_RECEIPTS.clear()
    assert backend.get(polls[-1]).json()["result"] == result


def test_missing_receipt_never_returns_another_result(monkeypatch):
    monkeypatch.setattr(api.time, "sleep", lambda _: None)
    def lost(*args):
        raise TimeoutError()
    def other_report(path):
        return {"state": "ready", "receipt_id": path.split("/")[-1],
                "result": {"receipt_id": str(uuid4()), "ok": True}}
    with pytest.raises(TimeoutError):
        api.ApiClient(other_report, lost).agent_run("fixture")


@pytest.mark.parametrize("failure", [False, True])
def test_closed_or_failed_run_has_terminal_receipt(backend, monkeypatch, failure):
    def finish(*args):
        if failure:
            raise RuntimeError("fixture failure")
        return {"ok": False, "cancelled": True}
    monkeypatch.setattr(main, "_sync_agent_result", finish)
    key = str(uuid4())
    client = TestClient(main.app, raise_server_exceptions=False)
    response = client.post("/api/agent/run", json={"receipt_id": key})
    assert response.status_code == (500 if failure else 200)
    receipt = backend.get("/api/agent/receipts/" + key).json()
    assert receipt["state"] == ("failed" if failure else "ready")
    if not failure:
        assert receipt["result"]["cancelled"]
    assert not main._AGENT_STATE["running"] and main._AGENT_STATE["last"] is None


def test_equal_counts_on_different_evidence_stay_visible():
    first = {"findings": [{"severity": "HIGH", "title": "First issue"}]}
    second = {"findings": [{"severity": "HIGH", "title": "Second issue"}]}
    text = screens.pipeline_summary({"dast": {"audit": first}, "audit": second}, "local", None).text
    assert "First issue" in text and "Second issue" in text
