"""V3.1 Parts 12/14/17: route compatibility, local-only API hardening, honest visual API."""

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_version_endpoint():
    response = client.get("/api/version")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "3.1.0"
    assert body["prompt_version"] == "3.1.0"


def test_v1_contract_routes_still_registered():
    paths = {route.path for route in app.routes}
    for path in (
        "/api/audit-stream", "/api/dast-stream", "/api/apply-patch",
        "/api/download-report", "/api/agent-stream", "/api/comparison/snapshots",
    ):
        assert path in paths, path


def test_cross_origin_api_request_is_rejected():
    response = client.get("/api/version", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert "origin" in response.json()["detail"].lower()


def test_visual_snapshot_api_is_honest_without_playwright():
    response = client.get("/api/comparison/snapshots")
    assert response.status_code == 200
    body = response.json()
    assert "available" in body and "snapshots" in body
    assert "Visual change" in body["policy"]


def test_unknown_image_diff_ids_do_not_fabricate_results():
    response = client.get("/api/comparison/image-diff?before=NOPE&after=NOPE")
    assert response.status_code == 200
    assert response.json()["ok"] is False


def test_agent_last_is_readable_without_a_run():
    response = client.get("/api/agent/last")
    assert response.status_code == 200
    assert set(("last", "history", "running")) <= set(response.json())
