"""V3.1 Part 3: centralized tool registry contracts (mocked, no binaries run)."""

from backend.security_agent import _DECLARATION_TO_CONTRACT, _tool_declarations
from backend.tool_registry import DEEP_TOOLS, TOOL_CONTRACTS


def test_every_registered_tool_has_a_full_contract():
    for name, meta in DEEP_TOOLS.items():
        assert meta.get("description"), name
        assert meta.get("parameters_schema", {}).get("type") == "OBJECT", name
        assert meta.get("permission_level"), name
        assert meta.get("output_schema", {}).get("type") == "OBJECT", name
        assert meta.get("timeout", 0) > 0, name
        assert meta.get("destructive") is False, name


def test_contracts_cover_the_model_facing_tools():
    assert set(TOOL_CONTRACTS) >= set(_DECLARATION_TO_CONTRACT.values())


def test_declarations_are_generated_with_real_parameter_schemas(monkeypatch):
    monkeypatch.setenv("AEGIS_BROWSER_ENABLED", "0")
    declarations = _tool_declarations()
    names = {item.name for item in declarations}
    assert len(declarations) == len(_DECLARATION_TO_CONTRACT)
    assert "run_semgrep" in names and "correlate_findings" in names
    semgrep = next(item for item in declarations if item.name == "run_semgrep")
    assert "path" in (semgrep.parameters.properties or {})
    httpx = next(item for item in declarations if item.name == "run_httpx")
    assert "target" in (httpx.parameters.properties or {})


def test_browser_declaration_is_added_only_when_enabled(monkeypatch):
    monkeypatch.setenv("AEGIS_BROWSER_ENABLED", "1")
    names = {item.name for item in _tool_declarations()}
    assert "run_browser" in names
    assert "action" in {
        item.name: item for item in _tool_declarations()
    }["run_browser"].parameters.properties
