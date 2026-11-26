"""V3.1 Part 11: version-controlled system prompt."""

from backend.security_agent import PROMPT_PATH, PROMPT_VERSION, SYSTEM_PROMPT, load_system_prompt


def test_prompt_file_exists_and_is_versioned():
    assert PROMPT_PATH.exists()
    assert PROMPT_VERSION == "3.1.0"
    body, version = load_system_prompt()
    assert version == "3.1.0"
    assert body == SYSTEM_PROMPT


def test_prompt_contains_required_guidance():
    for needle in (
        "You are AEGIS AI, an autonomous security assessment and defensive analysis agent.",
        "AUTHORIZED SCOPE",
        "HARD SAFETY RULES",
        "DECISION TRANSPARENCY",
        "INTERPRETING RESULTS",
        "WHEN TO STOP",
        "Maximum 8 tool calls.",
    ):
        assert needle in SYSTEM_PROMPT


def test_readme_documents_the_same_prompt_identity():
    readme = PROMPT_PATH.parent.parent / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert "You are AEGIS AI, an autonomous security assessment and defensive analysis agent." in text
    assert "prompts/security_agent.v3.1.md" in text
