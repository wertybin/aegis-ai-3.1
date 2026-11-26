"""V3.1 Part 8: cross-tool evidence merging and confidence (deterministic)."""

from backend.deep_correlation import correlate


def test_two_tools_same_endpoint_merge_with_both_evidence_sources():
    results = {
        "zap": {"findings": [{
            "title": "SQL Injection", "severity": "HIGH",
            "endpoint": "http://127.0.0.1:5000/api/user",
            "evidence": "boolean-based payload changed response",
            "cve": "CVE-2024-0001",
        }]},
        "nuclei": {"findings": [{
            "title": "SQL Injection", "severity": "HIGH",
            "endpoint": "http://127.0.0.1:5000/api/user",
            "evidence": "template matched SQLi signature",
            "cve": "CVE-2024-0001",
        }]},
    }
    result = correlate(deep_results=results)
    groups = result["groups"]
    assert len(groups) == 1
    group = groups[0]
    assert set(group["source_tools"]) == {"zap", "nuclei"}
    assert group["confidence"] == "confirmed"
    assert group["finding_class"] == "confirmed"
    assert group["verification_status"] == "evidence-backed"
    assert 0.9 <= group["confidence_score"] <= 1.0
    assert "CWE-89" in group["cwe"]
    assert result["stats"]["confirmed_findings"] == 1


def test_unrelated_findings_are_not_merged():
    results = {
        "semgrep": {"findings": [{"title": "Hardcoded secret", "severity": "HIGH",
                                  "file": "app.py", "evidence": "API_KEY = 'x'"}]},
        "httpx": {"findings": [{"title": "Missing CSP header", "severity": "LOW",
                                "endpoint": "http://127.0.0.1:5002/", "evidence": "no CSP"}]},
    }
    result = correlate(deep_results=results)
    assert len(result["groups"]) == 2
