"""V3.1 Part 14: real PDF generation from evidence (no mocked scanner data)."""

from backend.deep_pdf import generate_deep_report
from backend.deep_correlation import correlate


def test_deep_pdf_is_generated_from_real_correlation_schema(tmp_path):
    correlation = correlate(deep_results={
        "semgrep": {"findings": [{
            "title": "SQL Injection", "severity": "HIGH", "file": "app.py", "line": 12,
            "evidence": "cursor.execute('SELECT * FROM users WHERE name=' + name)",
            "cwe": ["CWE-89"],
        }]}
    })
    path = generate_deep_report(correlation, tmp_path)
    assert path.exists() and path.stat().st_size > 1000
    assert path.read_bytes()[:4] == b"%PDF"
