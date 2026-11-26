"""AEGIS AI V3 — Central registry for deep security scanning tools.

Every tool is described here once: availability check, version probe, install
guidance, timeout and safety classification. Missing tools never crash the app;
they are reported with an honest installation guide.

All external binaries are executed through backend.wsl_scanner._run, which
enforces the command allowlist, localhost-only network guardrail, cooperative
cancellation and a hard timeout.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from backend.wsl_scanner import DastError, ScanCancelled, _run

BASE_DIR = Path(__file__).resolve().parent.parent
LAB_DIR = BASE_DIR / "sample_vulnerable_app"

# Only these local trees may be scanned by source/dependency/secret tools.
ALLOWED_SCAN_DIRS = (LAB_DIR, BASE_DIR / "wordlists")


DEEP_TOOLS: dict[str, dict] = {
    "metasploit": {
        "label": "Metasploit Framework",
        "category": "Exploit Validation Lab",
        "kind": "external",
        # The Rapid7 apt package installs msfconsole on PATH (/usr/bin), while
        # older manuals clone it to ~/metasploit-framework. Accept both.
        "binary": "msfconsole",
        "check": (
            'command -v msfconsole >/dev/null 2>&1 && echo OK || '
            '{ [ -x "$HOME/metasploit-framework/msfconsole" ] && echo OK || echo MISSING; }'
        ),
        "version_cmd": (
            'command -v msfconsole >/dev/null 2>&1 && msfconsole --version 2>&1 | head -n 1 || '
            '"$HOME/metasploit-framework/msfconsole" --version 2>&1 | head -n 1'
        ),
        "install": (
            "WSL: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/"
            "config/templates/metasploit-framework-wrappers/msfupdate.erb -o msfinstall && "
            "chmod +x msfinstall && sudo ./msfinstall"
        ),
        "timeout": 120,
        "destructive": False,
        "note": (
            "Safe validation only: version, read-only module inventory and CVE/service "
            "mapping. Exploit/payload execution is disabled by policy."
        ),
    },
    "burp": {
        "label": "Burp Suite",
        "category": "Web Application Analysis",
        "kind": "external",
        "binary": "burpsuite",
        "check": 'command -v burpsuite >/dev/null 2>&1 && echo OK || echo MISSING',
        "version_cmd": "burpsuite --version 2>&1 | head -n 2",
        "install": (
            "Download Burp Suite Community from https://portswigger.net/burp/communitydownload, "
            "make the launcher executable and add it to WSL PATH."
        ),
        "timeout": 240,
        "destructive": False,
        "note": "Headless spider/scan when a licensed CLI is present; otherwise reports availability only.",
    },
    "semgrep": {
        "label": "Semgrep",
        "category": "Source Code Analysis",
        "kind": "external",
        # The pip wrapper `semgrep` is the OCaml launcher; it execs
        # `pysemgrep` from PATH, which a non-login WSL shell does not have.
        # Calling pysemgrep directly is the real, working entry point.
        "binary": "$HOME/.local/bin/pysemgrep",
        "check": '[ -x "$HOME/.local/bin/pysemgrep" ] && echo OK || echo MISSING',
        "version_cmd": '"$HOME/.local/bin/pysemgrep" --version 2>&1 | head -n 1',
        "install": "python3 -m pip install --user --break-system-packages semgrep",
        "timeout": 300,
        "destructive": False,
        "note": "SAST rules: SQL injection, XSS, hardcoded credentials, unsafe functions.",
    },
    "trivy": {
        "label": "Trivy",
        "category": "Dependency & Container Security",
        "kind": "external",
        "binary": "$HOME/.local/bin/trivy",
        "check": '[ -x "$HOME/.local/bin/trivy" ] && echo OK || echo MISSING',
        "version_cmd": '"$HOME/.local/bin/trivy" --version 2>&1 | head -n 1',
        "install": (
            "curl -LO https://github.com/aquasecurity/trivy/releases/latest/download/"
            "trivy_0.76.2_Linux-64bit.tar.gz && tar -xzf trivy_*.tar.gz -C ~/.local/bin trivy"
        ),
        "timeout": 300,
        "destructive": False,
        "note": "Filesystem dependency CVEs, misconfigurations and optional image scanning.",
    },
    "gitleaks": {
        "label": "Gitleaks",
        "category": "Secret Detection",
        "kind": "external",
        "binary": "$HOME/.local/bin/gitleaks",
        "check": '[ -x "$HOME/.local/bin/gitleaks" ] && echo OK || echo MISSING',
        "version_cmd": '"$HOME/.local/bin/gitleaks" version 2>&1 | head -n 1',
        "install": (
            "Download gitleaks_linux_x64.tar.gz from https://github.com/gitleaks/gitleaks/releases "
            "and extract to ~/.local/bin"
        ),
        "timeout": 240,
        "destructive": False,
        "note": "API keys, tokens, passwords and git-history secrets. All values are masked.",
    },
    "testssl": {
        "label": "testssl.sh",
        "category": "TLS Intelligence",
        "kind": "external",
        "binary": "$HOME/tools/testssl.sh/testssl.sh",
        "check": '[ -x "$HOME/tools/testssl.sh/testssl.sh" ] && echo OK || echo MISSING',
        "version_cmd": '"$HOME/tools/testssl.sh/testssl.sh" --version 2>&1 | grep -i version | head -n 1',
        "install": "sudo apt install testssl.sh  (or clone https://github.com/testssl/testssl.sh)",
        "timeout": 300,
        "destructive": False,
        "note": "Certificate, protocol and cipher checks against localhost TLS endpoints only.",
    },
    "httpx": {
        "label": "httpx",
        "category": "HTTP Probing",
        "kind": "external",
        "binary": "$HOME/tools/httpx",
        "check": '[ -x "$HOME/tools/httpx" ] && echo OK || echo MISSING',
        "version_cmd": '"$HOME/tools/httpx" -version 2>&1 | head -n 1',
        "install": (
            "Download httpx_linux_amd64.zip from https://github.com/projectdiscovery/httpx/releases "
            "and extract to ~/tools"
        ),
        "timeout": 180,
        "destructive": False,
        "note": "Fast HTTP probing, status/title/technology fingerprinting in authorized scope.",
    },
    "katana": {
        "label": "Katana",
        "category": "Endpoint Crawling",
        "kind": "external",
        "binary": "$HOME/tools/katana",
        "check": '[ -x "$HOME/tools/katana" ] && echo OK || echo MISSING',
        "version_cmd": '"$HOME/tools/katana" -version 2>&1 | head -n 1',
        "install": (
            "Download katana_linux_amd64.zip from https://github.com/projectdiscovery/katana/releases "
            "and extract to ~/tools"
        ),
        "timeout": 240,
        "destructive": False,
        "note": "Application crawling and endpoint discovery limited to the local target.",
    },
    "api_security": {
        "label": "Advanced API Security",
        "category": "REST / GraphQL Analysis",
        "kind": "builtin",
        "binary": "builtin",
        "check": "echo OK",
        "version_cmd": "echo builtin-v3",
        "install": "Built into AEGIS AI V3 — no installation required.",
        "timeout": 60,
        "destructive": False,
        "note": "Auth, authorization, rate limit, CORS, validation, headers and BOLA heuristics.",
    },
    "ai_correlation": {
        "label": "Unified AI Correlation",
        "category": "Correlation Engine",
        "kind": "builtin",
        "binary": "builtin",
        "check": "echo OK",
        "version_cmd": "echo builtin-v3",
        "install": "Built into AEGIS AI V3 — no installation required.",
        "timeout": 60,
        "destructive": False,
        "note": "Deduplicates findings from all tools into one evidence-preserving finding.",
    },
    "tool_center": {
        "label": "Tool Management Center",
        "category": "Management",
        "kind": "builtin",
        "binary": "builtin",
        "check": "echo OK",
        "version_cmd": "echo builtin-v3",
        "install": "Built into AEGIS AI V3 — no installation required.",
        "timeout": 60,
        "destructive": False,
        "note": "Live status, version, last execution, configuration and error logs for every tool.",
    },
}

# V3.1 tool contracts. These are fed to Gemini as real JSON parameter schemas and
# are returned by /api/tools. A tool is never exposed to the model without an
# explicit contract, permission level and declared output shape.
PATH_PARAM = {
    "path": {
        "type": "STRING",
        "description": "Authorized local source tree. Defaults to the run's validated lab path.",
    }
}
TARGET_PARAM = {
    "target": {
        "type": "STRING",
        "description": "Authorized http(s)://localhost or 127.0.0.1 URL. Defaults to the validated run target.",
    },
    "url": {
        "type": "STRING",
        "description": "Alias for target; must also be an authorized localhost URL.",
    },
}
FINDINGS_OUTPUT = {
    "type": "OBJECT",
    "properties": {
        "ok": {"type": "BOOLEAN"},
        "available": {"type": "BOOLEAN"},
        "findings_count": {"type": "INTEGER"},
        "findings": {"type": "ARRAY"},
        "duration_ms": {"type": "INTEGER"},
        "error": {"type": "STRING"},
    },
}

TOOL_CONTRACTS: dict[str, dict] = {
    "semgrep": {
        "description": "Static application security testing (SAST) on the authorized source tree.",
        "parameters_schema": {"type": "OBJECT", "properties": dict(PATH_PARAM)},
        "permission_level": "read-local-source",
        "output_schema": FINDINGS_OUTPUT,
    },
    "trivy": {
        "description": "Dependency and misconfiguration CVE scanning on the authorized local path.",
        "parameters_schema": {"type": "OBJECT", "properties": dict(PATH_PARAM)},
        "permission_level": "read-local-source",
        "output_schema": FINDINGS_OUTPUT,
    },
    "gitleaks": {
        "description": "Secret detection on the authorized local path; secret values are masked.",
        "parameters_schema": {"type": "OBJECT", "properties": dict(PATH_PARAM)},
        "permission_level": "read-local-source-masked",
        "output_schema": FINDINGS_OUTPUT,
    },
    "httpx": {
        "description": "HTTP status, title and technology fingerprint of the authorized localhost URL.",
        "parameters_schema": {"type": "OBJECT", "properties": dict(TARGET_PARAM)},
        "permission_level": "probe-localhost",
        "output_schema": FINDINGS_OUTPUT,
    },
    "katana": {
        "description": "Crawls the authorized localhost URL and lists discovered endpoints.",
        "parameters_schema": {"type": "OBJECT", "properties": dict(TARGET_PARAM)},
        "permission_level": "crawl-localhost",
        "output_schema": FINDINGS_OUTPUT,
    },
    "api_security": {
        "description": "REST/GraphQL security checks against the authorized localhost URL.",
        "parameters_schema": {"type": "OBJECT", "properties": dict(TARGET_PARAM)},
        "permission_level": "probe-localhost",
        "output_schema": FINDINGS_OUTPUT,
    },
    "testssl": {
        "description": "TLS/certificate analysis; only for an authorized https://localhost URL.",
        "parameters_schema": {
            "type": "OBJECT",
            "properties": {
                "target": {
                    "type": "STRING",
                    "description": "Authorized https://localhost URL only.",
                }
            },
        },
        "permission_level": "probe-localhost-tls",
        "output_schema": FINDINGS_OUTPUT,
    },
    "burp": {
        "description": "Safe Burp availability/version validation; never proxies live traffic or executes payloads.",
        "parameters_schema": {"type": "OBJECT", "properties": {}},
        "permission_level": "validate-only",
        "output_schema": FINDINGS_OUTPUT,
    },
    "metasploit": {
        "description": "Version and read-only module inventory; exploit and payload execution is disabled by policy.",
        "parameters_schema": {"type": "OBJECT", "properties": {}},
        "permission_level": "validate-only",
        "output_schema": FINDINGS_OUTPUT,
    },
    "ai_correlation": {
        "description": "Deduplicates real findings from all tools into one evidence-preserving result.",
        "parameters_schema": {"type": "OBJECT", "properties": {}},
        "permission_level": "read-results",
        "output_schema": {
            "type": "OBJECT",
            "properties": {"ok": {"type": "BOOLEAN"}, "stats": {"type": "OBJECT"}, "groups": {"type": "ARRAY"}},
        },
    },
    "tool_center": {
        "description": "Live status, version, install guide and execution metadata for every tool.",
        "parameters_schema": {"type": "OBJECT", "properties": {}},
        "permission_level": "read-status",
        "output_schema": {"type": "OBJECT", "properties": {"tools": {"type": "OBJECT"}}},
    },
}

for _tool_name, _contract in TOOL_CONTRACTS.items():
    if _tool_name in DEEP_TOOLS:
        DEEP_TOOLS[_tool_name].update(_contract)


def is_allowed_scan_path(path: str | Path) -> tuple[bool, str]:
    """Only explicitly defined local lab trees may be scanned by file-based tools."""
    try:
        raw = str(path)
        if os.name == "nt" and raw.startswith("/mnt/"):
            mount = re.fullmatch(r"/mnt/([A-Za-z])/(.+)", raw)
            if not mount:
                return False, "SCOPE BLOCKED: invalid WSL drive path."
            tail = mount.group(2)
            if any(c in tail for c in ("\\", ":", "\x00")) or any(
                part in {"", ".", ".."} for part in tail.rstrip("/").split("/")
            ):
                return False, "SCOPE BLOCKED: invalid WSL drive path."
            raw = mount.group(1) + ":/" + tail
        resolved = Path(raw).resolve()
    except (OSError, ValueError):
        return False, "Invalid path."
    for allowed in ALLOWED_SCAN_DIRS:
        try:
            if resolved == allowed.resolve() or allowed.resolve() in resolved.parents:
                return True, str(resolved)
        except OSError:
            continue
    return False, f"SCOPE BLOCKED: {resolved} is outside the allowed local lab paths."


def check_tool(name: str) -> dict:
    meta = DEEP_TOOLS.get(name)
    if not meta:
        return {"tool": name, "status": "UNKNOWN", "version": None, "error": "Unknown tool."}
    entry = {
        "tool": name,
        "label": meta["label"],
        "category": meta["category"],
        "kind": meta["kind"],
        "status": "MISSING",
        "version": None,
        "error": None,
        "install": meta["install"],
        "note": meta["note"],
        "description": meta.get("description", meta["note"]),
        "parameters_schema": meta.get("parameters_schema", {"type": "OBJECT", "properties": {}}),
        "permission_level": meta.get("permission_level", "read-status"),
        "output_schema": meta.get("output_schema", {"type": "OBJECT", "properties": {}}),
        "destructive": meta["destructive"],
        "timeout": meta["timeout"],
    }
    try:
        proc = _run(meta["check"], 30)
        entry["status"] = "OK" if "OK" in proc.stdout else "MISSING"
        if entry["status"] == "OK":
            try:
                ver = _run(meta["version_cmd"], 45)
                text = (ver.stdout or ver.stderr or "").strip().splitlines()
                entry["version"] = text[0][:120] if text else None
            except Exception as exc:
                entry["version"] = None
                entry["error"] = f"Version check failed: {type(exc).__name__}"
    except (DastError, ScanCancelled) as exc:
        entry["status"] = "ERROR"
        entry["error"] = str(exc)[:200]
    except Exception as exc:
        entry["status"] = "ERROR"
        entry["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
    return entry


def check_all_tools() -> dict[str, dict]:
    return {name: check_tool(name) for name in DEEP_TOOLS}


def available_tools() -> list[str]:
    return [name for name, entry in check_all_tools().items() if entry["status"] == "OK"]


def install_guide(name: str) -> dict:
    meta = DEEP_TOOLS.get(name)
    if not meta:
        return {"tool": name, "found": False, "guide": "Unknown tool."}
    return {
        "tool": name,
        "label": meta["label"],
        "found": True,
        "guide": meta["install"],
        "note": meta["note"],
    }
