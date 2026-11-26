"""AEGIS AI V3 — Real execution and result processing for deep security tools.

Every runner:
  * validates scope (localhost target / allowlisted local source tree)
  * executes through the guarded WSL subprocess executor
  * parses real tool output into one normalized finding schema
  * masks sensitive values before they reach reports or the AI engine

No synthetic findings are produced. Missing tools return an honest error and
installation guidance instead of crashing the scan.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from pathlib import Path

from backend.tool_registry import DEEP_TOOLS, check_tool, is_allowed_scan_path
from backend.wsl_scanner import (
    DastError, ScanCancelled, _run, _wsl_path, validate_dast_target,
)

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO", "NOTE": "INFO",
    "SEVERE": "HIGH", "MODERATE": "MEDIUM",
}


def mask_secret(value: str) -> str:
    """Masks a secret while keeping just enough shape to be useful in a report."""
    text = str(value or "")
    if not text:
        return "<redacted>"
    if len(text) <= 6:
        return "*" * len(text)
    return f"{text[:2]}{'*' * min(12, len(text) - 4)}{text[-2:]}"


def normalize_severity(value: str) -> str:
    return SEVERITY_MAP.get(str(value or "").strip().upper(), "MEDIUM")


def _finding(
    tool: str,
    fid: str,
    title: str,
    severity: str,
    *,
    file: str = "",
    line: int = 0,
    endpoint: str = "",
    evidence: str = "",
    cve: str = "",
    remediation: str = "",
    category: str = "",
) -> dict:
    return {
        "id": f"{tool.upper()}-{fid}"[:80],
        "tool": tool,
        "category": category or DEEP_TOOLS.get(tool, {}).get("category", "deep"),
        "title": str(title)[:180],
        "severity": normalize_severity(severity),
        "file": str(file)[:300],
        "line": int(line or 0),
        "endpoint": str(endpoint)[:300],
        "evidence": str(evidence)[:600],
        "cve": str(cve)[:60],
        "remediation": str(remediation)[:400],
    }


def empty_result(tool: str, error: str, available: bool = False) -> dict:
    return {
        "tool": tool,
        "ok": False,
        "available": available,
        "version": None,
        "findings": [],
        "error": str(error)[:300],
        "command": "",
        "raw_summary": "",
        "duration_ms": 0,
    }


def _result(tool: str, proc, findings: list[dict], started: float, command: str) -> dict:
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    entry = {
        "tool": tool,
        "ok": proc.returncode in (0, 1),
        "available": True,
        "version": None,
        "findings": findings,
        "error": None if proc.returncode in (0, 1) else out.strip()[-300:],
        "command": command[:300],
        "raw_summary": re.sub(r"\x1b\[[0-9;]*m", "", out).strip()[:1200],
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    return entry


def _parse_json_output(text: str):
    """Extracts the first JSON object/array from noisy tool output."""
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", text or "")
    cleaned = re.sub(r"```(?:json)?", "", cleaned)
    for opener, closer in (("{", "}"), ("[", "]")):
        start = cleaned.find(opener)
        if start < 0:
            continue
        depth = 0
        in_str = False
        escaped = False
        for idx in range(start, len(cleaned)):
            ch = cleaned[idx]
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_str:
                escaped = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start:idx + 1])
                    except (ValueError, TypeError):
                        break
    return None


LOG_MARKER = "__AEGIS_LOG__"


def _captured_command(tool_cmd: str, out_file: str, log_file: str) -> str:
    """Runs a tool with separated JSON output + stderr log.

    A tool that fails still exits 0 because the trailing `cat` succeeds, so the
    caller MUST inspect the log half and report the error honestly.
    """
    return (
        f"{tool_cmd} >{log_file} 2>&1; "
        f"cat {out_file} 2>/dev/null; echo {LOG_MARKER}; cat {log_file} 2>/dev/null"
    )


def _captured_stdout_command(tool_cmd: str, out_file: str, log_file: str) -> str:
    """For tools (Trivy) that emit JSON on stdout rather than a report file."""
    return (
        f"{tool_cmd} >{out_file} 2>{log_file}; "
        f"cat {out_file} 2>/dev/null; echo {LOG_MARKER}; cat {log_file} 2>/dev/null"
    )


def _split_captured(text: str) -> tuple[str, str]:
    parts = (text or "").split(LOG_MARKER, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def _parse_error(log_text: str, fallback: str) -> dict | None:
    tail = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "").strip()[-300:]
    if tail:
        return empty_result("", tail)  # replaced by caller with the real tool name
    return None


def _guarded_dir(path: str | Path) -> tuple[str | None, str | None]:
    ok, msg = is_allowed_scan_path(path)
    if not ok:
        return None, msg
    return _wsl_path(Path(msg)), None


def _guarded_target(target: str) -> tuple[str | None, str | None]:
    try:
        # Shared strict guard: literal loopback only, `localhost` canonicalized
        # to 127.0.0.1 so no tool can DNS-rebind the scan to an external host.
        return validate_dast_target(target), None
    except DastError as exc:
        return None, f"SCOPE BLOCKED: {exc}"


# ---------------------------------------------------------------------------
# 1. Metasploit — safe validation lab (inventory + CVE/service mapping only)
# ---------------------------------------------------------------------------
def run_metasploit(target: str, *, service_terms: list[str] | None = None) -> dict:
    status = check_tool("metasploit")
    if status["status"] != "OK":
        return empty_result("metasploit", f"Metasploit is not installed. {status['install']}", False)
    target, err = _guarded_target(target)
    if err:
        return empty_result("metasploit", err, True)

    findings: list[dict] = []
    started = time.monotonic()
    commands: list[str] = []
    try:
        # Resolve the real binary: Rapid7 apt installs it on PATH, older clones
        # live at ~/metasploit-framework/msfconsole. No $(...) — the command
        # guardrail deliberately rejects shell substitution.
        located = (_run("command -v msfconsole", 15).stdout or "").strip().splitlines()
        msf = located[0] if located and located[0].startswith("/") else '"$HOME/metasploit-framework/msfconsole"'
        ver = _run(f'{msf} --version 2>&1 | head -n 2', 90)
        commands.append("msfconsole --version")
        version_text = (ver.stdout or "").lower()
        if "metasploit" in version_text or "framework" in version_text:
            findings.append(_finding(
                "metasploit", "FRAMEWORK-READY", "Metasploit Framework verified", "INFO",
                endpoint=target,
                evidence=(ver.stdout or "").strip()[:200],
                remediation="Use only in an authorized laboratory environment.",
            ))

        # Read-only module inventory — NO exploit, NO payload, NO run command.
        terms = list(dict.fromkeys((service_terms or []) + ["http", "ssl"]))[:4]
        for term in terms:
            safe = re.sub(r"[^a-zA-Z0-9._-]", "", term)[:40]
            if not safe:
                continue
            # -x exits after the command; no `; exit` is needed (and the
            # guardrail correctly rejects embedded shell separators).
            # Modern Metasploit (6.5) dropped `type:scanner`; `search scanner`
            # is the portable form that still lists auxiliary scanner modules.
            cmd = (
                f'{msf} -q -x '
                f'"search scanner {safe}" 2>&1 | head -n 25'
            )
            proc = _run(cmd, DEEP_TOOLS["metasploit"]["timeout"])
            commands.append(f"msfconsole -q search scanner {safe}")
            body = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout or "")
            # msfconsole prints rows as "   0    auxiliary/scanner/http/...";
            # capture the module path after the optional numeric index.
            modules: list[str] = []
            for line in body.splitlines():
                match = re.match(r"\s*(?:\d+\s+)?((?:auxiliary|exploit|post)/[^\s]+)", line)
                if match:
                    modules.append(match.group(1))
                if len(modules) >= 8:
                    break
            if modules:
                findings.append(_finding(
                    "metasploit", f"MODULES-{safe}", f"Safe scanning modules for {safe}", "INFO",
                    endpoint=target,
                    evidence=" | ".join(modules[:5]),
                    remediation="These modules are for read-only validation; no exploit is executed automatically.",
                ))
        return _result("metasploit", ver, findings, started, " ; ".join(commands))
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("metasploit", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 2. Burp Suite — real CLI when present, guarded local HTTP analysis fallback
# ---------------------------------------------------------------------------
def run_burp(target: str) -> dict:
    target, err = _guarded_target(target)
    if err:
        return empty_result("burp", err)
    status = check_tool("burp")
    started = time.monotonic()
    findings: list[dict] = []
    command = ""
    if status["status"] == "OK":
        try:
            command = f"burpsuite -quickmode -f /tmp/aegis_burp_{int(started)}.burp -u {target}"
            proc = _run(f"timeout 240 burpsuite -quickmode -u {target} 2>&1 | head -n 40", 240)
            body = proc.stdout or ""
            for m in re.finditer(r"(?i)(missing|insecure|weak|exposed).{0,90}", body):
                findings.append(_finding("burp", f"CLI-{len(findings)+1}", m.group(0)[:140], "MEDIUM", endpoint=target, evidence=m.group(0)[:200]))
            return _result("burp", proc, findings, started, command)
        except (DastError, ScanCancelled) as exc:
            return {**empty_result("burp", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}
    return _burp_style_http_analysis(target, started)


def _burp_style_http_analysis(target: str, started: float) -> dict:
    """Real request/response analysis when Burp CLI is unavailable (honest fallback)."""
    import requests

    findings: list[dict] = []
    paths = ["/", "/backend.php?action=state", "/api.php?resource=product", "/secretfekx.php"]
    responses = []
    for path in paths:
        try:
            r = requests.get(target + path, timeout=6, allow_redirects=False, verify=False)
        except requests.RequestException as exc:
            findings.append(_finding("burp", f"CONN-{len(findings)+1}", f"Endpoint unreachable: {path}", "LOW", endpoint=path, evidence=type(exc).__name__))
            continue
        responses.append((path, r))
        h = {k.lower(): v for k, v in r.headers.items()}
        for header, title, sev in (
            ("content-security-policy", "Content Security Policy missing", "MEDIUM"),
            ("x-frame-options", "Anti-clickjacking header missing", "LOW"),
            ("x-content-type-options", "X-Content-Type-Options missing", "LOW"),
            ("strict-transport-security", "HSTS missing", "LOW"),
        ):
            if header not in h:
                findings.append(_finding(
                    "burp", f"HDR-{header[:6]}-{len(findings)}", title, sev,
                    endpoint=path, evidence=f"{path} response header '{header}' not found",
                    remediation=f"Add the '{header}' header.",
                ))
        if "access-control-allow-origin" in h and h.get("access-control-allow-origin") == "*":
            findings.append(_finding("burp", f"CORS-{len(findings)}", "CORS wildcard origin", "MEDIUM", endpoint=path,
                                     evidence="Access-Control-Allow-Origin: *", remediation="Use an origin allowlist."))
        body = r.text or ""
        if any(k in body.lower() for k in ("csrf", "token")) and "set-cookie" not in h:
            findings.append(_finding("burp", f"AUTH-{len(findings)}", "CSRF token present but no session cookie", "LOW",
                                     endpoint=path, evidence="token observed, Set-Cookie not observed"))

    return {
        "tool": "burp",
        "ok": True,
        "available": False,
        "version": "built-in local HTTP analysis (Burp CLI not installed)",
        "findings": findings,
        "error": None,
        "command": f"local request/response analysis -> {target}",
        "raw_summary": f"{len(responses)} endpoints analyzed, {len(findings)} findings.",
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


# ---------------------------------------------------------------------------
# 3. Semgrep — source code analysis
# ---------------------------------------------------------------------------
def run_semgrep(path: str | Path) -> dict:
    wsl_dir, err = _guarded_dir(path)
    if err:
        return empty_result("semgrep", err)
    status = check_tool("semgrep")
    if status["status"] != "OK":
        return empty_result("semgrep", f"Semgrep is not installed. {status['install']}", False)
    out = "/tmp/aegis_semgrep.json"
    log = "/tmp/aegis_semgrep.log"
    src = shlex.quote(wsl_dir)
    cmd = _captured_command(
        f'"$HOME/.local/bin/pysemgrep" scan --config auto --json --quiet '
        f'--output {out} {src}',
        out, log,
    )
    started = time.monotonic()
    try:
        proc = _run(cmd, DEEP_TOOLS["semgrep"]["timeout"])
        payload, log_text = _split_captured(proc.stdout or "")
        data = _parse_json_output(payload)
        if not isinstance(data, dict) or "results" not in data:
            detail = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "").strip()[-300:] or "Semgrep did not produce valid JSON."
            return {**empty_result("semgrep", detail, True),
                    "duration_ms": int((time.monotonic() - started) * 1000), "command": cmd[:300]}
        findings = []
        for item in (data.get("results") or [])[:80]:
            extra = item.get("extra") or {}
            finding = extra.get("metadata") or {}
            path_info = item.get("path") or ""
            findings.append(_finding(
                "semgrep", item.get("check_id", "SAST").rsplit(".", 1)[-1][:40],
                (finding.get("description") or extra.get("message") or item.get("check_id") or "SAST finding")[:160],
                extra.get("severity", finding.get("severity", "MEDIUM")),
                file=str(path_info).replace("\\", "/")[-200:],
                line=int((item.get("start") or {}).get("line") or 0),
                evidence=(extra.get("lines") or "")[:300],
                cve=",".join(finding.get("cve") or [])[:60],
                remediation=(finding.get("fix") or "Apply a secure code pattern.")[:300],
                category="Source Code Analysis",
            ))
        return _result("semgrep", proc, findings, started, cmd)
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("semgrep", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 4. Trivy — dependency / misconfiguration / container security
# ---------------------------------------------------------------------------
def run_trivy(path: str | Path, *, image: str | None = None) -> dict:
    started = time.monotonic()
    status = check_tool("trivy")
    if status["status"] != "OK":
        return empty_result("trivy", f"Trivy is not installed. {status['install']}", False)
    if image:
        if not re.fullmatch(r"[a-zA-Z0-9._:/@-]{1,120}", image):
            return empty_result("trivy", "Invalid image name.", True)
        # Image pulls are external network access. By default only images that
        # were explicitly whitelisted by the operator may be scanned.
        allowed = {
            item.strip() for item in os.getenv("AEGIS_ALLOWED_SCAN_IMAGES", "").split(",")
            if item.strip()
        }
        if image not in allowed:
            return empty_result(
                "trivy",
                "SCOPE BLOCKED: image is not in the explicit allowlist. "
                "Add it to the AEGIS_ALLOWED_SCAN_IMAGES environment variable.",
                True,
            )
        target_arg = shlex.quote(image)
        tool_cmd = f'"$HOME/.local/bin/trivy" image --format json --no-progress --quiet {target_arg}'
    else:
        wsl_dir, err = _guarded_dir(path)
        if err:
            return empty_result("trivy", err, True)
        target_arg = shlex.quote(wsl_dir)
        tool_cmd = f'"$HOME/.local/bin/trivy" fs --format json --no-progress --quiet {target_arg}'
    out = "/tmp/aegis_trivy.json"
    log = "/tmp/aegis_trivy.log"
    cmd = _captured_stdout_command(tool_cmd, out, log)
    try:
        proc = _run(cmd, DEEP_TOOLS["trivy"]["timeout"])
        payload, log_text = _split_captured(proc.stdout or "")
        data = _parse_json_output(payload)
        if not isinstance(data, dict):
            detail = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "").strip()[-300:] or "Trivy did not produce valid JSON."
            return {**empty_result("trivy", detail, True),
                    "duration_ms": int((time.monotonic() - started) * 1000), "command": cmd[:300]}
        findings = []
        for result in (data.get("Results") or [])[:40]:
            target = result.get("Target", "")
            for v in (result.get("Vulnerabilities") or [])[:40]:
                findings.append(_finding(
                    "trivy", (v.get("VulnerabilityID") or "VULN").replace("-", "_")[:50],
                    (v.get("Title") or v.get("Description") or v.get("VulnerabilityID") or "Dependency CVE")[:160],
                    v.get("Severity", "MEDIUM"),
                    file=str(target)[:200],
                    endpoint=str(target)[:200],
                    evidence=f"{v.get('PkgName','')} {v.get('InstalledVersion','')} -> {v.get('FixedVersion','')}".strip()[:250],
                    cve=v.get("VulnerabilityID", "")[:60],
                    remediation=f"Upgrade the {v.get('PkgName','')} package to version {v.get('FixedVersion','fixed version')}.",
                    category="Dependency & Container Security",
                ))
            for m in (result.get("Misconfigurations") or [])[:20]:
                findings.append(_finding(
                    "trivy", f"MISCONF-{len(findings)}", m.get("Title", "Misconfiguration")[:160],
                    m.get("Severity", "MEDIUM"), file=str(target)[:200],
                    evidence=(m.get("Message") or "")[:250],
                    remediation=(m.get("Resolution") or "Fix the configuration.")[:300],
                    category="Misconfiguration Detection",
                ))
        return _result("trivy", proc, findings, started, cmd)
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("trivy", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 5. Gitleaks — secret detection with mandatory masking
# ---------------------------------------------------------------------------
def run_gitleaks(path: str | Path) -> dict:
    wsl_dir, err = _guarded_dir(path)
    if err:
        return empty_result("gitleaks", err)
    status = check_tool("gitleaks")
    if status["status"] != "OK":
        return empty_result("gitleaks", f"Gitleaks is not installed. {status['install']}", False)
    out = "/tmp/aegis_gitleaks.json"
    log = "/tmp/aegis_gitleaks.log"
    src = shlex.quote(wsl_dir)
    cmd = _captured_command(
        f'"$HOME/.local/bin/gitleaks" dir {src} --report-format json '
        f'--report-path {out} --no-banner --exit-code 0 --redact',
        out, log,
    )
    started = time.monotonic()
    try:
        proc = _run(cmd, DEEP_TOOLS["gitleaks"]["timeout"])
        payload, log_text = _split_captured(proc.stdout or "")
        data = _parse_json_output(payload)
        if not isinstance(data, list):
            detail = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "").strip()[-300:] or "Gitleaks did not produce valid JSON."
            return {**empty_result("gitleaks", detail, True),
                    "duration_ms": int((time.monotonic() - started) * 1000), "command": cmd[:300]}
        findings = []
        for item in (data if isinstance(data, list) else [])[:80]:
            secret = item.get("Secret") or ""
            findings.append(_finding(
                "gitleaks", (item.get("RuleID") or "SECRET").upper()[:40],
                f"Possible secret: {item.get('RuleID','secret')}",
                "HIGH",
                file=str(item.get("File") or "").replace("\\", "/")[-200:],
                line=int(item.get("StartLine") or 0),
                evidence=f"{item.get('Description','Secret detected')} | value: {mask_secret(secret)}",
                remediation="Remove the secret, rotate it, and move it to an environment variable.",
                category="Secret Detection",
            ))
        result = _result("gitleaks", proc, findings, started, cmd)
        # Defence in depth: even the raw tool summary must never carry a secret.
        result["raw_summary"] = re.sub(
            r'("Secret"\s*:\s*")[^"]*(")',
            lambda m: m.group(1) + "<redacted>" + m.group(2),
            result["raw_summary"] or "",
        )
        return result
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("gitleaks", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 6. testssl.sh — TLS intelligence (localhost TLS endpoints only)
# ---------------------------------------------------------------------------
def run_testssl(target: str) -> dict:
    target, err = _guarded_target(target)
    if err:
        return empty_result("testssl", err)
    if not target.startswith("https://"):
        return empty_result("testssl", "testssl.sh runs only against HTTPS targets (https://...).")
    status = check_tool("testssl")
    if status["status"] != "OK":
        return empty_result("testssl", f"testssl.sh is not installed. {status['install']}", False)
    # The wrapper sets TESTSSL_INSTALL_DIR itself; a VAR=... prefix would be
    # rejected by the command allowlist (and is unnecessary). This distro build
    # writes structured JSON to a FILE, not to stdout.
    out = "/tmp/aegis_testssl.json"
    log = "/tmp/aegis_testssl.log"
    cmd = _captured_command(
        '"$HOME/tools/testssl.sh/testssl.sh" --quiet --jsonfile-pretty '
        f'{out} --overwrite {target}', out, log,
    )
    started = time.monotonic()
    try:
        proc = _run(cmd, DEEP_TOOLS["testssl"]["timeout"])
        payload, log_text = _split_captured(proc.stdout or "")
        data = _parse_json_output(payload)
        if not isinstance(data, dict):
            detail = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "").strip()[-300:] or "testssl.sh did not produce valid JSON."
            return {**empty_result("testssl", detail, True),
                    "duration_ms": int((time.monotonic()-started)*1000), "command": cmd[:300]}
        findings = []
        categories = (
            "protocols", "ciphers", "serverPreferences", "fs", "serverDefaults",
            "headerResponse", "vulnerabilities", "rating", "pretest",
        )
        for scan in (data.get("scanResult") or [])[:4]:
            for category in categories:
                for item in (scan.get(category) or [])[:30]:
                    severity = str(item.get("severity") or "INFO").upper()
                    if severity in {"OK", "INFO"}:
                        continue
                    finding_text = str(item.get("finding") or "").strip()
                    if not finding_text:
                        continue
                    findings.append(_finding(
                        "testssl", f"{category[:6]}-{item.get('id', 'TLS')}".replace("-", "_")[:40],
                        f"{category}: {item.get('id', 'TLS check')}",
                        "MEDIUM" if severity == "WARN" else severity,
                        endpoint=target,
                        evidence=finding_text[:300],
                        cve=str(item.get("cve") or "")[:60],
                        remediation="Apply a secure TLS configuration (strong protocol/cipher, valid certificate).",
                        category="TLS Intelligence",
                    ))
                    if len(findings) >= 80:
                        break
                if len(findings) >= 80:
                    break
            if len(findings) >= 80:
                break
        return _result("testssl", proc, findings, started, cmd)
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("testssl", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 7a. httpx — HTTP probing / technology detection
# ---------------------------------------------------------------------------
def run_httpx(target: str) -> dict:
    target, err = _guarded_target(target)
    if err:
        return empty_result("httpx", err)
    status = check_tool("httpx")
    if status["status"] != "OK":
        return empty_result("httpx", f"httpx is not installed. {status['install']}", False)
    cmd = f'"$HOME/tools/httpx" -u {target} -json -silent -no-color -timeout 8 2>/dev/null'
    started = time.monotonic()
    try:
        proc = _run(cmd, DEEP_TOOLS["httpx"]["timeout"])
        findings = []
        for line in (proc.stdout or "").splitlines()[:40]:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            tech = ", ".join((item.get("tech") or [])[:6])
            findings.append(_finding(
                "httpx", f"PROBE-{len(findings)+1}", f"HTTP probe: {item.get('status_code','?')} {item.get('url','')[:90]}",
                "INFO", endpoint=str(item.get("url", ""))[:200],
                evidence=f"title={str(item.get('title',''))[:80]} server={str(item.get('server',''))[:60]} tech={tech[:120]}",
                category="HTTP Probing",
            ))
        if not findings and (proc.stdout or "").strip():
            detail = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout).strip()[-300:]
            return {**empty_result("httpx", detail, True),
                    "duration_ms": int((time.monotonic()-started)*1000), "command": cmd[:300]}
        return _result("httpx", proc, findings, started, cmd)
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("httpx", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 7b. Katana — endpoint crawling
# ---------------------------------------------------------------------------
def run_katana(target: str) -> dict:
    target, err = _guarded_target(target)
    if err:
        return empty_result("katana", err)
    status = check_tool("katana")
    if status["status"] != "OK":
        return empty_result("katana", f"Katana is not installed. {status['install']}", False)
    cmd = f'"$HOME/tools/katana" -u {target} -jsonl -silent -no-color -d 2 2>&1 | head -n 60'
    started = time.monotonic()
    try:
        proc = _run(cmd, DEEP_TOOLS["katana"]["timeout"])
        findings = []
        seen = set()
        for line in (proc.stdout or "").splitlines()[:60]:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            request_info = item.get("request") or {}
            url = str(item.get("endpoint") or request_info.get("endpoint") or "")
            if not url or url in seen:
                continue
            seen.add(url)
            findings.append(_finding(
                "katana", f"EP-{len(findings)+1}", f"Discovered endpoint: {url[:90]}", "INFO",
                endpoint=url[:200], evidence=str(item.get("request", ""))[:200],
                category="Endpoint Crawling",
            ))
        if not findings and (proc.stdout or "").strip():
            detail = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout).strip()[-300:]
            return {**empty_result("katana", detail, True),
                    "duration_ms": int((time.monotonic()-started)*1000), "command": cmd[:300]}
        return _result("katana", proc, findings, started, cmd)
    except (DastError, ScanCancelled) as exc:
        return {**empty_result("katana", str(exc), True), "duration_ms": int((time.monotonic()-started)*1000)}


# ---------------------------------------------------------------------------
# 8. Advanced API Security — real local probes (REST + GraphQL)
# ---------------------------------------------------------------------------
def run_api_security(target: str) -> dict:
    target, err = _guarded_target(target)
    if err:
        return empty_result("api_security", err, True)
    import requests

    started = time.monotonic()
    findings: list[dict] = []
    probes = [
        ("/backend.php?action=state", "state"),
        ("/api.php?resource=product", "api"),
        ("/api.php?resource=category", "api"),
        ("/graphql", "graphql"),
    ]
    responses = {}
    for path, kind in probes:
        try:
            r = requests.get(target + path, timeout=6, allow_redirects=False, verify=False)
            responses[path] = r
        except requests.RequestException:
            continue
        h = {k.lower(): v for k, v in r.headers.items()}
        if kind == "graphql" and r.status_code in (200, 400, 405):
            findings.append(_finding("api_security", "GRAPHQL-EXPOSED", "GraphQL endpoint reachable", "MEDIUM",
                                     endpoint=path, evidence=f"HTTP {r.status_code}",
                                     remediation="Restrict GraphQL introspection and query depth."))
        if r.status_code == 200 and any(k in r.text.lower() for k in ("password", "secret", "token", "card_number")):
            findings.append(_finding("api_security", f"SENSITIVE-{len(findings)}", "Sensitive field name in API response", "HIGH",
                                     endpoint=path, evidence="response contains a password/secret/token/card_number field",
                                     remediation="Remove sensitive fields from the API response."))
        if h.get("access-control-allow-origin") == "*":
            findings.append(_finding("api_security", f"CORS-{len(findings)}", "API CORS wildcard", "MEDIUM",
                                     endpoint=path, evidence="Access-Control-Allow-Origin: *",
                                     remediation="Apply an origin allowlist."))
        if "x-ratelimit-limit" not in h and "retry-after" not in h:
            findings.append(_finding("api_security", f"RATELIMIT-{len(findings)}", "Rate-limit header missing", "LOW",
                                     endpoint=path, evidence="rate-limit header not observed",
                                     remediation="Add rate limiting for the API."))

    # BOLA heuristic: compare two adjacent object ids from an existing collection.
    for path, r in list(responses.items())[:1]:
        try:
            payload = r.json()
            rows = payload if isinstance(payload, list) else next(
                (v for v in payload.values() if isinstance(v, list) and v), []
            )
            if rows and isinstance(rows[0], dict) and "id" in rows[0]:
                first = str(rows[0]["id"])
                findings.append(_finding(
                    "api_security", "BOLA-REVIEW", "BOLA / authorization check required", "MEDIUM",
                    endpoint=path, evidence=f"Object identifier ('{first}') appears in the API response; "
                    "cross-identity access is not tested automatically (unauthorized access is blocked).",
                    remediation="User authorization must be verified server-side for every object access.",
                ))
        except (ValueError, StopIteration, KeyError):
            pass

    return {
        "tool": "api_security", "ok": True, "available": True, "version": "builtin-v3",
        "findings": findings, "error": None,
        "command": f"local REST/GraphQL probes -> {target}",
        "raw_summary": f"{len(responses)} endpoints probed, {len(findings)} findings.",
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
def run_tool(name: str, *, target: str = "",
             path: str | Path | None = None, image: str | None = None,
             service_terms: list[str] | None = None) -> dict:
    name = str(name or "").strip().lower()
    try:
        if name == "metasploit":
            return run_metasploit(target, service_terms=service_terms)
        if name == "burp":
            return run_burp(target)
        if name == "semgrep":
            return run_semgrep(path or "")
        if name == "trivy":
            return run_trivy(path or "", image=image)
        if name == "gitleaks":
            return run_gitleaks(path or "")
        if name == "testssl":
            return run_testssl(target)
        if name == "httpx":
            return run_httpx(target)
        if name == "katana":
            return run_katana(target)
        if name == "api_security":
            return run_api_security(target)
        if name == "ai_correlation":
            return empty_result("ai_correlation", "AI Correlation is an aggregator; use /api/deep-correlate.", True)
        if name == "tool_center":
            return empty_result("tool_center", "Tool Management Center is a view; use /api/tools.", True)
        return empty_result(name or "unknown", "Unknown tool.")
    except Exception as exc:
        return empty_result(name, f"{type(exc).__name__}: {str(exc)[:200]}")
