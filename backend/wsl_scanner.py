"""WSL2-based dynamic application security testing (DAST) orchestration.

Only localhost / 127.0.0.1 targets are accepted. The tools are expected in the
default Ubuntu WSL distribution:

    ffuf    ~/tools/ffuf
    sqlmap  ~/.local/bin/sqlmap
    ZAP     ~/tools/ZAP_*/zap.sh

Missing tools degrade gracefully; the scan reports their status instead of
failing the whole run.
"""

import contextvars
import json
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, urlsplit, urlunsplit

from backend.guardrail import GuardrailBlocked, assert_safe_command

BASE_DIR = Path(__file__).resolve().parent.parent
WORDLIST = BASE_DIR / "wordlists" / "common.txt"
HIDDEN_WORDLIST = BASE_DIR / "wordlists" / "hidden_files.txt"
DNS_WORDLIST = BASE_DIR / "wordlists" / "dns_subdomains.txt"
NUCLEI_TEMPLATES = BASE_DIR / "wordlists" / "nuclei-templates"

FFUF_BIN = '"$HOME/tools/ffuf"'
SQLMAP_BIN = '"$HOME/.local/bin/sqlmap"'
NMAP_BIN = "/usr/bin/nmap"
GOFILE_BIN = "/usr/bin/gobuster"
NUCLEI_BIN = '"$HOME/tools/nuclei"'
DNSRECON_BIN = '"$HOME/.local/bin/dnsrecon"'
DIG_BIN = "/usr/bin/dig"
DNS_RESOLVER = "127.0.0.1"
DNS_LAB_DOMAIN = "aegis-lab.local"


class DastError(Exception):
    pass


class ScanCancelled(Exception):
    """Raised cooperatively when a running scan is cancelled."""


_cancel_event: contextvars.ContextVar = contextvars.ContextVar("aegis_cancel_event", default=None)


def bind_cancel_event(event):
    """Binds a threading.Event to the current execution context (scan task)."""
    return _cancel_event.set(event)


def clear_cancel_event(token) -> None:
    """Restores the previous cancellation binding."""
    _cancel_event.reset(token)


def check_cancelled() -> None:
    event = _cancel_event.get()
    if event is not None and event.is_set():
        raise ScanCancelled("The user cancelled the scan.")


def _wsl_path(path: Path) -> str:
    """Converts C:\\Users\\... to /mnt/c/Users/... for use inside WSL."""
    drive = path.drive.rstrip(":").lower()
    rest = str(path)[len(path.drive):].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def _terminate_process(proc: subprocess.Popen) -> None:
    """Best-effort termination of wsl.exe and its child processes on cancel."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass


def _run(cmd: str, timeout: int) -> subprocess.CompletedProcess:
    """Executes an allowlisted WSL command with cooperative cancellation.

    The loop keeps the original timeout behaviour but polls the scan-specific
    cancellation event every 500 ms so long ZAP/sqlmap runs can be stopped.
    """
    check_cancelled()
    try:
        assert_safe_command(cmd)
    except GuardrailBlocked as exc:
        raise DastError(f"GUARDRAIL: {exc}") from exc

    try:
        proc = subprocess.Popen(
            ["wsl", "-e", "bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise DastError("wsl.exe was not found. Is WSL2 installed?") from exc

    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                check_cancelled()
                if time.monotonic() >= deadline:
                    _terminate_process(proc)
                    raise DastError(f"Command timed out ({timeout}s).")
    except ScanCancelled:
        _terminate_process(proc)
        raise
    except DastError:
        raise
    except Exception as exc:
        _terminate_process(proc)
        raise DastError(f"Could not execute the WSL command: {exc}") from exc

    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout or "", stderr or "")


def validate_dast_target(target: str) -> str:
    """Strict localhost scope guard (SSRF + DNS-rebinding hardened).

    Only the two literal loopback names are accepted. `localhost` is rewritten
    to `127.0.0.1` so no downstream tool ever performs a DNS lookup that could
    be rebound to a non-loopback address. Userinfo and fragments are dropped;
    redirects are never followed by our own HTTP probes (see deep_scanner).
    """
    raw = str(target or "").strip()
    try:
        parsed = urlsplit(raw)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except (ValueError, AttributeError) as exc:
        raise DastError("Invalid target URL.") from exc
    if parsed.scheme not in {"http", "https"} or hostname not in {"localhost", "127.0.0.1"}:
        raise DastError("DAST runs only against localhost / 127.0.0.1 targets.")
    if port is not None and not (1 <= port <= 65535):
        raise DastError("Invalid port.")
    # Canonical loopback netloc: no hostname, no credentials, no rebinding.
    netloc = f"127.0.0.1:{port}" if port is not None else "127.0.0.1"
    canonical = urlunsplit((parsed.scheme, netloc, parsed.path or "", parsed.query, ""))
    return canonical.rstrip("/")


def _find_zap() -> str | None:
    proc = _run('ls -1 "$HOME"/tools/ZAP_*/zap.sh 2>/dev/null | sort -V | tail -n 1', 30)
    path = proc.stdout.strip()
    return path or None


def dast_tool_status() -> dict:
    checks = {
        "nmap": f"[ -x {NMAP_BIN} ] && echo OK || echo MISSING",
        "dnsrecon": f"[ -x {DNSRECON_BIN} ] && echo OK || echo MISSING",
        "ffuf": f"[ -x {FFUF_BIN} ] && echo OK || echo MISSING",
        "gofile": f"[ -x {GOFILE_BIN} ] && echo OK || echo MISSING",
        "sqlmap": f"[ -x {SQLMAP_BIN} ] && echo OK || echo MISSING",
        "zap": 'ls -1 "$HOME"/tools/ZAP_*/zap.sh 2>/dev/null | head -n 1 | grep -q zap.sh && echo OK || echo MISSING',
        "nuclei": f"[ -x {NUCLEI_BIN} ] && echo OK || echo MISSING",
    }
    status = {}
    for name, check in checks.items():
        proc = _run(check, 30)
        state = "OK" if "OK" in proc.stdout else "MISSING"
        status[name] = {"status": state}
    return status


def run_ffuf(target: str) -> dict:
    out = "/tmp/aegis_ffuf.json"
    wordlist = shlex.quote(_wsl_path(WORDLIST))
    url = shlex.quote(target + "/FUZZ")
    cmd = (
        f"rm -f {out}; {FFUF_BIN} -u {url} -w {wordlist} "
        f"-mc 200,204,301,302,307,401,403 -of json -o {out} -s >/dev/null 2>&1; "
        f"cat {out} 2>/dev/null"
    )
    proc = _run(cmd, 180)
    raw = proc.stdout.strip()
    if not raw:
        return {"tool": "ffuf", "ok": False, "error": "ffuf did not produce output", "results": []}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"tool": "ffuf", "ok": False, "error": "Could not parse ffuf JSON output", "results": []}

    results = []
    for item in data.get("results", []):
        path = "/" + str(item.get("input", {}).get("FUZZ", "")).lstrip("/")
        results.append({"path": path, "status": item.get("status"), "length": item.get("length")})
    return {"tool": "ffuf", "ok": True, "results": results}


def run_gofile(target: str) -> dict:
    """GoBuster 'gofile' pass: hidden files, backups and forgotten directories."""
    out = "/tmp/aegis_gofile.txt"
    wordlist = shlex.quote(_wsl_path(HIDDEN_WORDLIST))
    cmd = (
        f"rm -f {out}; {GOFILE_BIN} dir -u {shlex.quote(target)} -w {wordlist} "
        f"-s 200,204,301,302,307,401,403 -b '' -x php,txt,json,bak,sql "
        f"-t 12 -q -np -nc -ne -e -o {out} >/dev/null 2>&1; cat {out} 2>/dev/null"
    )
    proc = _run(cmd, 300)
    raw = proc.stdout.strip()
    findings = []
    seen = set()
    for line in raw.splitlines():
        match = re.match(r"(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line.strip())
        if not match:
            continue
        url, status, size = match.groups()
        path = urlparse(url).path or "/"
        if path in seen:
            continue
        seen.add(path)
        segments = [seg for seg in path.split("/") if seg]
        hidden = (
            any(seg.startswith(".") for seg in segments)
            or path.lower().endswith((".bak", ".old", ".sql", ".zip", ".env"))
        )
        findings.append({"path": path, "status": int(status), "size": int(size), "hidden": hidden})

    return {
        "tool": "gofile",
        "ok": bool(findings),
        "findings": findings[:20],
        "count": len(findings),
        "hidden_count": sum(1 for f in findings if f["hidden"]),
        "error": None if findings else "No hidden-file findings.",
    }


def run_sqlmap(target: str) -> dict:
    outdir = "/tmp/aegis_sqlmap"
    cmd = (
        f"rm -rf {outdir}; {SQLMAP_BIN} -u {shlex.quote(target)} "
        f"--crawl=2 --batch --level=1 --risk=1 --technique=BEU --flush-session "
        f"--threads=1 --timeout=10 --retries=1 --output-dir={outdir} 2>&1"
    )
    proc = _run(cmd, 420)
    log = (proc.stdout or "") + "\n" + (proc.stderr or "")

    parameters = list(dict.fromkeys(p.strip() for p in re.findall(r"Parameter: (.+)", log)))
    types = list(dict.fromkeys(t.strip() for t in re.findall(r"Type: (.+)", log)))
    payloads = list(dict.fromkeys(p.strip() for p in re.findall(r"Payload: (.+)", log)))
    dbms_match = re.search(r"back-end DBMS: (.+)", log)
    injectable = bool(parameters)

    return {
        "tool": "sqlmap",
        "ok": True,
        "injectable": injectable,
        "parameters": parameters,
        "types": types,
        "payloads": payloads[:3],
        "dbms": dbms_match.group(1).strip() if dbms_match else None,
        "error": None if injectable else "sqlmap did not detect an injection",
    }


def run_zap(target: str) -> dict:
    zap = _find_zap()
    if not zap:
        return {"tool": "zap", "ok": False, "error": "ZAP is not installed", "alerts": [], "alert_count": 0}

    out = "/tmp/aegis_zap.xml"
    cmd = (
        f"rm -f {out}; {shlex.quote(zap)} -cmd -quickurl {shlex.quote(target)} "
        f"-quickout {out} -quickprogress >/tmp/aegis_zap.log 2>&1; cat {out} 2>/dev/null"
    )
    proc = _run(cmd, 900)
    raw = proc.stdout.strip()
    if not raw:
        return {"tool": "zap", "ok": False, "error": "ZAP did not produce a report", "alerts": [], "alert_count": 0}

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"tool": "zap", "ok": False, "error": "Could not parse the ZAP XML report", "alerts": [], "alert_count": 0}

    alerts = []
    seen = set()
    for item in root.findall(".//alertitem"):
        risk = (item.findtext("riskdesc") or "").strip()
        if risk.split(" ")[0] not in {"High", "Medium"}:
            continue
        title = (item.findtext("alert") or "").strip()
        instances = item.findall(".//instance")
        uri = (instances[0].findtext("uri") or "").strip() if instances else ""
        key = (title, uri)
        if key in seen:
            continue
        seen.add(key)
        alerts.append({"title": title, "risk": risk, "endpoint": uri, "instances": len(instances)})

    return {
        "tool": "zap",
        "ok": True,
        "alerts": alerts,
        "alert_count": len(root.findall(".//alertitem")),
    }


def run_nmap(target: str) -> dict:
    """TCP connect + service/version scan of the local target (no raw sockets needed)."""
    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ports = str(port) if port not in (80, 443) else "80,443,5000,5001,8765"

    cmd = f"{NMAP_BIN} -sT -sV -Pn --open -p {ports} {shlex.quote(host)} 2>&1"
    proc = _run(cmd, 240)
    log = (proc.stdout or "") + "\n" + (proc.stderr or "")

    ports_found = []
    for line in log.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$", line.strip())
        if match:
            ports_found.append({
                "port": f"{match.group(1)}/{match.group(2)}",
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip(),
            })

    return {
        "tool": "nmap",
        "ok": True,
        "host": host,
        "ports": ports_found,
        "scanned_ports": ports,
        "error": None if ports_found else "nmap acik port bulamadi",
    }


def run_dnsrecon(target: str) -> dict:
    """Offline DNS recon against the local lab resolver (never queries the internet)."""
    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    domain = DNS_LAB_DOMAIN if host in {"127.0.0.1", "localhost"} else host
    wordlist = shlex.quote(_wsl_path(DNS_WORDLIST))

    cmd = (
        f"echo --A--; {DIG_BIN} +short @{DNS_RESOLVER} {domain} A; "
        f"echo --TXT--; {DIG_BIN} +short @{DNS_RESOLVER} {domain} TXT; "
        f"echo --NS--; {DIG_BIN} +short @{DNS_RESOLVER} {domain} NS; "
        f"echo --MX--; {DIG_BIN} +short @{DNS_RESOLVER} {domain} MX; "
        f"echo --BRT--; {DNSRECON_BIN} -d {domain} -n {DNS_RESOLVER} -t brt "
        f"-D {wordlist} 2>/dev/null | grep -F '[+]'; "
        f"echo --RVL--; {DNSRECON_BIN} -n {DNS_RESOLVER} -r 127.0.0.1-127.0.0.2 "
        f"-t rvl 2>/dev/null | grep -F '[+]'"
    )
    proc = _run(cmd, 180)
    log = proc.stdout or ""

    sections = {"A": [], "TXT": [], "NS": [], "MX": [], "BRT": [], "RVL": []}
    current = None
    for raw in log.splitlines():
        line = raw.strip()
        if line.startswith("--") and line.endswith("--"):
            current = line.strip("-")
            continue
        if not line or current not in sections:
            continue
        if current in {"BRT", "RVL"}:
            sections[current].append(line)
        else:
            sections[current].append(line)

    subdomains = []
    for line in sections["BRT"]:
        match = re.search(r"A\s+([\w.-]+)\s+([\d.]+)", line)
        if match:
            subdomains.append({"host": match.group(1), "ip": match.group(2)})

    ptr = []
    for line in sections["RVL"]:
        match = re.search(r"PTR\s+([\w.-]+)\s+([\d.]+)", line)
        if match:
            ptr.append({"host": match.group(1), "ip": match.group(2)})

    records = []
    for rtype in ("A", "TXT", "NS", "MX"):
        for value in sections[rtype]:
            records.append({"type": rtype, "value": value[:160]})

    offline = not (records or subdomains or ptr)
    return {
        "tool": "dnsrecon",
        "ok": not offline,
        "domain": domain,
        "resolver": DNS_RESOLVER,
        "records": records,
        "subdomains": subdomains,
        "ptr": ptr,
        "offline": offline,
        "error": None if not offline else "The local DNS lab server (127.0.0.1:53) is not running.",
    }


def run_nuclei(target: str) -> dict:
    """Template-driven vulnerability checks using the bundled local AegisAI templates."""
    templates = shlex.quote(_wsl_path(NUCLEI_TEMPLATES))
    cmd = (
        f"rm -f /tmp/aegis_nuclei.jsonl; {NUCLEI_BIN} -u {shlex.quote(target)} "
        f"-t {templates} -j -o /tmp/aegis_nuclei.jsonl -silent -no-color "
        f"-timeout 5 -retries 0 -duc >/dev/null 2>&1; "
        f"cat /tmp/aegis_nuclei.jsonl 2>/dev/null"
    )
    proc = _run(cmd, 240)
    raw = proc.stdout.strip()
    if not raw:
        return {"tool": "nuclei", "ok": False, "findings": [], "count": 0,
                "error": "Nuclei did not produce results."}

    findings = []
    seen = set()
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        template_id = item.get("template-id", "unknown")
        endpoint = item.get("matched-at", "")
        key = (template_id, endpoint)
        if key in seen:
            continue
        seen.add(key)
        info = item.get("info") or {}
        severity = info.get("severity", "info")
        if severity not in {"high", "medium", "critical"} and len(findings) >= 4:
            continue
        findings.append({
            "id": template_id,
            "name": info.get("name", template_id),
            "severity": severity,
            "endpoint": endpoint[:160],
        })

    return {"tool": "nuclei", "ok": bool(findings), "findings": findings,
            "count": len(findings), "error": None if findings else "No Nuclei findings."}
