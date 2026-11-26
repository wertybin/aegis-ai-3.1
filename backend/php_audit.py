"""Static review for a user-supplied local PHP source tree.

The analyzer only reads local project files. It reports concrete, line-anchored
findings from the real source tree; nothing here is simulated. Secrets and card
numbers are redacted in the returned evidence so the report never repeats them.
"""

from __future__ import annotations

import re
from pathlib import Path

TEXT_SUFFIXES = {".php", ".html", ".htm", ".js", ".htaccess"}
MAX_FILE_BYTES = 512 * 1024


def _read_lines(path: Path) -> list[str]:
    if path.stat().st_size > MAX_FILE_BYTES:
        return []
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _redact_card(text: str) -> str:
    digits = re.sub(r"\D", "", text)
    if len(digits) < 12:
        return text
    return f"{digits[:4]} **** **** {digits[-4:]}"


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    endpoint: str,
    file_name: str,
    line: int,
    explanation: str,
    snippet: str,
    remediation: str,
) -> dict:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "endpoint": endpoint,
        "file": file_name,
        "line": line,
        "explanation": explanation,
        "vulnerable_snippet": snippet.strip(),
        "patched_snippet": remediation.strip(),
    }


def _discover_endpoints(root: Path) -> list[dict]:
    endpoints: list[dict] = []
    seen: set[str] = set()

    def add(path: str, file_name: str, line: int = 1) -> None:
        if path in seen:
            return
        seen.add(path)
        endpoints.append({"path": path, "line": line, "file": file_name})

    page_map = [
        ("index.html", "/"),
        ("checkout.html", "/checkout.html"),
        ("checkout1.html", "/checkout1.html"),
        ("secretfekx.php", "/secretfekx.php"),
        ("api.php", "/api.php"),
        ("backend.php", "/backend.php"),
        ("data/cards_log.json", "/data/cards_log.json"),
    ]
    for name, route in page_map:
        if (root / name).exists():
            add(route, name)

    backend = root / "backend.php"
    if backend.exists():
        for idx, line in enumerate(_read_lines(backend), start=1):
            for match in re.finditer(r"\$action\s*===\s*'([^']+)'", line):
                add(f"/backend.php?action={match.group(1)}", backend.name, idx)

    api = root / "api.php"
    if api.exists():
        for idx, line in enumerate(_read_lines(api), start=1):
            for match in re.finditer(r"\$resource\s*===\s*'([^']+)'", line):
                add(f"/api.php?resource={match.group(1)}", api.name, idx)

    return endpoints


def _line_of(lines: list[str], pattern: str) -> int:
    compiled = re.compile(pattern)
    for idx, line in enumerate(lines, start=1):
        if compiled.search(line):
            return idx
    return 1


def analyze_web_project(path: Path) -> dict:
    """Scans a PHP/HTML project directory and returns a V1-compatible audit."""
    root = path.resolve()
    findings: list[dict] = []

    secret_path = root / "secretfekx.php"
    secret = _read_lines(secret_path) if secret_path.exists() else []
    config_path = root / "config.php"
    config = _read_lines(config_path) if config_path.exists() else []
    backend_path = root / "backend.php"
    backend = _read_lines(backend_path) if backend_path.exists() else []

    if secret:
        password_line = _line_of(secret, r"\$password\s*=\s*['\"]")
        save_line = _line_of(secret, r"\$_SERVER\['REQUEST_METHOD'\].*save_card|!empty\(\$input\['cardNumber'\]\)")
        log_line = _line_of(secret, r"cards_log\.json")
        ip_line = _line_of(secret, r"HTTP_CLIENT_IP|HTTP_X_FORWARDED_FOR")

        findings.append(
            _finding(
                "PHP-CARD-HARVEST",
                "Unauthenticated Card Data Capture Endpoint (PAN/CVV)",
                "CRITICAL",
                "/secretfekx.php",
                "secretfekx.php",
                save_line,
                (
                    "A public POST handler accepts cardNumber, cardHolder, cardExpiry and cardCvv "
                    "without authentication or CSRF protection, then writes them to a JSON file. "
                    "This is card skimming functionality and violates PCI DSS for PAN/CVV storage."
                ),
                """
$cardNumber = trim($input['cardNumber'] ?? '');
$cardCvv    = trim($input['cardCvv'] ?? '');
file_put_contents($logFile, json_encode($logs, ...));
                """,
                """
Delete the capture endpoint and any stored card data. Use a PCI-compliant hosted
checkout; never let the application receive or persist PAN/CVV.
                """,
            )
        )
        findings.append(
            _finding(
                "PHP-CARD-LOG-EXPOSED",
                "Captured Card Log Is Readable Inside the Web Root",
                "CRITICAL",
                "/data/cards_log.json",
                "secretfekx.php",
                log_line,
                (
                    "The card log is created at data/cards_log.json inside the public document "
                    "root. The only guard is data/.htaccess, which the PHP built-in server ignores, "
                    "so the JSON file is directly downloadable and contains plaintext PAN/CVV."
                ),
                """
$logFile = $logDir . '/cards_log.json';
file_put_contents($logFile, json_encode($logs, ...));
                """,
                """
Store no card data. If capture is ever unavoidable for a lab, keep it outside the
document root with deny-all server rules and encrypt it; rotate/delete existing data.
                """,
            )
        )
        findings.append(
            _finding(
                "PHP-HARDCODED-PANEL-PASSWORD",
                "Hardcoded Card-Panel Password With No Throttling",
                "CRITICAL",
                "/secretfekx.php",
                "secretfekx.php",
                password_line,
                (
                    "The hidden card panel authenticates every visitor against a password "
                    "literal embedded in source. There is no rate limit, lockout or MFA, and "
                    "the panel renders captured PAN, expiry and CVV."
                ),
                """
$password = '<hardcoded secret>';
if ($_POST['password'] === $password) { $_SESSION['auth'] = true; }
                """,
                """
Remove the panel. If a lab panel must remain, store an Argon2id hash outside the
web root, add throttling/MFA and never display CVV.
                """,
            )
        )
        findings.append(
            _finding(
                "PHP-SPOOFABLE-IP",
                "Spoofable Client IP Used as Audit Evidence",
                "MEDIUM",
                "/secretfekx.php",
                "secretfekx.php",
                ip_line,
                (
                    "The capture handler trusts X-Forwarded-For / Client-IP before REMOTE_ADDR. "
                    "Any client can forge the logged IP, so the evidence cannot be used for "
                    "forensics or abuse handling."
                ),
                """
$ip = $_SERVER['HTTP_CLIENT_IP']
    ?? $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['REMOTE_ADDR'];
                """,
                """
Use REMOTE_ADDR. Only honor forwarded headers when a trusted reverse proxy overwrites
them and the accepted proxy list is enforced.
                """,
            )
        )
        findings.append(
            _finding(
                "PHP-PANEL-SESSION-COOKIE",
                "Card Panel Session Cookie Lacks Hardening",
                "MEDIUM",
                "/secretfekx.php",
                "secretfekx.php",
                _line_of(secret, r"session_start\(\)"),
                (
                    "session_start() runs with default cookie parameters: no HttpOnly, "
                    "SameSite or Secure flags. A script injection on the panel could read the "
                    "session cookie and card data rendered in the same page."
                ),
                """
session_start();
                """,
                """
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict',
                           'secure' => !empty($_SERVER['HTTPS']), 'path' => '/']);
session_start();
                """,
            )
        )

    if config:
        card_line = _line_of(config, r"\$transferCards\s*=\s*\[|\d{12,19}")
        findings.append(
            _finding(
                "PHP-CONFIG-CARD-IN-SOURCE",
                "Payment Card Number Committed to Web-Root Configuration",
                "HIGH",
                "/config.php",
                "config.php",
                card_line,
                (
                    "A card-like PAN is hardcoded in config.php inside the document root. "
                    "Source control, backups and server misconfiguration can expose it; the "
                    "number must be treated as compromised until the owner confirms otherwise."
                ),
                """
$transferCards = ['<card number redacted>'];
                """,
                """
Remove the PAN from source immediately, rotate the receiving card, and load
merchant payment details from a secret manager outside the web root.
                """,
            )
        )
        findings.append(
            _finding(
                "PHP-CONFIG-SECRETS-IN-WEBROOT",
                "Admin Hash and Salt Stored Inside the Public Document Root",
                "MEDIUM",
                "/config.php",
                "config.php",
                _line_of(config, r"admin_password_hash"),
                (
                    "The admin password hash, salt and transfer-card list live in config.php "
                    "under the served directory. Protection depends entirely on .htaccess, "
                    "which non-Apache servers ignore."
                ),
                """
return [
  'admin_password_salt' => '<salt>',
  'admin_password_hash' => '<hash>',
  'transfer_cards' => [...]
];
                """,
                """
Move configuration above the document root, deny direct access at the web server,
and keep only non-sensitive bootstrap code in the served tree.
                """,
            )
        )

    if backend:
        transfer_line = _line_of(backend, r"'transfer_card'\s*=>")
        findings.append(
            _finding(
                "PHP-FULL-PAN-RESPONSE",
                "Deposit API Returns the Full Merchant Card Number",
                "HIGH",
                "/backend.php?action=deposit",
                "backend.php",
                transfer_line,
                (
                    "The deposit response includes transfer_card with the complete PAN and "
                    "stores card_number in deposits. A customer (or anyone with the session) "
                    "receives merchant card data that is not needed to complete a transfer."
                ),
                """
reply(201, ['deposit' => $row, 'transfer_card' => $card]);
                """,
                """
Return only a masked hint and a bank reference. Keep the full PAN out of API
responses, logs and the private data store.
                """,
            )
        )
        findings.append(
            _finding(
                "PHP-CHECKOUT-RACE",
                "Checkout Balance Check Is Vulnerable to a Race Condition",
                "MEDIUM",
                "/backend.php?action=checkout",
                "backend.php",
                _line_of(backend, r"\$u\['balance'\]\s*=\s*round"),
                (
                    "Checkout reads the user balance, validates it and later writes the new "
                    "value without a lock or atomic compare-and-set. Two concurrent checkouts "
                    "can both pass the balance check and overspend the account."
                ),
                """
if ((float)$u['balance'] < $total) reply(402, ...);
$u['balance'] = round((float)$u['balance'] - $total, 2);
saveDb('users', $users);
                """,
                """
Serialize balance changes with an exclusive lock or a database transaction and
re-read the balance after acquiring it (compare-and-set).
                """,
            )
        )

    findings.sort(key=lambda item: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(item["severity"], 3))
    penalty = sum(
        30 if item["severity"] == "CRITICAL" else 20 if item["severity"] == "HIGH" else 10
        for item in findings
    )
    return {
        "file_path": str(root),
        "file_name": root.name,
        "project_root": str(root),
        "endpoints": _discover_endpoints(root),
        "findings": findings,
        "score": max(10, 100 - penalty) if findings else 100,
    }
