"""Defensive localhost-only HTTP snapshot collector.

Used by Attack Surface and later Before & After modules. It connects to the
literal loopback IP (never through DNS), enforces a strict timeout and size cap,
and does not follow redirects outside the authorized localhost scope.
"""

import hashlib
import http.client
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

MAX_BYTES = 512 * 1024
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
TIMEOUT_SECONDS = 6


class SnapshotError(Exception):
    pass


def validate_snapshot_target(target: str) -> tuple[str, int, str, str]:
    parsed = urlparse(target.strip())
    if parsed.scheme not in {"http", "https"}:
        raise SnapshotError("Snapshot works only against http/https targets.")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise SnapshotError("Snapshot target is out of scope: the target must be localhost/127.0.0.1.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    host_header = parsed.hostname if not parsed.port else f"{parsed.hostname}:{parsed.port}"
    return parsed.scheme, port, path, host_header


def _redirect_decision(target: str, location: str) -> dict:
    absolute = urljoin(target, location)
    try:
        validate_snapshot_target(absolute)
        return {"detected": True, "url": absolute[:200], "allowed": True, "reason": "localhost scope"}
    except SnapshotError as exc:
        return {"detected": True, "url": absolute[:200], "allowed": False, "reason": str(exc)}


def _extract_paths(body: str, base_target: str) -> list[str]:
    patterns = [
        r'(?:action|href|src)\s*=\s*["\']([^"\']+)["\']',
        r'url\(["\']?([^\)"\']+)["\']?\)',
    ]
    seen = []
    for pattern in patterns:
        for match in re.findall(pattern, body, flags=re.IGNORECASE):
            value = match.strip()
            if not value or value.startswith(("data:", "javascript:", "mailto:", "#")):
                continue
            parsed = urlparse(urljoin(base_target, value))
            if parsed.hostname not in ALLOWED_HOSTS:
                continue
            path = parsed.path or "/"
            if path not in seen:
                seen.append(path)
    return seen[:60]


def _technologies(headers: dict, body: str) -> list[dict]:
    found: dict[str, dict] = {}

    def add(name: str, source: str, raw: str) -> None:
        if name not in found:
            found[name] = {"name": name, "source": source, "evidence": raw[:120]}

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        add(server.split()[0], "http_header:server", f"Server: {server}")
    if powered:
        add(powered, "http_header:x-powered-by", f"X-Powered-By: {powered}")
    lowered = body.lower()
    for name, marker in (
        ("jQuery", "jquery"),
        ("React", "react"),
        ("Vue", "vue"),
        ("Flask/Werkzeug", "werkzeug"),
        ("Django", "csrfmiddlewaretoken"),
    ):
        if marker in lowered:
            add(name, "html_body", f"marker: {marker}")

    return list(found.values())[:15]


def fetch_target_snapshot(target: str) -> dict:
    """Fetches a bounded, evidence-only snapshot of an authorized local app."""
    scheme, port, path, host_header = validate_snapshot_target(target)
    connection = (
        http.client.HTTPSConnection("127.0.0.1", port, timeout=TIMEOUT_SECONDS)
        if scheme == "https"
        else http.client.HTTPConnection("127.0.0.1", port, timeout=TIMEOUT_SECONDS)
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "AegisAI-V2-Defensive-Scanner/2.0",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = {str(key).lower(): str(value) for key, value in response.getheaders()}
        raw = response.read(MAX_BYTES + 1)
        truncated = len(raw) > MAX_BYTES
        charset = response.headers.get_content_charset() or "utf-8"
        body = raw[:MAX_BYTES].decode(charset, errors="replace")
        status = int(response.status)
    except Exception as exc:
        raise SnapshotError(f"Could not capture the local HTTP snapshot: {type(exc).__name__}: {exc}") from exc
    finally:
        connection.close()

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:160] if title_match else None

    security_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    present = [name for name in security_headers if name in headers]
    missing = [name for name in security_headers if name not in headers]

    redirect = None
    if status in {301, 302, 303, 307, 308} and headers.get("location"):
        redirect = _redirect_decision(target, headers["location"])

    return {
        "tool": "local_http",
        "target": target,
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "status_code": status,
        "headers": headers,
        "security_headers_present": present,
        "security_headers_missing": missing,
        "redirect": redirect,
        "title": title,
        "body_bytes": len(raw[:MAX_BYTES]),
        "body_truncated": truncated,
        "html_sha256": hashlib.sha256(raw[:MAX_BYTES]).hexdigest(),
        "html_excerpt": body[:4000],
        "endpoints": _extract_paths(body, target),
        "technologies": _technologies(headers, body),
    }
