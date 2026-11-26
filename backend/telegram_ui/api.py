"""Thin, injectable client for the local AEGIS API + real gate probes.

The bot passes its own ``api_get``/``api_post`` callables in, so this module
never reads the bot token and stays trivially mockable in tests. Gate probes
are direct HTTP calls to user-configured local targets; they never leave
localhost.
"""

from __future__ import annotations

import json
from http.client import IncompleteRead
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from uuid import uuid4

from backend.telegram_ui import config

_probe_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_SCAN_ID_RE = re.compile(r"^scan_[0-9]{8}_[0-9]{6}_[0-9a-f]{6}$")


class ApiError(RuntimeError):
    """A sanitized backend failure (no URL, no token)."""

    def __init__(self, status: int | None, detail: str) -> None:
        self.status = status
        self.detail = (detail or "").strip()[:400]
        super().__init__(self.detail or f"HTTP {status}")


def connection_notice(exc: BaseException) -> str | None:
    if isinstance(exc, urllib.error.HTTPError):
        return None
    cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(cause, TimeoutError):
        return "The local backend did not reply before the wait expired."
    if isinstance(cause, ConnectionRefusedError):
        return "The local backend is not accepting connections."
    if isinstance(cause, (ConnectionError, IncompleteRead, EOFError)) or isinstance(exc, urllib.error.URLError):
        return "The local backend connection ended before a response arrived."
    return None


def describe_error(exc: BaseException) -> str:
    """Never includes ``exc.url``: the Telegram URL embeds the bot token."""
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                body = parsed.get("detail") or parsed.get("message") or body
        except (ValueError, TypeError):
            pass
        return f"HTTP {exc.code}: {str(body or exc.reason)[:300]}"
    if notice := connection_notice(exc):
        return notice
    return f"{type(exc).__name__}: {str(exc)[:200]}"


def _query(path: str, params: dict | None = None) -> str:
    if not params:
        return path
    clean = {key: value for key, value in params.items() if value is not None}
    return f"{path}?{urllib.parse.urlencode(clean)}" if clean else path


class ApiClient:
    def __init__(self, api_get, api_post, stream_get=None) -> None:
        self._get = api_get
        self._post = api_post
        self._stream = stream_get

    # -- reads -------------------------------------------------------------
    def version(self) -> dict:
        return self._get("/api/version")

    def agent_last(self) -> dict:
        return self._get("/api/agent/last")

    def reports(self) -> dict:
        return self._get("/api/reports")

    def tools(self, force: bool = False) -> dict:
        return self._get(_query("/api/tools", {"force": "true" if force else None}))

    def tool_check(self, name: str) -> dict:
        safe = urllib.parse.quote(name, safe="")
        return self._post(f"/api/tools/{safe}/check", {})

    def health(self) -> dict:
        started = time.monotonic()
        try:
            data = self.version()
            return {
                "online": True,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "version": data.get("version") or data.get("app") or "",
            }
        except Exception as exc:
            return {
                "online": False,
                "latency_ms": None,
                "error": describe_error(exc),
            }

    # -- agent -------------------------------------------------------------
    def agent_run(self, task: str, target: str | None = None, use_ai: bool = True) -> dict:
        receipt_id = str(uuid4())
        payload: dict = {"task": task, "use_ai": bool(use_ai), "receipt_id": receipt_id}
        if target:
            payload["target"] = target
        try:
            result = self._post("/api/agent/run", payload)
            if not isinstance(result, dict) or not result:
                raise EOFError("Empty report response")
            return result
        except Exception as exc:
            if not connection_notice(exc):
                raise
            cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if isinstance(cause, ConnectionRefusedError):
                raise
            return self._await_report(receipt_id, exc)

    def _await_report(self, receipt_id: str, original_error: Exception) -> dict:
        """Recover only this request's response. All follow-up requests are reads."""
        deadline = time.monotonic() + 20 * 60
        misses = 0
        while time.monotonic() < deadline:
            try:
                receipt = self._get(f"/api/agent/receipts/{receipt_id}")
            except urllib.error.HTTPError as exc:
                if exc.code < 500:
                    raise original_error from exc
                receipt = {}
            except (OSError, IncompleteRead, EOFError):
                receipt = {}
            if not isinstance(receipt, dict) or receipt.get("receipt_id") != receipt_id:
                receipt = {}
            state = receipt.get("state")
            if state == "ready":
                result = receipt.get("result")
                if isinstance(result, dict) and result.get("receipt_id") == receipt_id:
                    return result
                raise original_error
            if state == "failed":
                raise ApiError(None, "The backend recorded a failure for this run.") from original_error
            misses = 0 if state == "pending" else misses + 1
            if misses >= 3:
                raise original_error
            time.sleep(5)
        raise TimeoutError("Report still pending after the delivery window.") from original_error

    def agent_cancel(self) -> dict:
        return self._post("/api/agent/cancel", {})

    # -- engine pipeline ----------------------------------------------------
    def engine_start(self, mode: str, target: str) -> dict:
        """Starts a real DAST or Audit scan through the existing engine API."""
        clean_mode = str(mode or "").lower()
        if clean_mode not in {"dast", "audit"}:
            raise ValueError("engine mode must be 'dast' or 'audit'")
        return self._post(
            "/api/engine/start", {"mode": clean_mode, "target": str(target or "")}
        )

    def engine_stream(self, scan_id: str, on_event) -> dict:
        """Consumes the real SSE stream and forwards each decoded event."""
        clean_id = str(scan_id or "")
        if not _SCAN_ID_RE.match(clean_id):
            raise ValueError("invalid engine scan id")
        if self._stream is None:
            raise RuntimeError("engine stream transport is unavailable")
        return self._stream(f"/api/engine/stream/{clean_id}", on_event)

    def engine_cancel(self, scan_id: str) -> dict:
        """Cancels only the supplied scan id; the backend validates the state."""
        clean_id = str(scan_id or "")
        if not _SCAN_ID_RE.match(clean_id):
            raise ValueError("invalid engine scan id")
        return self._post(f"/api/engine/scans/{clean_id}/cancel", {})


def quick_source_audit(gate_id: str) -> dict:
    """Review only the user-configured local source for this gate."""
    from pathlib import Path

    from backend.auditor import analyze_source_file, validate_local_scope
    from backend.tool_registry import is_allowed_scan_path

    gate = config.GATE_BY_ID[gate_id]
    url_ok, url_message, _ = validate_local_scope(gate["url"])
    if not url_ok:
        raise ValueError(url_message)
    source = gate.get("source") or ""
    if not source:
        raise ValueError(
            f"Set {gate['source_env_var']} in .env to the local source you want to audit."
        )
    allowed, message, path = validate_local_scope(source)
    if not allowed or not Path(path).exists() or not is_allowed_scan_path(path)[0]:
        raise ValueError(message or "The configured local source is unavailable.")
    audit = analyze_source_file(path)
    rows = [{"severity": f["severity"], "title": f["title"]} for f in audit["findings"]]
    return {"source": path.name, "findings": rows}


def probe_gate(gate: dict, timeout: float = config.GATE_PROBE_TIMEOUT) -> dict:
    """Real HTTP probe of one user-configured local gate."""
    url = gate.get("url") or ""
    if not url:
        return {
            "online": False,
            "status": None,
            "latency_ms": 0,
            "error": f"Not configured. Set {gate.get('env_var', 'AEGIS_GATE_URL')} in .env.",
        }
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "AEGIS-Telegram/3.1"})
        with _probe_opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200) or 200)
        return {
            "online": True,
            "status": status,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "error": "",
        }
    except urllib.error.HTTPError as exc:
        # Any HTTP response proves the service is listening.
        return {
            "online": True,
            "status": int(exc.code),
            "latency_ms": int((time.monotonic() - started) * 1000),
            "error": "",
        }
    except Exception as exc:
        return {
            "online": False,
            "status": None,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "error": describe_error(exc),
        }


def probe_gates(timeout: float = config.GATE_PROBE_TIMEOUT) -> dict[str, dict]:
    """Probes every gate concurrently so the callback stays responsive."""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=len(config.GATES)) as pool:
        futures = {
            gate["id"]: pool.submit(probe_gate, gate, timeout) for gate in config.GATES
        }
        return {gate_id: future.result() for gate_id, future in futures.items()}


def gate_for_target(target: str | None) -> dict | None:
    if not target:
        return None
    try:
        parsed = urllib.parse.urlparse(str(target))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    for gate in config.GATES:
        if gate["port"] == port:
            return gate
    return None


def mask_chat(chat_id) -> str:
    text = str(chat_id)
    if len(text) <= 5:
        return text
    return f"{text[:3]}…{text[-2:]}"


def mask_target(target) -> str:
    """Keeps only scheme://host:port so credentials and query secrets never log."""
    text = str(target or "")
    try:
        parsed = urllib.parse.urlparse(text)
        if parsed.scheme and parsed.hostname:
            try:
                port = f":{parsed.port}" if parsed.port else ""
            except ValueError:
                port = ""
            return f"{parsed.scheme}://{parsed.hostname}{port}"
        if parsed.netloc and parsed.hostname:
            try:
                port = f":{parsed.port}" if parsed.port else ""
            except ValueError:
                port = ""
            return f"//{parsed.hostname}{port}"
    except ValueError:
        pass
    return "custom" if text else "default"
