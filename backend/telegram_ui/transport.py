"""Telegram transport with honest premium fallbacks.

Capabilities differ per bot/chat: a bot without a Fragment username (or whose
owner has no Premium) cannot send custom emoji at all. This layer attempts the
verified custom emoji once, then permanently downgrades the process to Unicode
and retries. It also retries HTML parse failures as plain text, honours 429
retry-after, and converts "message not modified" into success.

Logs never contain the bot token or a request URL.
"""

from __future__ import annotations

import json
import time
import urllib.error

from backend.telegram_ui import config, emoji

NETWORK_ATTEMPTS = 3
NETWORK_BACKOFF_SECONDS = 0.5


class TelegramError(RuntimeError):
    def __init__(self, method: str, code: int | None, description: str) -> None:
        self.method = method
        self.code = code
        self.description = (description or "").strip()[:400]
        super().__init__(f"{method}: {self.description or code}")


def _error_body(exc: urllib.error.HTTPError) -> tuple[int | None, str, int | None]:
    """Returns (code, description, retry_after) without touching exc.url."""
    try:
        raw = exc.read().decode("utf-8", "replace")
    except Exception:
        raw = ""
    code = getattr(exc, "code", None)
    description = str(getattr(exc, "reason", "") or "")
    retry_after = None
    try:
        data = json.loads(raw)
        description = str(data.get("description") or description)
        code = int(data.get("error_code") or code or 0) or code
        retry_after = (data.get("parameters") or {}).get("retry_after")
    except (ValueError, TypeError, AttributeError):
        if raw:
            description = raw[:300]
    return code, description, retry_after


def _is_custom_emoji_rejection(description: str) -> bool:
    return emoji.looks_like_custom_emoji_error(description)


def _is_parse_rejection(description: str) -> bool:
    lowered = (description or "").lower()
    return any(
        marker in lowered
        for marker in (
            "can't parse entities",
            "can't find end tag",
            "unsupported start tag",
            "unexpected end tag",
            "parse entities",
            "unsupported parse_mode",
        )
    )


class Transport:
    def __init__(self, tg_callable, log=None, upload_callable=None) -> None:
        self._tg = tg_callable
        self._upload = upload_callable
        self._log = log or (lambda message: None)

    # -- public API --------------------------------------------------------
    def send(
        self,
        chat_id,
        text: str,
        keyboard: list[list[dict]] | None = None,
        preview: bool = False,
        timeout: int = 30,
    ) -> dict | None:
        payload = self._message_payload(chat_id, text, keyboard, preview)
        try:
            return self._call("sendMessage", payload, timeout)
        except TelegramError as exc:
            self._log(f"sendMessage failed for chat {chat_id}: {exc.description}")
            return None

    def send_text(self, chat_id, text: str, timeout: int = 30) -> dict | None:
        """Plain-text send used by the legacy compatibility helper."""
        payload = {"chat_id": chat_id, "text": str(text or "")[: config.MAX_MESSAGE_CHARS]}
        try:
            return self._call("sendMessage", payload, timeout)
        except TelegramError as exc:
            self._log(f"sendMessage(plain) failed for chat {chat_id}: {exc.description}")
            return None

    def send_document(
        self,
        chat_id,
        file_path: str,
        caption: str = "",
        timeout: int = 60,
    ) -> dict | None:
        """Uploads a real generated file. No URL or token is ever logged."""
        if self._upload is None:
            self._log("sendDocument ignored: no upload callable configured")
            return None
        try:
            return self._upload(chat_id, file_path, caption, timeout)
        except TelegramError as exc:
            self._log(f"sendDocument failed for chat {chat_id}: {exc.description}")
            return None
        except Exception as exc:
            self._log(
                f"sendDocument failed for chat {chat_id}: {type(exc).__name__}"
            )
            return None

    def edit(
        self,
        chat_id,
        message_id: int | None,
        text: str,
        keyboard: list[list[dict]] | None = None,
        preview: bool = False,
        timeout: int = 30,
    ) -> dict | None:
        if message_id is None:
            return self.send(chat_id, text, keyboard, preview, timeout)
        payload = self._message_payload(chat_id, text, keyboard, preview)
        payload["message_id"] = int(message_id)
        try:
            return self._call("editMessageText", payload, timeout)
        except TelegramError as exc:
            lowered = exc.description.lower()
            if "message is not modified" in lowered:
                return {"ok": True, "unchanged": True}
            if "message to edit not found" in lowered or "message can't be edited" in lowered:
                return self.send(chat_id, text, keyboard, preview, timeout)
            self._log(f"editMessageText failed for chat {chat_id}: {exc.description}")
            return None

    def answer(
        self,
        callback_id: str,
        text: str = "",
        show_alert: bool = False,
        timeout: int = 15,
    ) -> dict | None:
        if not callback_id:
            return None
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = str(text)[:200]
            payload["show_alert"] = bool(show_alert)
        try:
            return self._call("answerCallbackQuery", payload, timeout)
        except TelegramError as exc:
            # A stale callback id is harmless; never break the poll loop.
            self._log(f"answerCallbackQuery ignored: {exc.description}")
            return None

    def delete(self, chat_id, message_id: int, timeout: int = 15) -> bool:
        try:
            self._call(
                "deleteMessage",
                {"chat_id": chat_id, "message_id": int(message_id)},
                timeout,
            )
            return True
        except TelegramError as exc:
            self._log(f"deleteMessage ignored: {exc.description}")
            return False

    def get_me(self, timeout: int = 15) -> dict:
        return self._call("getMe", {}, timeout).get("result") or {}

    # -- internals ---------------------------------------------------------
    def _message_payload(
        self,
        chat_id,
        text: str,
        keyboard: list[list[dict]] | None,
        preview: bool,
    ) -> dict:
        body = self._fit(text)
        payload: dict = {
            "chat_id": chat_id,
            "text": body,
            "parse_mode": "HTML",
            "disable_web_page_preview": not preview,
        }
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        return payload

    def _fit(self, text: str) -> str:
        body = str(text or "").strip() or "No output."
        if len(body) <= config.MAX_MESSAGE_CHARS:
            return body
        # Oversized HTML cannot be cut safely; degrade to valid plain text.
        return emoji.strip_html(body)[: config.MAX_MESSAGE_CHARS - 20].rstrip() + "\n\n…truncated"

    def _call(self, method: str, payload: dict, timeout: int) -> dict:
        attempt = 0
        while True:
            attempt += 1
            try:
                return self._tg(method, payload, timeout=timeout)
            except urllib.error.HTTPError as exc:
                code, description, retry_after = _error_body(exc)
                if code == 429 and attempt == 1:
                    delay = retry_after if isinstance(retry_after, int) else 2
                    time.sleep(max(1, min(10, delay)))
                    continue
                if code == 400 and "text" in payload:
                    if _is_custom_emoji_rejection(description) and emoji.custom_enabled():
                        emoji.disable_custom(description)
                        self._log(
                            "custom emoji rejected by Telegram; switching to Unicode fallbacks"
                        )
                        payload = dict(payload)
                        payload["text"] = emoji.strip_custom(payload["text"])
                        continue
                    if _is_parse_rejection(description) and payload.get("parse_mode") == "HTML":
                        payload = dict(payload)
                        payload["text"] = emoji.strip_html(payload["text"])
                        payload.pop("parse_mode", None)
                        continue
                raise TelegramError(method, code, description) from None
            except urllib.error.URLError as exc:
                if attempt < NETWORK_ATTEMPTS:
                    time.sleep(NETWORK_BACKOFF_SECONDS * attempt)
                    continue
                raise TelegramError(method, None, f"network error: {exc.reason}") from None
            except (ConnectionResetError, TimeoutError) as exc:
                if attempt < NETWORK_ATTEMPTS:
                    time.sleep(NETWORK_BACKOFF_SECONDS * attempt)
                    continue
                raise TelegramError(
                    method, None, f"network error: {type(exc).__name__}: {exc}"
                ) from None
            except Exception as exc:
                raise TelegramError(method, None, f"{type(exc).__name__}: {exc}") from None
