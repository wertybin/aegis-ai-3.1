"""Mock-only regression tests for the Telegram bot transport.

No Telegram network call is made here; these guard the opener bug that made
every getUpdates/sendMessage call fail with
``AttributeError: module 'urllib.request' has no attribute 'open'``.
"""

import backend.telegram_bot as bot


def test_tg_uses_an_opener_instance_not_the_urllib_module(monkeypatch):
    calls = []

    def fake_request(opener, url, payload=None, timeout=30):
        calls.append((opener, url, payload, timeout))
        return {"ok": True}

    monkeypatch.setattr(bot, "_request", fake_request)
    result = bot.tg("getMe")

    assert result == {"ok": True}
    assert len(calls) == 1
    opener, url, payload, timeout = calls[0]
    assert opener is bot._tg_opener
    assert hasattr(opener, "open"), "tg() must pass an OpenerDirector, not urllib.request"
    assert url.endswith("/getMe")
    assert payload is None


def test_request_reads_json_from_a_real_opener_interface():
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"ok": true, "result": {"username": "mock_bot"}}'

    class FakeOpener:
        def open(self, request, timeout=30):
            return FakeResponse()

    data = bot._request(FakeOpener(), "https://example.test/method")
    assert data["result"]["username"] == "mock_bot"
