"""Regression coverage for provider history, scope and fallback routing."""
import pytest
from google.genai import types
from backend.ollama_provider import messages_from_history, schema
from backend.browser_agent import BrowserSession
from backend import security_agent as sa


def test_history_preserves_function_names_and_results():
    history = [types.Content(role='model', parts=[types.Part(function_call=types.FunctionCall(name='run_browser', args={'action': 'inspect'}))]),
               types.Content(role='user', parts=[types.Part.from_function_response(name='run_browser', response={'ok': True})])]
    converted = messages_from_history(history, 'system')
    assert converted[1]['tool_calls'][0]['function']['name'] == 'run_browser'
    assert converted[2]['role'] == 'tool'
    assert converted[2]['tool_name'] == 'run_browser'
    assert schema({'type': 'OBJECT', 'properties': {'action': {'type': 'STRING'}}})['properties']['action']['type'] == 'string'


def test_browser_scope_blocks_external_origin_and_ports():
    session = BrowserSession('http://localhost:5002')
    assert session._allowed('http://127.0.0.1:5002/about')
    assert not session._allowed('http://127.0.0.1:8765/api/settings')
    assert not session._allowed('https://example.com')
    assert not session._allowed('file:///C:/Windows/win.ini')


def test_ollama_without_gemini_key_runs_native_tool_loop(monkeypatch):
    import backend.ollama_provider as provider
    monkeypatch.setenv('AEGIS_MODEL_PROVIDER', 'ollama')
    monkeypatch.setenv('AEGIS_BROWSER_ENABLED', '0')
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    monkeypatch.setattr(sa, 'check_tool', lambda name: {'status': 'OK'})
    monkeypatch.setattr(sa, 'deep_correlate', lambda **kwargs: {})
    def fake_call(history, prompt, contracts, mapping, state):
        state.update(model='qwen2.5:14b', provider='ollama')
        if len(history) == 1:
            parts = [types.Part(function_call=types.FunctionCall(name='run_api_security', args={}))]
        else:
            assert history[-1].role == 'user'
            parts = [types.Part(text='Evidence inspected.')]
        return types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(role='model', parts=parts))])
    monkeypatch.setattr(provider, 'call_ollama', fake_call)
    def execute(name, args, target, path, cache):
        cache['results'][name] = {'findings': [], 'ok': True}
        return {'ok': True, 'available': True}
    monkeypatch.setattr(sa, '_execute', execute)
    result = sa.run_agent('test local model', max_steps=2)
    assert result['mode'] == 'ollama-function-calling'
    assert result['decisions'][0]['source'] == 'ollama'
    assert result['model'] == 'qwen2.5:14b'


def test_local_failure_switches_to_gemini(monkeypatch):
    import backend.ollama_provider as provider
    monkeypatch.setenv('AEGIS_MODEL_PROVIDER', 'ollama')
    monkeypatch.setenv('AEGIS_BROWSER_ENABLED', '0')
    monkeypatch.setenv('GEMINI_API_KEY', 'mock-not-a-real-key')
    monkeypatch.setattr(sa, 'check_tool', lambda name: {'status': 'MISSING'})
    monkeypatch.setattr(sa, 'deep_correlate', lambda **kwargs: {})
    def unavailable(*args):
        raise ConnectionError('local server unavailable')
    def fallback(history, key, models, state):
        state['model'] = 'mock-gemini'
        return types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(role='model', parts=[types.Part(text='No scanners are installed.')]))])
    monkeypatch.setattr(provider, 'call_ollama', unavailable)
    monkeypatch.setattr(sa, '_call_gemini', fallback)
    result = sa.run_agent('check fallback', max_steps=1)
    assert result['mode'] == 'gemini-function-calling'
    assert result['provider'] == 'gemini'
    assert result['model'] == 'mock-gemini'
