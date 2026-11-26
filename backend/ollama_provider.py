"""Local Ollama adapter for the existing agent's function-call history."""
import json
import os
import urllib.request
from urllib.parse import urlsplit


def schema(node):
    if isinstance(node, list):
        return [schema(x) for x in node]
    if not isinstance(node, dict):
        return node
    return {k: (str(v).lower() if k == 'type' else schema(v)) for k, v in node.items()}


def messages_from_history(contents, system_prompt):
    messages = [{'role': 'system', 'content': system_prompt}]
    for content in contents:
        parts = getattr(content, 'parts', []) or []
        text = '\n'.join(p.text for p in parts if getattr(p, 'text', None))
        calls = [p.function_call for p in parts if getattr(p, 'function_call', None)]
        responses = [p.function_response for p in parts if getattr(p, 'function_response', None)]
        if responses:
            for response in responses:
                result = dict(response.response or {})
                observation = result.get('observation')
                if isinstance(observation, dict):
                    result['observation'] = {**observation, 'text': str(observation.get('text') or '')[:1500], 'elements': (observation.get('elements') or [])[:25]}
                messages.append({'role': 'tool', 'tool_name': response.name,
                                 'content': json.dumps(result, ensure_ascii=False)})
        else:
            item = {'role': 'assistant' if content.role == 'model' else 'user', 'content': text}
            if calls:
                item['tool_calls'] = [{'type': 'function', 'function': {'name': c.name, 'arguments': dict(c.args or {})}} for c in calls]
            messages.append(item)
    return messages


def call_ollama(contents, system_prompt, contracts, mapping, state):
    from google.genai import types
    base = os.getenv('AEGIS_OLLAMA_URL', '').strip().rstrip('/')
    parsed = urlsplit(base)
    if not base:
        raise ValueError('Set AEGIS_OLLAMA_URL in .env to your local Ollama endpoint.')
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.username or parsed.password:
        raise ValueError('Ollama must use a local HTTP endpoint you configure yourself.')
    model = os.getenv('AEGIS_OLLAMA_MODEL', 'qwen2.5:14b')
    tools = [{'type': 'function', 'function': {'name': name,
             'description': contracts[key]['description'],
             'parameters': schema(contracts[key]['parameters_schema'])}}
             for name, key in mapping.items() if key in contracts]
    payload = {'model': model, 'messages': messages_from_history(contents, system_prompt),
               'tools': tools, 'stream': False, 'keep_alive': '2m',
               'options': {'temperature': 0.2, 'num_ctx': int(os.getenv('AEGIS_OLLAMA_CONTEXT', '4096')), 'num_predict': 1024}}
    request = urllib.request.Request(base + '/api/chat', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=int(os.getenv('AEGIS_OLLAMA_TIMEOUT', '180'))) as response:
        data = json.load(response)
    message = data.get('message') or {}
    parts = []
    if message.get('content'):
        parts.append(types.Part(text=message['content']))
    for call in message.get('tool_calls') or []:
        func = call.get('function') or {}
        args = func.get('arguments') or {}
        if isinstance(args, str):
            args = json.loads(args)
        parts.append(types.Part(function_call=types.FunctionCall(name=func['name'], args=args)))
    if not parts:
        raise RuntimeError('Ollama returned an empty response.')
    state.update(model=model, provider='ollama')
    return types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(role='model', parts=parts))])
