import os
import json
import httpx

OLLAMA_URL = 'http://127.0.0.1:11434'


def provider_config():
    provider = os.getenv('AI_PROVIDER', 'ollama').strip().lower()
    if provider == 'openai':
        return {'provider': provider, 'model': os.getenv('OPENAI_MODEL', 'gpt-4o-mini'),
                'configured': bool(os.getenv('OPENAI_API_KEY', '').strip()), 'reason': None}
    if provider != 'ollama':
        return {'provider': 'disabled', 'model': None, 'configured': False, 'reason': 'provider_disabled'}
    model = os.getenv('OLLAMA_MODEL', 'qwen3:4b').strip()
    result = {'provider': 'ollama', 'model': model, 'configured': False, 'reason': 'model_missing'}
    if not model or ':cloud' in model.lower():
        result['reason'] = 'local_only'
        return result
    try:
        # Fixed loopback endpoint, no redirects and no environment proxy.
        response = httpx.post(OLLAMA_URL + '/api/show', json={'model': model}, timeout=3.0, trust_env=False)
        if response.status_code == 404:
            return result
        response.raise_for_status()
        info = response.json()
        if info.get('remote_host') or info.get('remote_model'):
            result['reason'] = 'local_only'
        else:
            result.update(configured=True, reason=None)
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        result['reason'] = 'server_unavailable'
    return result


def request_output(config, instructions, evidence, schema):
    if config['provider'] == 'ollama':
        response = httpx.post(OLLAMA_URL + '/api/chat',
            json={'model': config['model'], 'stream': False, 'think': False,
                  'messages': [{'role': 'system', 'content': instructions},
                               {'role': 'user', 'content': json.dumps(evidence)}],
                  'format': schema, 'options': {'temperature': 0, 'num_ctx': 16384, 'num_predict': 6000}},
            timeout=httpx.Timeout(180.0, connect=3.0), trust_env=False)
        response.raise_for_status()
        data = response.json()
        if data.get('done') is not True or data.get('done_reason') != 'stop':
            raise ValueError('Incomplete local response')
        return data['message']['content']
    response = httpx.post('https://api.openai.com/v1/responses',
        headers={'Authorization': 'Bearer ' + os.environ['OPENAI_API_KEY']},
        json={'model': config['model'], 'store': False, 'instructions': instructions,
              'input': json.dumps(evidence), 'max_output_tokens': 6000,
              'text': {'format': {'type': 'json_schema', 'name': 'scan_advice', 'strict': True, 'schema': schema}}},
        timeout=45.0)
    response.raise_for_status()
    data = response.json()
    if data.get('status') != 'completed':
        raise ValueError('Incomplete response')
    return ''.join(part['text'] for item in data.get('output', []) if item.get('type') == 'message'
                   for part in item.get('content', []) if part.get('type') == 'output_text')
