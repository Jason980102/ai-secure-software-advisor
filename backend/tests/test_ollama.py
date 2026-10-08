import json
import httpx
import pytest
from app.services import ai_advice, ai_provider
from .test_ai_advice import report, output


@pytest.fixture(autouse=True)
def local_provider(monkeypatch):
    monkeypatch.setenv('AI_PROVIDER', 'ollama')
    monkeypatch.setenv('OLLAMA_MODEL', 'qwen3:4b')
    monkeypatch.setenv('OPENAI_API_KEY', 'must-not-be-used')


def install_local(monkeypatch, content=None, reason='stop', remote=False):
    calls=[]
    def post(url, **kw):
        assert url.startswith('http://127.0.0.1:11434/')
        assert kw['trust_env'] is False
        assert 'Authorization' not in kw.get('headers', {})
        calls.append((url, kw))
        data = {'remote_model': 'cloud-model'} if remote else {}
        if url.endswith('/chat'):
            data = {'done': True, 'done_reason': reason, 'message': {'content': json.dumps(content or output())}}
        return httpx.Response(200, json=data, request=httpx.Request('POST', url))
    monkeypatch.setattr(ai_provider.httpx, 'post', post)
    return calls


def test_ollama_is_default_even_with_openai_key(monkeypatch):
    monkeypatch.delenv('AI_PROVIDER', raising=False)
    calls=install_local(monkeypatch)
    result=ai_advice.generate_advice(report(), 'zh-Hant')
    assert result.status == 'generated' and result.provider == 'ollama'
    assert len(calls) == 2
    payload=calls[1][1]['json']
    assert payload['stream'] is False and payload['think'] is False
    assert payload['format']['type'] == 'object'
    assert 'must-not-be-used' not in json.dumps(payload)


@pytest.mark.parametrize('case', ['cloud_tag', 'remote_metadata'])
def test_cloud_models_are_rejected(monkeypatch, case):
    calls=install_local(monkeypatch, remote=True)
    if case=='cloud_tag':monkeypatch.setenv('OLLAMA_MODEL','example:cloud')
    result=ai_advice.generate_advice(report(),'en')
    assert result.status == 'not_configured' and result.reason == 'local_only'
    assert not any(url.endswith('/chat') for url,kw in calls)


def test_offline_server_never_falls_back_to_openai(monkeypatch):
    def post(url, **kw):
        assert url.startswith(ai_provider.OLLAMA_URL)
        raise httpx.ConnectError('offline')
    monkeypatch.setattr(ai_provider.httpx,'post',post)
    result=ai_advice.generate_advice(report(),'en')
    assert result.reason=='server_unavailable' and result.status=='not_configured'


def test_missing_model_is_reported(monkeypatch):
    monkeypatch.setattr(ai_provider.httpx,'post',lambda url,**kw:httpx.Response(404,request=httpx.Request('POST',url)))
    assert ai_provider.provider_config()['reason']=='model_missing'


@pytest.mark.parametrize('reason', ['length', 'load'])
def test_incomplete_local_generation_is_rejected(monkeypatch, reason):
    install_local(monkeypatch,reason=reason)
    assert ai_advice.generate_advice(report(),'en').status=='unavailable'


def test_local_hallucinated_reference_is_rejected(monkeypatch):
    install_local(monkeypatch,content=output(finding_id='invented'))
    assert ai_advice.generate_advice(report(),'en').status=='unavailable'


def test_disabled_provider_makes_no_requests(monkeypatch):
    monkeypatch.setenv('AI_PROVIDER','none')
    monkeypatch.setattr(ai_provider.httpx,'post',lambda *a,**kw:pytest.fail('unexpected request'))
    assert ai_advice.generate_advice(report(),'en').status=='not_configured'
