import httpx
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.scan import ReleaseValidation
from app.services import pypi_service
from app.services.recommendation import recommend_upgrade
from app.schemas.vulnerability import VulnerabilityFinding

def metadata(files):
    return {"info": {"version": "2.0"}, "urls": files}

def mock_response(monkeypatch, data, code=200):
    monkeypatch.setattr(pypi_service.httpx, "get", lambda url, **kw:
        httpx.Response(code, json=data, request=httpx.Request("GET", url)))

@pytest.mark.parametrize("files,target,status,compatible", [
    ([{"yanked":False,"requires_python":">=3.9,<3.13"}], "3.12.0", "available", True),
    ([{"yanked":False,"requires_python":">=3.13"}], "3.12.0", "python_incompatible", False),
    ([{"yanked":False,"requires_python":None}], "3.12.0", "python_unknown", None),
    ([{"yanked":False,"requires_python":"oops"}], "3.12.0", "python_unknown", None),
    ([{"yanked":True,"requires_python":">=3"}], "3.12.0", "yanked", None),
    ([], "3.12.0", "no_files", None),
    ([{"yanked":False,"requires_python":">=3.13"}], None, "available", None),
    ([{"yanked":True,"requires_python":">=3"}, {"yanked":False,"requires_python":">=3.13"}], "3.12.0", "python_incompatible", False),
    ([{"yanked":False,"requires_python":None}, {"yanked":False,"requires_python":">=3.9"}], "3.12.0", "available", True),
])
def test_release_metadata(monkeypatch, files, target, status, compatible):
    mock_response(monkeypatch, metadata(files))
    result = pypi_service.check_release("example", "2.0", target)
    assert (result.status, result.python_compatible) == (status, compatible)

def test_not_found(monkeypatch):
    mock_response(monkeypatch, {}, 404)
    assert pypi_service.check_release("example", "2.0", None).status == "not_found"

@pytest.mark.parametrize("data,code", [({},503), ({},200), (metadata([{}]),200),
    ({"info":{"version":"3.0"},"urls":[]},200)])
def test_invalid_upstream(monkeypatch, data, code):
    mock_response(monkeypatch, data, code)
    with pytest.raises(pypi_service.PyPIServiceError):
        pypi_service.check_release("example", "2.0", None)

def test_timeout(monkeypatch):
    def fail(*a, **kw):
        raise httpx.ReadTimeout('timeout')
    monkeypatch.setattr(pypi_service.httpx, 'get', fail)
    with pytest.raises(pypi_service.PyPIServiceError):
        pypi_service.check_release('example', '2.0', None)

def test_rejected_candidates_not_sent_to_osv():
    calls = []
    findings = [VulnerabilityFinding(id='test', aliases=[], summary='', fixed_versions=['2','3'])]
    def release(name, version, target):
        assert target == '3.12.0'
        return ReleaseValidation(version=version, status='yanked' if version == '2' else 'available', python_compatible=True)
    def lookup(name, version):
        calls.append(version)
        return []
    result = recommend_upgrade('a', '1', findings, lookup, '3.12.0', release)
    assert calls == ['3']
    assert result.recommended_version == '3'
    assert [r.status for r in result.release_checks] == ['yanked', 'available']

def test_pypi_failure_preserves_findings():
    findings = [VulnerabilityFinding(id='test', aliases=[], summary='', fixed_versions=['2'])]
    def release(*args):
        raise pypi_service.PyPIServiceError('timeout')
    result = recommend_upgrade('a','1',findings,lambda *a: pytest.fail('OSV called'),release_lookup=release)
    assert result.status == 'verification_failed'
    assert result.recommended_version is None

@pytest.mark.parametrize('version',['3.12','latest','2.7.18','3.12.0rc1'])
def test_target_validation(version):
    assert TestClient(app).post('/api/v1/scan',json={'requirements':'a==1','target_python':version}).status_code == 422

def test_batch_propagates_target_and_retains_installed_findings(monkeypatch):
    from app.services import recommendation, scanner
    findings = [VulnerabilityFinding(id='test', aliases=[], summary='', fixed_versions=['2'])]
    monkeypatch.setattr(scanner, 'query_vulnerabilities', lambda *args: findings)
    def release(name, version, target):
        assert (name, version, target) == ('a', '2', '3.12.0')
        return ReleaseValidation(version=version, status='python_incompatible', python_compatible=False)
    monkeypatch.setattr(recommendation, 'check_release', release)
    response = TestClient(app).post('/api/v1/scan',json={'requirements':'a==1','target_python':'3.12.0'})
    assert response.status_code == 200
    data = response.json()
    assert data['total_vulnerabilities'] == 1
    result = data['results'][0]['upgrade_recommendation']
    assert result['status'] == 'manual_review'
    assert result['release_checks'][0]['python_compatible'] is False
