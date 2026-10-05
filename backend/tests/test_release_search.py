import httpx
import pytest
from packaging.version import Version
from app.services import release_search
from app.services.recommendation import recommend_upgrade
from app.services.pypi_service import PyPIServiceError
from app.schemas.scan import ReleaseValidation
from app.schemas.vulnerability import VulnerabilityFinding

def finding(fixes):
    return VulnerabilityFinding(id='CVE-test',aliases=[],summary='',fixed_versions=fixes)

def file(version, tag='cp312-cp312-win_amd64', **extra):
    return {'filename':f'demo-{version}-{tag}.whl','requires-python':'>=3.8','yanked':False,**extra}

def mock_index(monkeypatch,files):
    def get(url,**kw):
        assert url == 'https://pypi.org/simple/demo/'
        assert kw['headers']['Accept'] == 'application/vnd.pypi.simple.v1+json'
        return httpx.Response(200,json={'files':files},request=httpx.Request('GET',url))
    monkeypatch.setattr(release_search.httpx,'get',get)

def test_index_filters_and_numeric_order(monkeypatch):
    mock_index(monkeypatch,[file('2.10'),file('2.9'),file('2.9'),file('1'),file('3rc1'),file('3.dev1'),
        file('3+local'),file('4',yanked='reason'),file('5',**{'requires-python':'<3.12'}),
        file('6','cp311-cp311-win_amd64'),file('7',**{'requires-python':None})])
    assert release_search.search_releases('demo',Version('2'),Version('1'),'3.12.0','win_amd64') == ['2.9','2.10']

def test_source_allowed_only_without_platform(monkeypatch):
    mock_index(monkeypatch,[{'filename':'demo-2.tar.gz','yanked':False,'requires-python':'>=3.8'}])
    args=('demo',Version('2'),Version('1'),'3.12.0')
    assert release_search.search_releases(*args,None) == ['2']
    assert release_search.search_releases(*args,'win_amd64') == []

def test_fallback_success_and_duplicate_skip():
    checked=[]
    def validate(name,version,target):
        checked.append(version)
        return ReleaseValidation(version=version,status='no_compatible_wheel' if version=='2' else 'available')
    result=recommend_upgrade('demo','1',[finding(['2'])],lambda *args:[],
        release_lookup=validate,search_lookup=lambda *args:['2','2.1','3'])
    assert checked == ['2','2.1']
    assert result.recommended_version == '2.1'
    assert result.candidate_source == 'pypi_release' and result.expanded_search is True

def test_no_index_query_when_boundary_passes():
    result=recommend_upgrade('demo','1',[finding(['2'])],lambda *a:[],
        search_lookup=lambda *a:pytest.fail('unnecessary index lookup'))
    assert result.candidate_source == 'fix_boundary'
    assert result.expanded_search is False

def test_shared_budget_and_vulnerability_evidence():
    result=recommend_upgrade('demo','1',[finding(['2'])],lambda *a:[finding([])],
        search_lookup=lambda *a:[str(v) for v in range(3,10)])
    assert result.checked_versions == ['2','3','4','5','6']
    assert result.status == 'manual_review'
    assert result.release_checks[0].remaining_vulnerability_ids == ['CVE-test']

def test_search_failure_preserves_original_findings():
    def search(*args):
        raise PyPIServiceError('timeout')
    result=recommend_upgrade('demo','1',[finding(['2'])],lambda *a:[finding([])],search_lookup=search)
    assert result.status == 'verification_failed'
    assert result.checked_versions == ['2']

def test_missing_fix_keeps_manual_review():
    result=recommend_upgrade('demo','1',[finding([])],lambda *a:pytest.fail('query'),
        search_lookup=lambda *a:pytest.fail('search without fix boundary'))
    assert result.status == 'manual_review'

@pytest.mark.parametrize('failure',['timeout','http','shape','file','json'])
def test_index_errors(monkeypatch,failure):
    def get(url,**kw):
        request=httpx.Request('GET',url)
        if failure=='timeout': raise httpx.ReadTimeout('timeout')
        if failure=='http': return httpx.Response(503,request=request)
        if failure=='json': return httpx.Response(200,text='bad',request=request)
        return httpx.Response(200,json={} if failure=='shape' else {'files':[{}]},request=request)
    monkeypatch.setattr(release_search.httpx,'get',get)
    with pytest.raises(PyPIServiceError):
        release_search.search_releases('demo',Version('2'),Version('1'),None,None)
