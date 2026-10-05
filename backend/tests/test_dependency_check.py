import httpx
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.scan import PackageScanResult, UpgradeRecommendation
from app.services import dependency_check, scanner

def package(name,installed='1',candidate=None):
    return PackageScanResult(package=name,installed_version=installed,vulnerabilities=[],
        upgrade_recommendation=UpgradeRecommendation(status='candidate' if candidate else 'not_needed',
            recommended_version=candidate,reason='test'))

def run(requirements,python='3.12.0',platform='win_amd64'):
    return dependency_check.check_dependencies([package('a',candidate='2'),package('b',candidate='2.5')],
        python,platform,metadata_lookup=lambda name,version:requirements if name=='a' else [])

def test_conflict_uses_proposed_versions():
    report=run(['b<2'])
    assert report.selected_versions=={'a':'2','b':'2.5'}
    assert report.status=='conflicts_found' and report.conflict_count==1

def test_satisfied_missing_and_unknown():
    report=run(['b>=2','missing>=1','invalid ???'])
    assert [c.status for c in report.checks]==['satisfied','missing','unknown']
    assert report.status=='incomplete' and report.unresolved_count==2

def test_target_markers_do_not_use_host():
    report=run(['b<2; sys_platform == "linux"','b>=2; python_version >= "3.12"'])
    assert [c.status for c in report.checks]==['skipped','satisfied']
    assert report.status=='no_direct_conflicts'

@pytest.mark.parametrize('requirement',[
 'b<2; python_version >= "3.12"','b<2; sys_platform == "win32"',
 'b<2; platform_machine == "AMD64"','b<2; extra == "test"'])
def test_missing_context_is_unknown(requirement):
    assert run([requirement],None,None).checks[0].status=='unknown'

def test_url_and_extras_unresolved():
    assert [c.status for c in run(['b @ https://example.com/b.whl','b[test]>=2']).checks]==['unknown','unknown']

def test_metadata_failure_keeps_other_constraints():
    def lookup(name,version):
        if name=='a': raise dependency_check.DependencyMetadataError('unavailable')
        return ['a>=1']
    report=dependency_check.check_dependencies([package('a'),package('b')],metadata_lookup=lookup)
    assert report.status=='incomplete'
    assert [c.status for c in report.checks]==['unknown','satisfied']

@pytest.mark.parametrize('data,code',[
 ({'info':{'name':'a','version':'1','requires_dist':None}},200),
 ({'info':{'name':'other','version':'1','requires_dist':[]}},200),({},503),({},200)])
def test_metadata_errors(monkeypatch,data,code):
    monkeypatch.setattr(dependency_check.httpx,'get',lambda url,**kw:httpx.Response(code,json=data,request=httpx.Request('GET',url)))
    with pytest.raises(dependency_check.DependencyMetadataError):dependency_check.get_dependencies('a','1')

def test_endpoint_opt_in(monkeypatch):
    monkeypatch.setattr(scanner,'query_vulnerabilities',lambda *a:[])
    calls=[]
    def lookup(name,version):
        calls.append(name)
        return ['b<2'] if name=='a' else []
    monkeypatch.setattr(dependency_check,'get_dependencies',lookup)
    request={'requirements':'a==1\nb==2','target_python':'3.12.0','target_platform':'win_amd64'}
    client=TestClient(app)
    assert client.post('/api/v1/scan',json=request).json()['dependency_check'] is None
    assert calls==[]
    request['check_dependencies']=True
    response=client.post('/api/v1/scan',json=request)
    assert response.status_code==200
    assert response.json()['dependency_check']['conflict_count']==1
    assert response.json()['total_vulnerabilities']==0
