import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.wheels import compatible_wheels
from app.services import pypi_service, recommendation, scanner
from app.schemas.scan import ReleaseValidation
from app.schemas.vulnerability import VulnerabilityFinding

@pytest.mark.parametrize('filename,platform,expected', [
 ('demo-1.0-py3-none-any.whl','win_amd64',True),
 ('demo-1.0-cp312-cp312-win_amd64.whl','win_amd64',True),
 ('demo-1.0-cp311-cp311-win_amd64.whl','win_amd64',False),
 ('demo-1.0-cp39-abi3-win_amd64.whl','win_amd64',True),
 ('demo-1.0-cp312-cp312-win_arm64.whl','win_amd64',False),
 ('demo-1.0-cp312-cp312-win_arm64.whl','win_arm64',True),
 ('demo-1.0-cp312-cp312-manylinux2014_x86_64.whl','manylinux_2_17_x86_64',True),
 ('demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl','manylinux_2_17_x86_64',False),
 ('demo-1.0-cp312-cp312-manylinux2014_aarch64.whl','manylinux_2_17_aarch64',True),
 ('demo-1.0-cp312-cp312-musllinux_1_2_x86_64.whl','manylinux_2_17_x86_64',False),
 ('demo-1.0.tar.gz','win_amd64',False),
])
def test_tags(filename,platform,expected):
    matches, _ = compatible_wheels([{'filename':filename,'requires_python':'>=3.8'}],'3.12.0',platform)
    assert bool(matches) is expected

def test_python_constraint_on_matching_wheel():
    matches, unknown = compatible_wheels([{'filename':'demo-1.0-py3-none-any.whl','requires_python':'<3.12'}],'3.12.0','win_amd64')
    assert matches == [] and unknown is False
    _, unknown = compatible_wheels([{'filename':'demo-1.0-py3-none-any.whl'}],'3.12.0','win_amd64')
    assert unknown is True

def test_same_file_must_meet_both_checks(monkeypatch):
    import httpx
    data = {'info':{'version':'1.0'},'urls':[
        {'filename':'demo-1.0-cp312-cp312-win_amd64.whl','requires_python':'<3.12','yanked':False},
        {'filename':'demo-1.0-py3-none-any.whl','requires_python':'>=3.8','yanked':True},
        {'filename':'demo-1.0.tar.gz','requires_python':'>=3.8','yanked':False}]}
    monkeypatch.setattr(pypi_service.httpx,'get',lambda url,**kw:httpx.Response(200,json=data,request=httpx.Request('GET',url)))
    result = pypi_service.check_release('demo','1.0','3.12.0','win_amd64')
    assert result.status == 'no_compatible_wheel'
    assert result.wheel_compatible is False

def test_platform_requires_python():
    response = TestClient(app).post('/api/v1/scan',json={'requirements':'a==1','target_platform':'win_amd64'})
    assert response.status_code == 422

def test_platform_end_to_end(monkeypatch):
    finding = VulnerabilityFinding(id='test',aliases=[],summary='',fixed_versions=['2'])
    monkeypatch.setattr(scanner,'query_vulnerabilities',lambda *a:[finding])
    def check(name,version,python,platform):
        assert (python,platform) == ('3.12.0','win_amd64')
        return ReleaseValidation(version=version,status='no_compatible_wheel',wheel_compatible=False)
    monkeypatch.setattr(recommendation,'check_release',check)
    response = TestClient(app).post('/api/v1/scan',json={'requirements':'a==1','target_python':'3.12.0','target_platform':'win_amd64'})
    assert response.status_code == 200
    result = response.json()['results'][0]['upgrade_recommendation']
    assert result['status'] == 'manual_review'
    assert result['target_platform'] == 'win_amd64'
