from fastapi.testclient import TestClient
from app.main import app
from app.services import scanner, dependency_check
from app.services.dependency_parser import parse_pinned_requirements
from app.schemas.scan import PackageScanResult, UpgradeRecommendation

def test_duplicate_pins_merge_normalized_extras():
    deps = parse_pinned_requirements('Requests[SOCKS]==2.33.0\nrequests[use_chardet_on_py3]==2.33.0\nrequests==2.33.0')
    assert len(deps) == 1
    assert deps[0].extras == ('socks', 'use-chardet-on-py3')

def result(extras):
    return PackageScanResult(package='requests', installed_version='2.33.0', extras=extras,
        vulnerabilities=[], upgrade_recommendation=UpgradeRecommendation(status='not_needed', reason='test'))

def check(extras, metadata, python=None):
    return dependency_check.check_dependencies([result(extras)], python=python,
        metadata_lookup=lambda *args: metadata)

def test_unselected_optional_dependencies_are_skipped():
    report = check([], ['PySocks>=1; extra == "socks"'])
    assert report.checks[0].status == 'skipped'
    assert report.unresolved_count == 0

def test_selected_extra_applies_and_base_dependencies_remain():
    report = check(['socks'], ['PySocks>=1; extra == "socks"', 'certifi>=1', 'chardet; extra == "test"'])
    assert [c.status for c in report.checks] == ['missing', 'missing', 'skipped']

def test_multiple_extras_and_target_marker():
    report = check(['socks', 'test'], ['PySocks; extra == "socks" and python_version >= "3.12"',
        'pytest; extra == "test"', 'old; extra == "socks" and python_version < "3.12"'], '3.12.0')
    assert [c.status for c in report.checks] == ['missing', 'missing', 'skipped']

def test_extra_does_not_supply_unknown_environment():
    report = check(['socks'], ['PySocks; extra == "socks" and platform_machine == "AMD64"'])
    assert report.checks[0].status == 'unknown'

def test_api_preserves_extras_and_queries_package_once(monkeypatch):
    queried = []
    monkeypatch.setattr(scanner, 'query_vulnerabilities', lambda name, version: queried.append((name, version)) or [])
    monkeypatch.setattr(dependency_check, 'get_dependencies', lambda *args: ['PySocks; extra == "socks"'])
    response = TestClient(app).post('/api/v1/scan', json={'requirements': 'requests[socks]==2.33.0\nrequests==2.33.0', 'check_dependencies': True})
    assert response.status_code == 200
    data = response.json()
    assert data['results'][0]['extras'] == ['socks']
    assert data['dependency_check']['checks'][0]['status'] == 'missing'
    assert queried == [('requests', '2.33.0')]
