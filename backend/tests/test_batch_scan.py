import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import osv_service, scanner
from app.services.dependency_parser import parse_requirements

client = TestClient(app)


def record(identifier="GHSA-test", aliases=None, package="requests", fixed="2.10.0"):
    return {
        "id": identifier, "aliases": aliases or [], "summary": "Example finding",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": package, "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": fixed}]}]}],
    }


def install_osv(monkeypatch, handler):
    original = httpx.Client
    monkeypatch.setattr(osv_service.httpx, "Client", lambda **kw: original(
        transport=httpx.MockTransport(handler), **kw))


def test_batch_full_pipeline(monkeypatch):
    import json
    calls = []
    def handler(request):
        payload = json.loads(request.content)
        calls.append(payload)
        assert payload["package"]["ecosystem"] == "PyPI"
        if payload["package"]["name"] == "flask":
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"vulns": [
            record(aliases=["CVE-2024-12345"]),
            record("CVE-2024-12345", fixed="2.9.0"),
        ]})
    install_osv(monkeypatch, handler)
    response = client.post("/api/v1/scan", json={"requirements":
        "# demo\nRequests[security]==2.0.0 # old\nrequests==2.0.0\nflask==2.0.0"})
    assert response.status_code == 200
    data = response.json()
    assert (data["total_packages"], data["vulnerable_packages"], data["total_vulnerabilities"]) == (2, 1, 1)
    assert len(calls) == 4
    finding = data["results"][0]["vulnerabilities"][0]
    assert finding["id"] == "CVE-2024-12345"
    assert finding["aliases"] == ["GHSA-test"]
    assert finding["fixed_versions"] == ["2.9.0", "2.10.0"]
    assert data["results"][1]["vulnerabilities"] == []


@pytest.mark.parametrize("text", ["", "# comment", "requests", "requests>=2", "requests==2.*",
    "requests==2; python_version>'3'", "-r other.txt", "a==1\na==2", "a==oops",
    "a @ https://example.com/a.whl", "a==1 --hash=sha256:abc"])
def test_invalid_input_never_queries_osv(monkeypatch, text):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda *a: pytest.fail("unexpected query"))
    assert client.post("/api/v1/scan", json={"requirements": text}).status_code == 422


def test_package_limit():
    with pytest.raises(ValueError, match="Maximum"):
        parse_requirements("\n".join(f"p{i}==1" for i in range(101)), strict=True)


def test_pagination_alias_bridge_and_fixed_filter(monkeypatch):
    import json
    def handler(request):
        payload = json.loads(request.content)
        if "page_token" not in payload:
            return httpx.Response(200, json={"vulns": [record("GHSA-a"), record("GHSA-b")], "next_page_token": "next"})
        assert payload["page_token"] == "next"
        bridge = record("CVE-2024-12345", ["GHSA-a", "GHSA-b"])
        bridge["affected"] += record(package="other", fixed="99")["affected"]
        bridge["affected"][0]["ranges"].append({"type": "GIT", "events": [{"fixed": "abcdef"}]})
        return httpx.Response(200, json={"vulns": [bridge, {**record("withdrawn"), "withdrawn": "2024-01-01"}]})
    install_osv(monkeypatch, handler)
    findings = osv_service.query_vulnerabilities("requests", "2.0.0")
    assert len(findings) == 1
    assert findings[0].aliases == ["GHSA-a", "GHSA-b"]
    assert findings[0].fixed_versions == ["2.10.0"]


@pytest.mark.parametrize("failure", ["http", "timeout", "json", "shape", "record", "pagination"])
def test_osv_failure_returns_502(monkeypatch, failure):
    def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("timed out", request=request)
        if failure == "http":
            return httpx.Response(503)
        if failure == "json":
            return httpx.Response(200, text="not json")
        payload = {"shape": {"vulns": {}}, "record": {"vulns": [{}]},
                   "pagination": {"next_page_token": "same"}}[failure]
        return httpx.Response(200, json=payload)
    install_osv(monkeypatch, handler)
    response = client.post("/api/v1/scan", json={"requirements": "requests==2.0.0"})
    assert response.status_code == 502
    assert "requests==2.0.0" in response.json()["detail"]


def test_counts_package_findings_even_for_shared_cve(monkeypatch):
    from app.schemas.vulnerability import VulnerabilityFinding
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda *args: [
        VulnerabilityFinding(id="CVE-2024-12345", aliases=[], summary="shared")])
    data = client.post("/api/v1/scan", json={"requirements": "a==1\nb==1"}).json()
    assert data["total_vulnerabilities"] == 2
    assert data["vulnerable_packages"] == 2
