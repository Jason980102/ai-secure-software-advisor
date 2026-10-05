from app.services.recommendation import recommend_upgrade
from app.schemas.scan import PackageScanResult, ScanReport
from app.services.dependency_parser import parse_requirements
from app.services.osv_service import query_vulnerabilities

def scan_requirements(content: str, target_python: str | None = None) -> ScanReport:
    dependencies = parse_requirements(content, strict=True)
    results = []
    for d in dependencies:
        findings = query_vulnerabilities(d.name, d.version)
        results.append(PackageScanResult(
            package=d.name, installed_version=d.version, vulnerabilities=findings,
            upgrade_recommendation=recommend_upgrade(d.name, d.version, findings, query_vulnerabilities, target_python),
        ))
    return ScanReport(
        total_packages=len(results),
        vulnerable_packages=sum(bool(r.vulnerabilities) for r in results),
        total_vulnerabilities=sum(len(r.vulnerabilities) for r in results),
        results=results,
    )
