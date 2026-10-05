from app.services.dependency_check import check_dependencies as check_plan
from app.services.recommendation import recommend_upgrade
from app.schemas.scan import PackageScanResult, ScanReport
from app.services.dependency_parser import parse_pinned_requirements
from app.services.osv_service import query_vulnerabilities

def scan_requirements(content: str, target_python: str | None = None, target_platform: str | None = None, check_dependencies: bool = False) -> ScanReport:
    dependencies = parse_pinned_requirements(content)
    results = []
    for d in dependencies:
        findings = query_vulnerabilities(d.package, d.version)
        results.append(PackageScanResult(
            package=d.package, installed_version=d.version, extras=d.extras, vulnerabilities=findings,
            upgrade_recommendation=recommend_upgrade(d.package, d.version, findings, query_vulnerabilities, target_python, target_platform=target_platform),
        ))
    return ScanReport(
        dependency_check=check_plan(results, target_python, target_platform) if check_dependencies else None,
        total_packages=len(results),
        vulnerable_packages=sum(bool(r.vulnerabilities) for r in results),
        total_vulnerabilities=sum(len(r.vulnerabilities) for r in results),
        results=results,
    )
