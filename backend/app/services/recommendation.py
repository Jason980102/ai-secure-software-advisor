from collections.abc import Callable
from packaging.version import InvalidVersion, Version
from app.schemas.scan import UpgradeRecommendation
from app.schemas.vulnerability import VulnerabilityFinding
from app.services.osv_service import OSVServiceError
from app.services.pypi_service import check_release, PyPIServiceError
from app.services.release_search import search_releases

MAX_CANDIDATE_CHECKS = 5

def recommend_upgrade(package: str, installed: str, findings: list[VulnerabilityFinding],
                      lookup: Callable, target_python: str | None = None,
                      release_lookup: Callable | None = None, target_platform: str | None = None,
                      search_lookup: Callable | None = None) -> UpgradeRecommendation:
    context = dict(target_python=target_python,target_platform=target_platform)
    if not findings:
        return UpgradeRecommendation(status='not_needed',reason='No known vulnerabilities found for the installed version.',**context)
    installed_version = Version(installed)
    bounds,candidates = [],set()
    for finding in findings:
        fixes = set()
        for raw in finding.fixed_versions:
            try:
                version = Version(raw)
            except InvalidVersion:
                continue
            if version > installed_version and not version.is_prerelease and not version.is_devrelease and not version.local:
                fixes.add(version)
        if not fixes:
            return UpgradeRecommendation(status='manual_review',reason='At least one finding has no stable fix newer than the installed version.',**context)
        bounds.append(min(fixes))
        candidates.update(fixes)
    minimum = max(bounds)
    checked,checks = [],[]
    validate = release_lookup or check_release
    search = search_lookup or search_releases
    fallback_used = False

    def result(status,reason,**extra):
        return UpgradeRecommendation(status=status,reason=reason,checked_versions=checked,
            release_checks=checks,expanded_search=fallback_used,**context,**extra)

    def attempt(candidate,source):
        checked.append(str(candidate))
        release = validate(package,str(candidate),target_python,target_platform) if target_platform else validate(package,str(candidate),target_python)
        checks.append(release)
        if release.status != 'available':
            return None
        remaining = lookup(package,str(candidate))
        release.remaining_vulnerability_ids = sorted({v.id for v in remaining})
        if remaining:
            return None
        return result('candidate','PyPI release and requested compatibility checks passed; OSV reports no known vulnerabilities. Installation, dependency resolution and application compatibility are not verified.',
            recommended_version=str(candidate),candidate_source=source,major_upgrade=candidate.major > installed_version.major)

    try:
        for candidate in sorted(v for v in candidates if v >= minimum)[:MAX_CANDIDATE_CHECKS]:
            success = attempt(candidate,'fix_boundary')
            if success:
                return success
        if len(checked) < MAX_CANDIDATE_CHECKS:
            fallback_used = True
            for raw in search(package,minimum,installed_version,target_python,target_platform):
                candidate = Version(raw)
                if candidate in {Version(v) for v in checked} or candidate < minimum or candidate <= installed_version:
                    continue
                if candidate.is_prerelease or candidate.is_devrelease or candidate.local:
                    continue
                if len(checked) >= MAX_CANDIDATE_CHECKS:
                    break
                success = attempt(candidate,'pypi_release')
                if success:
                    return success
    except (OSVServiceError,PyPIServiceError):
        return result('verification_failed','Candidate verification or PyPI search failed; installed-version findings remain valid.')
    return result('manual_review','No candidate passed within the five-candidate verification budget. See release_checks; this does not prove that no compatible release exists.')
