from collections.abc import Callable
from packaging.version import InvalidVersion, Version

from app.schemas.scan import UpgradeRecommendation
from app.schemas.vulnerability import VulnerabilityFinding
from app.services.osv_service import OSVServiceError
from app.services.pypi_service import check_release, PyPIServiceError


def recommend_upgrade(package: str, installed: str, findings: list[VulnerabilityFinding],
                      lookup: Callable, target_python: str | None = None, release_lookup: Callable | None = None) -> UpgradeRecommendation:
    if not findings:
        return UpgradeRecommendation(status="not_needed", reason="No known vulnerabilities found for the installed version.")
    candidates = set()
    for finding in findings:
        for raw in finding.fixed_versions:
            try:
                version = Version(raw)
            except InvalidVersion:
                continue
            if version > Version(installed) and not version.is_prerelease and not version.is_devrelease:
                candidates.add(version)
    # Prefer a boundary at or above a fix for every finding; OSV re-query is
    # decisive because fixes can belong to separate or reintroduced branches.
    lower_bounds = []
    for finding in findings:
        versions = [v for v in candidates if str(v) in finding.fixed_versions]
        if not versions:
            return UpgradeRecommendation(status="manual_review", reason="At least one finding has no stable fix newer than the installed version.")
        lower_bounds.append(min(versions))
    eligible = sorted(v for v in candidates if v >= max(lower_bounds))
    checked = []
    release_checks = []
    validate = release_lookup or check_release
    for candidate in eligible[:5]:
        checked.append(str(candidate))
        try:
            release = validate(package, str(candidate), target_python)
            release_checks.append(release)
            if release.status != "available":
                continue
            remaining = lookup(package, str(candidate))
        except (OSVServiceError, PyPIServiceError):
            return UpgradeRecommendation(status="verification_failed", checked_versions=checked, release_checks=release_checks, target_python=target_python,
                reason="Candidate verification failed; the installed-version findings remain valid.")
        if not remaining:
            return UpgradeRecommendation(status="candidate", recommended_version=str(candidate),
                checked_versions=checked, release_checks=release_checks, target_python=target_python, major_upgrade=candidate.major > Version(installed).major,
                reason="OSV reports no known vulnerabilities for this fix-boundary candidate. PyPI has a non-yanked release file. Python Requires-Python metadata is checked only when target_python is supplied; wheel/platform, dependency and application compatibility are not verified.")
    return UpgradeRecommendation(status="manual_review", checked_versions=checked, release_checks=release_checks, target_python=target_python,
        reason="No candidate cleared OSV verification within the five-candidate limit.")
