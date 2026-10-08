from packaging.utils import canonicalize_name
from packaging.version import Version
from app.schemas.plan import UpgradePlan, UpgradePlanItem


def build_upgrade_plan(results, dependency_check=None):
    """Only verified candidates can change pins. AI never chooses export versions."""
    warnings = []
    if dependency_check is None:
        warnings.append('dependencies_not_checked')
    else:
        if dependency_check.conflict_count:
            warnings.append('dependency_conflicts')
        if dependency_check.unresolved_count:
            warnings.append('dependency_incomplete')
    items = []
    pins = []
    for package in results:
        name = canonicalize_name(package.package, validate=True)
        extras = sorted({canonicalize_name(e, validate=True) for e in package.extras})
        installed = Version(package.installed_version)
        recommendation = package.upgrade_recommendation
        proposed = installed
        action = 'review' if package.vulnerabilities else 'keep'
        if recommendation.status == 'candidate' and recommendation.recommended_version:
            candidate = Version(recommendation.recommended_version)
            evidence = any(
                Version(check.version) == candidate and check.status == 'available'
                and check.remaining_vulnerability_ids == []
                and (recommendation.target_python is None or check.python_compatible is True)
                and (recommendation.target_platform is None or check.wheel_compatible is True)
                for check in recommendation.release_checks
            )
            if evidence and candidate > installed and not (candidate.is_prerelease or candidate.is_devrelease or candidate.local):
                proposed, action = candidate, 'upgrade'
        major = action == 'upgrade' and proposed.major > installed.major
        if major:
            warnings.append('major_upgrade')
        if action == 'review':
            warnings.append('retained_vulnerable')
        severities = {v.severity for v in package.vulnerabilities}
        priority = ('high' if severities & {'CRITICAL', 'HIGH'} else
                    'medium' if severities & {'MEDIUM', 'MODERATE'} else
                    'low' if not severities or severities == {'LOW'} else 'unknown')
        items.append(UpgradePlanItem(
            package=name, extras=extras, installed_version=str(installed),
            proposed_version=str(proposed), action=action, priority=priority,
            finding_ids=[v.id for v in package.vulnerabilities], major_upgrade=major,
        ))
        suffix = '[' + ','.join(extras) + ']' if extras else ''
        pins.append(f'{name}{suffix}=={proposed}')
    warnings = list(dict.fromkeys(warnings))
    header = ['# Proposed upgrade plan: review and test in a separate environment.',
              '# Not a lockfile; installation and transitive dependencies are not verified.']
    header.extend('# Review: ' + code for code in warnings)
    return UpgradePlan(status='review_required' if warnings else 'ready_for_testing',
                       warnings=warnings, items=items,
                       requirements_text='\n'.join([*header, *pins]) + '\n')
