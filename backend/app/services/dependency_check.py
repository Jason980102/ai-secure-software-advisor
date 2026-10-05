import re
from urllib.parse import quote
import httpx
from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import Version
from app.schemas.scan import DependencyCheckReport, DependencyConstraint


class DependencyMetadataError(Exception):
    pass


def get_dependencies(package: str, version: str) -> list[str]:
    try:
        response = httpx.get(f'https://pypi.org/pypi/{quote(package,safe="")}/{quote(version,safe="")}/json',timeout=10.0)
        response.raise_for_status()
        info = response.json()['info']
        if canonicalize_name(info['name']) != package or Version(info['version']) != Version(version):
            raise ValueError('Metadata identity mismatch')
        dependencies = info.get('requires_dist')
        if not isinstance(dependencies,list) or any(not isinstance(item,str) for item in dependencies):
            raise ValueError('Missing or invalid dependency metadata')
        return dependencies
    except (httpx.HTTPError,ValueError,TypeError,KeyError) as exc:
        raise DependencyMetadataError(f'Cannot read dependencies for {package}=={version}') from exc


def target_environment(python, platform):
    env={'implementation_name':'cpython','platform_python_implementation':'CPython'}
    if python:
        env.update(python_version='.'.join(python.split('.')[:2]),python_full_version=python,implementation_version=python)
    if platform:
        windows=platform.startswith('win_')
        env.update(sys_platform='win32' if windows else 'linux',os_name='nt' if windows else 'posix',
                   platform_system='Windows' if windows else 'Linux')
    # CPU spelling and OS release/version are intentionally unresolved.
    return env


def check_dependencies(results, python=None, platform=None, metadata_lookup=None):
    lookup=metadata_lookup or get_dependencies
    plan={r.package:r.upgrade_recommendation.recommended_version
          if r.upgrade_recommendation.status=='candidate' else r.installed_version for r in results}
    checks=[]
    env=target_environment(python,platform)
    known_variables={'python_version','python_full_version','implementation_name','implementation_version',
        'platform_python_implementation','sys_platform','os_name','platform_system','platform_machine',
        'platform_release','platform_version','extra','extras','dependency_groups'}
    selected_extras = {r.package: r.extras for r in results}
    for name,version in plan.items():
        marker_env = dict(env, extra="")
        try:
            dependencies=lookup(name,version)
        except DependencyMetadataError as exc:
            checks.append(DependencyConstraint(package=name,selected_version=version,status='unknown',reason=str(exc)))
            continue
        for raw in dependencies:
            entry=dict(package=name,selected_version=version,requirement=raw)
            try:
                requirement=Requirement(raw)
            except InvalidRequirement:
                checks.append(DependencyConstraint(**entry,status='unknown',reason='Invalid dependency requirement metadata'))
                continue
            dependency=canonicalize_name(requirement.name)
            entry.update(dependency=dependency,dependency_version=plan.get(dependency))
            if requirement.marker:
                expression=re.sub(r'"[^"]*"|\x27[^\x27]*\x27','',str(requirement.marker))
                referenced=set(re.findall(r'\b[a-z_]+\b',expression)) & known_variables
                if not referenced <= marker_env.keys():
                    checks.append(DependencyConstraint(**entry,status='unknown',reason='Marker needs target context not available to this check'))
                    continue
                try:
                    applies=any(requirement.marker.evaluate(environment=dict(marker_env, extra=extra))
                                for extra in ["", *selected_extras[name]])
                except (ValueError,KeyError):
                    checks.append(DependencyConstraint(**entry,status='unknown',reason='Cannot evaluate environment marker'))
                    continue
                if not applies:
                    checks.append(DependencyConstraint(**entry,status='skipped',reason='Requirement does not apply to the specified target'))
                    continue
            if requirement.url or requirement.extras:
                checks.append(DependencyConstraint(**entry,status='unknown',reason='URL or extras dependencies require a full resolver'))
            elif dependency not in plan:
                checks.append(DependencyConstraint(**entry,status='missing',reason='Dependency is outside the supplied package set; it has not been resolved'))
            elif requirement.specifier.contains(plan[dependency],prereleases=True):
                checks.append(DependencyConstraint(**entry,status='satisfied',reason='Selected version satisfies this direct constraint'))
            else:
                checks.append(DependencyConstraint(**entry,status='conflict',reason='Selected version violates this direct constraint'))
    conflicts=sum(c.status=='conflict' for c in checks)
    unresolved=sum(c.status in {'missing','unknown'} for c in checks)
    return DependencyCheckReport(status='conflicts_found' if conflicts else ('incomplete' if unresolved else 'no_direct_conflicts'),
        selected_versions=plan,conflict_count=conflicts,unresolved_count=unresolved,checks=checks)
