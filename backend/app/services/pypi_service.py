from urllib.parse import quote
import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version
from app.schemas.scan import ReleaseValidation


class PyPIServiceError(Exception):
    pass


def check_release(package: str, version: str, target_python: str | None) -> ReleaseValidation:
    url = f"https://pypi.org/pypi/{quote(package, safe='')}/{quote(version, safe='')}/json"
    try:
        response = httpx.get(url, timeout=10.0)
        if response.status_code == 404:
            return ReleaseValidation(version=version, status="not_found")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("info"), dict) or not isinstance(data.get("urls"), list):
            raise ValueError("Invalid release response")
        if Version(data["info"]["version"]) != Version(version):
            raise ValueError("Release version mismatch")
        files = data["urls"]
        if any(not isinstance(f, dict) or not isinstance(f.get("yanked"), bool) for f in files):
            raise ValueError("Invalid file metadata")
        active = [f for f in files if not f["yanked"]]
        if not files:
            return ReleaseValidation(version=version, status="no_files")
        if not active:
            return ReleaseValidation(version=version, status="yanked")
        requirements = sorted({f["requires_python"] for f in active if isinstance(f.get("requires_python"), str) and f["requires_python"]})
        if target_python is None:
            return ReleaseValidation(version=version, status="available", requires_python=requirements,
                python_compatible=None)
        unknown = False
        for file in active:
            spec = file.get("requires_python")
            if not isinstance(spec, str) or not spec:
                unknown = True
                continue
            try:
                if SpecifierSet(spec).contains(target_python, prereleases=False):
                    return ReleaseValidation(version=version, status="available", requires_python=requirements,
                        python_compatible=True)
            except InvalidSpecifier:
                unknown = True
        return ReleaseValidation(version=version, status="python_unknown" if unknown else "python_incompatible",
            requires_python=requirements, python_compatible=None if unknown else False)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise PyPIServiceError(f"Failed to verify PyPI release {package}=={version}") from exc
