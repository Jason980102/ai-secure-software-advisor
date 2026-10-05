from urllib.parse import quote
import httpx
from packaging.utils import parse_wheel_filename, parse_sdist_filename, canonicalize_name
from packaging.version import Version
from packaging.specifiers import SpecifierSet
from app.services.pypi_service import PyPIServiceError
from app.services.wheels import compatible_wheels

def search_releases(package, minimum, installed, target_python, target_platform):
    try:
        response = httpx.get(f"https://pypi.org/simple/{quote(package, safe='')}/",
            headers={"Accept":"application/vnd.pypi.simple.v1+json"}, timeout=10.0)
        if response.status_code == 404:
            return []
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get('files'), list):
            raise ValueError('Invalid PyPI index')
        eligible = set()
        for file in data['files']:
            if not isinstance(file, dict) or not isinstance(file.get('filename'), str):
                raise ValueError('Invalid index file')
            if not isinstance(file.get('yanked'), (bool,str)):
                raise ValueError('Invalid yanked metadata')
            if file['yanked'] is not False:
                continue
            filename = file['filename']
            try:
                name, version = parse_wheel_filename(filename)[:2] if filename.endswith('.whl') else parse_sdist_filename(filename)
            except ValueError:
                continue
            if canonicalize_name(name) != canonicalize_name(package):
                continue
            if version <= installed or version < minimum or version.is_prerelease or version.is_devrelease or version.local:
                continue
            spec = file.get('requires-python')
            if target_python is not None:
                if not isinstance(spec,str) or not spec:
                    continue
                try:
                    if not SpecifierSet(spec).contains(target_python,prereleases=False):
                        continue
                except ValueError:
                    continue
            if target_platform:
                matches,_ = compatible_wheels([{'filename':filename,'requires_python':spec}],target_python,target_platform)
                if not matches:
                    continue
            eligible.add(version)
        return [str(v) for v in sorted(eligible)]
    except (httpx.HTTPError,ValueError,TypeError,KeyError) as exc:
        raise PyPIServiceError(f'Failed to search PyPI releases for {package}') from exc
