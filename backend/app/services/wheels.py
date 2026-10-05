from packaging.tags import cpython_tags, compatible_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.specifiers import SpecifierSet, InvalidSpecifier


def platform_tags(platform: str) -> list[str]:
    if platform.startswith('win_'):
        return [platform]
    architecture = platform.removeprefix('manylinux_2_17_')
    tags = [f'manylinux_2_{minor}_{architecture}' for minor in range(17, 4, -1)]
    tags.append(f'manylinux2014_{architecture}')
    if architecture == 'x86_64':
        tags.extend(['manylinux2010_x86_64', 'manylinux1_x86_64'])
    return tags


def compatible_wheels(files: list[dict], python: str, platform: str) -> tuple[list[str], bool]:
    version = tuple(int(part) for part in python.split('.')[:2])
    platforms = platform_tags(platform)
    supported = set(cpython_tags(version, abis=[f'cp{version[0]}{version[1]}'], platforms=platforms))
    supported.update(compatible_tags(version, interpreter=f'cp{version[0]}{version[1]}', platforms=platforms))
    matches, unknown = [], False
    for file in files:
        filename = file.get('filename', '')
        if not isinstance(filename, str) or not filename.endswith('.whl'):
            continue
        try:
            _, _, _, tags = parse_wheel_filename(filename)
        except InvalidWheelFilename:
            unknown = True
            continue
        if not tags & supported:
            continue
        spec = file.get('requires_python')
        if not isinstance(spec, str) or not spec:
            unknown = True
            continue
        try:
            if SpecifierSet(spec).contains(python, prereleases=False):
                matches.append(filename)
        except InvalidSpecifier:
            unknown = True
    return sorted(matches), unknown
