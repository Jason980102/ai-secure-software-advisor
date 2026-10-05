import re
from dataclasses import dataclass

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class Dependency:
    package: str
    version: str


def parse_pinned_requirements(text: str) -> list[Dependency]:
    dependencies = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirement = Requirement(line)
            specs = list(requirement.specifier)
            if requirement.url or requirement.marker or len(specs) != 1:
                raise ValueError("use an exact version; URLs and environment markers are unsupported")
            spec = specs[0]
            if spec.operator != "==" or "*" in spec.version:
                raise ValueError("use an exact version, e.g. requests==2.19.0")
            version = str(Version(spec.version))
        except (InvalidRequirement, InvalidVersion, ValueError) as exc:
            raise ValueError(f"Line {number}: {exc}") from exc
        name = canonicalize_name(requirement.name)
        if name in dependencies and dependencies[name].version != version:
            raise ValueError(f"Line {number}: conflicting versions for {name}")
        dependencies[name] = Dependency(name, version)
    if not dependencies:
        raise ValueError("No pinned packages found")
    if len(dependencies) > 100:
        raise ValueError("Maximum 100 unique packages per scan")
    return list(dependencies.values())


def parse_requirements(content: str, *, strict: bool = False):
    from app.schemas.dependency import Dependency as SchemaDependency
    if strict:
        parsed = parse_pinned_requirements(content)
    else:
        parsed = []
        for line in content.splitlines():
            try:
                parsed.extend(parse_pinned_requirements(line))
            except ValueError:
                continue
    return [SchemaDependency(name=d.package, version=d.version) for d in parsed]
