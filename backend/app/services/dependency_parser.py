from app.schemas.dependency import Dependency


def parse_requirements(content: str) -> list[Dependency]:
    dependencies = []

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "==" not in line:
            continue

        name, version = line.split("==", 1)

        name = name.strip()
        version = version.strip()

        if not name or not version:
            continue

        dependencies.append(
            Dependency(
                name=name,
                version=version,
            )
        )

    return dependencies