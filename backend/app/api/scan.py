from fastapi import APIRouter

from app.schemas.dependency import (
    ParseDependenciesRequest,
    ParseDependenciesResponse,
)
from app.services.dependency_parser import parse_requirements


router = APIRouter(
    prefix="/api/v1/scan",
    tags=["Scan"],
)


@router.post(
    "/parse",
    response_model=ParseDependenciesResponse,
)
def parse_dependencies(
    request: ParseDependenciesRequest,
) -> ParseDependenciesResponse:
    dependencies = parse_requirements(request.content)

    return ParseDependenciesResponse(
        dependencies=dependencies,
        total=len(dependencies),
    )