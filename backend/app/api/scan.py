from fastapi import APIRouter, HTTPException

from app.schemas.dependency import (
    ParseDependenciesRequest,
    ParseDependenciesResponse,
)
from app.schemas.vulnerability import VulnerabilityScanResponse
from app.services.dependency_parser import parse_requirements
from app.services.osv_service import query_vulnerabilities


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


@router.get(
    "/vulnerabilities/{package_name}/{version}",
    response_model=VulnerabilityScanResponse,
)
def get_vulnerabilities(
    package_name: str,
    version: str,
) -> VulnerabilityScanResponse:
    vulnerabilities = query_vulnerabilities(
        package_name=package_name,
        version=version,
    )

    return VulnerabilityScanResponse(
        package=package_name,
        version=version,
        vulnerability_count=len(vulnerabilities),
        vulnerabilities=vulnerabilities,
    )

from app.schemas.scan import ScanRequest, ScanReport
from app.services.scanner import scan_requirements
from app.services.osv_service import OSVServiceError

@router.post("", response_model=ScanReport)
def batch_scan(request: ScanRequest) -> ScanReport:
    try:
        return scan_requirements(request.requirements, request.target_python, request.target_platform, request.check_dependencies)
    except OSVServiceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
