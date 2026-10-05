from typing import Literal
import re
from pydantic import BaseModel, Field, field_validator
from app.schemas.vulnerability import VulnerabilityFinding

class ScanRequest(BaseModel):
    requirements: str = Field(min_length=1, max_length=100_000)

    target_python: str | None = Field(default=None, description="Target Python version, e.g. 3.12.0. Omit to skip Python compatibility verification.")

    @field_validator("target_python")
    @classmethod
    def validate_target(cls, value):
        if value is not None and not re.fullmatch(r"3\.\d+\.\d+", value):
            raise ValueError("Use a full Python 3 version, e.g. 3.12.0")
        return value

class ReleaseValidation(BaseModel):
    version: str
    status: Literal["available", "not_found", "no_files", "yanked", "python_incompatible", "python_unknown"]
    requires_python: list[str] = Field(default_factory=list)
    python_compatible: bool | None = None

class UpgradeRecommendation(BaseModel):
    status: Literal["not_needed", "candidate", "manual_review", "verification_failed"]
    recommended_version: str | None = None
    checked_versions: list[str] = Field(default_factory=list)
    major_upgrade: bool | None = None
    target_python: str | None = None
    release_checks: list[ReleaseValidation] = Field(default_factory=list)
    reason: str

class PackageScanResult(BaseModel):
    package: str
    installed_version: str
    vulnerabilities: list[VulnerabilityFinding]
    upgrade_recommendation: UpgradeRecommendation

class ScanReport(BaseModel):
    total_packages: int
    vulnerable_packages: int
    total_vulnerabilities: int
    results: list[PackageScanResult]
