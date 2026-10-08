from typing import Literal
from pydantic import BaseModel, Field


class UpgradePlanItem(BaseModel):
    package: str
    extras: list[str] = Field(default_factory=list)
    installed_version: str
    proposed_version: str
    action: Literal['upgrade', 'keep', 'review']
    priority: Literal['high', 'medium', 'low', 'unknown']
    finding_ids: list[str]
    major_upgrade: bool


class UpgradePlan(BaseModel):
    status: Literal['review_required', 'ready_for_testing']
    warnings: list[str]
    items: list[UpgradePlanItem]
    requirements_text: str
