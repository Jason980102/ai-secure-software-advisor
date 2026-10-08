from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.schemas.scan import ScanReport

Language = Literal['en', 'zh-Hant', 'zh-Hans', 'ja', 'es']


class AdviceRequest(BaseModel):
    report: ScanReport
    language: Language = 'en'

    @model_validator(mode='after')
    def bound_report(self):
        if not 1 <= len(self.report.results) <= 100:
            raise ValueError('Advice requires 1 to 100 packages')
        if len(self.report.model_dump_json()) > 250_000:
            raise ValueError('Report is too large for advice')
        return self


class PackageAdvice(BaseModel):
    model_config = ConfigDict(extra='forbid')
    package: str = Field(max_length=200)
    explanation: str = Field(min_length=1, max_length=1800)
    test_focus: str = Field(min_length=1, max_length=1200)
    finding_ids: list[str] = Field(max_length=20)


class AdviceContent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    summary: str = Field(min_length=1, max_length=2000)
    packages: list[PackageAdvice] = Field(max_length=100)
    next_steps: list[str] = Field(min_length=1, max_length=6)


class AdviceResponse(BaseModel):
    status: Literal['generated', 'not_configured', 'unavailable']
    language: Language
    content: AdviceContent | None = None
    provider: str | None = None
    model: str | None = None
    reason: str | None = None
