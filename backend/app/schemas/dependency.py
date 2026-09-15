from pydantic import BaseModel


class ParseDependenciesRequest(BaseModel):
    content: str


class Dependency(BaseModel):
    name: str
    version: str


class ParseDependenciesResponse(BaseModel):
    dependencies: list[Dependency]
    total: int