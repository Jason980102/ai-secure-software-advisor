import pytest
from app.schemas.scan import ReleaseValidation
from app.services import recommendation

@pytest.fixture(autouse=True)
def mock_release_validation(monkeypatch):
    # Existing OSV tests stay offline; PyPI service is tested separately.
    monkeypatch.setattr(recommendation, "check_release", lambda package, version, target:
        ReleaseValidation(version=version, status="available", python_compatible=True if target else None))
