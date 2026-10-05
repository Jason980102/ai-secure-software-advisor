from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "ai-secure-software-advisor",
    }


def test_parse_dependencies_endpoint():
    response = client.post(
        "/api/v1/scan/parse",
        json={
            "content": (
                "fastapi==0.95.0\n"
                "requests==2.19.0\n"
                "numpy==1.24.0"
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 3
    assert data["dependencies"][0] == {
        "name": "fastapi",
        "version": "0.95.0",
    }