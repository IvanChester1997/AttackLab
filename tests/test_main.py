from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["project"] == "AttackLab"


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_openapi_metadata_and_paths():
    response = client.get("/openapi.json")

    assert response.status_code == 200

    data = response.json()

    assert data["info"]["title"] == "AttackLab"
    assert data["info"]["version"] == "0.1.0"
    assert "/api/v1/assessments" in data["paths"]
    assert "/api/v1/scans" in data["paths"]
    assert "/api/v1/scans/{scan_id}" in data["paths"]
    assert "/health" in data["paths"]


def test_openapi_contains_assessment_request_examples():
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()["components"]["schemas"]["AssessmentRequest"]

    assert schema["properties"]["target"]["examples"] == ["127.0.0.1"]
    assert schema["properties"]["ports"]["examples"] == ["22,80,443"]
