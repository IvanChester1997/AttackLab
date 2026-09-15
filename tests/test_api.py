from unittest.mock import patch

from fastapi.testclient import TestClient

from app.database.scan_repository import ScanRepository
from app.main import app
from app.models.port import ScanResult
from app.models.report import ReportSummary, SecurityReport


def make_report(target: str = "127.0.0.1") -> SecurityReport:
    return SecurityReport(
        target=target,
        scan=ScanResult(target=target, ports=[]),
        linux_audit=None,
        findings=[],
        summary=ReportSummary(
            total_ports=0,
            total_findings=0,
            risk_score=0,
            risk_level="low",
        ),
    )


def test_create_assessment(monkeypatch, tmp_path):
    db_path = tmp_path / "attacklab.db"

    monkeypatch.setattr(
        "app.api.routes.DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        "app.database.db.DB_PATH",
        db_path,
    )

    with (
        patch(
            "app.services.assessment_job_service.AssessmentService.run",
            return_value=make_report(),
        ),
        TestClient(app) as client,
    ):
        response = client.post(
            "/api/v1/assessments",
            json={
                "target": "127.0.0.1",
                "ports": "22,80",
            },
        )

    assert response.status_code == 202

    data = response.json()
    assert data["id"] == 1
    assert data["status"] == "pending"
    assert data["report"] is None
    assert data["error_message"] is None


def test_list_scans(monkeypatch, tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)

    import asyncio

    report = make_report("10.0.0.1")
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.1"))
    asyncio.run(repository.complete_scan(scan_id, report))

    monkeypatch.setattr(
        "app.api.routes.DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        "app.database.db.DB_PATH",
        db_path,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": 1,
            "target": "10.0.0.1",
            "status": "completed",
            "risk_score": 0,
            "risk_level": "low",
            "total_findings": 0,
            "error_message": None,
        }
    ]


def test_get_scan(monkeypatch, tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)

    import asyncio

    report = make_report("10.0.0.2")
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.2"))
    asyncio.run(repository.complete_scan(scan_id, report))

    monkeypatch.setattr(
        "app.api.routes.DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        "app.database.db.DB_PATH",
        db_path,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/scans/1")

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["status"] == "completed"
    assert response.json()["report"]["target"] == "10.0.0.2"
    assert response.json()["error_message"] is None


def test_get_scan_returns_404(monkeypatch, tmp_path):
    db_path = tmp_path / "attacklab.db"

    monkeypatch.setattr(
        "app.api.routes.DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        "app.database.db.DB_PATH",
        db_path,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/scans/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan 999 not found"


def test_create_assessment_rejects_blank_target(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"
    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessments",
            json={"target": "   "},
        )

    assert response.status_code == 422


def test_create_assessment_rejects_invalid_target(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"

    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessments",
            json={"target": "!!!invalid!!!"},
        )

    assert response.status_code == 422


def test_create_assessment_accepts_hostname(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"

    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with (
        patch(
            "app.api.routes.AssessmentJobService.run",
        ),
        TestClient(app) as client,
    ):
        response = client.post(
            "/api/v1/assessments",
            json={
                "target": "scanme.nmap.org",
                "ports": "22,80",
            },
        )

    assert response.status_code == 202
    assert response.json()["status"] == "pending"


def test_create_assessment_accepts_network(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"

    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with (
        patch(
            "app.api.routes.AssessmentJobService.run",
        ),
        TestClient(app) as client,
    ):
        response = client.post(
            "/api/v1/assessments",
            json={
                "target": "192.168.1.0/30",
                "ports": "22",
            },
        )

    assert response.status_code == 202
    assert response.json()["status"] == "pending"


def test_create_assessment_rejects_blank_ports(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"
    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessments",
            json={"target": "127.0.0.1", "ports": "   "},
        )

    assert response.status_code == 422


def test_create_assessment_rejects_invalid_ssh_port(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"
    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessments",
            json={"target": "127.0.0.1", "ssh_port": 65536},
        )

    assert response.status_code == 422


def test_get_scan_rejects_non_positive_id(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"
    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/scans/0")

    assert response.status_code == 422


def test_list_scans_contract(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)

    import asyncio

    report = make_report("10.0.0.10")
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.10"))
    asyncio.run(repository.complete_scan(scan_id, report))

    monkeypatch.setattr("app.api.routes.DB_PATH", db_path)
    monkeypatch.setattr("app.database.db.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/scans")

    assert response.status_code == 200
    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == 1
    assert data[0]["status"] == "completed"
    assert set(data[0]) == {
        "id",
        "target",
        "status",
        "risk_score",
        "risk_level",
        "total_findings",
        "error_message",
    }
