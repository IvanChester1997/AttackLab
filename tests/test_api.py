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

    report = make_report()

    with patch(
        "app.api.routes.AssessmentService.run",
        return_value=report,
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/assessments",
                json={
                    "target": "127.0.0.1",
                    "ports": "22,80",
                },
            )

    assert response.status_code == 200

    data = response.json()
    assert data["id"] == 1
    assert data["report"]["target"] == "127.0.0.1"
    assert data["report"]["summary"]["risk_level"] == "low"


def test_list_scans(monkeypatch, tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)

    import asyncio

    report = make_report("10.0.0.1")
    asyncio.run(repository.init())
    asyncio.run(repository.save_report(report))

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
        }
    ]


def test_get_scan(monkeypatch, tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)

    import asyncio

    report = make_report("10.0.0.2")
    asyncio.run(repository.init())
    asyncio.run(repository.save_report(report))

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
    assert response.json()["report"]["target"] == "10.0.0.2"


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
