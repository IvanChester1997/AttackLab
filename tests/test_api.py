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

    with patch(
        "app.api.routes.AssessmentService.run",
        return_value=make_report(),
    ):
        with TestClient(app) as client:
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


def test_run_assessment_completes_scan(monkeypatch, tmp_path):
    import asyncio

    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.20"))

    report = make_report("10.0.0.20")

    monkeypatch.setattr(
        "app.api.routes.DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        "app.api.routes.AssessmentService.run",
        lambda **kwargs: report,
    )

    from app.api.routes import AssessmentRequest, run_assessment

    asyncio.run(
        run_assessment(
            scan_id,
            AssessmentRequest(
                target="10.0.0.20",
                ports="22,80",
            ),
        )
    )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "completed"
    assert scan.report.target == "10.0.0.20"
    assert scan.error_message is None


def test_run_assessment_marks_failed(monkeypatch, tmp_path):
    import asyncio

    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.21"))

    def fail_assessment(**kwargs):
        raise RuntimeError("Nmap execution failed")

    monkeypatch.setattr(
        "app.api.routes.DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        "app.api.routes.AssessmentService.run",
        fail_assessment,
    )

    from app.api.routes import AssessmentRequest, run_assessment

    asyncio.run(
        run_assessment(
            scan_id,
            AssessmentRequest(
                target="10.0.0.21",
                ports="22,80",
            ),
        )
    )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "failed"
    assert scan.error_message == "Nmap execution failed"
