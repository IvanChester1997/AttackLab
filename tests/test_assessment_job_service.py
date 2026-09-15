import asyncio
from unittest.mock import patch

from app.database.scan_repository import ScanRepository
from app.models.port import ScanResult
from app.models.report import ReportSummary, SecurityReport
from app.scanners.port_scanner import PortScanError
from app.services.assessment_job_service import AssessmentJobService
from app.services.nvd_client import NVDClientError


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


def test_run_completes_scan(tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.20"))

    report = make_report("10.0.0.20")

    with patch(
        "app.services.assessment_job_service.AssessmentService.run",
        return_value=report,
    ):
        asyncio.run(
            AssessmentJobService.run(
                repository,
                scan_id,
                "10.0.0.20",
                "22,80",
            )
        )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "completed"
    assert scan.report.target == "10.0.0.20"
    assert scan.error_message is None


def test_run_marks_failed_scan(tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.21"))

    with patch(
        "app.services.assessment_job_service.AssessmentService.run",
        side_effect=RuntimeError("Nmap execution failed"),
    ):
        asyncio.run(
            AssessmentJobService.run(
                repository,
                scan_id,
                "10.0.0.21",
                "22,80",
            )
        )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "failed"
    assert scan.error_message == "Nmap execution failed"


def test_run_marks_failed_when_nvd_assessment_fails(tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.22"))

    with patch(
        "app.services.assessment_job_service.AssessmentService.run",
        side_effect=NVDClientError("NVD API request failed"),
    ):
        asyncio.run(
            AssessmentJobService.run(
                repository,
                scan_id,
                "10.0.0.22",
                "22,80",
            )
        )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "failed"
    assert scan.error_message == "NVD API request failed"


def test_run_marks_failed_when_port_scan_fails(tmp_path):
    db_path = tmp_path / "attacklab.db"
    repository = ScanRepository(db_path)
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.23"))

    with patch(
        "app.services.assessment_job_service.AssessmentService.run",
        side_effect=PortScanError("Nmap scan timed out"),
    ):
        asyncio.run(
            AssessmentJobService.run(
                repository,
                scan_id,
                "10.0.0.23",
                "22,80",
            )
        )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "failed"
    assert scan.error_message == "Nmap scan timed out"
