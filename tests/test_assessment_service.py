from unittest.mock import MagicMock, patch

import paramiko
import pytest

from app.models.port import ScanResult
from app.models.report import SecurityReport
from app.services.assessment_service import AssessmentService


def test_run_performs_port_scan_and_generates_report():
    scan_result = MagicMock(spec=ScanResult)
    report = MagicMock(spec=SecurityReport)

    with (
        patch(
            "app.services.assessment_service.PortScanService.scan",
            return_value=scan_result,
        ) as scan_mock,
        patch(
            "app.services.assessment_service.ReportGenerator.generate",
            return_value=report,
        ) as generate_mock,
    ):
        result = AssessmentService.run(
            "127.0.0.1",
            ports="22,80",
        )

    assert result is report
    scan_mock.assert_called_once_with("127.0.0.1", "22,80")
    generate_mock.assert_called_once_with(
        scan_result,
        linux_audit=None,
    )


def test_run_performs_linux_audit_when_username_is_provided():
    scan_result = MagicMock(spec=ScanResult)
    linux_audit = MagicMock()
    report = MagicMock(spec=SecurityReport)

    connector = MagicMock()

    with (
        patch(
            "app.services.assessment_service.PortScanService.scan",
            return_value=scan_result,
        ) as scan_mock,
        patch(
            "app.services.assessment_service.SSHConnector",
            return_value=connector,
        ) as connector_mock,
        patch(
            "app.services.assessment_service.LinuxAuditScanner",
        ) as scanner_class_mock,
        patch(
            "app.services.assessment_service.ReportGenerator.generate",
            return_value=report,
        ) as generate_mock,
    ):
        scanner_class_mock.return_value.run_audit.return_value = linux_audit

        result = AssessmentService.run(
            "10.0.0.10",
            ports="22,80",
            username="root",
            ssh_port=2222,
            key_file="/tmp/id_ed25519",
        )

    assert result is report

    scan_mock.assert_called_once_with(
        "10.0.0.10",
        "22,80",
    )
    connector_mock.assert_called_once_with(
        host="10.0.0.10",
        username="root",
        port=2222,
        key_file="/tmp/id_ed25519",
    )
    scanner_class_mock.assert_called_once_with(connector)
    scanner_class_mock.return_value.run_audit.assert_called_once_with()
    generate_mock.assert_called_once_with(
        scan_result,
        linux_audit=linux_audit,
    )


def test_run_propagates_ssh_errors():
    scan_result = MagicMock(spec=ScanResult)

    with (
        patch(
            "app.services.assessment_service.PortScanService.scan",
            return_value=scan_result,
        ),
        patch(
            "app.services.assessment_service.SSHConnector",
            side_effect=paramiko.SSHException("connection failed"),
        ),
        pytest.raises(paramiko.SSHException, match="connection failed"),
    ):
        AssessmentService.run(
            "10.0.0.10",
            username="root",
        )
