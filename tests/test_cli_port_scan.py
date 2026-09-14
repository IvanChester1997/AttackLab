from pathlib import Path
import paramiko
from unittest.mock import patch

from typer.testing import CliRunner

from app.cli.main import app
from app.models.finding import Finding, Severity
from app.models.linux_audit import LinuxAuditResult
from app.models.port import PortResult, ScanResult
from app.models.report import ReportSummary, SecurityReport
from app.services.assessment_service import AssessmentService


runner = CliRunner()


def test_scan_command():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service={
                    "name": "ssh",
                },
            ),
            PortResult(
                port=80,
                protocol="tcp",
                state="open",
                service={
                    "name": "http",
                },
            ),
        ],
    )

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=SecurityReport(
            target=result_data.target,
            scan=result_data,
            findings=[],
            summary=ReportSummary(total_ports=len(result_data.ports), total_findings=0),
        ),
    ) as mock_run:
        result = runner.invoke(
            app,
            ["scan", "127.0.0.1"],
        )

    assert result.exit_code == 0
    mock_run.assert_called_once_with(
        target="127.0.0.1",
        ports="22,80,443",
        username=None,
        ssh_port=22,
        key_file=None,
    )

    assert "127.0.0.1" in result.stdout
    assert "22" in result.stdout
    assert "ssh" in result.stdout
    assert "80" in result.stdout
    assert "http" in result.stdout


def test_scan_command_with_custom_ports():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=8080,
                protocol="tcp",
                state="open",
                service={
                    "name": "http-proxy",
                },
            ),
        ],
    )

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=SecurityReport(
            target=result_data.target,
            scan=result_data,
            findings=[],
            summary=ReportSummary(total_ports=len(result_data.ports), total_findings=0),
        ),
    ) as mock_run:
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--ports",
                "1-1000",
            ],
        )

    assert result.exit_code == 0
    mock_run.assert_called_once_with(
        target="127.0.0.1",
        ports="1-1000",
        username=None,
        ssh_port=22,
        key_file=None,
    )

    assert "8080" in result.stdout
    assert "http-proxy" in result.stdout


def test_scan_command_displays_service_details():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service={
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "9.2p1",
                },
            ),
        ],
    )

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=SecurityReport(
            target=result_data.target,
            scan=result_data,
            findings=[],
            summary=ReportSummary(
                total_ports=len(result_data.ports),
                total_findings=0,
            ),
        ),
    ):
        result = runner.invoke(
            app,
            ["scan", "127.0.0.1"],
        )

    assert result.exit_code == 0
    assert "22/tcp open ssh (OpenSSH 9.2p1)" in result.stdout


def test_scan_command_displays_findings():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=23,
                protocol="tcp",
                state="open",
                service={
                    "name": "telnet",
                },
            ),
        ],
    )

    report = SecurityReport(
        target="127.0.0.1",
        scan=result_data,
        findings=[
            Finding(
                title="Exposed telnet service",
                severity=Severity.HIGH,
                description="Telnet is insecure.",
                port=23,
                service="telnet",
            )
        ],
        summary=ReportSummary(
            total_ports=1,
            total_findings=1,
            high=1,
        ),
    )

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=report,
    ):
        result = runner.invoke(app, ["scan", "127.0.0.1"])

    assert result.exit_code == 0
    assert "[HIGH] Exposed telnet service" in result.output
    assert "Summary:" in result.output
    assert "Total findings: 1" in result.output
    assert "High: 1" in result.output


def test_scan_command_writes_json_report(tmp_path):
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=23,
                protocol="tcp",
                state="open",
                service={
                    "name": "telnet",
                },
            ),
        ],
    )

    report = SecurityReport(
        target="127.0.0.1",
        scan=result_data,
        findings=[
            Finding(
                title="Exposed telnet service",
                severity=Severity.HIGH,
                description="Telnet is insecure.",
                port=23,
                service="telnet",
            )
        ],
        summary=ReportSummary(
            total_ports=1,
            total_findings=1,
            high=1,
        ),
    )

    output_file = tmp_path / "report.json"

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=report,
    ):
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--output",
                str(output_file),
            ],
        )

    assert result.exit_code == 0
    assert output_file.exists()

    data = output_file.read_text(encoding="utf-8")

    assert '"target": "127.0.0.1"' in data
    assert '"total_findings": 1' in data
    assert '"severity": "high"' in data
    assert "Report saved to:" in result.output


def test_scan_command_writes_empty_json_report(tmp_path):
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[],
    )

    report = SecurityReport(
        target="127.0.0.1",
        scan=result_data,
        findings=[],
        summary=ReportSummary(
            total_ports=0,
            total_findings=0,
        ),
    )

    output_file = tmp_path / "empty-report.json"

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=report,
    ):
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--output",
                str(output_file),
            ],
        )

    assert result.exit_code == 0
    assert output_file.exists()

    data = output_file.read_text(encoding="utf-8")

    assert '"target": "127.0.0.1"' in data
    assert '"total_ports": 0' in data
    assert '"total_findings": 0' in data
    assert "Report saved to:" in result.output
    assert "No open ports found." in result.output


def test_audit_command_runs_linux_audit():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[],
    )

    linux_audit = LinuxAuditResult(
        hostname="test-host",
        os={"name": "Debian"},
        users=[],
        interactive_users=[],
        uid_zero_accounts=[],
        service_accounts=[],
        findings=[
            Finding(
                title="NOPASSWD Sudo Rule",
                severity=Severity.HIGH,
                description="NOPASSWD sudo rule detected.",
            )
        ],
    )

    report = SecurityReport(
        target="127.0.0.1",
        scan=result_data,
        linux_audit=linux_audit,
        findings=[
            Finding(
                title="NOPASSWD Sudo Rule",
                severity=Severity.HIGH,
                description="NOPASSWD sudo rule detected.",
            )
        ],
        summary=ReportSummary(
            total_ports=0,
            total_findings=1,
            high=1,
        ),
    )

    with patch(
        "app.cli.main.AssessmentService.run",
        return_value=report,
    ) as mock_run:
        result = runner.invoke(
            app,
            [
                "audit",
                "127.0.0.1",
                "--user",
                "root",
                "--ssh-port",
                "2222",
                "--key",
                "~/.ssh/id_ed25519",
            ],
        )

    assert result.exit_code == 0

    mock_run.assert_called_once_with(
        target="127.0.0.1",
        ports="22,80,443",
        username="root",
        ssh_port=2222,
        key_file=Path("~/.ssh/id_ed25519"),
    )
    assert "No open ports found." in result.output


def test_audit_command_handles_ssh_error():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[],
    )

    with patch(
        "app.cli.main.AssessmentService.run",
        side_effect=paramiko.SSHException("connection failed"),
    ):
        result = runner.invoke(
            app,
            [
                "audit",
                "127.0.0.1",
                "--user",
                "root",
            ],
        )

    assert result.exit_code != 0
    assert "connection failed" in result.output
