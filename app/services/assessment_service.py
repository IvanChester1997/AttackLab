from pathlib import Path

from app.connectors.ssh import SSHConnector
from app.models.linux_audit import LinuxAuditResult
from app.models.port import ScanResult
from app.models.report import SecurityReport
from app.scanners.linux_audit_scanner import LinuxAuditScanner
from app.services.port_scan_service import PortScanService
from app.services.report_generator import ReportGenerator


class AssessmentService:
    @staticmethod
    def run(
        target: str,
        ports: str = "22,80,443",
        username: str | None = None,
        ssh_port: int = 22,
        key_file: str | Path | None = None,
    ) -> SecurityReport:
        scan_result: ScanResult = PortScanService.scan(
            target,
            ports,
        )

        linux_audit: LinuxAuditResult | None = None

        if username is not None:
            connector = SSHConnector(
                host=target,
                username=username,
                port=ssh_port,
                key_file=key_file,
            )
            linux_audit = LinuxAuditScanner(connector).run_audit()

        return ReportGenerator.generate(
            scan_result,
            linux_audit=linux_audit,
        )
