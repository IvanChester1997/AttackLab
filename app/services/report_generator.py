import json

from app.models.finding import Severity
from app.models.port import ScanResult
from app.models.report import ReportSummary, SecurityReport
from app.services.risk_engine import RiskEngine


class ReportGenerator:
    @staticmethod
    def generate(scan_result: ScanResult) -> SecurityReport:
        findings = RiskEngine.analyze(scan_result)

        risk_score = RiskEngine.calculate_score(findings)
        risk_level = RiskEngine.calculate_level(risk_score)

        summary = ReportSummary(
            total_ports=len(scan_result.ports),
            total_findings=len(findings),
            risk_score=risk_score,
            risk_level=risk_level,
            critical=sum(
                finding.severity == Severity.CRITICAL
                for finding in findings
            ),
            high=sum(
                finding.severity == Severity.HIGH
                for finding in findings
            ),
            medium=sum(
                finding.severity == Severity.MEDIUM
                for finding in findings
            ),
            low=sum(
                finding.severity == Severity.LOW
                for finding in findings
            ),
            info=sum(
                finding.severity == Severity.INFO
                for finding in findings
            ),
        )

        return SecurityReport(
            target=scan_result.target,
            scan=scan_result,
            findings=findings,
            summary=summary,
        )

    @staticmethod
    def generate_json(report: SecurityReport) -> str:
        return json.dumps(
            report.model_dump(mode="json"),
            indent=2,
        )
