from pydantic import BaseModel

from app.models.finding import Finding, Severity
from app.models.linux_audit import LinuxAuditResult
from app.models.port import ScanResult


class ReportSummary(BaseModel):
    total_ports: int
    total_findings: int
    risk_score: int = 0
    risk_level: str = "low"
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class SecurityReport(BaseModel):
    target: str
    scan: ScanResult
    linux_audit: LinuxAuditResult | None = None
    findings: list[Finding]
    summary: ReportSummary
