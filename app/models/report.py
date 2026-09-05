from pydantic import BaseModel

from app.models.finding import Finding, Severity
from app.models.port import ScanResult


class ReportSummary(BaseModel):
    total_ports: int
    total_findings: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class SecurityReport(BaseModel):
    target: str
    scan: ScanResult
    findings: list[Finding]
    summary: ReportSummary
