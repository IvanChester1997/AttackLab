from app.models.finding import Finding, Severity
from app.models.port import ScanResult


SERVICE_RISK_RULES = {
    "telnet": {
        "severity": Severity.HIGH,
        "description": "Telnet is an insecure plaintext remote access protocol.",
        "remediation": "Disable Telnet and use SSH instead.",
    },
    "ftp": {
        "severity": Severity.MEDIUM,
        "description": "FTP may transmit credentials and data without encryption.",
        "remediation": "Disable FTP or replace it with SFTP/FTPS.",
    },
    "ssh": {
        "severity": Severity.LOW,
        "description": "SSH is exposed on a network-accessible port.",
        "remediation": "Restrict SSH access to trusted networks and use key-based authentication.",
    },
    "http": {
        "severity": Severity.LOW,
        "description": "HTTP is exposed without transport encryption.",
        "remediation": "Use HTTPS and redirect plaintext HTTP traffic where appropriate.",
    },
}


class RiskEngine:
    SEVERITY_SCORES = {
        Severity.INFO: 0,
        Severity.LOW: 2,
        Severity.MEDIUM: 4,
        Severity.HIGH: 7,
        Severity.CRITICAL: 10,
    }

    @staticmethod
    def analyze(scan_result: ScanResult) -> list[Finding]:
        findings = []

        for port in scan_result.ports:
            if not port.service:
                continue

            service_name = port.service.name.lower()
            rule = SERVICE_RISK_RULES.get(service_name)

            if rule:
                severity = rule["severity"]
                description = rule["description"]
                remediation = rule["remediation"]
            else:
                severity = Severity.INFO
                description = (
                    f"The {port.service.name} service is exposed "
                    f"on port {port.port}/{port.protocol}."
                )
                remediation = None

            findings.append(
                Finding(
                    title=f"Exposed {port.service.name} service",
                    severity=severity,
                    description=description,
                    port=port.port,
                    service=port.service.name,
                    product=port.service.product,
                    version=port.service.version,
                    remediation=remediation,
                )
            )

        return findings

    @classmethod
    def calculate_score(cls, findings: list[Finding]) -> int:
        score = sum(
            cls.SEVERITY_SCORES[finding.severity]
            for finding in findings
        )

        return min(score, 100)

    @classmethod
    def calculate_level(cls, score: int) -> str:
        if score >= 70:
            return "critical"
        if score >= 40:
            return "high"
        if score >= 20:
            return "medium"
        return "low"
