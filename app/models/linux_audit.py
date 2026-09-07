from dataclasses import dataclass

from app.models.finding import Finding


@dataclass
class LinuxAuditResult:
    hostname: str
    os: dict

    users: list
    interactive_users: list
    uid_zero_accounts: list
    service_accounts: list

    findings: list[Finding]
