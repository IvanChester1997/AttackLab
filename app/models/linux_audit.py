from dataclasses import dataclass


@dataclass
class LinuxAuditResult:
    hostname: str
    os: dict
