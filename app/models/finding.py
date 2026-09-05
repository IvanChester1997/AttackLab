from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    port: int | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cve: str | None = None
    remediation: str | None = None
