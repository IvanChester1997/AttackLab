from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CvssInfo(BaseModel):
    version: str
    score: float = Field(ge=0, le=10)
    vector: str | None = None
    source: str | None = None


class FindingEvidence(BaseModel):
    source: str
    check: str | None = None
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


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
    cvss: CvssInfo | None = None
    evidence: list[FindingEvidence] = Field(default_factory=list)
