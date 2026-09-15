from enum import Enum

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi import Path as FastAPIPath
from pydantic import BaseModel, Field, field_validator

from app.core.config import DB_PATH
from app.database.scan_repository import ScanRepository
from app.models.report import SecurityReport
from app.models.target import TargetType
from app.services.assessment_job_service import AssessmentJobService
from app.services.target_parser import TargetParser

router = APIRouter(prefix="/api/v1")


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AssessmentRequest(BaseModel):
    target: str = Field(
        min_length=1,
        description="IPv4/IPv6 host, CIDR network, or hostname.",
        examples=["127.0.0.1"],
    )
    ports: str = Field(
        default="22,80,443",
        min_length=1,
        description="Ports or port ranges passed to Nmap.",
        examples=["22,80,443"],
    )
    username: str | None = Field(
        default=None,
        description="SSH username for optional Linux audit.",
        examples=["root"],
    )
    ssh_port: int = Field(
        default=22,
        ge=1,
        le=65535,
        description="SSH port used for Linux audit.",
        examples=[22],
    )
    key_file: str | None = Field(
        default=None,
        description="Path to the SSH private key used for Linux audit.",
        examples=["~/.ssh/id_ed25519"],
    )

    @field_validator("target", "ports")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if TargetParser.parse(value) == TargetType.INVALID:
            raise ValueError("invalid target")
        return value


class AssessmentResponse(BaseModel):
    id: int
    status: AssessmentStatus
    report: SecurityReport | None = None
    error_message: str | None = None


class ScanSummaryResponse(BaseModel):
    id: int
    target: str
    status: AssessmentStatus
    risk_score: int
    risk_level: str
    total_findings: int
    error_message: str | None = None


def get_repository() -> ScanRepository:
    return ScanRepository(DB_PATH)


@router.post(
    "/assessments",
    response_model=AssessmentResponse,
    status_code=202,
    summary="Start a security assessment",
    description=(
        "Create a background security assessment. The API returns immediately "
        "with a pending assessment ID; poll the scan endpoint for completion."
    ),
    response_description="Assessment accepted and queued for background execution.",
)
async def create_assessment(
    request: AssessmentRequest,
    background_tasks: BackgroundTasks,
) -> AssessmentResponse:
    repository = get_repository()
    scan_id = await repository.create_scan(request.target)

    background_tasks.add_task(
        AssessmentJobService.run,
        repository,
        scan_id,
        request.target,
        request.ports,
        request.username,
        request.ssh_port,
        request.key_file,
    )

    return AssessmentResponse(
        id=scan_id,
        status=AssessmentStatus.PENDING,
    )


@router.get(
    "/scans",
    response_model=list[ScanSummaryResponse],
    summary="List scan history",
    description="Return recent assessment summaries ordered from newest to oldest.",
)
async def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
):
    repository = get_repository()
    history = await repository.list_history(limit=limit)

    return [
        ScanSummaryResponse(
            id=item.id,
            target=item.target,
            status=AssessmentStatus(item.status),
            risk_score=item.risk_score,
            risk_level=item.risk_level,
            total_findings=item.total_findings,
            error_message=item.error_message,
        )
        for item in history
    ]


@router.get(
    "/scans/{scan_id}",
    response_model=AssessmentResponse,
    summary="Get assessment result",
    description=("Return the lifecycle state and report for a specific assessment."),
)
async def get_scan(
    scan_id: int = FastAPIPath(..., ge=1),
) -> AssessmentResponse:
    repository = get_repository()
    item = await repository.get_report(scan_id)

    if item is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    return AssessmentResponse(
        id=item.id,
        status=AssessmentStatus(item.status),
        report=item.report if item.status == "completed" else None,
        error_message=item.error_message,
    )
