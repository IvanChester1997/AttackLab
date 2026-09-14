import asyncio

from enum import Enum

from fastapi import APIRouter, BackgroundTasks, HTTPException, Path as FastAPIPath, Query
from pydantic import BaseModel, Field, field_validator

from app.core.config import DB_PATH
from app.database.scan_repository import ScanRepository
from app.models.report import SecurityReport
from app.services.assessment_service import AssessmentService


router = APIRouter(prefix="/api/v1")


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AssessmentRequest(BaseModel):
    target: str = Field(min_length=1)
    ports: str = Field(default="22,80,443", min_length=1)
    username: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    key_file: str | None = None

    @field_validator("target", "ports")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
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


async def run_assessment(
    scan_id: int,
    request: AssessmentRequest,
) -> None:
    repository = get_repository()

    await repository.update_status(scan_id, "running")

    try:
        report = await asyncio.to_thread(
            AssessmentService.run,
            target=request.target,
            ports=request.ports,
            username=request.username,
            ssh_port=request.ssh_port,
            key_file=request.key_file,
        )

        await repository.complete_scan(scan_id, report)
    except Exception as exc:
        await repository.update_status(
            scan_id,
            "failed",
            str(exc),
        )


@router.post(
    "/assessments",
    response_model=AssessmentResponse,
    status_code=202,
)
async def create_assessment(
    request: AssessmentRequest,
    background_tasks: BackgroundTasks,
) -> AssessmentResponse:
    repository = get_repository()
    scan_id = await repository.create_scan(request.target)

    background_tasks.add_task(
        run_assessment,
        scan_id,
        request,
    )

    return AssessmentResponse(
        id=scan_id,
        status=AssessmentStatus.PENDING,
    )


@router.get("/scans", response_model=list[ScanSummaryResponse])
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
