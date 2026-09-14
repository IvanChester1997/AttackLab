from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.config import DB_PATH
from app.database.scan_repository import ScanRepository
from app.models.report import SecurityReport
from app.services.assessment_service import AssessmentService


router = APIRouter(prefix="/api/v1")


class AssessmentRequest(BaseModel):
    target: str
    ports: str = "22,80,443"
    username: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    key_file: str | None = None


class AssessmentResponse(BaseModel):
    id: int
    report: SecurityReport


def get_repository() -> ScanRepository:
    return ScanRepository(DB_PATH)


@router.post("/assessments", response_model=AssessmentResponse)
async def create_assessment(request: AssessmentRequest) -> AssessmentResponse:
    report = AssessmentService.run(
        target=request.target,
        ports=request.ports,
        username=request.username,
        ssh_port=request.ssh_port,
        key_file=request.key_file,
    )

    repository = get_repository()
    scan_id = await repository.save_report(report)

    return AssessmentResponse(
        id=scan_id,
        report=report,
    )


@router.get("/scans")
async def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
):
    repository = get_repository()
    history = await repository.list_history(limit=limit)

    return [
        {
            "id": item.id,
            "target": item.target,
            "status": item.status,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "total_findings": item.total_findings,
        }
        for item in history
    ]


@router.get("/scans/{scan_id}", response_model=AssessmentResponse)
async def get_scan(scan_id: int) -> AssessmentResponse:
    repository = get_repository()
    item = await repository.get_report(scan_id)

    if item is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    return AssessmentResponse(
        id=item.id,
        report=item.report,
    )
