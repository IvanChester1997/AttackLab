import asyncio
from pathlib import Path

from app.database.scan_repository import ScanRepository
from app.services.assessment_service import AssessmentService


class AssessmentJobService:
    @staticmethod
    async def run(
        repository: ScanRepository,
        scan_id: int,
        target: str,
        ports: str = "22,80,443",
        username: str | None = None,
        ssh_port: int = 22,
        key_file: str | Path | None = None,
    ) -> None:
        await repository.update_status(scan_id, "running")

        try:
            report = await asyncio.to_thread(
                AssessmentService.run,
                target=target,
                ports=ports,
                username=username,
                ssh_port=ssh_port,
                key_file=key_file,
            )
            await repository.complete_scan(scan_id, report)
        except Exception as exc:
            await repository.update_status(scan_id, "failed", str(exc))
