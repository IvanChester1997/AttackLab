from dataclasses import dataclass
from pathlib import Path

import aiosqlite

from app.models.port import ScanResult
from app.models.report import ReportSummary, SecurityReport
from app.services.target_parser import TargetParser

CREATE_SCAN_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    total_findings INTEGER NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    report_json TEXT NOT NULL,
    error_message TEXT
);
"""


@dataclass(frozen=True)
class ScanHistory:
    id: int
    target: str
    status: str
    risk_score: int
    risk_level: str
    total_findings: int
    report: SecurityReport
    error_message: str | None = None


class ScanRepository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    async def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(CREATE_SCAN_HISTORY_TABLE)

            columns = await db.execute_fetchall("PRAGMA table_info(scan_history)")
            column_names = {column[1] for column in columns}

            if "error_message" not in column_names:
                await db.execute(
                    "ALTER TABLE scan_history ADD COLUMN error_message TEXT"
                )

            await db.commit()

    async def create_scan(self, target: str) -> int:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        placeholder_report = SecurityReport(
            target=target,
            scan=ScanResult(target=target, ports=[]),
            linux_audit=None,
            findings=[],
            summary=ReportSummary(
                total_ports=0,
                total_findings=0,
                risk_score=0,
                risk_level="low",
            ),
        )

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO scan_history (
                    target,
                    target_type,
                    status,
                    risk_score,
                    risk_level,
                    total_findings,
                    completed_at,
                    report_json,
                    error_message
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)
                """,
                (
                    target,
                    TargetParser.parse(target).value,
                    "pending",
                    0,
                    "low",
                    0,
                    placeholder_report.model_dump_json(),
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def update_status(
        self,
        scan_id: int,
        status: str,
        error_message: str | None = None,
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE scan_history
                SET status = ?,
                    error_message = ?,
                    completed_at = CASE
                        WHEN ? IN ('completed', 'failed')
                        THEN CURRENT_TIMESTAMP
                        ELSE completed_at
                    END
                WHERE id = ?
                """,
                (status, error_message, status, scan_id),
            )
            await db.commit()

    async def complete_scan(
        self,
        scan_id: int,
        report: SecurityReport,
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE scan_history
                SET status = ?,
                    risk_score = ?,
                    risk_level = ?,
                    total_findings = ?,
                    completed_at = CURRENT_TIMESTAMP,
                    report_json = ?,
                    error_message = NULL
                WHERE id = ?
                """,
                (
                    "completed",
                    report.summary.risk_score,
                    report.summary.risk_level,
                    report.summary.total_findings,
                    report.model_dump_json(),
                    scan_id,
                ),
            )
            await db.commit()

    async def save_report(self, report: SecurityReport) -> int:
        scan_id = await self.create_scan(report.target)
        await self.complete_scan(scan_id, report)
        return scan_id

    async def get_report(self, scan_id: int) -> ScanHistory | None:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT
                    id,
                    target,
                    status,
                    risk_score,
                    risk_level,
                    total_findings,
                    report_json,
                    error_message
                FROM scan_history
                WHERE id = ?
                """,
                (scan_id,),
            )
            row = await cursor.fetchone()

        if row is None:
            return None

        return ScanHistory(
            id=row[0],
            target=row[1],
            status=row[2],
            risk_score=row[3],
            risk_level=row[4],
            total_findings=row[5],
            report=SecurityReport.model_validate_json(row[6]),
            error_message=row[7],
        )

    async def list_history(self, limit: int = 50) -> list[ScanHistory]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT
                    id,
                    target,
                    status,
                    risk_score,
                    risk_level,
                    total_findings,
                    report_json,
                    error_message
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()

        return [
            ScanHistory(
                id=row[0],
                target=row[1],
                status=row[2],
                risk_score=row[3],
                risk_level=row[4],
                total_findings=row[5],
                report=SecurityReport.model_validate_json(row[6]),
                error_message=row[7],
            )
            for row in rows
        ]
