import json
from dataclasses import dataclass
from pathlib import Path

import aiosqlite

from app.models.report import SecurityReport


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
    report_json TEXT NOT NULL
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


class ScanRepository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    async def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(CREATE_SCAN_HISTORY_TABLE)
            await db.commit()

    async def save_report(self, report: SecurityReport) -> int:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

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
                    report_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.target,
                    "host",
                    "completed",
                    report.summary.risk_score,
                    report.summary.risk_level,
                    report.summary.total_findings,
                    report.model_dump_json(),
                ),
            )
            await db.commit()

            return cursor.lastrowid

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
                    report_json
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
                    report_json
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
            )
            for row in rows
        ]
