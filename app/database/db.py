import aiosqlite

from app.core.config import DB_PATH
from app.database.scan_repository import CREATE_SCAN_HISTORY_TABLE, ScanRepository

CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
"""


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_SCANS_TABLE)
        await db.execute(CREATE_SCAN_HISTORY_TABLE)
        await db.commit()

    await ScanRepository(DB_PATH).init()
