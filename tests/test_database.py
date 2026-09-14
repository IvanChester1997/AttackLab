import asyncio

import aiosqlite

from app.database import db
from app.database.scan_repository import ScanRepository
from tests.test_api import make_report


def test_init_db_creates_required_tables(tmp_path, monkeypatch):
    db_path = tmp_path / "attacklab.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)

    asyncio.run(db.init_db())

    async def read_tables():
        async with aiosqlite.connect(db_path) as connection:
            cursor = await connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                ORDER BY name
                """
            )
            return [row[0] for row in await cursor.fetchall()]

    tables = asyncio.run(read_tables())

    assert "scans" in tables
    assert "scan_history" in tables


def test_create_scan_lifecycle(tmp_path):
    import asyncio

    repository = ScanRepository(tmp_path / "attacklab.db")
    asyncio.run(repository.init())

    scan_id = asyncio.run(repository.create_scan("10.0.0.10"))
    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.id == scan_id
    assert scan.target == "10.0.0.10"
    assert scan.status == "pending"
    assert scan.error_message is None


def test_complete_scan_updates_existing_scan(tmp_path):
    import asyncio

    repository = ScanRepository(tmp_path / "attacklab.db")
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.11"))

    report = make_report("10.0.0.11")
    asyncio.run(repository.complete_scan(scan_id, report))

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.id == scan_id
    assert scan.status == "completed"
    assert scan.report.target == "10.0.0.11"
    assert scan.error_message is None


def test_update_status_marks_scan_failed(tmp_path):
    import asyncio

    repository = ScanRepository(tmp_path / "attacklab.db")
    asyncio.run(repository.init())
    scan_id = asyncio.run(repository.create_scan("10.0.0.12"))

    asyncio.run(
        repository.update_status(
            scan_id,
            "failed",
            "Nmap execution failed",
        )
    )

    scan = asyncio.run(repository.get_report(scan_id))

    assert scan is not None
    assert scan.status == "failed"
    assert scan.error_message == "Nmap execution failed"
