import asyncio

import aiosqlite

from app.database import db


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
