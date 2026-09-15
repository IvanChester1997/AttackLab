import asyncio
import json

import aiosqlite
import pytest

from app.database.scan_repository import ScanRepository
from app.models.port import ScanResult
from app.models.report import ReportSummary, SecurityReport


@pytest.fixture
def report():
    return SecurityReport(
        target="127.0.0.1",
        scan=ScanResult(
            target="127.0.0.1",
            ports=[],
        ),
        findings=[],
        summary=ReportSummary(
            total_ports=0,
            total_findings=0,
            risk_score=0,
            risk_level="low",
        ),
    )


def test_save_report_persists_security_report(tmp_path, report):
    asyncio.run(_test_save_report_persists_security_report(tmp_path, report))


async def _test_save_report_persists_security_report(tmp_path, report):
    db_path = tmp_path / "test.db"
    repository = ScanRepository(db_path)

    await repository.init()

    scan_id = await repository.save_report(report)

    assert scan_id == 1

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            """
            SELECT target, target_type, status, risk_score,
                   risk_level, total_findings, report_json
            FROM scan_history
            WHERE id = ?
            """,
            (scan_id,),
        )
        row = await cursor.fetchone()

    assert row is not None
    assert row[0] == "127.0.0.1"
    assert row[1] == "host"
    assert row[2] == "completed"
    assert row[3] == 0
    assert row[4] == "low"
    assert row[5] == 0

    stored_report = json.loads(row[6])
    assert stored_report["target"] == "127.0.0.1"
    assert stored_report["summary"]["risk_level"] == "low"


def test_create_scan_persists_network_target_type(tmp_path):
    asyncio.run(
        _test_create_scan_persists_target_type(tmp_path, "192.168.1.0/24", "network")
    )


def test_create_scan_persists_hostname_target_type(tmp_path):
    asyncio.run(
        _test_create_scan_persists_target_type(tmp_path, "scanme.nmap.org", "hostname")
    )


async def _test_create_scan_persists_target_type(
    tmp_path,
    target: str,
    expected_type: str,
):
    db_path = tmp_path / "test.db"
    repository = ScanRepository(db_path)

    await repository.init()
    scan_id = await repository.create_scan(target)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "SELECT target, target_type, status FROM scan_history WHERE id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()

    assert row == (target, expected_type, "pending")


def test_get_report_returns_saved_report(tmp_path, report):
    asyncio.run(_test_get_report_returns_saved_report(tmp_path, report))


async def _test_get_report_returns_saved_report(tmp_path, report):
    db_path = tmp_path / "test.db"
    repository = ScanRepository(db_path)

    await repository.init()
    scan_id = await repository.save_report(report)

    loaded = await repository.get_report(scan_id)

    assert loaded is not None
    assert loaded.id == scan_id
    assert loaded.target == "127.0.0.1"
    assert loaded.status == "completed"
    assert loaded.risk_score == 0
    assert loaded.risk_level == "low"
    assert loaded.total_findings == 0
    assert loaded.report.target == "127.0.0.1"


def test_get_report_returns_none_for_unknown_id(tmp_path):
    asyncio.run(_test_get_report_returns_none_for_unknown_id(tmp_path))


async def _test_get_report_returns_none_for_unknown_id(tmp_path):
    repository = ScanRepository(tmp_path / "test.db")

    await repository.init()

    result = await repository.get_report(999)

    assert result is None


def test_list_history_returns_latest_first(tmp_path):
    asyncio.run(_test_list_history_returns_latest_first(tmp_path))


async def _test_list_history_returns_latest_first(tmp_path):
    db_path = tmp_path / "test.db"
    repository = ScanRepository(db_path)

    first_report = SecurityReport(
        target="10.0.0.1",
        scan=ScanResult(target="10.0.0.1", ports=[]),
        findings=[],
        summary=ReportSummary(
            total_ports=0,
            total_findings=0,
        ),
    )
    second_report = SecurityReport(
        target="10.0.0.2",
        scan=ScanResult(target="10.0.0.2", ports=[]),
        findings=[],
        summary=ReportSummary(
            total_ports=0,
            total_findings=0,
        ),
    )

    await repository.init()
    first_id = await repository.save_report(first_report)
    second_id = await repository.save_report(second_report)

    history = await repository.list_history()

    assert [item.id for item in history] == [second_id, first_id]
    assert [item.target for item in history] == [
        "10.0.0.2",
        "10.0.0.1",
    ]
