from unittest.mock import patch

from typer.testing import CliRunner

from app.cli.main import app
from app.models.port import PortResult, ScanResult


runner = CliRunner()


def test_scan_command():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
            ),
            PortResult(
                port=80,
                protocol="tcp",
                state="open",
                service="http",
            ),
        ],
    )

    with patch(
        "app.cli.main.PortScanService.scan",
        return_value=result_data,
    ) as mock_scan:
        result = runner.invoke(
            app,
            ["scan", "127.0.0.1"],
        )

    assert result.exit_code == 0
    mock_scan.assert_called_once_with(
        "127.0.0.1",
        "22,80,443",
    )

    assert "127.0.0.1" in result.stdout
    assert "22" in result.stdout
    assert "ssh" in result.stdout
    assert "80" in result.stdout
    assert "http" in result.stdout


def test_scan_command_with_custom_ports():
    result_data = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=8080,
                protocol="tcp",
                state="open",
                service="http-proxy",
            ),
        ],
    )

    with patch(
        "app.cli.main.PortScanService.scan",
        return_value=result_data,
    ) as mock_scan:
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--ports",
                "1-1000",
            ],
        )

    assert result.exit_code == 0
    mock_scan.assert_called_once_with(
        "127.0.0.1",
        "1-1000",
    )

    assert "8080" in result.stdout
    assert "http-proxy" in result.stdout
