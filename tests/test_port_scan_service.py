from unittest.mock import patch

from app.models.port import PortResult, ScanResult
from app.services.port_scan_service import PortScanService


def test_scan_delegates_to_port_scanner():
    expected = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
            )
        ],
    )

    with patch(
        "app.services.port_scan_service.PortScanner.scan",
        return_value=expected,
    ) as mock_scan:
        result = PortScanService.scan("127.0.0.1")

    mock_scan.assert_called_once_with("127.0.0.1", "22,80,443")
    assert result == expected


def test_scan_passes_custom_ports():
    expected = ScanResult(
        target="127.0.0.1",
        ports=[],
    )

    with patch(
        "app.services.port_scan_service.PortScanner.scan",
        return_value=expected,
    ) as mock_scan:
        result = PortScanService.scan(
            "127.0.0.1",
            "1-1000",
        )

    mock_scan.assert_called_once_with(
        "127.0.0.1",
        "1-1000",
    )
    assert result == expected
