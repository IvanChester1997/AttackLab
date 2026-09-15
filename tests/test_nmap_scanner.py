from unittest.mock import Mock, patch

from app.scanners.nmap_scanner import NmapScanner


def test_discover_returns_string():
    completed = Mock(stdout="Nmap scan report for 127.0.0.1\n")

    with patch(
        "app.scanners.nmap_scanner.subprocess.run",
        return_value=completed,
    ):
        result = NmapScanner.discover("127.0.0.1")

    assert isinstance(result, str)
    assert "Nmap" in result
