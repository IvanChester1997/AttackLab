from app.scanners.nmap_scanner import NmapScanner


def test_discover_returns_string():
    result = NmapScanner.discover("127.0.0.1")

    assert isinstance(result, str)
    assert "Nmap" in result
