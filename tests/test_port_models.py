from app.models.port import PortResult, ScanResult


def test_port_result():
    result = PortResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
    )

    assert result.port == 22
    assert result.protocol == "tcp"
    assert result.state == "open"
    assert result.service == "ssh"


def test_scan_result():
    result = ScanResult(
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

    assert result.target == "127.0.0.1"
    assert len(result.ports) == 1
    assert result.ports[0].port == 22
