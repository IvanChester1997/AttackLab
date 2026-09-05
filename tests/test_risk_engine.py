from app.models.finding import Severity
from app.models.port import PortResult, ScanResult
from app.models.service import ServiceInfo
from app.services.risk_engine import RiskEngine


def test_risk_engine_creates_finding_for_exposed_service():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service=ServiceInfo(
                    name="ssh",
                    product="OpenSSH",
                    version="9.2p1",
                ),
            )
        ],
    )

    findings = RiskEngine.analyze(scan_result)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Exposed ssh service"
    assert finding.severity == Severity.LOW
    assert finding.port == 22
    assert finding.service == "ssh"
    assert finding.product == "OpenSSH"
    assert finding.version == "9.2p1"
    assert finding.remediation is not None


def test_telnet_gets_high_severity():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=23,
                state="open",
                service=ServiceInfo(name="telnet"),
            )
        ],
    )

    findings = RiskEngine.analyze(scan_result)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].service == "telnet"
    assert findings[0].remediation == (
        "Disable Telnet and use SSH instead."
    )


def test_ftp_gets_medium_severity():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=21,
                state="open",
                service=ServiceInfo(name="ftp"),
            )
        ],
    )

    findings = RiskEngine.analyze(scan_result)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_http_gets_low_severity():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=80,
                state="open",
                service=ServiceInfo(name="http"),
            )
        ],
    )

    findings = RiskEngine.analyze(scan_result)

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_unknown_service_gets_info_severity():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=9000,
                state="open",
                service=ServiceInfo(name="custom-service"),
            )
        ],
    )

    findings = RiskEngine.analyze(scan_result)

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].remediation is None


def test_risk_engine_ignores_ports_without_service():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=8080,
                state="open",
                service=None,
            )
        ],
    )

    findings = RiskEngine.analyze(scan_result)

    assert findings == []
