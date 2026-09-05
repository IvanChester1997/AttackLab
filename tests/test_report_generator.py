from app.models.port import PortResult, ScanResult
from app.models.service import ServiceInfo
from app.services.report_generator import ReportGenerator


def test_report_contains_scan_and_findings():
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
            ),
            PortResult(
                port=23,
                protocol="tcp",
                state="open",
                service=ServiceInfo(
                    name="telnet",
                ),
            ),
        ],
    )

    report = ReportGenerator.generate(scan_result)

    assert report.target == "127.0.0.1"
    assert len(report.scan.ports) == 2
    assert len(report.findings) == 2


def test_report_summary_counts_severities():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service=ServiceInfo(name="ssh"),
            ),
            PortResult(
                port=23,
                protocol="tcp",
                state="open",
                service=ServiceInfo(name="telnet"),
            ),
            PortResult(
                port=80,
                protocol="tcp",
                state="open",
                service=ServiceInfo(name="http"),
            ),
            PortResult(
                port=21,
                protocol="tcp",
                state="open",
                service=ServiceInfo(name="ftp"),
            ),
            PortResult(
                port=9999,
                protocol="tcp",
                state="open",
                service=ServiceInfo(name="unknown-service"),
            ),
        ],
    )

    report = ReportGenerator.generate(scan_result)

    assert report.summary.total_ports == 5
    assert report.summary.total_findings == 5
    assert report.summary.high == 1
    assert report.summary.medium == 1
    assert report.summary.low == 2
    assert report.summary.info == 1
    assert report.summary.critical == 0


def test_report_handles_empty_scan():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[],
    )

    report = ReportGenerator.generate(scan_result)

    assert report.target == "127.0.0.1"
    assert report.findings == []
    assert report.summary.total_ports == 0
    assert report.summary.total_findings == 0
    assert report.summary.critical == 0
    assert report.summary.high == 0
    assert report.summary.medium == 0
    assert report.summary.low == 0
    assert report.summary.info == 0


def test_report_generates_json():
    scan_result = ScanResult(
        target="127.0.0.1",
        ports=[
            PortResult(
                port=23,
                protocol="tcp",
                state="open",
                service=ServiceInfo(name="telnet"),
            ),
        ],
    )

    report = ReportGenerator.generate(scan_result)
    output = ReportGenerator.generate_json(report)

    assert '"target": "127.0.0.1"' in output
    assert '"total_findings": 1' in output
    assert '"severity": "high"' in output
    assert '"service": "telnet"' in output
