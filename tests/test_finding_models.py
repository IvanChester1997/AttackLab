from app.models.finding import Finding, Severity


def test_finding():
    finding = Finding(
        title="Exposed SSH service",
        severity=Severity.LOW,
        description="SSH is exposed on a network-accessible port.",
        port=22,
        service="ssh",
        product="OpenSSH",
        version="9.2p1",
        remediation="Restrict SSH access to trusted networks.",
    )

    assert finding.title == "Exposed SSH service"
    assert finding.severity == Severity.LOW
    assert finding.port == 22
    assert finding.service == "ssh"
    assert finding.product == "OpenSSH"
    assert finding.version == "9.2p1"
    assert finding.cve is None
    assert finding.remediation == "Restrict SSH access to trusted networks."


def test_finding_optional_fields():
    finding = Finding(
        title="HTTP service detected",
        severity=Severity.INFO,
        description="An HTTP service was detected.",
    )

    assert finding.port is None
    assert finding.service is None
    assert finding.product is None
    assert finding.version is None
    assert finding.cve is None
    assert finding.remediation is None
