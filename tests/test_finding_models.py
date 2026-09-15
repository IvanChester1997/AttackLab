from app.models.finding import CvssInfo, Finding, FindingEvidence, Severity


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
    assert finding.cvss is None
    assert finding.evidence == []


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
    assert finding.cvss is None
    assert finding.evidence == []


def test_finding_supports_cvss_and_evidence():
    finding = Finding(
        title="OpenSSH vulnerability",
        severity=Severity.HIGH,
        description="A vulnerable OpenSSH version was identified.",
        cve="CVE-2024-6387",
        cvss=CvssInfo(
            version="3.1",
            score=8.1,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            source="nvd@nist.gov",
        ),
        evidence=[
            FindingEvidence(
                source="nvd",
                check="cve_match",
                details={"cpe": ("cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*")},
            )
        ],
    )

    assert finding.cvss is not None
    assert finding.cvss.version == "3.1"
    assert finding.cvss.score == 8.1
    assert finding.cvss.vector.startswith("CVSS:3.1/")
    assert finding.evidence[0].source == "nvd"
    assert finding.evidence[0].check == "cve_match"
