from app.models.linux_audit import LinuxAuditResult


def test_linux_audit_result():
    result = LinuxAuditResult(
        hostname="server01",
        os={
            "id": "ubuntu",
            "pretty_name": "Ubuntu 22.04 LTS",
        },
        users=[],
        interactive_users=[],
        uid_zero_accounts=[],
        service_accounts=[],
        findings=[],
    )

    assert result.hostname == "server01"
    assert result.os["id"] == "ubuntu"


def test_linux_audit_result_extended():
    result = LinuxAuditResult(
        hostname="server01",
        os={"id": "ubuntu"},
        users=[],
        interactive_users=[],
        uid_zero_accounts=[],
        service_accounts=[],
        findings=[],
    )

    assert result.hostname == "server01"
    assert result.os["id"] == "ubuntu"
    assert result.findings == []
