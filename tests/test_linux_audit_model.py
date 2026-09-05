from app.models.linux_audit import LinuxAuditResult


def test_linux_audit_result():
    result = LinuxAuditResult(
        hostname="server01",
        os={
            "id": "ubuntu",
            "pretty_name": "Ubuntu 22.04 LTS",
        },
    )

    assert result.hostname == "server01"
    assert result.os["id"] == "ubuntu"
