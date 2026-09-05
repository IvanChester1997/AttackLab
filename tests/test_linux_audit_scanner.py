from unittest.mock import Mock

from app.scanners.linux_audit_scanner import LinuxAuditScanner


def test_get_hostname():
    connector = Mock()

    connector.execute.return_value = "attacklab"

    scanner = LinuxAuditScanner(connector)

    assert scanner.get_hostname() == "attacklab"

    connector.execute.assert_called_once_with(
        "hostname"
    )


def test_get_os_release():
    connector = Mock()

    connector.execute.return_value = """
NAME="Ubuntu"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.5 LTS"
""".strip()

    scanner = LinuxAuditScanner(connector)

    result = scanner.get_os_release()

    assert result["name"] == "Ubuntu"
    assert result["id"] == "ubuntu"
    assert result["version_id"] == "22.04"
    assert result["pretty_name"] == "Ubuntu 22.04.5 LTS"

    connector.execute.assert_called_once_with(
        "cat /etc/os-release"
    )


def test_run_audit():
    connector = Mock()

    connector.execute.side_effect = [
        "server01",
        """
NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 LTS"
""".strip(),
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert result.hostname == "server01"
    assert result.os["id"] == "ubuntu"
    assert result.os["pretty_name"] == "Ubuntu 22.04 LTS"
