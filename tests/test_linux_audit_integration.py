import pytest

from app.connectors.ssh import SSHConnector
from app.scanners.linux_audit_scanner import LinuxAuditScanner

pytestmark = pytest.mark.integration


def test_linux_audit_hostname():
    connector = SSHConnector(
        host="127.0.0.1",
        username="root",
        port=2222,
        key_file="~/.ssh/id_ed25519",
    )

    scanner = LinuxAuditScanner(connector)

    hostname = scanner.get_hostname()

    assert hostname
    assert isinstance(hostname, str)
