from app.connectors.ssh import SSHConnector
from app.models.linux_audit import LinuxAuditResult


class LinuxAuditScanner:
    def __init__(self, connector: SSHConnector):
        self.connector = connector

    def get_hostname(self) -> str:
        return self.connector.execute("hostname")

    def get_os_release(self) -> dict:
        content = self.connector.execute(
            "cat /etc/os-release"
        )

        result = {}

        for line in content.splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            result[key.lower()] = value.strip('"')

        return result

    def run_audit(self) -> LinuxAuditResult:
        return LinuxAuditResult(
            hostname=self.get_hostname(),
            os=self.get_os_release(),
        )
