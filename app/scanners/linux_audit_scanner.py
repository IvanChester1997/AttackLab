from app.connectors.ssh import SSHConnector
from app.models.linux_audit import LinuxAuditResult
from app.models.linux_user import LinuxUser


class LinuxAuditScanner:
    def __init__(self, connector: SSHConnector):
        self.connector = connector

    def get_hostname(self) -> str:
        return self.connector.execute("hostname")

    def get_os_release(self) -> dict:
        content = self.connector.execute("cat /etc/os-release")

        result = {}

        for line in content.splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            result[key.lower()] = value.strip('"')

        return result

    def get_users(self) -> list[LinuxUser]:
        content = self.connector.execute("cat /etc/passwd")

        users = []

        for line in content.splitlines():
            parts = line.split(":")

            if len(parts) < 7:
                continue

            users.append(
                LinuxUser(
                    username=parts[0],
                    uid=int(parts[2]),
                    gid=int(parts[3]),
                    home=parts[5],
                    shell=parts[6],
                )
            )

        return users

    def get_interactive_users(
        self,
        users: list[LinuxUser] | None = None,
    ) -> list[LinuxUser]:
        users = users or self.get_users()

        non_interactive_shells = {
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/bin/false",
        }

        return [user for user in users if user.shell not in non_interactive_shells]

    def get_uid_zero_accounts(
        self,
        users: list[LinuxUser] | None = None,
    ) -> list[LinuxUser]:
        users = users or self.get_users()

        return [user for user in users if user.uid == 0]

    def get_service_accounts(
        self,
        users: list[LinuxUser] | None = None,
    ) -> list[LinuxUser]:
        users = users or self.get_users()

        return [user for user in users if user.uid < 1000 and user.username != "root"]

    def detect_uid_zero_findings(
        self,
        users: list[LinuxUser] | None = None,
    ) -> list[dict]:
        users = users if users is not None else self.get_users()
        uid_zero_users = [user for user in users if user.uid == 0]

        extra_users = [user for user in uid_zero_users if user.username != "root"]

        if not extra_users:
            return []

        return [
            {
                "title": "Additional UID 0 Account",
                "severity": "high",
                "description": (
                    f"Additional UID 0 account detected: " f"{user.username}"
                ),
            }
            for user in extra_users
        ]

    def get_sshd_config(self) -> str:
        return self.connector.execute("cat /etc/ssh/sshd_config")

    def detect_ssh_root_login_findings(
        self,
        config: str | None = None,
    ) -> list[dict]:
        config = config if config is not None else self.get_sshd_config()

        if "PermitRootLogin yes" not in config:
            return []

        return [
            {
                "title": "PermitRootLogin Enabled",
                "severity": "high",
                "description": ("SSH root login is enabled"),
            }
        ]

    def detect_password_authentication_findings(
        self,
        config: str | None = None,
    ) -> list[dict]:
        config = config if config is not None else self.get_sshd_config()

        if "PasswordAuthentication yes" not in config:
            return []

        return [
            {
                "title": ("PasswordAuthentication Enabled"),
                "severity": "medium",
                "description": ("SSH password authentication " "is enabled"),
            }
        ]

    def detect_pubkey_authentication_findings(
        self,
        config: str | None = None,
    ) -> list[dict]:
        config = config if config is not None else self.get_sshd_config()

        if "PubkeyAuthentication no" not in config:
            return []

        return [
            {
                "title": "PubkeyAuthentication Disabled",
                "severity": "medium",
                "description": "SSH public key authentication is disabled",
            }
        ]

    def run_ssh_audit(self) -> list[dict]:
        config = self.get_sshd_config()

        findings = []

        findings.extend(self.detect_ssh_root_login_findings(config))
        findings.extend(self.detect_password_authentication_findings(config))
        findings.extend(self.detect_pubkey_authentication_findings(config))

        return findings

    def run_audit(self) -> LinuxAuditResult:
        hostname = self.get_hostname()
        os_info = self.get_os_release()

        users = self.get_users()

        interactive_users = self.get_interactive_users(users)
        uid_zero_accounts = self.get_uid_zero_accounts(users)
        service_accounts = self.get_service_accounts(users)

        findings = []

        findings.extend(self.detect_uid_zero_findings(users))
        findings.extend(self.run_ssh_audit())

        return LinuxAuditResult(
            hostname=hostname,
            os=os_info,
            users=users,
            interactive_users=interactive_users,
            uid_zero_accounts=uid_zero_accounts,
            service_accounts=service_accounts,
            findings=findings,
        )
