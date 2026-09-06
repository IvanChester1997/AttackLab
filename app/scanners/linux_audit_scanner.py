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

    def get_world_writable_files(self) -> list[str]:
        command = (
            "find / "
            "-xdev "
            "\\( -path /proc -o -path /sys -o -path /dev -o -path /run \\) "
            "-prune -o "
            "-type f -perm -0002 -print "
            "2>/dev/null | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def get_suid_sgid_files(self) -> list[str]:
        command = (
            "find / "
            "-xdev "
            "\\( -path /proc -o -path /sys -o -path /dev -o -path /run \\) "
            "-prune -o "
            "-type f "
            "\\( -perm -4000 -o -perm -2000 \\) "
            "-print "
            "2>/dev/null | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_suid_sgid_findings(
        self,
        files: list[str] | None = None,
    ) -> list[dict]:
        files = files if files is not None else self.get_suid_sgid_files()

        if not files:
            return []

        return [
            {
                "title": "SUID/SGID File",
                "severity": "medium",
                "description": (f"SUID/SGID file detected: {file_path}"),
            }
            for file_path in files
        ]

    def get_cron_entries(self) -> list[str]:
        command = (
            "find /etc/cron.d /etc/cron.daily " "-type f 2>/dev/null | sort | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_cron_findings(
        self,
        entries: list[str] | None = None,
    ) -> list[dict]:
        entries = entries if entries is not None else self.get_cron_entries()

        if not entries:
            return []

        return [
            {
                "title": "Cron Job Detected",
                "severity": "low",
                "description": (f"Cron entry detected: {entry}"),
            }
            for entry in entries
        ]

    def get_writable_cron_files(self) -> list[str]:
        command = (
            "find /etc/cron.d /etc/cron.daily "
            "-type f "
            "\\( -perm -0002 -o -perm -0020 \\) "
            "2>/dev/null | sort | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_writable_cron_findings(
        self,
        files: list[str] | None = None,
    ) -> list[dict]:
        files = files if files is not None else self.get_writable_cron_files()

        if not files:
            return []

        return [
            {
                "title": "Writable Cron File",
                "severity": "high",
                "description": (f"Writable cron file detected: {file_path}"),
            }
            for file_path in files
        ]

    def detect_world_writable_findings(
        self,
        files: list[str] | None = None,
    ) -> list[dict]:
        files = files if files is not None else self.get_world_writable_files()

        if not files:
            return []

        return [
            {
                "title": "World-Writable File",
                "severity": "medium",
                "description": (f"World-writable file detected: {file_path}"),
            }
            for file_path in files
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
                "remediation": "Set PermitRootLogin no and use a dedicated administrative account.",
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
                "remediation": "Disable PasswordAuthentication and use SSH public key authentication.",
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
                "remediation": "Enable PubkeyAuthentication and configure authorized SSH keys.",
            }
        ]

    def detect_max_auth_tries_findings(
        self,
        config: str | None = None,
    ) -> list[dict]:
        config = config if config is not None else self.get_sshd_config()

        for line in config.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            if parts[0].lower() != "maxauthtries":
                continue

            try:
                value = int(parts[1])
            except ValueError:
                return []

            if value <= 6:
                return []

            return [
                {
                    "title": "MaxAuthTries Too High",
                    "severity": "medium",
                    "description": (
                        f"SSH MaxAuthTries is set to {value}, "
                        "which allows excessive authentication attempts"
                    ),
                    "remediation": "Set MaxAuthTries to 6 or lower.",
                }
            ]

        return []

    def run_ssh_audit(self) -> list[dict]:
        config = self.get_sshd_config()

        findings = []

        findings.extend(self.detect_ssh_root_login_findings(config))
        findings.extend(self.detect_password_authentication_findings(config))
        findings.extend(self.detect_pubkey_authentication_findings(config))
        findings.extend(self.detect_max_auth_tries_findings(config))

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

        world_writable_files = self.get_world_writable_files()
        findings.extend(self.detect_world_writable_findings(world_writable_files))

        suid_sgid_files = self.get_suid_sgid_files()

        findings.extend(self.detect_suid_sgid_findings(suid_sgid_files))

        cron_entries = self.get_cron_entries()

        findings.extend(self.detect_cron_findings(cron_entries))

        writable_cron_files = self.get_writable_cron_files()

        findings.extend(self.detect_writable_cron_findings(writable_cron_files))

        authorized_keys_files = self.get_authorized_keys_files()

        findings.extend(self.detect_authorized_keys_findings(authorized_keys_files))

        writable_authorized_keys_files = self.get_writable_authorized_keys_files()

        findings.extend(
            self.detect_writable_authorized_keys_findings(
                writable_authorized_keys_files
            )
        )

        sudoers_entries = self.get_sudoers_entries()

        findings.extend(self.detect_nopasswd_sudo_findings(sudoers_entries))

        return LinuxAuditResult(
            hostname=hostname,
            os=os_info,
            users=users,
            interactive_users=interactive_users,
            uid_zero_accounts=uid_zero_accounts,
            service_accounts=service_accounts,
            findings=findings,
        )

    def get_sudoers_entries(self) -> list[str]:
        command = (
            "(cat /etc/sudoers 2>/dev/null; "
            "cat /etc/sudoers.d/* 2>/dev/null) "
            "| grep -v '^#' "
            "| grep -v '^$' "
            "| head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_nopasswd_sudo_findings(
        self,
        entries: list[str] | None = None,
    ) -> list[dict]:
        entries = entries if entries is not None else self.get_sudoers_entries()

        findings = []

        for entry in entries:
            if "NOPASSWD:" not in entry:
                continue

            findings.append(
                {
                    "title": "NOPASSWD Sudo Rule",
                    "severity": "high",
                    "description": (f"NOPASSWD sudo rule detected: {entry}"),
                }
            )

        return findings

    def get_authorized_keys_files(self) -> list[str]:
        command = (
            "find / "
            "-xdev "
            "-type f "
            "-name authorized_keys "
            "2>/dev/null | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def get_writable_authorized_keys_files(self) -> list[str]:
        command = (
            "find / "
            "-xdev "
            "-type f "
            "-name authorized_keys "
            "\\( -perm -0020 -o -perm -0002 \\) "
            "2>/dev/null | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_writable_authorized_keys_findings(
        self,
        files: list[str] | None = None,
    ) -> list[dict]:
        files = (
            files
            if files is not None
            else self.get_writable_authorized_keys_files()
        )

        if not files:
            return []

        return [
            {
                "title": "Writable Authorized Keys File",
                "severity": "high",
                "description": (
                    f"Group/world-writable authorized_keys file detected: "
                    f"{file_path}"
                ),
            }
            for file_path in files
        ]

    def detect_authorized_keys_findings(
        self,
        files: list[str] | None = None,
    ) -> list[dict]:
        files = files if files is not None else self.get_authorized_keys_files()

        if not files:
            return []

        return [
            {
                "title": "Authorized Keys File Detected",
                "severity": "info",
                "description": (f"SSH authorized_keys file detected: {file_path}"),
            }
            for file_path in files
        ]
