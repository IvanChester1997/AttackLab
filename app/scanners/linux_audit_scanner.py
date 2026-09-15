from app.connectors.ssh import SSHConnector
from app.models.finding import Finding, FindingEvidence, Severity
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

    def get_docker_group_members(self) -> list[str]:
        output = self.connector.execute("getent group docker")

        if not output.strip():
            return []

        try:
            members = output.strip().split(":")[3]
        except IndexError:
            return []

        return [member.strip() for member in members.split(",") if member.strip()]

    def detect_docker_group_findings(
        self,
        members: list[str] | None = None,
    ) -> list[Finding]:
        members = members if members is not None else self.get_docker_group_members()

        return [
            Finding(
                title="User In Docker Group",
                severity=Severity.HIGH,
                description=(
                    f"User '{member}' is a member of docker group "
                    "and may obtain root privileges."
                ),
            )
            for member in members
        ]

    def get_sudo_group_members(self) -> list[str]:
        output = self.connector.execute("getent group sudo || getent group wheel")

        if not output.strip():
            return []

        try:
            members = output.strip().split(":")[3]
        except IndexError:
            return []

        return [member.strip() for member in members.split(",") if member.strip()]

    def detect_sudo_group_findings(
        self,
        members: list[str] | None = None,
    ) -> list[Finding]:
        members = members if members is not None else self.get_sudo_group_members()

        return [
            Finding(
                title="User In Privileged Group",
                severity=Severity.MEDIUM,
                description=(
                    f"User '{member}' is a member of sudo/wheel group "
                    "and has elevated privileges."
                ),
            )
            for member in members
        ]

    def detect_uid_zero_findings(
        self,
        users: list[LinuxUser] | None = None,
    ) -> list[Finding]:
        users = users if users is not None else self.get_users()
        uid_zero_users = [user for user in users if user.uid == 0]

        extra_users = [user for user in uid_zero_users if user.username != "root"]

        if not extra_users:
            return []

        return [
            Finding(
                title="Additional UID 0 Account",
                severity=Severity.HIGH,
                description=(f"Additional UID 0 account detected: {user.username}"),
            )
            for user in extra_users
        ]

    def _collect_privilege_findings(
        self,
        users: list[LinuxUser],
    ) -> list[Finding]:
        findings = []

        findings.extend(self.detect_uid_zero_findings(users))

        docker_members = self.get_docker_group_members()
        findings.extend(self.detect_docker_group_findings(docker_members))

        sudo_members = self.get_sudo_group_members()
        findings.extend(self.detect_sudo_group_findings(sudo_members))

        return findings

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
    ) -> list[Finding]:
        files = files if files is not None else self.get_suid_sgid_files()

        if not files:
            return []

        return [
            Finding(
                title="SUID/SGID File",
                severity=Severity.MEDIUM,
                description=f"SUID/SGID file detected: {file_path}",
            )
            for file_path in files
        ]

    def _collect_filesystem_findings(self) -> list[Finding]:
        findings = []

        world_writable_files = self.get_world_writable_files()
        findings.extend(self.detect_world_writable_findings(world_writable_files))

        suid_sgid_files = self.get_suid_sgid_files()
        findings.extend(self.detect_suid_sgid_findings(suid_sgid_files))

        return findings

    def get_cron_entries(self) -> list[str]:
        command = (
            "find /etc/cron.d /etc/cron.daily -type f 2>/dev/null | sort | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_cron_findings(
        self,
        entries: list[str] | None = None,
    ) -> list[Finding]:
        entries = entries if entries is not None else self.get_cron_entries()

        if not entries:
            return []

        return [
            Finding(
                title="Cron Job Detected",
                severity=Severity.LOW,
                description=f"Cron entry detected: {entry}",
            )
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
    ) -> list[Finding]:
        files = files if files is not None else self.get_writable_cron_files()

        if not files:
            return []

        return [
            Finding(
                title="Writable Cron File",
                severity=Severity.HIGH,
                description=f"Writable cron file detected: {file_path}",
            )
            for file_path in files
        ]

    def detect_world_writable_findings(
        self,
        files: list[str] | None = None,
    ) -> list[Finding]:
        files = files if files is not None else self.get_world_writable_files()

        if not files:
            return []

        return [
            Finding(
                title="World-Writable File",
                severity=Severity.MEDIUM,
                description=f"World-writable file detected: {file_path}",
            )
            for file_path in files
        ]

    def get_sshd_config(self) -> str:
        return self.connector.execute("cat /etc/ssh/sshd_config")

    def detect_ssh_root_login_findings(
        self,
        config: str | None = None,
    ) -> list[Finding]:
        config = config if config is not None else self.get_sshd_config()

        if "PermitRootLogin yes" not in config:
            return []

        return [
            Finding(
                title="PermitRootLogin Enabled",
                severity=Severity.HIGH,
                description="SSH root login is enabled",
                remediation="Set PermitRootLogin no and use a dedicated administrative account.",
            )
        ]

    def detect_password_authentication_findings(
        self,
        config: str | None = None,
    ) -> list[Finding]:
        config = config if config is not None else self.get_sshd_config()

        if "PasswordAuthentication yes" not in config:
            return []

        return [
            Finding(
                title="PasswordAuthentication Enabled",
                severity=Severity.MEDIUM,
                description="SSH password authentication is enabled",
                remediation="Disable PasswordAuthentication and use SSH public key authentication.",
            )
        ]

    def detect_pubkey_authentication_findings(
        self,
        config: str | None = None,
    ) -> list[Finding]:
        config = config if config is not None else self.get_sshd_config()

        if "PubkeyAuthentication no" not in config:
            return []

        return [
            Finding(
                title="PubkeyAuthentication Disabled",
                severity=Severity.MEDIUM,
                description="SSH public key authentication is disabled",
                remediation="Enable PubkeyAuthentication and configure authorized SSH keys.",
            )
        ]

    def detect_max_auth_tries_findings(
        self,
        config: str | None = None,
    ) -> list[Finding]:
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
                Finding(
                    title="MaxAuthTries Too High",
                    severity=Severity.MEDIUM,
                    description=(
                        f"SSH MaxAuthTries is set to {value}, "
                        "which allows excessive authentication attempts"
                    ),
                    remediation="Set MaxAuthTries to 6 or lower.",
                )
            ]

        return []

    def run_ssh_audit(self) -> list[Finding]:
        config = self.get_sshd_config()

        findings = []

        findings.extend(self.detect_ssh_root_login_findings(config))
        findings.extend(self.detect_password_authentication_findings(config))
        findings.extend(self.detect_pubkey_authentication_findings(config))
        findings.extend(self.detect_max_auth_tries_findings(config))

        return findings

    @staticmethod
    def _add_finding_evidence(
        findings: list[Finding],
        check: str,
    ) -> list[Finding]:
        for finding in findings:
            finding.evidence.append(
                FindingEvidence(
                    source="linux_audit",
                    check=check,
                    details={
                        "observation": finding.description,
                    },
                )
            )

        return findings

    def run_audit(self) -> LinuxAuditResult:
        hostname = self.get_hostname()
        os_info = self.get_os_release()

        users = self.get_users()

        interactive_users = self.get_interactive_users(users)
        uid_zero_accounts = self.get_uid_zero_accounts(users)
        service_accounts = self.get_service_accounts(users)

        findings = []

        findings.extend(
            self._add_finding_evidence(
                self._collect_privilege_findings(users),
                "privilege_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self.run_ssh_audit(),
                "ssh_hardening",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_filesystem_findings(),
                "filesystem_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_cron_findings(),
                "cron_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_authorized_keys_findings(),
                "authorized_keys_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_password_policy_findings(),
                "password_policy_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_sudoers_findings(),
                "sudoers_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_ssh_host_key_findings(),
                "ssh_host_key_audit",
            )
        )

        findings.extend(
            self._add_finding_evidence(
                self._collect_network_findings(),
                "network_audit",
            )
        )

        return LinuxAuditResult(
            hostname=hostname,
            os=os_info,
            users=users,
            interactive_users=interactive_users,
            uid_zero_accounts=uid_zero_accounts,
            service_accounts=service_accounts,
            findings=findings,
        )

    def _collect_cron_findings(self) -> list[Finding]:
        findings = []

        cron_entries = self.get_cron_entries()
        findings.extend(self.detect_cron_findings(cron_entries))

        writable_cron_files = self.get_writable_cron_files()
        findings.extend(self.detect_writable_cron_findings(writable_cron_files))

        return findings

    def _collect_password_policy_findings(self) -> list[Finding]:
        password_policy = self.get_password_policy()
        return self.detect_password_policy_findings(password_policy)

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
    ) -> list[Finding]:
        entries = entries if entries is not None else self.get_sudoers_entries()

        findings = []

        for entry in entries:
            if "NOPASSWD:" not in entry:
                continue

            findings.append(
                Finding(
                    title="NOPASSWD Sudo Rule",
                    severity=Severity.HIGH,
                    description=f"NOPASSWD sudo rule detected: {entry}",
                )
            )

        return findings

    def _collect_sudoers_findings(self) -> list[Finding]:
        sudoers_entries = self.get_sudoers_entries()
        return self.detect_nopasswd_sudo_findings(sudoers_entries)

    def get_authorized_keys_files(self) -> list[str]:
        command = "find / -xdev -type f -name authorized_keys 2>/dev/null | head -100"

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
    ) -> list[Finding]:
        files = (
            files if files is not None else self.get_writable_authorized_keys_files()
        )

        if not files:
            return []

        return [
            Finding(
                title="Writable Authorized Keys File",
                severity=Severity.HIGH,
                description=(
                    f"Group/world-writable authorized_keys file detected: {file_path}"
                ),
            )
            for file_path in files
        ]

    def detect_authorized_keys_findings(
        self,
        files: list[str] | None = None,
    ) -> list[Finding]:
        files = files if files is not None else self.get_authorized_keys_files()

        if not files:
            return []

        return [
            Finding(
                title="Authorized Keys File Detected",
                severity=Severity.INFO,
                description=f"SSH authorized_keys file detected: {file_path}",
            )
            for file_path in files
        ]

    def _collect_authorized_keys_findings(self) -> list[Finding]:
        findings = []

        authorized_keys_files = self.get_authorized_keys_files()
        findings.extend(self.detect_authorized_keys_findings(authorized_keys_files))

        writable_authorized_keys_files = self.get_writable_authorized_keys_files()
        findings.extend(
            self.detect_writable_authorized_keys_findings(
                writable_authorized_keys_files
            )
        )

        return findings

    def get_ssh_host_keys(self) -> list[str]:
        command = (
            "find /etc/ssh "
            "-type f "
            "-name 'ssh_host_*_key' "
            "2>/dev/null | sort | head -100"
        )

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_ssh_host_key_findings(
        self,
        files: list[str] | None = None,
    ) -> list[Finding]:
        files = files if files is not None else self.get_ssh_host_keys()

        if not files:
            return []

        return [
            Finding(
                title="SSH Host Key Detected",
                severity=Severity.INFO,
                description=f"SSH host private key detected: {file_path}",
            )
            for file_path in files
        ]

    def _collect_ssh_host_key_findings(self) -> list[Finding]:
        ssh_host_keys = self.get_ssh_host_keys()
        return self.detect_ssh_host_key_findings(ssh_host_keys)

    def get_firewall_ruleset(self) -> list[str]:
        output = self.connector.execute("nft list ruleset")

        return [line.strip() for line in output.splitlines() if line.strip()]

    def detect_firewall_findings(
        self,
        ruleset: list[str] | None = None,
    ) -> list[Finding]:
        ruleset = ruleset if ruleset is not None else self.get_firewall_ruleset()

        if not ruleset:
            return []

        in_input_chain = False

        for line in ruleset:
            normalized = line.lower()

            if normalized.startswith("chain "):
                chain_name = normalized.split()[1]
                in_input_chain = chain_name == "input"
                continue

            if in_input_chain and "policy accept" in normalized:
                return [
                    Finding(
                        title="Firewall Input Policy Accept",
                        severity=Severity.HIGH,
                        description="Firewall input policy is set to accept",
                        remediation="Configure a restrictive inbound firewall policy and explicitly allow required services.",
                    )
                ]

            if in_input_chain and normalized == "}":
                in_input_chain = False

        return []

    def _collect_network_findings(self) -> list[Finding]:
        findings = []

        firewall_ruleset = self.get_firewall_ruleset()
        findings.extend(self.detect_firewall_findings(firewall_ruleset))

        listening_tcp_ports = self.get_listening_tcp_ports()
        findings.extend(self.detect_listening_tcp_port_findings(listening_tcp_ports))

        listening_udp_ports = self.get_listening_udp_ports()
        findings.extend(self.detect_listening_udp_port_findings(listening_udp_ports))

        return findings

    def get_listening_tcp_ports(self) -> list[str]:
        command = "ss -lnt | tail -n +2 | head -100"

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]

    def get_password_policy(self) -> dict[str, str]:
        output = self.connector.execute(
            "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs"
        )

        result = {}

        for line in output.splitlines():
            parts = line.split()

            if len(parts) < 2:
                continue

            result[parts[0]] = parts[1]

        return result

    def detect_password_policy_findings(
        self,
        policy: dict[str, str] | None = None,
    ) -> list[Finding]:
        policy = policy if policy is not None else self.get_password_policy()

        findings = []

        max_days = policy.get("PASS_MAX_DAYS")

        if max_days and max_days.isdigit() and int(max_days) > 90:
            findings.append(
                Finding(
                    title="Weak Password Expiration Policy",
                    severity=Severity.MEDIUM,
                    description=(
                        f"PASS_MAX_DAYS is set to {max_days}. "
                        "Recommended value is 90 days or less."
                    ),
                )
            )

        warn_age = policy.get("PASS_WARN_AGE")

        if warn_age and warn_age.isdigit() and int(warn_age) < 7:
            findings.append(
                Finding(
                    title="Weak Password Warning Policy",
                    severity=Severity.LOW,
                    description=(
                        f"PASS_WARN_AGE is set to {warn_age}. "
                        "Recommended value is at least 7 days."
                    ),
                )
            )

        return findings

    def detect_listening_tcp_port_findings(
        self,
        ports: list[str] | None = None,
    ) -> list[Finding]:
        ports = ports if ports is not None else self.get_listening_tcp_ports()

        if not ports:
            return []

        return [
            Finding(
                title="Listening TCP Port Detected",
                severity=Severity.INFO,
                description=f"Listening TCP port detected: {port}",
            )
            for port in ports
        ]

    def detect_listening_udp_port_findings(
        self,
        ports: list[str] | None = None,
    ) -> list[Finding]:
        ports = ports if ports is not None else self.get_listening_udp_ports()

        if not ports:
            return []

        return [
            Finding(
                title="Listening UDP Port Detected",
                severity=Severity.INFO,
                description=f"Listening UDP port detected: {port}",
            )
            for port in ports
        ]

    def get_listening_udp_ports(self) -> list[str]:
        command = "ss -lnu | tail -n +2 | head -100"

        output = self.connector.execute(command)

        return [line.strip() for line in output.splitlines() if line.strip()]
