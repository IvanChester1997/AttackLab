from unittest.mock import Mock

from app.scanners.linux_audit_scanner import LinuxAuditScanner


def test_get_hostname():
    connector = Mock()

    connector.execute.return_value = "attacklab"

    scanner = LinuxAuditScanner(connector)

    assert scanner.get_hostname() == "attacklab"

    connector.execute.assert_called_once_with("hostname")


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

    connector.execute.assert_called_once_with("cat /etc/os-release")


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
        "root:x:0:0:root:/root:/bin/bash",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert result.hostname == "server01"
    assert result.os["id"] == "ubuntu"
    assert result.os["pretty_name"] == "Ubuntu 22.04 LTS"

    assert isinstance(result.users, list)
    assert isinstance(result.findings, list)


def test_get_users():
    connector = Mock()

    connector.execute.return_value = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
user1:x:1000:1000:user1:/home/user1:/bin/bash
""".strip()

    scanner = LinuxAuditScanner(connector)

    users = scanner.get_users()

    assert len(users) == 3

    assert users[0].username == "root"
    assert users[0].uid == 0

    assert users[2].username == "user1"
    assert users[2].uid == 1000

    connector.execute.assert_called_once_with("cat /etc/passwd")


def test_get_interactive_users():
    connector = Mock()

    connector.execute.return_value = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
user1:x:1000:1000:user1:/home/user1:/bin/bash
""".strip()

    scanner = LinuxAuditScanner(connector)

    users = scanner.get_interactive_users()

    assert len(users) == 2

    usernames = [u.username for u in users]

    assert "root" in usernames
    assert "user1" in usernames


def test_get_uid_zero_accounts():
    connector = Mock()

    connector.execute.return_value = """
root:x:0:0:root:/root:/bin/bash
admin:x:0:0:admin:/root:/bin/bash
user1:x:1000:1000:user1:/home/user1:/bin/bash
""".strip()

    scanner = LinuxAuditScanner(connector)

    users = scanner.get_uid_zero_accounts()

    assert len(users) == 2

    usernames = [u.username for u in users]

    assert "root" in usernames
    assert "admin" in usernames


def test_get_service_accounts():
    connector = Mock()

    connector.execute.return_value = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
user1:x:1000:1000:user1:/home/user1:/bin/bash
""".strip()

    scanner = LinuxAuditScanner(connector)

    users = scanner.get_service_accounts()

    usernames = [u.username for u in users]

    assert "daemon" in usernames
    assert "www-data" in usernames

    assert "user1" not in usernames


def test_get_docker_group_members():
    connector = Mock()

    connector.execute.return_value = "docker:x:999:user1,user2"

    scanner = LinuxAuditScanner(connector)

    members = scanner.get_docker_group_members()

    assert members == [
        "user1",
        "user2",
    ]

    connector.execute.assert_called_once_with("getent group docker")


def test_get_docker_group_members_empty():
    connector = Mock()

    connector.execute.return_value = ""

    scanner = LinuxAuditScanner(connector)

    assert scanner.get_docker_group_members() == []


def test_detect_docker_group_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_docker_group_findings(
        [
            "user1",
            "user2",
        ]
    )

    assert len(findings) == 2

    assert findings[0]["title"] == "User In Docker Group"
    assert findings[0]["severity"] == "high"
    assert "user1" in findings[0]["description"]

    assert findings[1]["title"] == "User In Docker Group"
    assert "user2" in findings[1]["description"]


def test_detect_additional_uid_zero_accounts():
    connector = Mock()

    connector.execute.return_value = """
root:x:0:0:root:/root:/bin/bash
admin:x:0:0:admin:/root:/bin/bash
user1:x:1000:1000:user1:/home/user1:/bin/bash
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_uid_zero_findings()

    assert len(findings) == 1

    assert findings[0]["severity"] == "high"
    assert "admin" in findings[0]["description"]


def test_detect_permit_root_login_enabled():
    connector = Mock()

    connector.execute.return_value = """
Port 22
PermitRootLogin yes
PasswordAuthentication no
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_ssh_root_login_findings()

    assert len(findings) == 1

    assert findings[0]["severity"] == "high"
    assert "PermitRootLogin" in findings[0]["title"]


def test_detect_password_authentication_enabled():
    connector = Mock()

    connector.execute.return_value = """
Port 22
PermitRootLogin no
PasswordAuthentication yes
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_password_authentication_findings()

    assert len(findings) == 1

    assert findings[0]["severity"] == "medium"

    assert "PasswordAuthentication" in findings[0]["title"]


def test_run_ssh_audit():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin yes
PasswordAuthentication yes
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.run_ssh_audit()

    assert len(findings) == 2

    titles = [f["title"] for f in findings]

    assert "PermitRootLogin Enabled" in titles
    assert "PasswordAuthentication Enabled" in titles


def test_run_audit_collects_users_and_findings():
    connector = Mock()

    passwd_content = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
user1:x:1000:1000:user1:/home/user1:/bin/bash
""".strip()

    "",

    connector.execute.side_effect = [
        "server01",
        """
    NAME="Ubuntu"
    ID=ubuntu
    VERSION_ID="22.04"
    PRETTY_NAME="Ubuntu 22.04 LTS"
    """.strip(),
        passwd_content,
        passwd_content,
        passwd_content,
        passwd_content,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.users) == 3
    assert len(result.interactive_users) == 2
    assert len(result.uid_zero_accounts) == 1
    assert len(result.service_accounts) == 1


def test_detect_pubkey_authentication_disabled():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication no
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_pubkey_authentication_findings()

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "PubkeyAuthentication" in findings[0]["title"]


def test_run_ssh_audit_reads_sshd_config_once():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication no
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.run_ssh_audit()

    assert len(findings) == 3
    assert connector.execute.call_count == 1
    connector.execute.assert_called_once_with("cat /etc/ssh/sshd_config")


def test_run_ssh_audit_reads_sshd_config_once():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication no
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.run_ssh_audit()

    assert len(findings) == 3
    assert connector.execute.call_count == 1
    connector.execute.assert_called_once_with("cat /etc/ssh/sshd_config")


def test_detect_max_auth_tries_too_high():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 10
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_max_auth_tries_findings()

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "MaxAuthTries" in findings[0]["title"]


def test_detect_max_auth_tries_safe():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_max_auth_tries_findings()

    assert findings == []


def test_run_ssh_audit_reads_sshd_config_once_with_all_checks():
    connector = Mock()

    connector.execute.return_value = """
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication no
MaxAuthTries 10
""".strip()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.run_ssh_audit()

    assert len(findings) == 4
    assert connector.execute.call_count == 1
    connector.execute.assert_called_once_with("cat /etc/ssh/sshd_config")


def test_get_world_writable_files():
    connector = Mock()
    connector.execute.return_value = """
/tmp/world-writable.txt
/var/tmp/test.log
""".strip()

    scanner = LinuxAuditScanner(connector)

    files = scanner.get_world_writable_files()

    assert files == [
        "/tmp/world-writable.txt",
        "/var/tmp/test.log",
    ]
    connector.execute.assert_called_once()


def test_detect_world_writable_findings():
    connector = Mock()
    scanner = LinuxAuditScanner(connector)

    files = [
        "/tmp/world-writable.txt",
        "/var/tmp/test.log",
    ]

    findings = scanner.detect_world_writable_findings(files)

    assert len(findings) == 2

    assert findings[0]["title"] == "World-Writable File"
    assert findings[0]["severity"] == "medium"
    assert "/tmp/world-writable.txt" in findings[0]["description"]

    assert findings[1]["title"] == "World-Writable File"
    assert findings[1]["severity"] == "medium"
    assert "/var/tmp/test.log" in findings[1]["description"]


def test_run_audit_includes_world_writable_findings():
    connector = Mock()

    connector.execute.side_effect = [
        "attacklab",
        """
ID=debian
NAME="Debian GNU/Linux"
""".strip(),
        """
root:x:0:0:root:/root:/bin/bash
""".strip(),
        "",  # docker
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "/tmp/world-writable.txt",  # world_writable
        "",  # suid
        "",  # cron
        "",  # writable_cron
        "",  # authorized_keys
        "",  # writabl_authorized_keys
        "",  # sudoers
        "",
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1
    assert result.findings[0]["title"] == "World-Writable File"
    assert result.findings[0]["severity"] == "medium"
    assert "/tmp/world-writable.txt" in result.findings[0]["description"]


def test_get_suid_sgid_files():
    connector = Mock()

    connector.execute.return_value = """
/usr/bin/passwd
/usr/bin/su
""".strip()

    scanner = LinuxAuditScanner(connector)

    files = scanner.get_suid_sgid_files()

    assert files == [
        "/usr/bin/passwd",
        "/usr/bin/su",
    ]

    connector.execute.assert_called_once()


def test_detect_suid_sgid_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    files = [
        "/usr/bin/passwd",
        "/usr/bin/su",
    ]

    findings = scanner.detect_suid_sgid_findings(files)

    assert len(findings) == 2

    assert findings[0]["title"] == "SUID/SGID File"
    assert findings[0]["severity"] == "medium"
    assert "/usr/bin/passwd" in findings[0]["description"]

    assert findings[1]["title"] == "SUID/SGID File"
    assert findings[1]["severity"] == "medium"
    assert "/usr/bin/su" in findings[1]["description"]


def test_run_audit_includes_suid_sgid_findings():
    connector = Mock()

    connector.execute.side_effect = [
        "attacklab",
        """
ID=debian
NAME="Debian GNU/Linux"
""".strip(),
        """
root:x:0:0:root:/root:/bin/bash
""".strip(),
        "",  # docker
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",  # world_writable
        "/usr/bin/passwd",  # suid_sgid
        "",  # cron
        "",  # writable_cron
        "",  # authorized_keys
        "",  # writable_authorized_keys
        "",  # sudoers
        "",
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1

    assert result.findings[0]["title"] == "SUID/SGID File"
    assert result.findings[0]["severity"] == "medium"
    assert "/usr/bin/passwd" in result.findings[0]["description"]


def test_get_cron_entries():
    connector = Mock()

    connector.execute.return_value = """
/etc/cron.d/e2scrub_all
/etc/cron.daily/apt-compat
""".strip()

    scanner = LinuxAuditScanner(connector)

    entries = scanner.get_cron_entries()

    assert entries == [
        "/etc/cron.d/e2scrub_all",
        "/etc/cron.daily/apt-compat",
    ]

    connector.execute.assert_called_once()


def test_detect_cron_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    entries = [
        "/etc/cron.d/e2scrub_all",
        "/etc/cron.daily/apt-compat",
    ]

    findings = scanner.detect_cron_findings(entries)

    assert len(findings) == 2

    assert findings[0]["title"] == "Cron Job Detected"
    assert findings[0]["severity"] == "low"
    assert "/etc/cron.d/e2scrub_all" in findings[0]["description"]


def test_run_audit_includes_cron_findings():
    connector = Mock()

    connector.execute.side_effect = [
        "attacklab",
        """
ID=debian
NAME="Debian GNU/Linux"
""".strip(),
        """
root:x:0:0:root:/root:/bin/bash
""".strip(),
        "",  # docker
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",  # world_writable
        "",  # suid_sgid
        "/etc/cron.d/e2scrub_all",  # cron
        "",  # writable_cron
        "",  # authorized_keys
        "",  # writable_authorized_keys
        "",  # sudoers
        "",
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1

    assert result.findings[0]["title"] == "Cron Job Detected"
    assert result.findings[0]["severity"] == "low"


def test_get_writable_cron_files():
    connector = Mock()

    connector.execute.return_value = """
/etc/cron.d/backdoor
/etc/cron.daily/update.sh
""".strip()

    scanner = LinuxAuditScanner(connector)

    files = scanner.get_writable_cron_files()

    assert files == [
        "/etc/cron.d/backdoor",
        "/etc/cron.daily/update.sh",
    ]


def test_detect_writable_cron_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_writable_cron_findings(
        [
            "/etc/cron.d/backdoor",
        ]
    )

    assert len(findings) == 1
    assert findings[0]["title"] == "Writable Cron File"
    assert findings[0]["severity"] == "high"


def test_run_audit_includes_writable_cron_findings():
    connector = Mock()

    connector.execute.side_effect = [
        "attacklab",
        """
ID=debian
NAME="Debian GNU/Linux"
""".strip(),
        """
root:x:0:0:root:/root:/bin/bash
""".strip(),
        "",  # docker
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",  # world_writable
        "",  # suid_sgid
        "",  # cron
        "/etc/cron.d/backdoor",  # writable_cron
        "",  # authorized_keys
        "",  # writable_authorized_keys
        "",  # sudoers
        "",
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1

    assert result.findings[0]["title"] == "Writable Cron File"
    assert result.findings[0]["severity"] == "high"


def test_get_sudoers_entries():
    connector = Mock()

    connector.execute.return_value = """
root ALL=(ALL) NOPASSWD: ALL
""".strip()

    scanner = LinuxAuditScanner(connector)

    entries = scanner.get_sudoers_entries()

    assert entries == [
        "root ALL=(ALL) NOPASSWD: ALL",
    ]


def test_detect_nopasswd_sudo_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_nopasswd_sudo_findings(
        [
            "root ALL=(ALL) NOPASSWD: ALL",
        ]
    )

    assert len(findings) == 1
    assert findings[0]["title"] == "NOPASSWD Sudo Rule"
    assert findings[0]["severity"] == "high"


def test_run_audit_includes_nopasswd_sudo_findings():
    connector = Mock()

    connector.execute.side_effect = [
        "attacklab",
        """
    ID=debian
    NAME="Debian GNU/Linux"
    """.strip(),
        """
    root:x:0:0:root:/root:/bin/bash
    """.strip(),
        "",  # docker
        """
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    MaxAuthTries 6
    """.strip(),
        "",  # world_writable
        "",  # suid_sgid
        "",  # cron
        "",  # writable_cron
        "",  # authorized_keys
        "",  # writable_authorized_keys
        "root ALL=(ALL) NOPASSWD: ALL",  # sudoers
        "",  # ssh_host_keys
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1

    assert result.findings[0]["title"] == "NOPASSWD Sudo Rule"
    assert result.findings[0]["severity"] == "high"


def test_get_authorized_keys_files():
    connector = Mock()
    connector.execute.return_value = """
/root/.ssh/authorized_keys
/home/test/.ssh/authorized_keys
""".strip()

    scanner = LinuxAuditScanner(connector)

    files = scanner.get_authorized_keys_files()

    assert files == [
        "/root/.ssh/authorized_keys",
        "/home/test/.ssh/authorized_keys",
    ]


def test_detect_authorized_keys_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_authorized_keys_findings(
        [
            "/root/.ssh/authorized_keys",
            "/home/test/.ssh/authorized_keys",
        ]
    )

    assert len(findings) == 2
    assert findings[0]["title"] == "Authorized Keys File Detected"
    assert findings[0]["severity"] == "info"
    assert findings[0]["description"] == (
        "SSH authorized_keys file detected: /root/.ssh/authorized_keys"
    )
    assert findings[1]["description"] == (
        "SSH authorized_keys file detected: /home/test/.ssh/authorized_keys"
    )


def test_get_writable_authorized_keys_files():
    connector = Mock()

    connector.execute.return_value = """
/root/.ssh/authorized_keys
/home/test/.ssh/authorized_keys
""".strip()

    scanner = LinuxAuditScanner(connector)

    files = scanner.get_writable_authorized_keys_files()

    assert files == [
        "/root/.ssh/authorized_keys",
        "/home/test/.ssh/authorized_keys",
    ]

    connector.execute.assert_called_once_with(
        "find / -xdev -type f -name authorized_keys "
        "\\( -perm -0020 -o -perm -0002 \\) "
        "2>/dev/null | head -100"
    )


def test_detect_writable_authorized_keys_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_writable_authorized_keys_findings(
        [
            "/root/.ssh/authorized_keys",
            "/home/test/.ssh/authorized_keys",
        ]
    )

    assert len(findings) == 2

    assert findings[0]["title"] == "Writable Authorized Keys File"
    assert findings[0]["severity"] == "high"
    assert findings[0]["description"] == (
        "Group/world-writable authorized_keys file detected: "
        "/root/.ssh/authorized_keys"
    )

    assert findings[1]["description"] == (
        "Group/world-writable authorized_keys file detected: "
        "/home/test/.ssh/authorized_keys"
    )


def test_get_ssh_host_keys():
    connector = Mock()

    connector.execute.return_value = """
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_ed25519_key
""".strip()

    scanner = LinuxAuditScanner(connector)

    files = scanner.get_ssh_host_keys()

    assert files == [
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
    ]


def test_detect_ssh_host_key_findings():
    connector = Mock()

    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_ssh_host_key_findings(
        [
            "/etc/ssh/ssh_host_rsa_key",
            "/etc/ssh/ssh_host_ed25519_key",
        ]
    )

    assert len(findings) == 2

    assert findings[0]["title"] == "SSH Host Key Detected"
    assert findings[0]["severity"] == "info"

    assert findings[1]["title"] == "SSH Host Key Detected"


def test_run_audit_includes_ssh_host_key_findings():
    connector = Mock()

    connector.execute.side_effect = [
        "attacklab",
        """
ID=debian
NAME="Debian GNU/Linux"
""".strip(),
        """
root:x:0:0:root:/root:/bin/bash
""".strip(),
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        """
/etc/ssh/ssh_host_rsa_key
""".strip(),
        "",  # firewall_ruleset
        "",  # listening_tcp_ports
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1

    assert result.findings[0]["title"] == "SSH Host Key Detected"
    assert result.findings[0]["severity"] == "info"
    assert "/etc/ssh/ssh_host_rsa_key" in result.findings[0]["description"]


def test_get_listening_tcp_ports():
    connector = Mock()

    connector.execute.return_value = """
tcp LISTEN 0 128 0.0.0.0:22
tcp LISTEN 0 128 0.0.0.0:80
""".strip()

    scanner = LinuxAuditScanner(connector)

    ports = scanner.get_listening_tcp_ports()

    assert ports == [
        "tcp LISTEN 0 128 0.0.0.0:22",
        "tcp LISTEN 0 128 0.0.0.0:80",
    ]

def test_detect_listening_tcp_port_findings():
    connector = Mock()
    scanner = LinuxAuditScanner(connector)

    ports = [
        "tcp LISTEN 0 128 0.0.0.0:22",
        "tcp LISTEN 0 128 0.0.0.0:80",
    ]

    findings = scanner.detect_listening_tcp_port_findings(ports)

    assert findings == [
        {
            "title": "Listening TCP Port Detected",
            "severity": "info",
            "description": (
                "Listening TCP port detected: "
                "tcp LISTEN 0 128 0.0.0.0:22"
            ),
        },
        {
            "title": "Listening TCP Port Detected",
            "severity": "info",
            "description": (
                "Listening TCP port detected: "
                "tcp LISTEN 0 128 0.0.0.0:80"
            ),
        },
    ]


def test_detect_listening_tcp_port_findings_empty():
    connector = Mock()
    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_listening_tcp_port_findings([])

    assert findings == []

def test_run_audit_includes_listening_tcp_port_findings():
    connector = Mock()

    def execute(command):
        if command == "hostname":
            return "test-host"
        if command == "cat /etc/os-release":
            return 'NAME="Test Linux"'
        if command == "ss -lnt " "| tail -n +2 " "| head -100":
            return "tcp LISTEN 0 128 0.0.0.0:22"
        return ""

    connector.execute.side_effect = execute

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    listening_findings = [
        finding
        for finding in result.findings
        if finding["title"] == "Listening TCP Port Detected"
    ]

    assert listening_findings == [
        {
            "title": "Listening TCP Port Detected",
            "severity": "info",
            "description": (
                "Listening TCP port detected: "
                "tcp LISTEN 0 128 0.0.0.0:22"
            ),
        }
    ]


def test_get_firewall_ruleset():
    connector = Mock()
    connector.execute.return_value = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
    }
}
""".strip()

    scanner = LinuxAuditScanner(connector)

    ruleset = scanner.get_firewall_ruleset()

    assert ruleset == [
        "table inet filter {",
        "chain input {",
        "type filter hook input priority filter; policy drop;",
        "}",
        "}",
    ]


def test_detect_firewall_findings_policy_accept():
    connector = Mock()
    scanner = LinuxAuditScanner(connector)

    ruleset = [
        "table inet filter {",
        "chain input {",
        "type filter hook input priority filter; policy accept;",
        "}",
        "}",
    ]

    findings = scanner.detect_firewall_findings(ruleset)

    assert findings == [
        {
            "title": "Firewall Input Policy Accept",
            "severity": "high",
            "description": "Firewall input policy is set to accept",
            "remediation": "Configure a restrictive inbound firewall policy and explicitly allow required services.",
        }
    ]


def test_detect_firewall_findings_policy_drop():
    connector = Mock()
    scanner = LinuxAuditScanner(connector)

    ruleset = [
        "table inet filter {",
        "chain input {",
        "type filter hook input priority filter; policy drop;",
        "}",
        "}",
    ]

    findings = scanner.detect_firewall_findings(ruleset)

    assert findings == []


def test_detect_firewall_findings_empty():
    connector = Mock()
    scanner = LinuxAuditScanner(connector)

    findings = scanner.detect_firewall_findings([])

    assert findings == []


def test_run_audit_includes_firewall_findings():
    connector = Mock()

    def execute(command):
        if command == "hostname":
            return "test-host"
        if command == "cat /etc/os-release":
            return 'NAME="Test Linux"'
        if command == "nft list ruleset":
            return """
table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
    }
}
""".strip()
        return ""

    connector.execute.side_effect = execute

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    firewall_findings = [
        finding
        for finding in result.findings
        if finding["title"] == "Firewall Input Policy Accept"
    ]

    assert firewall_findings == [
        {
            "title": "Firewall Input Policy Accept",
            "severity": "high",
            "description": "Firewall input policy is set to accept",
            "remediation": "Configure a restrictive inbound firewall policy and explicitly allow required services.",
        }
    ]
