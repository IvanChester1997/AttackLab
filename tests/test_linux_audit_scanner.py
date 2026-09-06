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
        "root:x:0:0:root:/root:/bin/bash",
        "root:x:0:0:root:/root:/bin/bash",
        "root:x:0:0:root:/root:/bin/bash",
        "root:x:0:0:root:/root:/bin/bash",
        "",
        "",
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
        """
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    MaxAuthTries 6
    """.strip(),
        """
    /tmp/world-writable.txt
    """.strip(),
        "",
        "",
        "",
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
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",
        """
/usr/bin/passwd
""".strip(),
        "",
        "",
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
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",
        "",
        """
/etc/cron.d/e2scrub_all
""".strip(),
        "",
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
        """
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 6
""".strip(),
        "",
        "",
        "",
        "/etc/cron.d/backdoor",
    ]

    scanner = LinuxAuditScanner(connector)

    result = scanner.run_audit()

    assert len(result.findings) == 1

    assert result.findings[0]["title"] == "Writable Cron File"
    assert result.findings[0]["severity"] == "high"
