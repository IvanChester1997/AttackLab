from unittest.mock import Mock, patch

import pytest

from app.connectors.ssh import SSHConnector


@pytest.mark.integration
def test_execute_remote_command():
    connector = SSHConnector(
        host="127.0.0.1",
        username="root",
        port=2222,
        key_file="~/.ssh/id_ed25519",
    )

    result = connector.execute("whoami")

    assert result == "root"


def test_connect_creates_client_and_rejects_unknown_host_key():
    connector = SSHConnector(
        host="example.com",
        username="root",
        port=2222,
        key_file="~/.ssh/id_ed25519",
    )

    client = Mock()
    policy = Mock()

    with (
        patch(
            "app.connectors.ssh.paramiko.SSHClient", return_value=client
        ) as ssh_client,
        patch("app.connectors.ssh.paramiko.RejectPolicy", return_value=policy),
    ):
        connector.connect()

    ssh_client.assert_called_once_with()
    client.set_missing_host_key_policy.assert_called_once_with(policy)
    client.connect.assert_called_once_with(
        hostname="example.com",
        username="root",
        port=2222,
        timeout=10,
        key_filename="/root/.ssh/id_ed25519",
    )
    assert connector._client is client


def test_execute_reuses_existing_connection():
    connector = SSHConnector(
        host="example.com",
        username="root",
    )

    client = Mock()
    stdout = Mock()
    stderr = Mock()

    stdout.read.return_value = b"hello\n"
    stderr.read.return_value = b""
    client.exec_command.return_value = (Mock(), stdout, stderr)

    connector._client = client

    result = connector.execute("echo hello")

    assert result == "hello"
    client.exec_command.assert_called_once_with("echo hello")
    client.connect.assert_not_called()


def test_close_closes_existing_connection():
    connector = SSHConnector(
        host="example.com",
        username="root",
    )

    client = Mock()
    connector._client = client

    connector.close()

    client.close.assert_called_once_with()
    assert connector._client is None
