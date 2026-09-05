from app.connectors.ssh import SSHConnector


def test_execute_remote_command():
    connector = SSHConnector(
        host="127.0.0.1",
        username="root",
        port=2222,
        key_file="~/.ssh/id_ed25519",
    )

    result = connector.execute("whoami")

    assert result == "root"
