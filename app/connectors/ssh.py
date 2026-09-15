from pathlib import Path

import paramiko


class SSHConnector:
    def __init__(
        self,
        host: str,
        username: str,
        port: int = 22,
        key_file: str | None = None,
    ):
        self.host = host
        self.username = username
        self.port = port
        self.key_file = key_file
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        if self._client is not None:
            return

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        kwargs = {
            "hostname": self.host,
            "username": self.username,
            "port": self.port,
            "timeout": 10,
        }

        if self.key_file:
            kwargs["key_filename"] = str(Path(self.key_file).expanduser())

        try:
            client.connect(**kwargs)
        except Exception:
            client.close()
            raise

        self._client = client

    def execute(self, command: str) -> str:
        self.connect()

        _stdin, stdout, stderr = self._client.exec_command(command)

        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        return output if output else error

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
