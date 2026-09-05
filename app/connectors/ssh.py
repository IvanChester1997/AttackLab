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

    def execute(self, command: str) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        kwargs = {
            "hostname": self.host,
            "username": self.username,
            "port": self.port,
            "timeout": 10,
        }

        if self.key_file:
            kwargs["key_filename"] = str(
                Path(self.key_file).expanduser()
            )

        client.connect(**kwargs)

        try:
            stdin, stdout, stderr = client.exec_command(command)

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            return output if output else error

        finally:
            client.close()
