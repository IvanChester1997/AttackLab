import socket

from app.models.discovery import DiscoveryResult


class DiscoveryScanner:
    @staticmethod
    def tcp_discover(
        target: str,
        port: int = 80,
        timeout: float = 1.0
    ) -> DiscoveryResult:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((target, port))
            alive = result == 0
        finally:
            sock.close()

        return DiscoveryResult(
            target=target,
            alive=alive,
            method="tcp"
        )
