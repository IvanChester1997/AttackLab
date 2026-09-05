import subprocess

from app.models.port import PortResult, ScanResult


DEFAULT_PORTS = "22,80,443"


class PortScanner:
    @staticmethod
    def scan(target: str, ports: str = DEFAULT_PORTS) -> ScanResult:
        try:
            result = subprocess.run(
                [
                    "nmap",
                    "-Pn",
                    "-n",
                    "-p",
                    ports,
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=target,
                ports=[],
            )

        parsed_ports = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line or "/" not in line:
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            port_protocol = parts[0]
            state = parts[1]
            service = parts[2]

            try:
                port, protocol = port_protocol.split("/", 1)
                port_number = int(port)
            except ValueError:
                continue

            if state != "open":
                continue

            parsed_ports.append(
                PortResult(
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service=service,
                )
            )

        return ScanResult(
            target=target,
            ports=parsed_ports,
        )
