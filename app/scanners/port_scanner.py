import re
import subprocess

from app.models.port import PortResult, ScanResult
from app.models.service import ServiceInfo


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
                    "-sV",
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
            service_name = parts[2]

            try:
                port, protocol = port_protocol.split("/", 1)
                port_number = int(port)
            except ValueError:
                continue

            if state != "open":
                continue

            product = None
            version = None

            if len(parts) >= 4:
                service_details = " ".join(parts[3:])

                match = re.match(
                    r"(.+?)\s+(\d+(?:\.\d+)*(?:p\d+)?)$",
                    service_details,
                )

                if match:
                    product = match.group(1)
                    version = match.group(2)
                else:
                    product = service_details

            service = ServiceInfo(
                name=service_name,
                product=product,
                version=version,
            )

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
