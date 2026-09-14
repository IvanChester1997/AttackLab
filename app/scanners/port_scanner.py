import re
import subprocess
import xml.etree.ElementTree as ET

from app.models.port import PortResult, ScanResult
from app.models.service import ServiceInfo


DEFAULT_PORTS = "22,80,443"


class PortScanError(Exception):
    """Raised when Nmap cannot complete a port scan."""


class PortScanner:
    @staticmethod
    def _parse_xml(output: str) -> list[PortResult]:
        root = ET.fromstring(output)
        parsed_ports = []

        for port in root.findall(".//port"):
            state_node = port.find("./state")
            service_node = port.find("./service")

            if state_node is None or state_node.get("state") != "open":
                continue

            port_id = port.get("portid")
            protocol = port.get("protocol", "tcp")

            if port_id is None:
                continue

            try:
                port_number = int(port_id)
            except ValueError:
                continue

            if service_node is None:
                continue

            service = ServiceInfo(
                name=service_node.get("name", "unknown"),
                product=service_node.get("product"),
                version=service_node.get("version"),
                cpe=(
                    service_node.get("cpe")
                    or (
                        service_node.find("./cpe").text
                        if service_node.find("./cpe") is not None
                        else None
                    )
                ),
            )

            parsed_ports.append(
                PortResult(
                    port=port_number,
                    protocol=protocol,
                    state="open",
                    service=service,
                )
            )

        return parsed_ports

    @staticmethod
    def _parse_text(output: str) -> list[PortResult]:
        parsed_ports = []

        for line in output.splitlines():
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

        return parsed_ports

    @staticmethod
    def scan(target: str, ports: str = DEFAULT_PORTS) -> ScanResult:
        try:
            result = subprocess.run(
                [
                    "nmap",
                    "-Pn",
                    "-n",
                    "-sT",
                    "-sV",
                    "-oX",
                    "-",
                    "-p",
                    ports,
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PortScanError("Nmap scan timed out") from exc

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            message = f"Nmap scan failed with exit code {result.returncode}"
            if stderr:
                message = f"{message}: {stderr}"
            raise PortScanError(message)

        output = result.stdout.strip()

        if not output:
            return ScanResult(
                target=target,
                ports=[],
            )

        try:
            parsed_ports = PortScanner._parse_xml(output)
        except ET.ParseError:
            parsed_ports = PortScanner._parse_text(output)

        return ScanResult(
            target=target,
            ports=parsed_ports,
        )
