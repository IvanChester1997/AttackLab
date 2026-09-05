from app.models.port import ScanResult
from app.scanners.port_scanner import PortScanner


class PortScanService:
    @staticmethod
    def scan(
        target: str,
        ports: str = "22,80,443",
    ) -> ScanResult:
        return PortScanner.scan(target, ports)
