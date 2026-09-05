from pydantic import BaseModel

from app.models.service import ServiceInfo


class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str
    service: str | ServiceInfo | None = None


class ScanResult(BaseModel):
    target: str
    ports: list[PortResult]
