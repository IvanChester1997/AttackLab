from pydantic import BaseModel


class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str
    service: str | None = None


class ScanResult(BaseModel):
    target: str
    ports: list[PortResult]
