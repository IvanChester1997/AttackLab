from pydantic import BaseModel


class ServiceInfo(BaseModel):
    name: str
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
