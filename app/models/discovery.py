from pydantic import BaseModel


class DiscoveryResult(BaseModel):
    target: str
    alive: bool
    method: str
