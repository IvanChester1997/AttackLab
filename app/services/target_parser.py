import ipaddress
import re

from app.models.target import TargetType


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}"
    r"(\.(?!-)[A-Za-z0-9-]{1,63})*$"
)


class TargetParser:
    @staticmethod
    def parse(target: str) -> TargetType:
        try:
            ipaddress.ip_address(target)
            return TargetType.HOST
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            return TargetType.NETWORK
        except ValueError:
            pass

        if HOSTNAME_RE.match(target):
            return TargetType.HOSTNAME

        return TargetType.INVALID

    @staticmethod
    def expand_network(network: str) -> list[str]:
        net = ipaddress.ip_network(network, strict=False)
        return [str(host) for host in net.hosts()]
