import ipaddress


class TargetValidator:
    @staticmethod
    def is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_network(value: str) -> bool:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
