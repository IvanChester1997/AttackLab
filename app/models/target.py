from enum import Enum


class TargetType(str, Enum):
    HOST = "host"
    NETWORK = "network"
    HOSTNAME = "hostname"
    INVALID = "invalid"
