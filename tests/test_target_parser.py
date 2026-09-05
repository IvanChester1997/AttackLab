from app.models.target import TargetType
from app.services.target_parser import TargetParser


def test_parse_host():
    assert TargetParser.parse("127.0.0.1") == TargetType.HOST


def test_parse_network():
    assert TargetParser.parse("192.168.1.0/24") == TargetType.NETWORK


def test_parse_hostname():
    assert TargetParser.parse("scanme.nmap.org") == TargetType.HOSTNAME


def test_invalid_target():
    assert TargetParser.parse("!!!invalid!!!") == TargetType.INVALID


def test_expand_network():
    hosts = TargetParser.expand_network("192.168.1.0/30")

    assert hosts == [
        "192.168.1.1",
        "192.168.1.2",
    ]
