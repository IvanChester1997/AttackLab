from app.services.target_validator import TargetValidator


def test_valid_ip():
    assert TargetValidator.is_ip("127.0.0.1")


def test_invalid_ip():
    assert not TargetValidator.is_ip("999.999.999.999")


def test_valid_network():
    assert TargetValidator.is_network("192.168.1.0/24")
