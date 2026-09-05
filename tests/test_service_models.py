from app.models.service import ServiceInfo


def test_service_info():
    result = ServiceInfo(
        name="ssh",
        product="OpenSSH",
        version="9.2p1",
        cpe="cpe:/a:openbsd:openssh:9.2p1",
    )

    assert result.name == "ssh"
    assert result.product == "OpenSSH"
    assert result.version == "9.2p1"
    assert result.cpe == "cpe:/a:openbsd:openssh:9.2p1"


def test_service_info_optional_fields():
    result = ServiceInfo(
        name="http",
    )

    assert result.name == "http"
    assert result.product is None
    assert result.version is None
    assert result.cpe is None
