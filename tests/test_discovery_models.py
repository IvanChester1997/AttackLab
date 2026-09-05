from app.models.discovery import DiscoveryResult


def test_discovery_result():
    result = DiscoveryResult(
        target="127.0.0.1",
        alive=True,
        method="tcp"
    )

    assert result.target == "127.0.0.1"
    assert result.alive is True
