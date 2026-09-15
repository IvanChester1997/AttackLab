import json
from io import BytesIO
from unittest.mock import patch

import pytest

from app.services.nvd_client import NVDClient, NVDClientError


class FakeResponse(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_lookup_cves_returns_vulnerabilities():
    payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-38408",
                }
            }
        ],
    }

    with patch(
        "app.services.nvd_client.urlopen",
        return_value=FakeResponse(json.dumps(payload).encode()),
    ) as mock_urlopen:
        result = NVDClient().lookup_cves(
            "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*"
        )

    assert result == payload["vulnerabilities"]

    request = mock_urlopen.call_args.args[0]
    assert "cpeName=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A9.2p1" in request.full_url


def test_lookup_cves_uses_custom_base_url():
    payload = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "vulnerabilities": [],
    }

    with patch(
        "app.services.nvd_client.urlopen",
        return_value=FakeResponse(json.dumps(payload).encode()),
    ) as mock_urlopen:
        NVDClient(base_url="http://nvd-mock:8080/cves/2.0").lookup_cves(
            "cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*"
        )

    request = mock_urlopen.call_args.args[0]
    assert request.full_url.startswith("http://nvd-mock:8080/cves/2.0?cpeName=")


def test_lookup_cves_uses_environment_base_url(monkeypatch):
    payload = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "vulnerabilities": [],
    }

    monkeypatch.setenv(
        "NVD_BASE_URL",
        "http://nvd-mock:8081/rest/json/cves/2.0",
    )

    with patch(
        "app.services.nvd_client.urlopen",
        return_value=FakeResponse(json.dumps(payload).encode()),
    ) as mock_urlopen:
        NVDClient().lookup_cves("cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*")

    request = mock_urlopen.call_args.args[0]

    assert request.full_url.startswith(
        "http://nvd-mock:8081/rest/json/cves/2.0?cpeName="
    )


def test_lookup_cves_returns_empty_list_when_nvd_has_no_results():
    payload = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "vulnerabilities": [],
    }

    with patch(
        "app.services.nvd_client.urlopen",
        return_value=FakeResponse(json.dumps(payload).encode()),
    ):
        result = NVDClient().lookup_cves("cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*")

    assert result == []


def test_lookup_cves_raises_on_http_error():
    from urllib.error import HTTPError

    error = HTTPError(
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=None,
    )

    with (
        patch(
            "app.services.nvd_client.urlopen",
            side_effect=error,
        ),
        pytest.raises(NVDClientError, match="NVD API request failed"),
    ):
        NVDClient().lookup_cves("cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*")


def test_lookup_cves_raises_on_invalid_json():
    with (
        patch(
            "app.services.nvd_client.urlopen",
            return_value=FakeResponse(b"not-json"),
        ),
        pytest.raises(NVDClientError, match="invalid JSON"),
    ):
        NVDClient().lookup_cves("cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*")
