import json
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

import pytest

API_BASE_URL = "http://127.0.0.1:8000"


def get_json(path: str) -> dict | list:
    request = Request(f"{API_BASE_URL}{path}")
    with urlopen(request, timeout=10) as response:
        assert response.status == 200
        return json.load(response)


def wait_for_health(timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            data = get_json("/health")
            if data == {"status": "healthy"}:
                return
        except (URLError, OSError):
            pass

        time.sleep(1)

    raise AssertionError("AttackLab API did not become healthy")


@pytest.mark.integration
def test_assessment_e2e():
    wait_for_health()

    payload = json.dumps(
        {
            "target": "target",
            "ports": "22,23,80",
        }
    ).encode()

    request = Request(
        f"{API_BASE_URL}/api/v1/assessments",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(request, timeout=10) as response:
        assert response.status == 202
        created = json.load(response)

    scan_id = created["id"]

    assert created["status"] == "pending"

    deadline = time.monotonic() + 120

    while time.monotonic() < deadline:
        data = get_json(f"/api/v1/scans/{scan_id}")

        if data["status"] == "completed":
            report = data["report"]

            assert report["target"] == "target"
            assert report["summary"]["total_ports"] >= 1
            assert report["summary"]["total_findings"] >= 1
            assert report["summary"]["risk_score"] > 0
            assert any(
                finding.get("cve") == "CVE-2099-0001" for finding in report["findings"]
            )
            assert any(
                finding.get("cvss", {}).get("score") == 9.8
                for finding in report["findings"]
                if finding.get("cvss") is not None
            )

            return

        if data["status"] == "failed":
            raise AssertionError(data.get("error_message"))

        time.sleep(2)

    raise AssertionError("Assessment did not complete within 120 seconds")
