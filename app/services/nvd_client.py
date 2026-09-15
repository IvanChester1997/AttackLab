import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class NVDClientError(Exception):
    """Raised when the NVD API request fails."""


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        user_agent: str = "AttackLab/0.1",
        timeout: int = 30,
        base_url: str | None = None,
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.base_url = base_url or os.getenv("NVD_BASE_URL") or self.BASE_URL

    def lookup_cves(self, cpe: str) -> list[dict]:
        url = f"{self.base_url}?cpeName={quote(cpe, safe='')}"

        request = Request(
            url,
            headers={"User-Agent": self.user_agent},
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                data = json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise NVDClientError(f"NVD API request failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise NVDClientError("NVD API returned invalid JSON") from exc

        return data.get("vulnerabilities", [])
