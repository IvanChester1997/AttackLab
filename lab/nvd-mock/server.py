import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


class NVDMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path != "/rest/json/cves/2.0":
            self.send_response(404)
            self.end_headers()
            return

        payload = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0001",
                        "sourceIdentifier": "attacklab-e2e",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Synthetic vulnerability for AttackLab E2E testing.",
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                            "S:U/C:H/I:H/A:H"
                                        ),
                                        "baseScore": 9.8,
                                    }
                                }
                            ]
                        },
                        "configurations": [
                            {
                                "operator": "OR",
                                "nodes": [
                                    {
                                        "operator": "OR",
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": (
                                                    "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*:*"
                                                ),
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                }
            ],
        }

        body = json.dumps(payload).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


HTTPServer(("0.0.0.0", 8081), NVDMockHandler).serve_forever()
