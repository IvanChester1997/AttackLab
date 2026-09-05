import subprocess


class NmapScanner:
    @staticmethod
    def discover(target: str) -> str:
        result = subprocess.run(
            [
                "nmap",
                "-Pn",
                "-n",
                "-p",
                "22,80,443",
                target,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        return result.stdout
