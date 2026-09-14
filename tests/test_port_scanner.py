from unittest.mock import patch

import pytest

from app.scanners.port_scanner import PortScanError, PortScanner


def test_scan_parses_open_ports():
    nmap_output = """
Starting Nmap
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
"""

    with patch("app.scanners.port_scanner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = nmap_output
        mock_run.return_value.returncode = 0

        result = PortScanner.scan("127.0.0.1")

    assert result.target == "127.0.0.1"
    assert len(result.ports) == 3

    assert result.ports[0].port == 22
    assert result.ports[0].protocol == "tcp"
    assert result.ports[0].state == "open"
    assert result.ports[0].service.name == "ssh"

    assert result.ports[1].port == 80
    assert result.ports[1].service.name == "http"

    assert result.ports[2].port == 443
    assert result.ports[2].service.name == "https"


def test_scan_ignores_closed_ports():
    nmap_output = """
Starting Nmap
PORT    STATE  SERVICE
22/tcp  open   ssh
23/tcp  closed telnet
80/tcp  open   http
"""

    with patch("app.scanners.port_scanner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = nmap_output
        mock_run.return_value.returncode = 0

        result = PortScanner.scan("127.0.0.1")

    assert len(result.ports) == 2
    assert [port.port for port in result.ports] == [22, 80]


def test_scan_uses_nmap():
    with patch("app.scanners.port_scanner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = """
Starting Nmap
PORT    STATE SERVICE
22/tcp  open  ssh
"""
        mock_run.return_value.returncode = 0

        PortScanner.scan("127.0.0.1")

    mock_run.assert_called_once()

    command = mock_run.call_args.args[0]

    assert command[0] == "nmap"
    assert "-sT" in command
    assert "127.0.0.1" in command


def test_scan_raises_on_timeout():
    import subprocess

    with patch(
        "app.scanners.port_scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd=["nmap"],
            timeout=60,
        ),
    ):
        with pytest.raises(PortScanError, match="timed out"):
            PortScanner.scan("127.0.0.1")


def test_scan_raises_on_nmap_failure():
    with patch("app.scanners.port_scanner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "Failed to resolve target"
        mock_run.return_value.returncode = 2

        with pytest.raises(
            PortScanError,
            match="Nmap scan failed with exit code 2: Failed to resolve target",
        ):
            PortScanner.scan("invalid-target")


def test_scan_parses_service_details():
    nmap_output = """
Starting Nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
80/tcp open  http    nginx 1.24.0
"""

    with patch("app.scanners.port_scanner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = nmap_output
        mock_run.return_value.returncode = 0

        result = PortScanner.scan("127.0.0.1")

    assert len(result.ports) == 2

    ssh = result.ports[0]
    assert ssh.port == 22
    assert ssh.service.name == "ssh"
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "9.2p1"

    http = result.ports[1]
    assert http.port == 80
    assert http.service.name == "http"
    assert http.service.product == "nginx"
    assert http.service.version == "1.24.0"


def test_scan_parses_service_cpe_from_nmap_xml():
    nmap_output = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service
          name="ssh"
          product="OpenSSH"
          version="9.2p1"
          cpe="cpe:/a:openbsd:openssh:9.2p1"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    with patch("app.scanners.port_scanner.subprocess.run") as mock_run:
        mock_run.return_value.stdout = nmap_output
        mock_run.return_value.returncode = 0

        result = PortScanner.scan("127.0.0.1", ports="22")

    assert len(result.ports) == 1

    ssh = result.ports[0]

    assert ssh.port == 22
    assert ssh.protocol == "tcp"
    assert ssh.state == "open"
    assert ssh.service.name == "ssh"
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "9.2p1"
    assert ssh.service.cpe == "cpe:/a:openbsd:openssh:9.2p1"
