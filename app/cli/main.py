from pathlib import Path

import typer

from app.connectors.ssh import SSHConnector
from app.scanners.linux_audit_scanner import LinuxAuditScanner
from app.services.port_scan_service import PortScanService
from app.services.report_generator import ReportGenerator


app = typer.Typer(
    help="AttackLab - Automated Pentest Laboratory"
)


@app.callback()
def main():
    """
    AttackLab CLI
    """
    pass


@app.command("version")
def version():
    """
    Show AttackLab version.
    """
    typer.echo("AttackLab v0.1.0")


def _run_audit(
    target: str,
    ports: str,
    output: Path | None,
    username: str | None = None,
    ssh_port: int = 22,
    key_file: str | None = None,
) -> None:
    result = PortScanService.scan(target, ports)

    typer.echo(f"Target: {result.target}")

    linux_audit = None

    if username is not None:
        connector = SSHConnector(
            host=target,
            username=username,
            port=ssh_port,
            key_file=key_file,
        )
        linux_audit = LinuxAuditScanner(connector).run_audit()

    report = ReportGenerator.generate(
        result,
        linux_audit=linux_audit,
    )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            ReportGenerator.generate_json(report),
            encoding="utf-8",
        )
        typer.echo(f"Report saved to: {output}")

    if not result.ports:
        typer.echo("No open ports found.")
        return

    typer.echo("")
    typer.echo("Open ports:")

    for port in result.ports:
        if port.service:
            service = port.service.name

            if port.service.product:
                service += f" ({port.service.product}"

                if port.service.version:
                    service += f" {port.service.version}"

                service += ")"
        else:
            service = "unknown"

        typer.echo(
            f"{port.port}/{port.protocol} "
            f"{port.state} "
            f"{service}"
        )

    typer.echo("")

    findings = report.findings

    typer.echo("Findings:")

    if findings:
        for finding in findings:
            typer.echo(
                f"[{finding.severity.value.upper()}] "
                f"{finding.title}"
            )
    else:
        typer.echo("No security findings.")

    typer.echo("")
    typer.echo("Summary:")
    typer.echo(f"Risk score: {report.summary.risk_score}/100")
    typer.echo(f"Risk level: {report.summary.risk_level}")
    typer.echo(f"Total findings: {report.summary.total_findings}")
    typer.echo(f"Critical: {report.summary.critical}")
    typer.echo(f"High: {report.summary.high}")
    typer.echo(f"Medium: {report.summary.medium}")
    typer.echo(f"Low: {report.summary.low}")
    typer.echo(f"Info: {report.summary.info}")


@app.command("audit")
def audit(
    target: str,
    ports: str = typer.Option(
        "22,80,443",
        "--ports",
        "-p",
        help="Ports to scan, e.g. 22,80,443 or 1-1000.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the security report to a JSON file.",
    ),
    username: str = typer.Option(
        "root",
        "--user",
        "-u",
        help="SSH username for Linux audit.",
    ),
    ssh_port: int = typer.Option(
        22,
        "--ssh-port",
        help="SSH port for Linux audit.",
    ),
    key_file: Path | None = typer.Option(
        None,
        "--key",
        "-k",
        help="Path to the SSH private key.",
    ),
):
    """
    Run a security audit against a target.
    """
    _run_audit(
        target,
        ports,
        output,
        username=username,
        ssh_port=ssh_port,
        key_file=key_file,
    )


@app.command("scan")
def scan(
    target: str,
    ports: str = typer.Option(
        "22,80,443",
        "--ports",
        "-p",
        help="Ports to scan, e.g. 22,80,443 or 1-1000.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the security report to a JSON file.",
    ),
):
    """
    Scan target ports.
    """
    _run_audit(target, ports, output)


if __name__ == "__main__":
    app()
