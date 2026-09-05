from pathlib import Path

import typer

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
) -> None:
    result = PortScanService.scan(target, ports)

    typer.echo(f"Target: {result.target}")

    report = ReportGenerator.generate(result)

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
):
    """
    Run a security audit against a target.
    """
    _run_audit(target, ports, output)


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
