import typer

from app.services.port_scan_service import PortScanService
from app.services.risk_engine import RiskEngine


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


@app.command("scan")
def scan(
    target: str,
    ports: str = typer.Option(
        "22,80,443",
        "--ports",
        "-p",
        help="Ports to scan, e.g. 22,80,443 or 1-1000.",
    ),
):
    """
    Scan target ports.
    """
    result = PortScanService.scan(target, ports)

    typer.echo(f"Target: {result.target}")

    if not result.ports:
        typer.echo("No open ports found.")
        return

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

    findings = RiskEngine.analyze(result)

    if not findings:
        return

    typer.echo("")
    typer.echo("Findings:")

    for finding in findings:
        typer.echo(
            f"[{finding.severity.value.upper()}] "
            f"{finding.title}"
        )


if __name__ == "__main__":
    app()
