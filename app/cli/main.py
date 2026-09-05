import typer

from app.services.port_scan_service import PortScanService


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
        service = port.service or "unknown"
        typer.echo(
            f"{port.port}/{port.protocol} "
            f"{port.state} "
            f"{service}"
        )


if __name__ == "__main__":
    app()
