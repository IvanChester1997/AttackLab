import typer

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


if __name__ == "__main__":
    app()
