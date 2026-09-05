from typer.testing import CliRunner

from app.cli.main import app


runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "AttackLab v0.1.0" in result.stdout
