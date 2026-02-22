"""
CTF Kit - AI-assisted CTF challenge solver toolkit.

Main CLI entry point using Typer.
"""

from pathlib import Path

from rich.console import Console
import typer

from ctf_kit import __version__
from ctf_kit.commands import analyze, check, flag, here, init, run, status, writeup

app = typer.Typer(
    name="ctf",
    help="AI-assisted CTF challenge solver toolkit.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold green]CTF Kit[/] version [cyan]{__version__}[/]")
        raise typer.Exit()


@app.callback()  # type: ignore[misc]
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """
    CTF Kit - Solve CTF challenges faster with AI assistance.

    Use [bold cyan]ctf init[/] to initialize a challenge, then launch your
    AI agent and use /ctf.* slash commands.
    """


# Register subcommands
app.add_typer(init.app, name="init")
app.command(name="check")(check.check_tools)
app.command(name="run")(run.run_tool)
app.command(name="analyze")(analyze.analyze_challenge)
app.command(name="writeup")(writeup.generate_writeup)
app.command(name="here")(here.here_command)
app.command(name="status")(status.status_command)
app.command(name="flag")(flag.flag_command)


@app.command()  # type: ignore[misc]
def new(
    path: str = typer.Argument(..., help="Path for new challenge (e.g., crypto/rsa-baby)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Challenge category"),
) -> None:
    """
    Create a new challenge folder and initialize CTF Kit.

    Example: ctf new crypto/rsa-baby
    """
    challenge_path = Path(path)
    challenge_path.mkdir(parents=True, exist_ok=True)

    console.print(f"[green]Created challenge folder:[/] [cyan]{challenge_path}[/]")

    # Initialize CTF Kit in the new folder
    from ctf_kit.commands.init import init_challenge

    init_challenge(challenge_path, category=category)


@app.command()  # type: ignore[misc]
def tools(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    install: bool = typer.Option(False, "--install", "-i", help="Show install commands"),
) -> None:
    """
    List available tools and their installation status.
    """
    from ctf_kit.commands.check import list_tools

    list_tools(category=category, show_install=install)


if __name__ == "__main__":
    app()
