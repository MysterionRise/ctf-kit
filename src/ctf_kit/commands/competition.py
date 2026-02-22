"""
Competition management CLI commands.

Provides commands for initializing competitions, tracking challenges,
managing team members, and viewing competition status.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from ctf_kit.competition import (
    COMPETITION_FILE,
    ChallengeStatus,
    Competition,
    find_competition_root,
    load_competition,
    save_competition,
    scan_challenges,
)

app = typer.Typer(help="Manage CTF competitions")
console = Console()


def _load_or_exit(path: Path | None = None) -> tuple[Competition, Path]:
    """Load competition or exit with error."""
    root = find_competition_root(path)
    if not root:
        console.print("[red]No competition found. Run 'ctf competition init' first.[/]")
        raise typer.Exit(1)

    comp = load_competition(root)
    if not comp:
        console.print("[red]Failed to load competition config.[/]")
        raise typer.Exit(1)

    return comp, root


@app.command(name="init")  # type: ignore[misc]
def init_competition(
    name: Annotated[str, typer.Option("--name", "-n", help="Competition name")],
    url: Annotated[str | None, typer.Option("--url", "-u", help="Competition URL")] = None,
    flag_format: Annotated[
        str | None,
        typer.Option("--flag-format", "-f", help="Flag format regex"),
    ] = None,
    path: Annotated[
        Path | None,
        typer.Argument(help="Competition directory (default: current directory)"),
    ] = None,
) -> None:
    """
    Initialize a new CTF competition.

    Creates a .ctf-competition.yaml in the specified directory.

    Examples:
        ctf competition init --name "AmateursCTF 2026"
        ctf competition init -n "PicoCTF" -u "https://play.picoctf.org" -f "picoCTF\\{.*\\}"
    """
    target = path or Path.cwd()

    config_file = target / COMPETITION_FILE
    if config_file.exists():
        console.print("[yellow]Competition already initialized here.[/]")
        raise typer.Exit(1)

    comp = Competition(
        name=name,
        url=url,
        flag_format=flag_format,
        start_time=datetime.now(tz=UTC).isoformat(),
    )

    save_competition(comp, target)

    console.print(
        Panel(
            f"[green]Competition initialized![/]\n\n"
            f"Name: [cyan]{name}[/]\n"
            f"Config: [cyan]{config_file}[/]\n\n"
            f"Next steps:\n"
            f"  [cyan]ctf competition add <challenge>[/] - Add a challenge\n"
            f"  [cyan]ctf competition team-add <name>[/] - Add team member\n"
            f"  [cyan]ctf competition status[/] - View scoreboard",
            title="Competition Ready",
        )
    )


@app.command(name="add")  # type: ignore[misc]
def add_challenge(
    name: Annotated[str, typer.Argument(help="Challenge name")],
    category: Annotated[
        str | None, typer.Option("--category", "-c", help="Challenge category")
    ] = None,
    points: Annotated[int | None, typer.Option("--points", "-p", help="Challenge points")] = None,
) -> None:
    """
    Add a challenge to the competition tracker.

    Examples:
        ctf competition add rsa-baby --category crypto --points 100
        ctf competition add web-sqli -c web -p 200
    """
    comp, root = _load_or_exit()

    try:
        entry = comp.add_challenge(name, category=category, points=points)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None

    save_competition(comp, root)
    console.print(
        f"[green]Added challenge:[/] [cyan]{entry.name}[/]"
        f"{f' ({entry.category})' if entry.category else ''}"
        f"{f' [{entry.points}pts]' if entry.points else ''}"
    )


@app.command(name="start")  # type: ignore[misc]
def start_challenge(
    name: Annotated[str, typer.Argument(help="Challenge name")],
    assigned_to: Annotated[
        str | None, typer.Option("--assign", "-a", help="Assign to team member")
    ] = None,
) -> None:
    """
    Mark a challenge as in-progress.

    Examples:
        ctf competition start rsa-baby
        ctf competition start rsa-baby --assign alice
    """
    comp, root = _load_or_exit()

    try:
        entry = comp.start_challenge(name, assigned_to=assigned_to)
    except KeyError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None

    save_competition(comp, root)
    msg = f"[yellow]Started:[/] [cyan]{entry.name}[/]"
    if entry.assigned_to:
        msg += f" (assigned to {entry.assigned_to})"
    console.print(msg)


@app.command(name="solve")  # type: ignore[misc]
def solve_challenge(
    name: Annotated[str, typer.Argument(help="Challenge name")],
    flag: Annotated[str | None, typer.Option("--flag", "-f", help="The captured flag")] = None,
    points: Annotated[int | None, typer.Option("--points", "-p", help="Points awarded")] = None,
) -> None:
    """
    Mark a challenge as solved.

    Examples:
        ctf competition solve rsa-baby --flag "flag{easy_rsa}" --points 100
        ctf competition solve web-sqli -f "flag{sql_master}"
    """
    comp, root = _load_or_exit()

    try:
        entry = comp.solve_challenge(name, flag=flag, points=points)
    except KeyError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None

    save_competition(comp, root)

    duration_str = ""
    if entry.solve_duration:
        minutes = int(entry.solve_duration.total_seconds() // 60)
        duration_str = f" in {minutes}m"

    console.print(
        f"[green]Solved:[/] [cyan]{entry.name}[/]{duration_str}"
        f"{f' [{entry.points}pts]' if entry.points else ''}"
    )


@app.command(name="status")  # type: ignore[misc]
def show_status(
    path: Annotated[
        Path | None,
        typer.Argument(help="Competition directory (default: current directory)"),
    ] = None,
    scan: Annotated[
        bool,
        typer.Option("--scan", "-s", help="Scan filesystem for challenge folders"),
    ] = False,
) -> None:
    """
    Show competition status and scoreboard.

    Examples:
        ctf competition status
        ctf competition status --scan
    """
    comp, root = _load_or_exit(path)

    if scan:
        scanned = scan_challenges(root)
        for entry in scanned:
            if not comp.get_challenge(entry.name):
                comp.challenges.append(entry)
        save_competition(comp, root)

    # Header
    console.print(Panel(f"[bold cyan]{comp.name}[/]", title="Competition"))

    # Summary stats
    console.print(
        f"  Solved: [green]{comp.solved_count}[/] | "
        f"In Progress: [yellow]{comp.in_progress_count}[/] | "
        f"Unsolved: [red]{comp.unsolved_count}[/] | "
        f"Total Points: [bold]{comp.total_points}[/]"
    )
    console.print()

    if not comp.challenges:
        console.print("[dim]No challenges tracked yet. Use 'ctf competition add' or '--scan'.[/]")
        return

    # Challenge table
    table = Table(title="Challenges")
    table.add_column("Challenge", style="cyan")
    table.add_column("Category", style="blue")
    table.add_column("Status")
    table.add_column("Points", justify="right")
    table.add_column("Assigned", style="dim")
    table.add_column("Time", style="dim")

    status_styles = {
        ChallengeStatus.SOLVED: "[green]solved[/]",
        ChallengeStatus.IN_PROGRESS: "[yellow]in_progress[/]",
        ChallengeStatus.UNSOLVED: "[red]unsolved[/]",
        ChallengeStatus.SKIPPED: "[dim]skipped[/]",
    }

    for ch in comp.challenges:
        duration = ""
        if ch.solve_duration:
            total_secs = int(ch.solve_duration.total_seconds())
            hours, remainder = divmod(total_secs, 3600)
            minutes = remainder // 60
            duration = f"{hours}h{minutes:02d}m" if hours else f"{minutes}m"

        table.add_row(
            ch.name,
            ch.category or "-",
            status_styles.get(ch.status, str(ch.status)),
            str(ch.points) if ch.points else "-",
            ch.assigned_to or "-",
            duration or "-",
        )

    console.print(table)

    # Team info
    if comp.team:
        console.print()
        console.print("[bold]Team:[/]")
        for member in comp.team:
            role_str = f" ({member.role})" if member.role else ""
            console.print(f"  - {member.name}{role_str}")


@app.command(name="team-add")  # type: ignore[misc]
def add_team_member(
    name: Annotated[str, typer.Argument(help="Team member name")],
    role: Annotated[str | None, typer.Option("--role", "-r", help="Team member role")] = None,
) -> None:
    """
    Add a team member to the competition.

    Examples:
        ctf competition team-add alice --role "crypto"
        ctf competition team-add bob -r "web/pwn"
    """
    comp, root = _load_or_exit()

    member = comp.add_team_member(name, role=role)
    save_competition(comp, root)

    msg = f"[green]Added team member:[/] [cyan]{member.name}[/]"
    if member.role:
        msg += f" (role: {member.role})"
    console.print(msg)
