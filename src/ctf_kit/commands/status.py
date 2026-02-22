"""
Show CTF challenge progress dashboard.

Reads .ctf/ metadata and displays a summary of challenge state,
files, tools available, and solve status.
"""

from pathlib import Path
from typing import Annotated

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer
import yaml

from ctf_kit.config import load_challenge_config

console = Console()


def _find_challenges(root: Path) -> list[Path]:
    """Find all subdirectories containing .ctf/ folders."""
    challenges = []
    for ctf_dir in root.rglob(".ctf"):
        if ctf_dir.is_dir() and ctf_dir.parent != root:
            challenges.append(ctf_dir.parent)
    # Also check root itself
    if (root / ".ctf").is_dir():
        challenges.insert(0, root)
    return challenges


def _read_competition_meta(path: Path) -> dict | None:
    """Read .ctf-competition.yaml if present."""
    comp_file = path / ".ctf-competition.yaml"
    if not comp_file.exists():
        return None
    with comp_file.open() as f:
        return yaml.safe_load(f) or {}


def _format_size(size: int) -> str:
    """Format file size as human-readable string."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _print_file_table(files: list[Path]) -> None:
    """Print a table of challenge files."""
    file_table = Table(title="Challenge Files", show_header=True, header_style="bold")
    file_table.add_column("File", style="cyan")
    file_table.add_column("Size", justify="right", style="dim")
    file_table.add_column("Type", style="yellow")

    for f in files[:20]:
        ext = f.suffix.lower() or "(none)"
        file_table.add_row(f.name, _format_size(f.stat().st_size), ext)

    if len(files) > 20:
        file_table.add_row(f"... +{len(files) - 20} more", "", "")

    console.print(file_table)
    console.print()


def _print_notes_table(ctf_files: list[Path]) -> None:
    """Print a table of .ctf/ note files."""
    notes_table = Table(title="CTF Kit Notes", show_header=False, box=None)
    notes_table.add_column("File", style="cyan")
    notes_table.add_column("Status", style="dim")
    for f in ctf_files:
        content = f.read_text().strip() if f.stat().st_size < 10_000 else ""
        has_content = bool(content) and "<!-- " not in content.split("\n")[-1]
        status = "has content" if has_content else "template only"
        notes_table.add_row(f.name, status)
    console.print(notes_table)
    console.print()


def _show_single_challenge(target: Path) -> None:
    """Show status for a single challenge directory."""
    config = load_challenge_config(target)
    ctf_dir = target / ".ctf"

    if not ctf_dir.exists():
        console.print(
            f"[yellow]No .ctf/ folder in {target}.[/] Run [cyan]ctf here[/] to set up context."
        )
        raise typer.Exit(1)

    # Challenge metadata
    name = config.name if config else target.name
    category = config.category if config else "Unknown"
    solved = config.solved if config else False
    flag = config.flag if config else None
    points = config.points if config else None

    # Check for flag.txt as fallback
    flag_file = target / "flag.txt"
    if not flag and flag_file.exists():
        flag = flag_file.read_text().strip()
        solved = bool(flag)

    # Build and print status panel
    status_str = "[bold green]SOLVED[/]" if solved else "[bold yellow]IN PROGRESS[/]"
    info_lines = [
        f"[bold]{name}[/]  {status_str}",
        f"Category: [cyan]{category}[/]",
    ]
    if points:
        info_lines.append(f"Points: [cyan]{points}[/]")
    if flag:
        flag_display = flag[:40] + "..." if len(flag) > 40 else flag
        info_lines.append(f"Flag: [green]{flag_display}[/]")

    console.print(Panel("\n".join(info_lines), title="Challenge Status"))

    # File and notes tables
    files = sorted(f for f in target.iterdir() if f.is_file() and not f.name.startswith("."))
    if files:
        _print_file_table(files)

    ctf_files = sorted(f for f in ctf_dir.iterdir() if f.is_file())
    if ctf_files:
        _print_notes_table(ctf_files)


def _show_competition_dashboard(root: Path) -> None:
    """Show overview dashboard for a competition directory."""
    meta = _read_competition_meta(root)
    challenges = _find_challenges(root)

    # Header
    comp_name = meta.get("name", root.name) if meta else root.name
    console.print(Panel(f"[bold]{comp_name}[/]", title="Competition Dashboard"))

    if not challenges:
        console.print("[yellow]No challenges found. Create challenge folders and run ctf here.[/]")
        return

    # Build summary table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Challenge", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Status", justify="center")
    table.add_column("Points", justify="right", style="dim")

    solved_count = 0
    total_points = 0

    for ch_path in sorted(challenges):
        config = load_challenge_config(ch_path)
        ch_name = config.name if config else ch_path.name
        ch_category = config.category if config else "?"
        ch_points = config.points if config else None
        ch_solved = config.solved if config else False

        # Check flag.txt fallback
        if not ch_solved and (ch_path / "flag.txt").exists():
            ch_solved = bool((ch_path / "flag.txt").read_text().strip())

        status = "[green]SOLVED[/]" if ch_solved else "[yellow]...[/]"
        if ch_solved:
            solved_count += 1
            if ch_points:
                total_points += ch_points

        table.add_row(
            ch_name,
            ch_category or "?",
            status,
            str(ch_points) if ch_points else "-",
        )

    console.print(table)
    console.print(
        f"\n[bold]Progress:[/] {solved_count}/{len(challenges)} solved"
        f"{f' | {total_points} points' if total_points else ''}"
    )


def status_command(
    path: Annotated[
        Path | None,
        typer.Argument(help="Challenge or competition directory (default: current directory)"),
    ] = None,
    competition: Annotated[
        bool,
        typer.Option("--competition", "-C", help="Show competition-level dashboard"),
    ] = False,
) -> None:
    """
    Show CTF challenge or competition status.

    Without flags, shows status for the current challenge directory.
    With --competition, scans subdirectories for a competition overview.

    Examples:
        ctf status                    # Current challenge status
        ctf status --competition      # Competition dashboard
        ctf status path/to/challenge  # Specific challenge
    """
    target = path or Path.cwd()

    if not target.is_dir():
        console.print(f"[red]Not a directory:[/] {target}")
        raise typer.Exit(1)

    if competition or (target / ".ctf-competition.yaml").exists():
        _show_competition_dashboard(target)
    else:
        _show_single_challenge(target)
