"""
Set competition context for the current challenge directory.

This is the AI-agent-facing companion to `ctf init`. It initializes
a .ctf/ folder, detects existing files, and creates a challenge.yaml
with metadata so that /ctf-status and /ctf-flag know what's going on.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from ctf_kit.config import ChallengeConfig, load_challenge_config, save_challenge_config

console = Console()


def _detect_files(path: Path) -> list[Path]:
    """Return non-hidden files in the challenge directory."""
    return sorted(f for f in path.iterdir() if f.is_file() and not f.name.startswith("."))


def _guess_category(files: list[Path]) -> str | None:
    """Heuristic category guess from filenames and extensions."""
    names = " ".join(f.name.lower() for f in files)
    extensions = {f.suffix.lower() for f in files}

    # Extension-based hints
    if extensions & {".pcap", ".pcapng", ".mem", ".raw", ".dmp", ".E01"}:
        return "forensics"
    if extensions & {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".wav", ".mp3"}:
        return "stego"
    if extensions & {".elf", ".exe", ".so", ".dll", ".bin"} or any("libc" in f.name for f in files):
        return "pwn"

    # Name-based hints
    if any(kw in names for kw in ("rsa", "aes", "cipher", "encrypt", "decrypt", "xor")):
        return "crypto"
    if any(kw in names for kw in ("index.html", "app.py", "server", "flask", "django")):
        return "web"
    if any(kw in names for kw in ("crackme", "reverse", "keygen")):
        return "reversing"

    return None


def here_command(
    path: Annotated[
        Path | None,
        typer.Argument(help="Challenge directory (default: current directory)"),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", "-c", help="Challenge category hint"),
    ] = None,
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Challenge name (default: directory name)"),
    ] = None,
    flag_format: Annotated[
        str | None,
        typer.Option("--flag-format", "-f", help="Expected flag format regex"),
    ] = None,
    points: Annotated[
        int | None,
        typer.Option("--points", "-p", help="Challenge point value"),
    ] = None,
) -> None:
    """
    Set competition context for a challenge directory.

    Initializes .ctf/ if needed, detects files, guesses category,
    and saves challenge metadata to .ctf/challenge.yaml.

    Examples:
        ctf here                           # Current directory
        ctf here -c crypto                 # With category hint
        ctf here -n "RSA Baby" -p 100      # With name and points
        ctf here path/to/challenge         # Specific path
    """
    target = path or Path.cwd()

    if not target.is_dir():
        console.print(f"[red]Not a directory:[/] {target}")
        raise typer.Exit(1)

    ctf_dir = target / ".ctf"
    is_new = not ctf_dir.exists()

    # Create .ctf/ structure if it doesn't exist
    if is_new:
        ctf_dir.mkdir(parents=True)
        (ctf_dir / "artifacts").mkdir()

    # Detect files
    files = _detect_files(target)

    # Determine category
    resolved_category = category or _guess_category(files)

    # Load or create challenge config
    challenge_name = name or target.name
    existing = load_challenge_config(target)

    if existing:
        # Update existing config with any new overrides
        if category:
            existing.category = category
        if name:
            existing.name = name
        if flag_format:
            existing.flag_format = flag_format
        if points is not None:
            existing.points = points
        config = existing
    else:
        config = ChallengeConfig(
            name=challenge_name,
            category=resolved_category,
            flag_format=flag_format,
            points=points,
        )

    save_challenge_config(config, target)

    # Create analysis/approach/attempts templates if new
    if is_new:
        _write_templates(ctf_dir, challenge_name, resolved_category, files)

    # Display summary
    _show_summary(target, config, files, is_new)


def _write_templates(
    ctf_dir: Path,
    challenge_name: str,
    category: str | None,
    files: list[Path],
) -> None:
    """Write initial .ctf/ template files."""
    files_list = "\n".join(f"- `{f.name}`" for f in files) or "- No files detected"
    detected_time = datetime.now(tz=UTC).isoformat()

    analysis = f"""# Challenge Analysis

## Metadata
- **Name**: {challenge_name}
- **Category**: {category or "Unknown"}
- **Detected**: {detected_time}

## Files
{files_list}

## Initial Observations
<!-- AI will fill this section -->

## Potential Approaches
<!-- AI will fill this section -->

## Required Tools
<!-- AI will fill this section -->
"""
    (ctf_dir / "analysis.md").write_text(analysis)

    approach = """# Solution Approach

## Selected Strategy
<!-- Describe the chosen approach -->

## Step-by-Step Plan
1. [ ] Step 1
2. [ ] Step 2
3. [ ] Step 3

## Key Insights
<!-- Important observations -->

## Resources
<!-- Helpful links and references -->
"""
    (ctf_dir / "approach.md").write_text(approach)

    (ctf_dir / "attempts.md").write_text(
        "# Solution Attempts\n\n<!-- Track what you've tried -->\n"
    )


def _show_summary(
    target: Path,
    config: ChallengeConfig,
    files: list[Path],
    is_new: bool,
) -> None:
    """Display a rich summary panel."""
    # Build file table
    file_table = Table(show_header=False, box=None, padding=(0, 1))
    file_table.add_column("File", style="cyan")
    file_table.add_column("Size", style="dim")
    for f in files[:15]:  # Cap at 15 for readability
        size = f.stat().st_size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        file_table.add_row(f.name, size_str)
    if len(files) > 15:
        file_table.add_row(f"... and {len(files) - 15} more", "")

    # Check for flag.txt
    flag_file = target / "flag.txt"
    solved_str = ""
    if config.solved and config.flag:
        solved_str = (
            f"\nFlag: [green]{config.flag[:30]}...[/]"
            if len(config.flag) > 30
            else f"\nFlag: [green]{config.flag}[/]"
        )
    elif flag_file.exists():
        solved_str = "\nFlag file: [green]flag.txt found[/]"

    action = "initialized" if is_new else "updated"

    console.print(
        Panel(
            f"[green]Challenge {action}:[/] [bold]{config.name}[/]\n"
            f"Category: [cyan]{config.category or 'Unknown'}[/]\n"
            f"Files: {len(files)}"
            f"{f' | Points: {config.points}' if config.points else ''}"
            f"{solved_str}\n",
            title="CTF Here",
        )
    )

    if files:
        console.print(file_table)
        console.print()

    if is_new:
        console.print("Next: Use [bold cyan]/ctf-kit:analyze[/] to examine the challenge files.")
