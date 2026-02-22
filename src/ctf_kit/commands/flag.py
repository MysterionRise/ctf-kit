"""
Submit and validate CTF flags.

Saves the flag to flag.txt, updates .ctf/challenge.yaml with solved status,
and optionally validates against expected flag format.
"""

from pathlib import Path
import re
from typing import Annotated

from rich.console import Console
from rich.panel import Panel
import typer

from ctf_kit.config import (
    ChallengeConfig,
    load_challenge_config,
    load_config,
    save_challenge_config,
)

console = Console()


def _validate_flag_format(flag: str, patterns: list[str]) -> bool:
    """Check if flag matches any of the expected flag format patterns."""
    for pattern in patterns:
        try:
            if re.fullmatch(pattern, flag):
                return True
        except re.error:
            continue
    return False


def flag_command(
    flag_value: Annotated[
        str,
        typer.Argument(help="The flag to submit"),
    ],
    path: Annotated[
        Path | None,
        typer.Option("--path", "-p", help="Challenge directory (default: current directory)"),
    ] = None,
    no_validate: Annotated[
        bool,
        typer.Option("--no-validate", help="Skip flag format validation"),
    ] = False,
) -> None:
    """
    Submit a flag for the current challenge.

    Saves the flag to flag.txt, marks the challenge as solved in
    .ctf/challenge.yaml, and validates against known flag formats.

    Examples:
        ctf flag "flag{s0m3_fl4g_h3r3}"
        ctf flag "picoCTF{example}" --path ./crypto/rsa-baby
        ctf flag "non_standard_flag" --no-validate
    """
    target = path or Path.cwd()

    if not target.is_dir():
        console.print(f"[red]Not a directory:[/] {target}")
        raise typer.Exit(1)

    # Validate flag format unless skipped
    if not no_validate:
        config = load_config()
        if config.flag_formats and not _validate_flag_format(flag_value, config.flag_formats):
            console.print(
                f"[yellow]Warning:[/] Flag does not match expected formats: "
                f"{', '.join(config.flag_formats)}"
            )
            console.print("Use [cyan]--no-validate[/] to skip this check.\n")

    # Save flag to flag.txt
    flag_file = target / "flag.txt"
    flag_file.write_text(flag_value + "\n")

    # Update challenge config
    ctf_dir = target / ".ctf"
    challenge = load_challenge_config(target)

    if challenge:
        challenge.solved = True
        challenge.flag = flag_value
    else:
        # Create minimal config if .ctf/ exists but no challenge.yaml
        challenge = ChallengeConfig(
            name=target.name,
            solved=True,
            flag=flag_value,
        )

    # Ensure .ctf/ directory exists
    ctf_dir.mkdir(parents=True, exist_ok=True)
    save_challenge_config(challenge, target)

    # Display result
    flag_display = flag_value[:50] + "..." if len(flag_value) > 50 else flag_value

    console.print(
        Panel(
            f"[bold green]Flag submitted![/]\n\n"
            f"Challenge: [cyan]{challenge.name}[/]\n"
            f"Flag: [green]{flag_display}[/]\n"
            f"Saved to: [dim]{flag_file}[/]\n"
            f"Status: [bold green]SOLVED[/]",
            title="Flag Captured",
        )
    )
