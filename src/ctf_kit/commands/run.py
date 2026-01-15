"""
Run CTF tools directly from the CLI.
"""

import shutil
import subprocess  # nosec B404 - subprocess is required for tool execution
from typing import Annotated, Any

from rich.console import Console
import typer

console = Console()

# Tool shortcuts for common operations
TOOL_SHORTCUTS: dict[str, dict[str, Any]] = {
    "zsteg": {"binary": "zsteg", "default_args": ["-a"]},
    "binwalk": {"binary": "binwalk", "default_args": []},
    "exiftool": {"binary": "exiftool", "default_args": []},
    "strings": {"binary": "strings", "default_args": []},
    "file": {"binary": "file", "default_args": []},
    "xxd": {"binary": "xxd", "default_args": []},
    "volatility": {"binary": "vol", "default_args": []},
    "vol": {"binary": "vol", "default_args": []},
    "tshark": {"binary": "tshark", "default_args": []},
    "hashid": {"binary": "hashid", "default_args": []},
    "xortool": {"binary": "xortool", "default_args": []},
    "bkcrack": {"binary": "bkcrack", "default_args": []},
    "john": {"binary": "john", "default_args": []},
    "hashcat": {"binary": "hashcat", "default_args": []},
    "sqlmap": {"binary": "sqlmap", "default_args": []},
    "gobuster": {"binary": "gobuster", "default_args": []},
    "r2": {"binary": "r2", "default_args": []},
    "radare2": {"binary": "r2", "default_args": []},
}


def run_tool(
    tool: Annotated[str, typer.Argument(help="Tool to run (e.g., zsteg, binwalk, volatility)")],
    args: Annotated[list[str] | None, typer.Argument(help="Arguments to pass to the tool")] = None,
) -> None:
    """
    Run a CTF tool directly.

    Examples:
        ctf run zsteg image.png
        ctf run binwalk -e firmware.bin
        ctf run volatility -f memory.dmp windows.pslist
        ctf run bkcrack -L encrypted.zip
    """
    # Resolve tool shortcut
    if tool in TOOL_SHORTCUTS:
        tool_info = TOOL_SHORTCUTS[tool]
        binary: str = tool_info["binary"]
        default_args: list[str] = tool_info["default_args"]
    else:
        binary = tool
        default_args = []

    # Check if tool is installed
    binary_path = shutil.which(binary)
    if not binary_path:
        console.print(f"[red]Tool not found: [cyan]{tool}[/][/]")
        console.print(f"  Binary searched: {binary}")
        console.print("\n  Try: [cyan]ctf check --category all[/] to see installation commands")
        raise typer.Exit(1)

    # Build command
    cmd: list[str] = [binary_path, *default_args, *(args or [])]

    console.print(f"[dim]Running: {' '.join(cmd)}[/]\n")

    # Run the tool
    try:
        result = subprocess.run(cmd, check=False)  # nosec B603 - intentional tool execution
        raise typer.Exit(result.returncode)  # noqa: TRY301
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
        raise typer.Exit(130) from None
    except typer.Exit:
        raise
    except OSError as e:
        console.print(f"[red]Error running {tool}: {e}[/]")
        raise typer.Exit(1) from None
