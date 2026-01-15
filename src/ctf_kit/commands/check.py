"""
Check installed tools and system requirements.
"""

import shutil
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()

# Type alias for tool info
ToolInfo = dict[str, str]

# Tool registry with installation info
TOOL_REGISTRY: dict[str, dict[str, ToolInfo]] = {
    "essential": {
        "file": {"binary": "file", "description": "File type identification"},
        "strings": {"binary": "strings", "description": "Extract printable strings"},
        "xxd": {"binary": "xxd", "description": "Hex dump"},
        "python3": {"binary": "python3", "description": "Python interpreter"},
    },
    "crypto": {
        "xortool": {
            "binary": "xortool",
            "description": "XOR cipher analysis",
            "install": "pip install xortool",
        },
        "hashcat": {
            "binary": "hashcat",
            "description": "Password cracking",
            "install": "apt install hashcat",
        },
        "john": {"binary": "john", "description": "John the Ripper", "install": "apt install john"},
        "hashid": {
            "binary": "hashid",
            "description": "Hash identification",
            "install": "pip install hashid",
        },
    },
    "archive": {
        "bkcrack": {"binary": "bkcrack", "description": "ZIP known plaintext attack"},
        "zip2john": {"binary": "zip2john", "description": "ZIP hash extractor"},
        "fcrackzip": {
            "binary": "fcrackzip",
            "description": "ZIP password cracker",
            "install": "apt install fcrackzip",
        },
    },
    "forensics": {
        "binwalk": {
            "binary": "binwalk",
            "description": "Firmware analysis",
            "install": "apt install binwalk",
        },
        "foremost": {
            "binary": "foremost",
            "description": "File carving",
            "install": "apt install foremost",
        },
        "volatility3": {
            "binary": "vol",
            "description": "Memory forensics",
            "install": "pip install volatility3",
        },
        "tshark": {
            "binary": "tshark",
            "description": "Packet analysis",
            "install": "apt install tshark",
        },
        "exiftool": {
            "binary": "exiftool",
            "description": "Metadata extraction",
            "install": "apt install exiftool",
        },
    },
    "stego": {
        "zsteg": {
            "binary": "zsteg",
            "description": "PNG/BMP steganography",
            "install": "gem install zsteg",
        },
        "steghide": {
            "binary": "steghide",
            "description": "JPEG/WAV steganography",
            "install": "apt install steghide",
        },
    },
    "web": {
        "sqlmap": {
            "binary": "sqlmap",
            "description": "SQL injection",
            "install": "apt install sqlmap",
        },
        "gobuster": {
            "binary": "gobuster",
            "description": "Directory bruteforce",
            "install": "apt install gobuster",
        },
        "ffuf": {
            "binary": "ffuf",
            "description": "Web fuzzer",
            "install": "go install github.com/ffuf/ffuf/v2@latest",
        },
    },
    "pwn": {
        "gdb": {"binary": "gdb", "description": "GNU Debugger", "install": "apt install gdb"},
        "ROPgadget": {
            "binary": "ROPgadget",
            "description": "ROP chain finder",
            "install": "pip install ROPgadget",
        },
        "one_gadget": {
            "binary": "one_gadget",
            "description": "One-shot RCE finder",
            "install": "gem install one_gadget",
        },
    },
    "reversing": {
        "radare2": {
            "binary": "r2",
            "description": "Reverse engineering",
            "install": "apt install radare2",
        },
        "objdump": {
            "binary": "objdump",
            "description": "Object file analysis",
            "install": "apt install binutils",
        },
    },
    "osint": {
        "sherlock": {
            "binary": "sherlock",
            "description": "Username search",
            "install": "pip install sherlock-project",
        },
    },
}


def check_tool(binary: str) -> bool:
    """Check if a tool is installed."""
    return shutil.which(binary) is not None


def check_tools(
    category: str | None = None,
    verbose: bool = False,
) -> None:
    """
    Check which tools are installed.

    Args:
        category: Filter by category (crypto, forensics, etc.)
        verbose: Show installation commands
    """
    categories: Any = [category] if category else TOOL_REGISTRY.keys()

    total_installed = 0
    total_tools = 0

    for cat in categories:
        if cat not in TOOL_REGISTRY:
            console.print(f"[red]Unknown category: {cat}[/]")
            continue

        table = Table(title=f"{cat.upper()}")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Description")
        if verbose:
            table.add_column("Install Command")

        for name, info in TOOL_REGISTRY[cat].items():
            installed = check_tool(info["binary"])
            status = "[green]OK[/]" if installed else "[red]Missing[/]"

            if installed:
                total_installed += 1
            total_tools += 1

            row: list[str] = [name, status, info["description"]]
            if verbose:
                row.append(info.get("install", ""))

            table.add_row(*row)

        console.print(table)
        console.print()

    # Summary
    percentage = (total_installed / total_tools * 100) if total_tools > 0 else 0
    console.print(
        f"[bold]Total: {total_installed}/{total_tools} tools installed ({percentage:.0f}%)[/]"
    )


def list_tools(category: str | None = None, show_install: bool = False) -> None:
    """List all available tools."""
    check_tools(category=category, verbose=show_install)
