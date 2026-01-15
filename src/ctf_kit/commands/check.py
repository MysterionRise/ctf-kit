"""
Check installed tools and system requirements.
"""

import contextlib
import shutil

from rich.console import Console
from rich.table import Table
import typer

from ctf_kit.integrations.base import (
    ToolCategory,
    get_all_tools,
    get_tools_by_category,
)

console = Console()


# Tool registry with installation info (for tools not yet wrapped)
TOOL_REGISTRY: dict[str, dict[str, dict[str, str]]] = {
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
            "install": "brew install hashcat",
        },
        "john": {
            "binary": "john",
            "description": "John the Ripper",
            "install": "brew install john",
        },
        "hashid": {
            "binary": "hashid",
            "description": "Hash identification",
            "install": "pip install hashid",
        },
        "openssl": {"binary": "openssl", "description": "Crypto toolkit"},
    },
    "archive": {
        "bkcrack": {"binary": "bkcrack", "description": "ZIP known plaintext attack"},
        "zip2john": {"binary": "zip2john", "description": "ZIP hash extractor"},
        "fcrackzip": {
            "binary": "fcrackzip",
            "description": "ZIP password cracker",
            "install": "brew install fcrackzip",
        },
        "7z": {"binary": "7z", "description": "7-zip archiver", "install": "brew install p7zip"},
    },
    "forensics": {
        "binwalk": {
            "binary": "binwalk",
            "description": "Firmware analysis",
            "install": "brew install binwalk",
        },
        "foremost": {
            "binary": "foremost",
            "description": "File carving",
            "install": "brew install foremost",
        },
        "volatility3": {
            "binary": "vol",
            "description": "Memory forensics",
            "install": "pip install volatility3",
        },
        "tshark": {
            "binary": "tshark",
            "description": "Packet analysis",
            "install": "brew install wireshark",
        },
        "exiftool": {
            "binary": "exiftool",
            "description": "Metadata extraction",
            "install": "brew install exiftool",
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
            "install": "brew install steghide",
        },
        "stegsolve": {
            "binary": "stegsolve",
            "description": "Image steganography analysis",
        },
    },
    "web": {
        "sqlmap": {
            "binary": "sqlmap",
            "description": "SQL injection",
            "install": "brew install sqlmap",
        },
        "gobuster": {
            "binary": "gobuster",
            "description": "Directory bruteforce",
            "install": "brew install gobuster",
        },
        "ffuf": {
            "binary": "ffuf",
            "description": "Web fuzzer",
            "install": "brew install ffuf",
        },
        "nikto": {
            "binary": "nikto",
            "description": "Web vulnerability scanner",
            "install": "brew install nikto",
        },
    },
    "pwn": {
        "gdb": {"binary": "gdb", "description": "GNU Debugger", "install": "brew install gdb"},
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
        "checksec": {
            "binary": "checksec",
            "description": "Binary security checker",
            "install": "pip install checksec.py",
        },
        "pwntools": {
            "binary": "pwn",
            "description": "CTF exploitation framework",
            "install": "pip install pwntools",
        },
    },
    "reversing": {
        "radare2": {
            "binary": "r2",
            "description": "Reverse engineering",
            "install": "brew install radare2",
        },
        "objdump": {
            "binary": "objdump",
            "description": "Object file analysis",
            "install": "brew install binutils",
        },
        "nm": {
            "binary": "nm",
            "description": "Symbol table viewer",
        },
        "ltrace": {
            "binary": "ltrace",
            "description": "Library call tracer",
        },
        "strace": {
            "binary": "strace",
            "description": "System call tracer",
        },
    },
    "osint": {
        "sherlock": {
            "binary": "sherlock",
            "description": "Username search",
            "install": "pip install sherlock-project",
        },
        "theHarvester": {
            "binary": "theHarvester",
            "description": "Email/domain harvester",
            "install": "pip install theHarvester",
        },
    },
}


def check_tool(binary: str) -> bool:
    """Check if a tool is installed."""
    return shutil.which(binary) is not None


def check_tools(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show installation commands"),
    registered: bool = typer.Option(
        False, "--registered", "-r", help="Show registered tool wrappers"
    ),
) -> None:
    """
    Check which CTF tools are installed.

    Shows tool availability and installation commands.

    Examples:
        ctf check                    # Check all tools
        ctf check --category crypto  # Check only crypto tools
        ctf check -v                 # Show install commands
    """
    if registered:
        _show_registered_tools(category)
        return

    categories: list[str] = [category] if category else list(TOOL_REGISTRY.keys())

    total_installed = 0
    total_tools = 0

    for cat in categories:
        if cat not in TOOL_REGISTRY:
            console.print(f"[red]Unknown category: {cat}[/]")
            console.print(f"Available: {', '.join(TOOL_REGISTRY.keys())}")
            continue

        table = Table(title=f"[bold]{cat.upper()}[/]")
        table.add_column("Tool", style="cyan", no_wrap=True)
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
    color = "green" if percentage >= 70 else "yellow" if percentage >= 40 else "red"
    console.print(
        f"[bold]Total: [{color}]{total_installed}/{total_tools}[/{color}] tools installed ({percentage:.0f}%)[/]"
    )

    if percentage < 50:
        console.print("\n[yellow]Tip: Run 'ctf check -v' to see installation commands[/]")


def _show_registered_tools(category: str | None) -> None:
    """Show tools registered with the wrapper system."""
    # Import tool implementations to register them
    with contextlib.suppress(ImportError):
        from ctf_kit.integrations import basic  # noqa: F401

    if category:
        try:
            cat_enum = ToolCategory(category)
            tools = get_tools_by_category(cat_enum)
        except ValueError:
            console.print(f"[red]Unknown category: {category}[/]")
            return
    else:
        tools = get_all_tools()

    if not tools:
        console.print("[yellow]No tool wrappers registered yet[/]")
        return

    table = Table(title="[bold]Registered Tool Wrappers[/]")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Category")
    table.add_column("Description")
    table.add_column("Version")

    for name, tool in sorted(tools.items()):
        installed = tool.is_installed
        status = "[green]OK[/]" if installed else "[red]Missing[/]"
        version = tool.get_version() if installed else "-"

        table.add_row(
            name,
            status,
            tool.category.value,
            tool.description[:50],
            version[:30] if version else "-",
        )

    console.print(table)


def list_tools(category: str | None = None, show_install: bool = False) -> None:
    """List all available tools (alias for check_tools)."""
    check_tools(category=category, verbose=show_install)


def get_missing_tools(category: str | None = None) -> list[str]:
    """Get list of missing tools."""
    categories = [category] if category else list(TOOL_REGISTRY.keys())
    missing: list[str] = []

    for cat in categories:
        if cat in TOOL_REGISTRY:
            for name, info in TOOL_REGISTRY[cat].items():
                if not check_tool(info["binary"]):
                    missing.append(name)

    return missing


def get_installed_tools(category: str | None = None) -> list[str]:
    """Get list of installed tools."""
    categories = [category] if category else list(TOOL_REGISTRY.keys())
    installed: list[str] = []

    for cat in categories:
        if cat in TOOL_REGISTRY:
            for name, info in TOOL_REGISTRY[cat].items():
                if check_tool(info["binary"]):
                    installed.append(name)

    return installed
