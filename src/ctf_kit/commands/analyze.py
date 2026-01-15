"""
Analyze challenge files and detect category.
"""

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

console = Console()


# Type aliases for clarity
FileInfo = dict[str, Any]
SignatureInfo = dict[str, Any]


# File signatures for detection
FILE_SIGNATURES: dict[str, SignatureInfo] = {
    "PNG": {"magic": b"\x89PNG", "category": "stego", "tools": ["zsteg", "exiftool", "binwalk"]},
    "JPEG": {
        "magic": b"\xff\xd8\xff",
        "category": "stego",
        "tools": ["steghide", "exiftool", "binwalk"],
    },
    "GIF": {"magic": b"GIF8", "category": "stego", "tools": ["exiftool", "binwalk"]},
    "PDF": {
        "magic": b"%PDF",
        "category": "forensics",
        "tools": ["exiftool", "pdftotext", "binwalk"],
    },
    "ZIP": {"magic": b"PK\x03\x04", "category": "archive", "tools": ["unzip", "bkcrack", "john"]},
    "RAR": {"magic": b"Rar!", "category": "archive", "tools": ["unrar", "john"]},
    "7Z": {"magic": b"7z\xbc\xaf", "category": "archive", "tools": ["7z", "john"]},
    "GZIP": {"magic": b"\x1f\x8b", "category": "archive", "tools": ["gunzip", "zcat"]},
    "ELF": {"magic": b"\x7fELF", "category": "pwn", "tools": ["checksec", "file", "strings", "r2"]},
    "PE": {"magic": b"MZ", "category": "reversing", "tools": ["file", "strings", "r2"]},
    "PCAP": {"magic": b"\xd4\xc3\xb2\xa1", "category": "forensics", "tools": ["tshark", "tcpdump"]},
    "PCAPNG": {
        "magic": b"\x0a\x0d\x0d\x0a",
        "category": "forensics",
        "tools": ["tshark", "tcpdump"],
    },
    "SQLite": {"magic": b"SQLite", "category": "forensics", "tools": ["sqlite3"]},
}

# Content-based detection patterns
CONTENT_PATTERNS: dict[str, SignatureInfo] = {
    "RSA": {
        "patterns": [b"-----BEGIN", b"n = ", b"e = ", b"c = "],
        "category": "crypto",
        "tools": ["RsaCtfTool", "openssl"],
    },
    "Base64": {
        "patterns": [b"==", b"base64"],
        "category": "crypto",
        "tools": ["base64", "cyberchef"],
    },
    "Hex": {"patterns": [], "category": "crypto", "tools": ["xxd"]},
}

# Constants for text detection
ASCII_PRINTABLE_MIN = 32
ASCII_PRINTABLE_MAX = 127
WHITESPACE_CHARS = (9, 10, 13)  # tab, newline, carriage return
SAMPLE_SIZE = 1000
PRINTABLE_THRESHOLD = 0.8


def detect_file_type(file_path: Path) -> FileInfo:
    """Detect file type from magic bytes."""
    try:
        with file_path.open("rb") as f:
            header = f.read(16)

        for name, info in FILE_SIGNATURES.items():
            magic = info.get("magic", b"")
            if isinstance(magic, bytes) and header.startswith(magic):
                return {
                    "type": name,
                    "category": info["category"],
                    "tools": info["tools"],
                }

        # Try to detect text-based files
        try:
            content = file_path.read_bytes()
            # Check if mostly printable
            sample = content[:SAMPLE_SIZE]
            printable = sum(
                1
                for b in sample
                if ASCII_PRINTABLE_MIN <= b < ASCII_PRINTABLE_MAX or b in WHITESPACE_CHARS
            )
            if printable / max(len(sample), 1) > PRINTABLE_THRESHOLD:
                return {
                    "type": "TEXT",
                    "category": "misc",
                    "tools": ["strings", "file"],
                }
        except OSError:
            pass

        return {"type": "UNKNOWN", "category": "misc", "tools": ["file", "xxd"]}  # noqa: TRY300

    except OSError as e:
        return {"type": "ERROR", "category": None, "tools": [], "error": str(e)}


def analyze_challenge(
    path: Path | None = typer.Argument(None, help="Path to analyze (default: current directory)"),
    verbose: bool = typer.Option(  # noqa: ARG001
        False, "--verbose", "-v", help="Show detailed analysis"
    ),
) -> None:
    """
    Analyze challenge files and detect category.

    Examines files in the challenge folder and suggests:
    - Challenge category (crypto, forensics, pwn, etc.)
    - Recommended tools
    - Initial approach

    Examples:
        ctf analyze                  # Analyze current directory
        ctf analyze ./crypto/rsa     # Analyze specific folder
    """
    target_path = path or Path.cwd()

    if not target_path.exists():
        console.print(f"[red]Path not found: {target_path}[/]")
        raise typer.Exit(1)

    # Get all files
    if target_path.is_file():
        files = [target_path]
    else:
        files = [f for f in target_path.iterdir() if f.is_file() and not f.name.startswith(".")]

    if not files:
        console.print("[yellow]No files found to analyze[/]")
        raise typer.Exit(0)

    # Analyze each file
    results: list[FileInfo] = []
    category_votes: dict[str, int] = {}
    all_tools: set[str] = set()

    table = Table(title="File Analysis")
    table.add_column("File", style="cyan")
    table.add_column("Type")
    table.add_column("Category")
    table.add_column("Suggested Tools")

    for file in files:
        analysis = detect_file_type(file)
        results.append({"file": file, **analysis})

        if analysis.get("category"):
            cat = analysis["category"]
            category_votes[cat] = category_votes.get(cat, 0) + 1

        tools = analysis.get("tools", [])
        if isinstance(tools, list):
            all_tools.update(tools)

        table.add_row(
            file.name,
            str(analysis.get("type", "?")),
            str(analysis.get("category", "?")),
            ", ".join(tools[:3]) if isinstance(tools, list) else "",
        )

    console.print(table)
    console.print()

    # Determine primary category
    primary_category = "misc"
    if category_votes:
        primary_category = max(category_votes, key=lambda k: category_votes[k])

    # Summary panel
    summary = f"""[bold]Detected Category:[/] [cyan]{primary_category}[/]
[bold]Files:[/] {len(files)}
[bold]Suggested Tools:[/] {', '.join(sorted(all_tools)[:5])}

[bold]Next Steps:[/]
  1. Launch your AI agent: [cyan]claude[/] or [cyan]cursor .[/]
  2. Run: [bold cyan]/ctf.analyze[/] for detailed AI analysis
  3. Or: [bold cyan]/ctf.{primary_category}[/] for category-specific help"""

    console.print(Panel(summary, title="Analysis Summary"))
