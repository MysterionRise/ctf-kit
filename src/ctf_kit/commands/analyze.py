"""
Analyze challenge files and detect category.
"""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from ctf_kit.utils.file_detection import (
    CTFCategory,
    FileInfo,
    analyze_directory,
    detect_file_type,
    format_size,
)

console = Console()


# Tool recommendations by category
CATEGORY_TOOLS: dict[CTFCategory, list[str]] = {
    CTFCategory.CRYPTO: ["xortool", "hashid", "openssl", "RsaCtfTool", "cyberchef"],
    CTFCategory.FORENSICS: ["binwalk", "volatility", "tshark", "foremost", "exiftool"],
    CTFCategory.STEGO: ["zsteg", "steghide", "exiftool", "binwalk", "stegsolve"],
    CTFCategory.WEB: ["sqlmap", "gobuster", "ffuf", "nikto", "burpsuite"],
    CTFCategory.PWN: ["checksec", "gdb", "ROPgadget", "one_gadget", "pwntools"],
    CTFCategory.REVERSING: ["radare2", "ghidra", "ida", "objdump", "strings"],
    CTFCategory.OSINT: ["sherlock", "theHarvester", "maltego", "recon-ng"],
    CTFCategory.MISC: ["file", "strings", "xxd", "cyberchef"],
}

# Next steps by category
CATEGORY_APPROACHES: dict[CTFCategory, list[str]] = {
    CTFCategory.CRYPTO: [
        "Identify the cipher/encoding type",
        "Check for weak RSA parameters (small e, common n)",
        "Try frequency analysis for classical ciphers",
        "Look for padding oracle or timing attacks",
    ],
    CTFCategory.FORENSICS: [
        "Extract metadata with exiftool",
        "Search for embedded files with binwalk",
        "Analyze network captures for credentials/flags",
        "Check memory dumps for processes and artifacts",
    ],
    CTFCategory.STEGO: [
        "Check metadata with exiftool",
        "Run zsteg (PNG/BMP) or steghide (JPEG)",
        "Look at LSB (least significant bit) data",
        "Check for hidden data in color channels",
    ],
    CTFCategory.WEB: [
        "Check robots.txt and common paths",
        "Look for SQL injection points",
        "Test for XSS vulnerabilities",
        "Check for path traversal or LFI/RFI",
    ],
    CTFCategory.PWN: [
        "Run checksec to see protections",
        "Look for buffer overflow opportunities",
        "Find ROP gadgets for return-oriented programming",
        "Check for format string vulnerabilities",
    ],
    CTFCategory.REVERSING: [
        "Run strings to find readable text",
        "Identify the architecture and protections",
        "Load in Ghidra/radare2 for disassembly",
        "Look for hardcoded credentials or flags",
    ],
    CTFCategory.OSINT: [
        "Search for usernames across platforms",
        "Check social media accounts",
        "Use Google dorks for information gathering",
        "Look for leaked credentials or data",
    ],
    CTFCategory.MISC: [
        "Run file command to identify type",
        "Extract strings from binary data",
        "Check for base64/hex encoding",
        "Look for common CTF patterns",
    ],
}


def analyze_challenge(
    path: Path | None = typer.Argument(None, help="Path to analyze (default: current directory)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis"),
    output_md: bool = typer.Option(False, "--markdown", "-m", help="Output as markdown"),
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
        ctf analyze -v               # Detailed analysis
    """
    target_path = path or Path.cwd()

    if not target_path.exists():
        console.print(f"[red]Path not found: {target_path}[/]")
        raise typer.Exit(1)

    # Analyze files
    if target_path.is_file():
        files = [detect_file_type(target_path)]
    else:
        files = analyze_directory(target_path)

    if not files:
        console.print("[yellow]No files found to analyze[/]")
        raise typer.Exit(0)

    # Count category votes
    category_votes: dict[CTFCategory, int] = {}
    all_content_matches: list[str] = []

    for file_info in files:
        if file_info.suggested_category:
            cat = file_info.suggested_category
            category_votes[cat] = category_votes.get(cat, 0) + 1
        all_content_matches.extend(file_info.content_matches)

    # Determine primary category
    primary_category = CTFCategory.MISC
    if category_votes:
        primary_category = max(category_votes, key=lambda k: category_votes[k])

    if output_md:
        _output_markdown(files, primary_category, all_content_matches)
    else:
        _output_rich(files, primary_category, all_content_matches, verbose)


def _output_rich(
    files: list[FileInfo],
    primary_category: CTFCategory,
    content_matches: list[str],
    verbose: bool,
) -> None:
    """Output analysis in rich console format."""
    # File table
    table = Table(title="[bold]File Analysis[/]")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Size", justify="right")
    table.add_column("Type")
    table.add_column("Category")

    if verbose:
        table.add_column("Matches")

    for file_info in files:
        category_str = file_info.suggested_category.value if file_info.suggested_category else "?"
        row = [
            file_info.name,
            format_size(file_info.size),
            file_info.file_type[:40],
            category_str,
        ]

        if verbose:
            matches = ", ".join(file_info.content_matches[:2]) if file_info.content_matches else "-"
            row.append(matches[:40])

        table.add_row(*row)

    console.print(table)
    console.print()

    # Content matches
    if content_matches:
        unique_matches = list(set(content_matches))[:5]
        console.print("[bold]Interesting patterns found:[/]")
        for match in unique_matches:
            console.print(f"  - {match}")
        console.print()

    # Recommended tools
    tools = CATEGORY_TOOLS.get(primary_category, CATEGORY_TOOLS[CTFCategory.MISC])
    tools_str = ", ".join(tools[:5])

    # Next steps
    approaches = CATEGORY_APPROACHES.get(primary_category, CATEGORY_APPROACHES[CTFCategory.MISC])

    # Summary panel
    summary = f"""[bold]Detected Category:[/] [cyan]{primary_category.value}[/]
[bold]Files:[/] {len(files)}
[bold]Suggested Tools:[/] {tools_str}

[bold]Suggested Approach:[/]"""

    for i, approach in enumerate(approaches[:3], 1):
        summary += f"\n  {i}. {approach}"

    summary += f"""

[bold]Next Steps:[/]
  1. Launch your AI agent: [cyan]claude[/]
  2. Run: [bold cyan]/ctf.analyze[/] for AI-assisted analysis
  3. Or: [bold cyan]/ctf.{primary_category.value}[/] for category-specific help"""

    console.print(Panel(summary, title="Analysis Summary"))


def _output_markdown(
    files: list[FileInfo],
    primary_category: CTFCategory,
    content_matches: list[str],
) -> None:
    """Output analysis as markdown."""
    lines = ["# Challenge Analysis", ""]

    # File table
    lines.append("## Files")
    lines.append("")
    lines.append("| File | Size | Type | Category |")
    lines.append("|------|------|------|----------|")

    for file_info in files:
        category_str = file_info.suggested_category.value if file_info.suggested_category else "?"
        lines.append(
            f"| {file_info.name} | {format_size(file_info.size)} | "
            f"{file_info.file_type[:30]} | {category_str} |"
        )

    lines.append("")

    # Content matches
    if content_matches:
        lines.append("## Interesting Patterns")
        lines.append("")
        unique_matches = list(set(content_matches))[:5]
        lines.extend(f"- {match}" for match in unique_matches)
        lines.append("")

    # Category
    lines.append("## Detected Category")
    lines.append("")
    lines.append(f"**{primary_category.value}**")
    lines.append("")

    # Tools
    tools = CATEGORY_TOOLS.get(primary_category, CATEGORY_TOOLS[CTFCategory.MISC])
    lines.append("## Recommended Tools")
    lines.append("")
    lines.extend(f"- {tool}" for tool in tools[:5])
    lines.append("")

    # Approaches
    approaches = CATEGORY_APPROACHES.get(primary_category, CATEGORY_APPROACHES[CTFCategory.MISC])
    lines.append("## Suggested Approach")
    lines.append("")
    for i, approach in enumerate(approaches[:4], 1):
        lines.append(f"{i}. {approach}")
    lines.append("")

    console.print("\n".join(lines))


def get_analysis_summary(path: Path) -> dict[str, str | int | list[str]]:
    """Get analysis summary as dictionary (for programmatic use)."""
    files = [detect_file_type(path)] if path.is_file() else analyze_directory(path)

    category_votes: dict[CTFCategory, int] = {}
    content_matches: list[str] = []

    for file_info in files:
        if file_info.suggested_category:
            cat = file_info.suggested_category
            category_votes[cat] = category_votes.get(cat, 0) + 1
        content_matches.extend(file_info.content_matches)

    primary_category = CTFCategory.MISC
    if category_votes:
        primary_category = max(category_votes, key=lambda k: category_votes[k])

    tools = CATEGORY_TOOLS.get(primary_category, CATEGORY_TOOLS[CTFCategory.MISC])

    return {
        "category": primary_category.value,
        "file_count": len(files),
        "tools": tools[:5],
        "content_matches": list(set(content_matches))[:5],
    }
