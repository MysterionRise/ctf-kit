"""
Initialize CTF Kit for a repository or challenge.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from rich.console import Console
from rich.panel import Panel
import typer

app = typer.Typer(help="Initialize CTF Kit")
console = Console()

# Template for analysis.md
ANALYSIS_TEMPLATE = """# Challenge Analysis

## Metadata
- **Name**: {name}
- **Category**: {category}
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

# Template for approach.md
APPROACH_TEMPLATE = """# Solution Approach

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


def init_repo(path: Path) -> None:
    """Initialize CTF Kit at repository level."""
    ctf_kit_dir = path / ".ctf-kit"

    if ctf_kit_dir.exists():
        console.print("[yellow]CTF Kit already initialized in this repo[/]")
        return

    # Create directory structure
    ctf_kit_dir.mkdir(parents=True)
    (ctf_kit_dir / "templates").mkdir()
    (ctf_kit_dir / "wordlists").mkdir()

    # Create default config
    config_content = """# CTF Kit Configuration
version: "1.0"

# Your preferred AI agent
ai_agent: claude  # Options: claude, copilot, cursor, gemini

# Default flag formats (regex)
flag_formats:
  - "flag\\{.*\\}"
  - "CTF\\{.*\\}"

# Tool paths (if not in PATH)
tools:
  ghidra: null
  ida: null

# API keys (or use environment variables)
api_keys:
  shodan: null
  virustotal: null

# Preferences
preferences:
  auto_commit: false
  writeup_format: markdown
  include_failed_attempts: true
"""

    (ctf_kit_dir / "config.yaml").write_text(config_content)

    console.print(
        Panel(
            "[green]CTF Kit initialized![/]\n\n"
            f"Config: [cyan]{ctf_kit_dir / 'config.yaml'}[/]\n\n"
            "Next steps:\n"
            "1. Edit config.yaml with your preferences\n"
            "2. Create a challenge folder\n"
            "3. Run [cyan]ctf init[/] in the challenge folder",
            title="CTF Kit",
        )
    )


def init_challenge(path: Path, category: str | None = None) -> None:
    """Initialize CTF Kit for a specific challenge."""
    ctf_dir = path / ".ctf"

    if ctf_dir.exists():
        console.print("[yellow]Challenge already initialized[/]")
        return

    # Create directory structure
    ctf_dir.mkdir(parents=True)
    (ctf_dir / "artifacts").mkdir()

    # Detect files
    files = [f for f in path.iterdir() if f.is_file() and not f.name.startswith(".")]
    files_list = "\n".join(f"- `{f.name}`" for f in files) or "- No files detected"

    # Create analysis.md
    analysis_content = ANALYSIS_TEMPLATE.format(
        name=path.name,
        category=category or "Unknown",
        detected_time=datetime.now(tz=UTC).isoformat(),
        files_list=files_list,
    )
    (ctf_dir / "analysis.md").write_text(analysis_content)

    # Create approach.md
    (ctf_dir / "approach.md").write_text(APPROACH_TEMPLATE)

    # Create attempts.md
    (ctf_dir / "attempts.md").write_text(
        "# Solution Attempts\n\n<!-- Track what you've tried -->\n"
    )

    console.print(
        Panel(
            f"[green]Challenge initialized:[/] [cyan]{path.name}[/]\n\n"
            f"Category: {category or 'Auto-detect'}\n"
            f"Files found: {len(files)}\n\n"
            "Created:\n"
            f"  [cyan].ctf/analysis.md[/]\n"
            f"  [cyan].ctf/approach.md[/]\n"
            f"  [cyan].ctf/attempts.md[/]\n\n"
            "Now launch your AI agent and use:\n"
            "  [bold cyan]/ctf.analyze[/]",
            title="Challenge Ready",
        )
    )


@app.callback(invoke_without_command=True)  # type: ignore[misc]
def init_command(
    ctx: typer.Context,  # noqa: ARG001
    repo: Annotated[
        bool,
        typer.Option("--repo", "-r", help="Initialize at repository level"),
    ] = False,
    category: Annotated[
        str | None,
        typer.Option("--category", "-c", help="Challenge category hint"),
    ] = None,
    path: Annotated[
        Path | None,
        typer.Argument(help="Path to initialize (default: current directory)"),
    ] = None,
) -> None:
    """
    Initialize CTF Kit.

    Without --repo: Initialize for a specific challenge (creates .ctf/)
    With --repo: Initialize for entire repository (creates .ctf-kit/)

    Examples:
        ctf init                    # Init current folder as challenge
        ctf init --repo             # Init current folder as CTF repo
        ctf init --category crypto  # Init with category hint
    """
    target_path = path or Path.cwd()

    if repo:
        init_repo(target_path)
    else:
        init_challenge(target_path, category)
