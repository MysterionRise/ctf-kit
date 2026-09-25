# CTF Kit - Development Instructions

> AI-Assisted Capture The Flag Challenge Solver

## Project Overview

CTF Kit is a toolkit that helps security researchers and CTF players solve challenges faster using AI support, with specialized skills for different challenge categories (crypto, forensics, OSINT, web, pwn, reversing, stego, misc).

## Architecture

```
.claude-plugin/plugin.json    Claude Code plugin manifest (version lives here)
skills/<name>/SKILL.md        one skill per challenge category + analyze, compete, flag, here, status, team-solve; `_lib/` shared prompt parts
src/ctf_kit/cli.py            Typer entry point (`ctf`)
src/ctf_kit/commands/         one file per CLI subcommand
src/ctf_kit/skills/           Python skill classes (BaseSkill in base.py)
src/ctf_kit/integrations/     tool wrappers grouped by category (BaseTool + ToolResult in base.py)
src/ctf_kit/utils/            file detection, magic bytes
agents/claude/commands/       Claude slash commands; .claude/commands/ mirrors them for in-repo use
tests/                        pytest; fixtures/ holds sample challenges; slow/integration tests are marked
docs/plan/                    original planning docs (reference only, the code is the truth now)
```

### Plugin Structure

CTF Kit is distributed as a **Claude Code Plugin**. Users install it with `/plugin install` and all skills become available as `/ctf-kit:*` in any project. The `.claude/commands/` directory is kept for backward compatibility when working inside the ctf-kit repo itself.

## Tech Stack

- **Language**: Python 3.11+
- **CLI Framework**: Typer (with Rich for output)
- **Package Manager**: uv
- **Testing**: pytest
- **AI Agents**: Claude Code, GitHub Copilot, Cursor, Gemini CLI

## Development Commands

```bash
pip install -e ".[dev]"   # once; installs ruff, mypy, pytest, pre-commit
make check                # ruff + mypy --strict + pytest (fast set)
make test-all             # includes slow/integration tests that need real CTF tools
ctf --help
```

`make check` green before saying "done". CI and pre-commit run the same three.

## Key Design Decisions

### Tool Integration Pattern

All tools follow this pattern (`src/ctf_kit/integrations/base.py`):

```python
class BaseTool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[ToolCategory]
    binary_names: ClassVar[list[str]]
    install_commands: ClassVar[dict[str, str]]

    @property
    def is_installed(self) -> bool
    @abstractmethod
    def run(self, *args, **kwargs) -> ToolResult
    def parse_output(self, stdout, stderr) -> dict[str, Any]

@dataclass
class ToolResult:
    success: bool
    tool_name: str
    command: str
    stdout: str
    stderr: str
    parsed_data: dict[str, Any] | None = None
    artifacts: list[Path] | None = None
    suggestions: list[str] | None = None
    error_message: str | None = None
    execution_time: float = 0.0
```

### Skill Pattern

Skills are AI-facing interfaces that orchestrate tools:

```python
class BaseSkill(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[str]
    tool_names: ClassVar[list[str]]  # Tool names loaded from registry

    @abstractmethod
    def analyze(self, path: Path) -> SkillResult
    @abstractmethod
    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]
    def run_tool(self, name: str, *args, **kwargs) -> ToolResult | None
```

### User Workflow

CTF Kit adds `.ctf/` folders inside user's existing challenge folders:

- Never modify user's existing files
- Support both flat and nested folder structures
- Work with user's preferred AI agent

## Reference Documents

`docs/plan/` holds the original design (skills-analysis, tool-integrations, competition-workflow). Where it disagrees with the code, the code is right; update the doc only if asked.

## Code Style

- Use type hints everywhere
- Docstrings for all public functions
- Keep functions small and focused
- Prefer composition over inheritance
- Use dataclasses for data structures
- Rich console output for user feedback

## Testing Strategy

- Unit tests for tool integrations (mock subprocess calls)
- Integration tests with actual tools (marked as slow)
- Sample CTF challenges in `tests/fixtures/`
