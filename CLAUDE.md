# CTF Kit - Development Instructions

> AI-Assisted Capture The Flag Challenge Solver

## Project Overview

CTF Kit is a toolkit that helps security researchers and CTF players solve challenges faster using AI support, with specialized skills for different challenge categories (crypto, forensics, OSINT, web, pwn, reversing, stego, misc).

## Architecture

```text
ctf-kit/
├── .claude-plugin/
│   └── plugin.json               # Claude Code plugin manifest
├── skills/                       # Plugin skills (SKILL.md format)
│   ├── analyze/SKILL.md          # /ctf-kit:analyze
│   ├── crypto/SKILL.md           # /ctf-kit:crypto
│   ├── forensics/SKILL.md        # /ctf-kit:forensics
│   ├── stego/SKILL.md            # /ctf-kit:stego
│   ├── web/SKILL.md              # /ctf-kit:web
│   ├── pwn/SKILL.md              # /ctf-kit:pwn
│   ├── reverse/SKILL.md          # /ctf-kit:reverse
│   ├── osint/SKILL.md            # /ctf-kit:osint
│   └── misc/SKILL.md             # /ctf-kit:misc
├── .claude/
│   └── commands/                 # In-repo slash commands (backward compat)
├── src/ctf_kit/
│   ├── __init__.py
│   ├── cli.py                    # Main CLI entry point (Typer)
│   ├── config.py                 # Configuration management
│   ├── skills/                   # AI agent skills (Python)
│   │   ├── __init__.py
│   │   ├── base.py               # Base skill class
│   │   ├── analyze.py            # /ctf-kit:analyze
│   │   ├── crypto.py             # /ctf-kit:crypto
│   │   ├── forensics.py          # /ctf-kit:forensics
│   │   ├── stego.py              # /ctf-kit:stego
│   │   ├── web.py                # /ctf-kit:web
│   │   ├── pwn.py                # /ctf-kit:pwn
│   │   ├── reversing.py          # /ctf-kit:reverse
│   │   ├── osint.py              # /ctf-kit:osint
│   │   └── misc.py               # /ctf-kit:misc
│   ├── integrations/             # Tool wrappers
│   │   ├── __init__.py
│   │   ├── base.py               # BaseTool class, ToolResult
│   │   ├── crypto/               # xortool, rsactftool, hashcat, john
│   │   ├── archive/              # bkcrack, fcrackzip, zip2john
│   │   ├── forensics/            # binwalk, volatility, sleuthkit
│   │   ├── network/              # tshark, tcpdump
│   │   ├── stego/                # zsteg, steghide, exiftool
│   │   ├── web/                  # sqlmap, gobuster, ffuf
│   │   ├── pwn/                  # pwntools, ropgadget, one_gadget
│   │   ├── reversing/            # radare2, ghidra
│   │   └── osint/                # sherlock, theharvester
│   ├── templates/                # Markdown templates
│   │   ├── analysis.md
│   │   ├── approach.md
│   │   └── writeup.md
│   └── utils/
│       ├── __init__.py
│       ├── file_detection.py     # Detect file types, magic bytes
│       └── encoding.py           # CyberChef-like operations
├── agents/                       # AI agent configurations
│   ├── claude/
│   │   └── commands/             # Slash command definitions
│   ├── copilot/
│   └── cursor/
├── tests/
├── docs/
│   ├── plan/                     # Planning documents (reference)
│   │   ├── project-plan.md
│   │   ├── skills-analysis.md
│   │   ├── tool-integrations.md
│   │   └── competition-workflow.md
│   └── user-guide/
├── pyproject.toml
├── README.md
└── CLAUDE.md                     # This file
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
# Install in development mode
uv pip install -e ".[dev]"

# Run CLI
ctf --help

# Run tests
pytest

# Type checking
mypy src/

# Linting
ruff check src/
```

## Implementation Priority

### Phase 1: Foundation (Current)

1. ✅ Planning documents complete
2. 🔲 Project skeleton with pyproject.toml
3. 🔲 CLI framework (init, check, run commands)
4. 🔲 Base tool integration class
5. 🔲 Configuration system

### Phase 2: Core Skills

1. 🔲 `/ctf.analyze` - File analysis and categorization
2. 🔲 `/ctf.crypto` - Crypto tools (xortool, RsaCtfTool)
3. 🔲 `/ctf.misc` - Encoding chains, CyberChef operations

### Phase 3: Tool Integrations

1. 🔲 Crypto: xortool, hashcat, john
2. 🔲 Archive: bkcrack, fcrackzip
3. 🔲 Forensics: binwalk, volatility3, tshark
4. 🔲 Stego: zsteg, steghide, exiftool

### Phase 4: Advanced Skills

1. 🔲 `/ctf.forensics`
2. 🔲 `/ctf.stego`
3. 🔲 `/ctf.web`
4. 🔲 `/ctf.pwn`
5. 🔲 `/ctf.reverse`
6. 🔲 `/ctf.osint`

## Key Design Decisions

### Tool Integration Pattern

All tools follow the same pattern defined in `docs/plan/tool-integrations.md`:

```python
class BaseTool(ABC):
    name: str
    description: str
    category: str
    binary_names: List[str]
    install_commands: Dict[str, str]

    def is_installed(self) -> bool
    def run(self, *args, **kwargs) -> ToolResult
    def parse_output(self, stdout, stderr) -> Dict

@dataclass
class ToolResult:
    success: bool
    tool_name: str
    command: str
    stdout: str
    stderr: str
    parsed_data: Optional[Dict] = None
    artifacts: Optional[List[Path]] = None
    suggestions: Optional[List[str]] = None
```

### Skill Pattern

Skills are AI-facing interfaces that orchestrate tools:

```python
class BaseSkill:
    name: str
    commands: List[str]  # Slash commands this skill handles
    tools: List[BaseTool]  # Tools this skill uses

    def analyze(self, path: Path) -> SkillResult
    def suggest_approach(self, analysis: Dict) -> List[str]
    def execute(self, approach: str) -> ToolResult
```

### User Workflow

CTF Kit adds `.ctf/` folders inside user's existing challenge folders:

- Never modify user's existing files
- Support both flat and nested folder structures
- Work with user's preferred AI agent

## Reference Documents

When implementing features, refer to these planning documents in `docs/plan/`:

1. **project-plan.md** - Overall architecture, CLI design, implementation phases
2. **skills-analysis.md** - How AI should interact with each category
3. **tool-integrations.md** - Complete tool wrapper specifications (40+ tools)
4. **competition-workflow.md** - User workflow during competitions

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
