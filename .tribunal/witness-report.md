# Witness Report -- ctf-kit Codebase

*Generated: 2026-02-27*
*Constraint: Empirical observations only. No opinions or recommendations.*

## 1. Static Analysis (Ruff)

```text
$ ruff check src/

warning: The following rules have been removed and ignoring them has no effect:
    - ANN101
    - ANN102

All checks passed!
```

- **Total warnings/errors: 0**
- Two removed rule references (ANN101, ANN102) noted but not counted as violations.
- All source files pass ruff linting.

## 2. Type Checking (Mypy)

Mypy was run in two environments. The authoritative result uses the project's Python 3.14 venv with all dependencies installed.

### With correct Python 3.14 venv (authoritative result)

```text
$ mypy src/
src/ctf_kit/integrations/pwn/pwntools_wrapper.py:44:1: error: Skipping
analyzing "pwn": module is installed, but missing library stubs or py.typed
marker  [import-untyped]
                import pwn  # type: ignore[import-not-found]  # noqa: F401
    ^
src/ctf_kit/integrations/pwn/pwntools_wrapper.py:44:1: note: Error code
"import-untyped" not covered by "type: ignore" comment
Found 1 error in 1 file (checked 72 source files)
```

- **Total errors: 1**
- **Files checked: 72**
- **Affected file:** `src/ctf_kit/integrations/pwn/pwntools_wrapper.py`
- **Category:** `import-untyped` -- the `pwn` library is installed but lacks type stubs or a `py.typed` marker. The existing `# type: ignore[import-not-found]` comment does not suppress the `import-untyped` error code.

### With system Python 3.9 venv (supplementary, environment mismatch)

```text
Found 7 errors in 6 files (checked 72 source files)
```

The 7 errors broke down as:

| Error code | Count | Affected files |
|---|---|---|
| `import-untyped` (yaml) | 4 | `competition.py`, `commands/writeup.py`, `config.py`, `commands/status.py` |
| `import-not-found` (pydantic_settings) | 1 | `config.py` |
| `import-untyped` (pwn) | 1 | `integrations/pwn/pwntools_wrapper.py` |
| `call-arg` (Typer) | 1 | `cli.py` |

These extra 6 errors are attributable to the Python 3.9 environment lacking `types-PyYAML`, `pydantic-settings`, and having an older `typer` version. They do not reproduce in the correct 3.14 venv.

## 3. Test Suite & Coverage

```text
$ pytest tests/ -v --tb=long --cov=ctf_kit --cov-report=term-missing
platform darwin -- Python 3.14.2, pytest-9.0.2, pluggy-1.6.0
plugins: mock-3.15.1, cov-7.0.0
collected 880 items
...
880 passed in 46.10s
Required test coverage of 80% reached. Total coverage: 86.13%
```

- **Tests collected: 880**
- **Tests passed: 880**
- **Tests failed: 0**
- **Tests errored: 0**
- **Total coverage: 86.13% (6036 statements, 837 missed)**
- **Coverage threshold configured: 80% (met)**

### Coverage by Module

| Module | Stmts | Miss | Cover |
|---|---|---|---|
| `__init__.py` | 7 | 0 | 100% |
| `cli.py` | 33 | 7 | 79% |
| `commands/__init__.py` | 2 | 0 | 100% |
| `commands/analyze.py` | 110 | 10 | 91% |
| `commands/check.py` | 91 | 9 | 90% |
| `commands/competition.py` | 114 | 11 | 90% |
| `commands/flag.py` | 38 | 0 | 100% |
| `commands/here.py` | 91 | 10 | 89% |
| `commands/init.py` | 41 | 0 | 100% |
| `commands/run.py` | 33 | 2 | 94% |
| `commands/status.py` | 120 | 6 | 95% |
| `commands/writeup.py` | 153 | 15 | 90% |
| `competition.py` | 205 | 8 | 96% |
| `config.py` | 81 | 5 | 94% |
| `integrations/__init__.py` | 3 | 0 | 100% |
| `integrations/archive/__init__.py` | 2 | 0 | 100% |
| `integrations/archive/bkcrack.py` | 127 | 22 | 83% |
| `integrations/base.py` | 136 | 26 | 81% |
| `integrations/basic/__init__.py` | 3 | 0 | 100% |
| `integrations/basic/file_tool.py` | 99 | 15 | 85% |
| `integrations/basic/strings_tool.py` | 95 | 13 | 86% |
| `integrations/crypto/__init__.py` | 6 | 0 | 100% |
| `integrations/crypto/hashcat.py` | 87 | 10 | 89% |
| `integrations/crypto/hashid.py` | 74 | 17 | 77% |
| `integrations/crypto/john.py` | 72 | 8 | 89% |
| `integrations/crypto/rsactftool.py` | 78 | 6 | 92% |
| `integrations/crypto/xortool.py` | 77 | 16 | 79% |
| `integrations/encoding/__init__.py` | 2 | 0 | 100% |
| `integrations/encoding/cyberchef.py` | 162 | 8 | 95% |
| `integrations/forensics/__init__.py` | 5 | 0 | 100% |
| `integrations/forensics/binwalk.py` | 97 | 8 | 92% |
| `integrations/forensics/foremost.py` | 82 | 10 | 88% |
| `integrations/forensics/tshark.py` | 91 | 20 | 78% |
| `integrations/forensics/volatility.py` | 91 | 11 | 88% |
| `integrations/misc/__init__.py` | 3 | 0 | 100% |
| `integrations/misc/qrencode.py` | 35 | 2 | 94% |
| `integrations/misc/zbarimg.py` | 58 | 5 | 91% |
| `integrations/osint/__init__.py` | 6 | 0 | 100% |
| `integrations/osint/dig.py` | 109 | 26 | 76% |
| `integrations/osint/sherlock.py` | 56 | 3 | 95% |
| `integrations/osint/shodan_tool.py` | 101 | 19 | 81% |
| `integrations/osint/theharvester.py` | 73 | 7 | 90% |
| `integrations/osint/whois.py` | 88 | 18 | 80% |
| `integrations/pwn/__init__.py` | 4 | 0 | 100% |
| `integrations/pwn/checksec.py` | 60 | 3 | 95% |
| `integrations/pwn/pwntools_wrapper.py` | 108 | 46 | 57% |
| `integrations/pwn/ropgadget.py` | 82 | 5 | 94% |
| `integrations/reversing/__init__.py` | 3 | 0 | 100% |
| `integrations/reversing/ghidra.py` | 58 | 5 | 91% |
| `integrations/reversing/radare2.py` | 78 | 5 | 94% |
| `integrations/stego/__init__.py` | 4 | 0 | 100% |
| `integrations/stego/exiftool.py` | 121 | 25 | 79% |
| `integrations/stego/steghide.py` | 97 | 14 | 86% |
| `integrations/stego/zsteg.py` | 99 | 27 | 73% |
| `integrations/web/__init__.py` | 5 | 0 | 100% |
| `integrations/web/ffuf.py` | 97 | 12 | 88% |
| `integrations/web/gobuster.py` | 78 | 11 | 86% |
| `integrations/web/nikto.py` | 90 | 7 | 92% |
| `integrations/web/sqlmap.py` | 85 | 8 | 91% |
| `skills/__init__.py` | 11 | 0 | 100% |
| `skills/analyze.py` | 116 | 9 | 92% |
| `skills/base.py` | 79 | 6 | 92% |
| `skills/crypto.py` | 183 | 48 | 74% |
| `skills/forensics.py` | 158 | 10 | 94% |
| `skills/misc.py` | 232 | 53 | 77% |
| `skills/osint.py` | 188 | 38 | 80% |
| `skills/pwn.py` | 195 | 31 | 84% |
| `skills/reversing.py` | 245 | 51 | 79% |
| `skills/stego.py` | 193 | 19 | 90% |
| `skills/web.py` | 191 | 22 | 88% |
| `utils/__init__.py` | 2 | 0 | 100% |
| `utils/file_detection.py` | 137 | 29 | 79% |
| **TOTAL** | **6036** | **837** | **86%** |

### Modules Below 80% Coverage

| Module | Cover |
|---|---|
| `integrations/pwn/pwntools_wrapper.py` | 57% |
| `integrations/stego/zsteg.py` | 73% |
| `skills/crypto.py` | 74% |
| `integrations/osint/dig.py` | 76% |
| `integrations/crypto/hashid.py` | 77% |
| `skills/misc.py` | 77% |
| `integrations/forensics/tshark.py` | 78% |
| `cli.py` | 79% |
| `integrations/crypto/xortool.py` | 79% |
| `integrations/stego/exiftool.py` | 79% |
| `skills/reversing.py` | 79% |
| `utils/file_detection.py` | 79% |

12 modules are below 80% coverage. The lowest is `pwntools_wrapper.py` at 57%.

## 4. CLI Smoke Tests

### `python -m ctf_kit.cli --help`

**Exit code:** 0

```text
Usage: python -m ctf_kit.cli [OPTIONS] COMMAND [ARGS]...

AI-assisted CTF challenge solver toolkit.

Options:
  --version  -v   Show version and exit.
  --install-completion
  --show-completion
  --help          Show this message and exit.

Commands:
  check        Check which CTF tools are installed.
  run          Run a CTF tool directly.
  analyze      Analyze challenge files and detect category.
  writeup      Generate a writeup for a solved challenge or entire competition.
  here         Set competition context for a challenge directory.
  status       Show CTF challenge or competition status.
  flag         Submit a flag for the current challenge.
  new          Create a new challenge folder and initialize CTF Kit.
  tools        List available tools and their installation status.
  init         Initialize CTF Kit
  competition  Manage CTF competitions
```

11 commands registered.

### `python -m ctf_kit.cli check`

**Exit code:** 0

Output: Rich-formatted tables showing tool installation status across 9 categories (ESSENTIAL, CRYPTO, ARCHIVE, FORENSICS, STEGO, WEB, PWN, REVERSING, OSINT).

Summary line: `Total: 22/37 tools installed (59%)`

### `python -m ctf_kit.cli tools`

**Exit code:** 0

Output: Rich-formatted table titled "Registered Tool Wrappers" with columns: Tool, Status, Category, Description, Version.

32 tool wrappers listed. Status column shows OK or Missing. Version column attempts to read from tool binary; some tools that do not support `--version` show error text in the version column (e.g., `gobuster`: "Error: unknown flag: --version", `john`: 'Unknown option: "--version"', `binwalk`: "General Error: Cannot open fil").

### `python -m ctf_kit.cli analyze --help`

**Exit code:** 0

```text
Usage: python -m ctf_kit.cli analyze [OPTIONS] [PATH]

Analyze challenge files and detect category.

Arguments:
  path  [PATH]  Path to analyze (default: current directory)

Options:
  --verbose   -v   Show detailed analysis
  --markdown  -m   Output as markdown
  --help           Show this message and exit.
```

## 5. Security Scan (Bandit)

```text
Lines of code scanned: 12,041
Skipped tests: 21
nosec comments: 0
```

### Totals by Severity

| Severity | Count |
|---|---|
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 19 |

### Totals by Confidence

| Confidence | Count |
|---|---|
| HIGH | 14 |
| MEDIUM | 5 |
| LOW | 0 |

### Findings by Rule

| Rule | Name | Count | Files |
|---|---|---|---|
| B110 | try_except_pass | 8 | `cyberchef.py`, `misc.py` (x2), `pwn.py`, `reversing.py` (x3), `web.py` |
| B607 | start_process_with_partial_path | 6 | `pwn.py` (x2), `reversing.py` (x4) |
| B107 | hardcoded_password_default | 4 | `steghide.py` (x4) |
| B106 | hardcoded_password_funcarg | 1 | `stego.py` |

### All 19 Individual Findings

| # | Rule | File | Line | Severity | Confidence |
|---|---|---|---|---|---|
| 1 | B110 | `integrations/encoding/cyberchef.py` | 226 | LOW | HIGH |
| 2 | B107 | `integrations/stego/steghide.py` | 38 | LOW | MEDIUM |
| 3 | B107 | `integrations/stego/steghide.py` | 178 | LOW | MEDIUM |
| 4 | B107 | `integrations/stego/steghide.py` | 182 | LOW | MEDIUM |
| 5 | B107 | `integrations/stego/steghide.py` | 191 | LOW | MEDIUM |
| 6 | B110 | `skills/misc.py` | 201 | LOW | HIGH |
| 7 | B110 | `skills/misc.py` | 341 | LOW | HIGH |
| 8 | B607 | `skills/pwn.py` | 269 | LOW | HIGH |
| 9 | B607 | `skills/pwn.py` | 279 | LOW | HIGH |
| 10 | B110 | `skills/pwn.py` | 312 | LOW | HIGH |
| 11 | B607 | `skills/reversing.py` | 320 | LOW | HIGH |
| 12 | B110 | `skills/reversing.py` | 334 | LOW | HIGH |
| 13 | B607 | `skills/reversing.py` | 347 | LOW | HIGH |
| 14 | B607 | `skills/reversing.py` | 356 | LOW | HIGH |
| 15 | B110 | `skills/reversing.py` | 371 | LOW | HIGH |
| 16 | B607 | `skills/reversing.py` | 383 | LOW | HIGH |
| 17 | B110 | `skills/reversing.py` | 404 | LOW | HIGH |
| 18 | B106 | `skills/stego.py` | 260 | LOW | MEDIUM |
| 19 | B110 | `skills/web.py` | 227 | LOW | HIGH |

## 6. Import Chain Validation

```text
$ python -c "import importlib, pkgutil; ..."

Total submodules walked: 71
Import failures: 0
All imports succeeded.
```

71 submodules discovered and imported without error.

## 7. Circular Import Check

```text
ctf_kit: OK
ctf_kit.cli: OK
ctf_kit.config: OK
ctf_kit.skills: OK
ctf_kit.integrations: OK
ctf_kit.utils: OK
```

All 6 top-level entry points imported without circular import errors.

## 8. Codebase Statistics

| Metric | Count |
|---|---|
| Python files in `src/ctf_kit/` | 72 |
| Lines of code in `src/ctf_kit/` | 15,317 |
| Python files in `tests/` | 23 |
| Lines of code in `tests/` | 11,152 |
| **Total Python files** | **95** |
| **Total lines of code** | **26,469** |
| Test-to-source ratio (by lines) | 0.73 |
| Test-to-source ratio (by files) | 0.32 |

### Environment Facts

- `.python-version` file contains `3.14`.
- `pyproject.toml` requires `python >= 3.11`.
- `src/ctf_kit/__init__.py` enforces a runtime guard rejecting Python < 3.11.
- `uv run` without explicit `--python` flag resolved to system Python 3.9 on this machine, causing all 20 test files to fail collection. Tests pass when run under Python 3.14 via a properly configured venv.
- The `coverage` module emitted one warning: `Module ctf_kit was previously imported, but not measured (module-not-measured)`.
