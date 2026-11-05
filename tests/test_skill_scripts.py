"""Tests for skill shell scripts in skills/*/scripts/."""

import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - subprocess is required to run the scripts

import pytest

SKILLS_DIR = Path(__file__).parent.parent / "skills"
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "challenges"

# A shell variable spliced into a Python string literal, e.g. '$FILE',
# '''$FILE_TYPE''' or '''$(echo "$RAW" | sed ...)'''
INTERPOLATED_LITERAL = re.compile(r"""'(?:'')?\$[({A-Za-z_]""")


def _inline_python_lines(script: Path) -> list[tuple[int, str]]:
    """Return (line number, line) pairs inside multi-line python3 -c "..." blocks."""
    lines = []
    inside = False
    for n, line in enumerate(script.read_text().splitlines(), 1):
        if inside:
            if line.startswith('"'):
                inside = False
            else:
                lines.append((n, line))
        elif line.rstrip().endswith('python3 -c "'):
            inside = True
    return lines


class TestInlinePythonInputs:
    """Inline Python must take tool output and paths via sys.argv, not source code."""

    @pytest.mark.parametrize(
        "script", sorted(SKILLS_DIR.glob("*/scripts/*.sh")), ids=lambda p: p.name
    )
    def test_no_shell_values_in_python_literals(self, script):
        offenders = [
            f"{script.name}:{n}: {line.strip()}"
            for n, line in _inline_python_lines(script)
            if INTERPOLATED_LITERAL.search(line)
        ]
        assert not offenders, "\n".join(offenders)

    @pytest.mark.skipif(
        shutil.which("bash") is None or shutil.which("python3") is None,
        reason="bash/python3 not installed",
    )
    def test_triage_treats_hostile_filename_as_data(self, tmp_path):
        name = "x'+str(open('PWNED','w'))+'.txt"
        shutil.copy(FIXTURES_DIR / "crypto_base64.txt", tmp_path / name)

        result = subprocess.run(  # nosec B603 B607
            ["bash", str(SKILLS_DIR / "analyze" / "scripts" / "triage.sh"), name],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert not (tmp_path / "PWNED").exists()
        summary = json.loads(result.stdout.split("=== TRIAGE RESULTS (JSON) ===", 1)[1])
        assert summary["file"] == name
