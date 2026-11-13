"""Tests for the category -> plugin skill-name map and CLI hints (issue #22)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_kit.cli import app
from ctf_kit.utils.file_detection import CTFCategory
from ctf_kit.utils.skill_names import (
    CATEGORY_SKILL_NAMES,
    skill_command,
    skill_name,
)

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

runner = CliRunner()


def test_every_category_is_mapped() -> None:
    for category in CTFCategory:
        assert category in CATEGORY_SKILL_NAMES


@pytest.mark.parametrize("category", list(CTFCategory))
def test_mapped_skill_has_skill_md(category: CTFCategory) -> None:
    name = skill_name(category)
    assert (SKILLS_DIR / name / "SKILL.md").is_file(), f"missing skills/{name}/SKILL.md"


def test_reversing_maps_to_reverse() -> None:
    assert skill_name(CTFCategory.REVERSING) == "reverse"
    assert skill_command(CTFCategory.REVERSING) == "/ctf-kit:reverse"


def test_analyze_hint_uses_reverse_skill(tmp_path: Path) -> None:
    (tmp_path / "challenge.class").write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "/ctf-kit:reverse" in result.output
    assert "/ctf-kit:reversing" not in result.output


def test_run_missing_tool_hint_points_to_check(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "ctfkit-no-such-tool-xyz"])
    assert result.exit_code == 1
    assert "ctf check -v" in result.output


def test_init_panel_mentions_analyze_skill(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "/ctf-kit:analyze" in result.output


def test_main_help_mentions_analyze_skill() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "/ctf-kit:analyze" in result.output
