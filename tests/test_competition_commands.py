"""
Tests for competition workflow commands: here, status, flag.
"""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner
import yaml

from ctf_kit.cli import app
from ctf_kit.commands.flag import _validate_flag_format
from ctf_kit.commands.here import _detect_files, _guess_category
from ctf_kit.commands.status import _find_challenges, _read_competition_meta
from ctf_kit.config import ChallengeConfig, load_challenge_config, save_challenge_config

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. Commands: here.py
# ---------------------------------------------------------------------------


class TestHereCommand:
    """Tests for the ctf here command."""

    def test_here_creates_ctf_dir(self, tmp_path: Path) -> None:
        """ctf here should create .ctf/ directory structure."""
        result = runner.invoke(app, ["here", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".ctf").is_dir()
        assert (tmp_path / ".ctf" / "artifacts").is_dir()
        assert (tmp_path / ".ctf" / "analysis.md").is_file()
        assert (tmp_path / ".ctf" / "approach.md").is_file()
        assert (tmp_path / ".ctf" / "attempts.md").is_file()

    def test_here_creates_challenge_yaml(self, tmp_path: Path) -> None:
        """ctf here should create .ctf/challenge.yaml."""
        result = runner.invoke(app, ["here", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.name == tmp_path.name

    def test_here_with_category(self, tmp_path: Path) -> None:
        """ctf here -c crypto should set category."""
        result = runner.invoke(app, ["here", "-c", "crypto", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.category == "crypto"

    def test_here_with_name(self, tmp_path: Path) -> None:
        """ctf here -n should set challenge name."""
        result = runner.invoke(app, ["here", "-n", "RSA Baby", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.name == "RSA Baby"

    def test_here_with_points(self, tmp_path: Path) -> None:
        """ctf here -p should set points."""
        result = runner.invoke(app, ["here", "-p", "200", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.points == 200

    def test_here_with_flag_format(self, tmp_path: Path) -> None:
        """ctf here -f should set flag format."""
        result = runner.invoke(app, ["here", "-f", r"flag\{.*\}", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.flag_format == r"flag\{.*\}"

    def test_here_detects_existing_files(self, tmp_path: Path) -> None:
        """ctf here should list existing files in analysis.md."""
        (tmp_path / "challenge.bin").write_bytes(b"\x00" * 10)
        (tmp_path / "notes.txt").write_text("notes")

        result = runner.invoke(app, ["here", str(tmp_path)])
        assert result.exit_code == 0

        analysis = (tmp_path / ".ctf" / "analysis.md").read_text()
        assert "challenge.bin" in analysis
        assert "notes.txt" in analysis

    def test_here_updates_existing(self, tmp_path: Path) -> None:
        """Running ctf here twice should update rather than error."""
        runner.invoke(app, ["here", str(tmp_path)])
        result = runner.invoke(app, ["here", "-c", "web", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.category == "web"

    def test_here_invalid_path(self, tmp_path: Path) -> None:
        """ctf here with non-existent path should fail."""
        result = runner.invoke(app, ["here", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1

    def test_here_output_shows_initialized(self, tmp_path: Path) -> None:
        """First run should say 'initialized', second should say 'updated'."""
        result1 = runner.invoke(app, ["here", str(tmp_path)])
        assert "initialized" in result1.stdout

        result2 = runner.invoke(app, ["here", "-c", "misc", str(tmp_path)])
        assert "updated" in result2.stdout


class TestDetectFiles:
    """Tests for _detect_files helper."""

    def test_detect_files_excludes_hidden(self, tmp_path: Path) -> None:
        """Hidden files should be excluded."""
        (tmp_path / ".hidden").write_text("hidden")
        (tmp_path / "visible.txt").write_text("visible")

        files = _detect_files(tmp_path)
        names = [f.name for f in files]
        assert "visible.txt" in names
        assert ".hidden" not in names

    def test_detect_files_excludes_dirs(self, tmp_path: Path) -> None:
        """Directories should be excluded."""
        (tmp_path / "subdir").mkdir()
        (tmp_path / "file.txt").write_text("content")

        files = _detect_files(tmp_path)
        assert all(f.is_file() for f in files)


class TestGuessCategory:
    """Tests for _guess_category helper."""

    def test_guess_crypto(self, tmp_path: Path) -> None:
        """Files with crypto keywords should detect as crypto."""
        files = [tmp_path / "encrypt.py", tmp_path / "output.txt"]
        for f in files:
            f.write_text("")
        assert _guess_category(files) == "crypto"

    def test_guess_forensics(self, tmp_path: Path) -> None:
        """pcap files should detect as forensics."""
        files = [tmp_path / "capture.pcap"]
        for f in files:
            f.write_text("")
        assert _guess_category(files) == "forensics"

    def test_guess_stego(self, tmp_path: Path) -> None:
        """Image files should detect as stego."""
        files = [tmp_path / "secret.png"]
        for f in files:
            f.write_text("")
        assert _guess_category(files) == "stego"

    def test_guess_pwn(self, tmp_path: Path) -> None:
        """ELF files should detect as pwn."""
        files = [tmp_path / "vuln.elf", tmp_path / "libc.so.6"]
        for f in files:
            f.write_text("")
        assert _guess_category(files) == "pwn"

    def test_guess_web(self, tmp_path: Path) -> None:
        """Web-related files should detect as web."""
        files = [tmp_path / "app.py", tmp_path / "index.html"]
        for f in files:
            f.write_text("")
        assert _guess_category(files) == "web"

    def test_guess_unknown(self, tmp_path: Path) -> None:
        """Unrecognized files should return None."""
        files = [tmp_path / "data.dat"]
        for f in files:
            f.write_text("")
        assert _guess_category(files) is None

    def test_guess_empty(self) -> None:
        """Empty file list should return None."""
        assert _guess_category([]) is None


# ---------------------------------------------------------------------------
# 2. Commands: status.py
# ---------------------------------------------------------------------------


class TestStatusCommand:
    """Tests for the ctf status command."""

    def test_status_single_challenge(self, tmp_path: Path) -> None:
        """ctf status should show challenge info."""
        # Set up a challenge
        runner.invoke(app, ["here", "-c", "crypto", str(tmp_path)])
        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 0
        assert "Challenge Status" in result.stdout

    def test_status_no_ctf_dir(self, tmp_path: Path) -> None:
        """ctf status without .ctf/ should fail with helpful message."""
        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 1
        assert "ctf here" in result.stdout

    def test_status_shows_solved(self, tmp_path: Path) -> None:
        """Solved challenges should show SOLVED status."""
        config = ChallengeConfig(name="test", category="crypto", solved=True, flag="flag{test}")
        save_challenge_config(config, tmp_path)

        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 0
        assert "SOLVED" in result.stdout

    def test_status_shows_in_progress(self, tmp_path: Path) -> None:
        """Unsolved challenges should show IN PROGRESS."""
        config = ChallengeConfig(name="test", category="crypto")
        save_challenge_config(config, tmp_path)

        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 0
        assert "IN PROGRESS" in result.stdout

    def test_status_flag_txt_fallback(self, tmp_path: Path) -> None:
        """If flag.txt exists but config.solved is False, should still show solved."""
        config = ChallengeConfig(name="test")
        save_challenge_config(config, tmp_path)
        (tmp_path / "flag.txt").write_text("flag{from_file}")

        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 0
        assert "SOLVED" in result.stdout

    def test_status_shows_files(self, tmp_path: Path) -> None:
        """ctf status should list challenge files."""
        runner.invoke(app, ["here", str(tmp_path)])
        (tmp_path / "challenge.txt").write_text("challenge data")

        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 0
        assert "challenge.txt" in result.stdout

    def test_status_competition_mode(self, tmp_path: Path) -> None:
        """ctf status --competition should show dashboard."""
        # Create two challenge subdirectories
        ch1 = tmp_path / "crypto" / "rsa-baby"
        ch1.mkdir(parents=True)
        config1 = ChallengeConfig(name="rsa-baby", category="crypto", solved=True, points=100)
        save_challenge_config(config1, ch1)

        ch2 = tmp_path / "web" / "sqli"
        ch2.mkdir(parents=True)
        config2 = ChallengeConfig(name="sqli", category="web")
        save_challenge_config(config2, ch2)

        result = runner.invoke(app, ["status", "--competition", str(tmp_path)])
        assert result.exit_code == 0
        assert "Competition Dashboard" in result.stdout
        assert "rsa-baby" in result.stdout
        assert "sqli" in result.stdout

    def test_status_competition_auto_detect(self, tmp_path: Path) -> None:
        """If .ctf-competition.yaml exists, should auto-detect competition mode."""
        comp_meta = {"name": "TestCTF 2026"}
        with (tmp_path / ".ctf-competition.yaml").open("w") as f:
            yaml.dump(comp_meta, f)

        result = runner.invoke(app, ["status", str(tmp_path)])
        assert result.exit_code == 0
        assert "TestCTF 2026" in result.stdout

    def test_status_invalid_path(self, tmp_path: Path) -> None:
        """ctf status with invalid path should fail."""
        result = runner.invoke(app, ["status", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1


class TestFindChallenges:
    """Tests for _find_challenges helper."""

    def test_find_challenges(self, tmp_path: Path) -> None:
        """Should find all subdirectories with .ctf/ folders."""
        (tmp_path / "ch1" / ".ctf").mkdir(parents=True)
        (tmp_path / "ch2" / ".ctf").mkdir(parents=True)
        (tmp_path / "ch3").mkdir()

        challenges = _find_challenges(tmp_path)
        names = [c.name for c in challenges]
        assert "ch1" in names
        assert "ch2" in names
        assert "ch3" not in names

    def test_find_challenges_includes_root(self, tmp_path: Path) -> None:
        """Should include root if it has .ctf/."""
        (tmp_path / ".ctf").mkdir()
        challenges = _find_challenges(tmp_path)
        assert tmp_path in challenges

    def test_find_challenges_empty(self, tmp_path: Path) -> None:
        """Should return empty list when no .ctf/ dirs found."""
        challenges = _find_challenges(tmp_path)
        assert challenges == []


class TestReadCompetitionMeta:
    """Tests for _read_competition_meta helper."""

    def test_read_meta(self, tmp_path: Path) -> None:
        """Should read .ctf-competition.yaml."""
        meta = {"name": "Test CTF", "url": "https://ctf.example.com"}
        with (tmp_path / ".ctf-competition.yaml").open("w") as f:
            yaml.dump(meta, f)

        result = _read_competition_meta(tmp_path)
        assert result is not None
        assert result["name"] == "Test CTF"

    def test_read_meta_missing(self, tmp_path: Path) -> None:
        """Should return None when file doesn't exist."""
        result = _read_competition_meta(tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# 3. Commands: flag.py
# ---------------------------------------------------------------------------


class TestFlagCommand:
    """Tests for the ctf flag command."""

    def test_flag_saves_flag_txt(self, tmp_path: Path) -> None:
        """ctf flag should save the flag to flag.txt."""
        # Set up a challenge first
        runner.invoke(app, ["here", str(tmp_path)])

        result = runner.invoke(app, ["flag", "flag{test_flag}", "--path", str(tmp_path)])
        assert result.exit_code == 0

        flag_content = (tmp_path / "flag.txt").read_text().strip()
        assert flag_content == "flag{test_flag}"

    def test_flag_marks_solved(self, tmp_path: Path) -> None:
        """ctf flag should mark challenge as solved in challenge.yaml."""
        runner.invoke(app, ["here", str(tmp_path)])

        runner.invoke(app, ["flag", "flag{solved}", "--path", str(tmp_path)])

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.solved is True
        assert config.flag == "flag{solved}"

    def test_flag_creates_config_if_missing(self, tmp_path: Path) -> None:
        """ctf flag should create challenge config even without ctf here."""
        result = runner.invoke(app, ["flag", "flag{new}", "--path", str(tmp_path)])
        assert result.exit_code == 0

        config = load_challenge_config(tmp_path)
        assert config is not None
        assert config.solved is True

    def test_flag_shows_confirmation(self, tmp_path: Path) -> None:
        """ctf flag should show confirmation panel."""
        result = runner.invoke(app, ["flag", "flag{confirmed}", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "Flag Captured" in result.stdout
        assert "SOLVED" in result.stdout

    def test_flag_format_warning(self, tmp_path: Path) -> None:
        """Non-matching flag should show format warning."""
        with patch("ctf_kit.commands.flag.load_config") as mock_config:
            from ctf_kit.config import Config

            mock_config.return_value = Config(flag_formats=[r"flag\{.*\}"])
            result = runner.invoke(app, ["flag", "not_a_valid_flag", "--path", str(tmp_path)])
            assert result.exit_code == 0
            assert "Warning" in result.stdout

    def test_flag_no_validate(self, tmp_path: Path) -> None:
        """--no-validate should skip format warning."""
        result = runner.invoke(
            app,
            ["flag", "anything_goes", "--no-validate", "--path", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "Warning" not in result.stdout

    def test_flag_invalid_path(self, tmp_path: Path) -> None:
        """ctf flag with non-existent directory should fail."""
        result = runner.invoke(app, ["flag", "flag{x}", "--path", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1

    def test_flag_updates_existing_config(self, tmp_path: Path) -> None:
        """ctf flag should update an existing challenge config."""
        config = ChallengeConfig(name="test", category="crypto", points=200)
        save_challenge_config(config, tmp_path)

        runner.invoke(app, ["flag", "flag{updated}", "--path", str(tmp_path)])

        updated = load_challenge_config(tmp_path)
        assert updated is not None
        assert updated.name == "test"
        assert updated.category == "crypto"
        assert updated.points == 200
        assert updated.solved is True
        assert updated.flag == "flag{updated}"


class TestValidateFlagFormat:
    """Tests for the _validate_flag_format helper."""

    def test_valid_flag(self) -> None:
        """Flag matching a pattern should return True."""
        assert _validate_flag_format("flag{test}", [r"flag\{.*\}"]) is True

    def test_invalid_flag(self) -> None:
        """Flag not matching any pattern should return False."""
        assert _validate_flag_format("not_a_flag", [r"flag\{.*\}"]) is False

    def test_multiple_patterns(self) -> None:
        """Flag matching any of multiple patterns should return True."""
        patterns = [r"flag\{.*\}", r"CTF\{.*\}", r"picoCTF\{.*\}"]
        assert _validate_flag_format("CTF{test}", patterns) is True
        assert _validate_flag_format("picoCTF{test}", patterns) is True

    def test_empty_patterns(self) -> None:
        """Empty pattern list should return False."""
        assert _validate_flag_format("flag{test}", []) is False

    def test_invalid_regex(self) -> None:
        """Invalid regex pattern should be skipped without error."""
        assert _validate_flag_format("flag{test}", ["[invalid"]) is False
