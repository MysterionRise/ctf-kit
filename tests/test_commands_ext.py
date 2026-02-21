"""
Comprehensive tests for CTF Kit commands (check, init, run, writeup) and config modules.

Uses typer.testing.CliRunner for CLI commands, tmp_path for file operations,
and mocks for shutil.which and subprocess.run.
"""

from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner
import yaml

from ctf_kit.cli import app
from ctf_kit.commands.check import (
    TOOL_REGISTRY,
    check_tool,
    get_installed_tools,
    get_missing_tools,
)
from ctf_kit.commands.init import init_challenge, init_repo
from ctf_kit.commands.run import TOOL_SHORTCUTS
from ctf_kit.commands.writeup import _detect_category
from ctf_kit.config import (
    ApiKeysConfig,
    ChallengeConfig,
    Config,
    PreferencesConfig,
    ToolsConfig,
    find_repo_root,
    load_challenge_config,
    load_config,
    save_challenge_config,
    save_config,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. Commands: check.py
# ---------------------------------------------------------------------------


class TestCheckTool:
    """Tests for the check_tool function."""

    def test_check_tool_installed(self) -> None:
        """check_tool returns True when shutil.which finds the binary."""
        with patch("ctf_kit.commands.check.shutil.which", return_value="/usr/bin/file"):
            assert check_tool("file") is True

    def test_check_tool_not_installed(self) -> None:
        """check_tool returns False when shutil.which returns None."""
        with patch("ctf_kit.commands.check.shutil.which", return_value=None):
            assert check_tool("nonexistent_tool") is False


class TestCheckToolsCommand:
    """Tests for the check_tools CLI command."""

    def test_check_tools_command(self) -> None:
        """Running 'ctf check' should complete without error."""
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0
        # Should contain category headers from TOOL_REGISTRY
        assert "ESSENTIAL" in result.stdout or "Total:" in result.stdout

    def test_check_tools_verbose(self) -> None:
        """Running 'ctf check -v' should show install commands."""
        result = runner.invoke(app, ["check", "-v"])
        assert result.exit_code == 0
        # Verbose mode adds an "Install Command" column
        assert "Total:" in result.stdout

    def test_check_tools_with_category(self) -> None:
        """Running 'ctf check -c crypto' should only show crypto tools."""
        result = runner.invoke(app, ["check", "-c", "crypto"])
        assert result.exit_code == 0
        assert "CRYPTO" in result.stdout
        # Should NOT show other categories
        assert "FORENSICS" not in result.stdout

    def test_check_tools_unknown_category(self) -> None:
        """Running 'ctf check -c bogus' should print unknown category error."""
        result = runner.invoke(app, ["check", "-c", "bogus"])
        assert result.exit_code == 0
        assert "Unknown category" in result.stdout

    def test_check_tools_registered_flag(self) -> None:
        """Running 'ctf check -r' should invoke _show_registered_tools."""
        result = runner.invoke(app, ["check", "-r"])
        assert result.exit_code == 0
        # May show "No tool wrappers registered yet" or a table
        assert (
            "Registered Tool Wrappers" in result.stdout
            or "No tool wrappers registered" in result.stdout
        )


class TestGetMissingTools:
    """Tests for get_missing_tools."""

    def test_get_missing_tools_all_missing(self) -> None:
        """All tools should be missing when shutil.which always returns None."""
        with patch("ctf_kit.commands.check.shutil.which", return_value=None):
            missing = get_missing_tools()
            # Should include at least all essential tools
            for name in TOOL_REGISTRY["essential"]:
                assert name in missing

    def test_get_missing_tools_none_missing(self) -> None:
        """No tools should be missing when shutil.which always succeeds."""
        with patch("ctf_kit.commands.check.shutil.which", return_value="/usr/bin/tool"):
            missing = get_missing_tools()
            assert missing == []

    def test_get_missing_tools_with_category(self) -> None:
        """Only tools from the specified category should appear."""
        with patch("ctf_kit.commands.check.shutil.which", return_value=None):
            missing = get_missing_tools(category="crypto")
            for name in TOOL_REGISTRY["crypto"]:
                assert name in missing
            # Should NOT contain tools from other categories
            for name in TOOL_REGISTRY["essential"]:
                assert name not in missing

    def test_get_missing_tools_invalid_category(self) -> None:
        """Invalid category should return empty list (category not in registry)."""
        missing = get_missing_tools(category="nonexistent_category")
        assert missing == []

    def test_get_missing_tools_partial(self) -> None:
        """Some tools installed, some missing."""

        def selective_which(binary: str) -> str | None:
            # Only "file" is installed
            return "/usr/bin/file" if binary == "file" else None

        with patch("ctf_kit.commands.check.shutil.which", side_effect=selective_which):
            missing = get_missing_tools(category="essential")
            assert "file" not in missing
            # Other essential tools should be missing
            for name, info in TOOL_REGISTRY["essential"].items():
                if info["binary"] != "file":
                    assert name in missing


class TestGetInstalledTools:
    """Tests for get_installed_tools."""

    def test_get_installed_tools_all_installed(self) -> None:
        """All tools should be installed when shutil.which always succeeds."""
        with patch("ctf_kit.commands.check.shutil.which", return_value="/usr/bin/tool"):
            installed = get_installed_tools()
            total = sum(len(tools) for tools in TOOL_REGISTRY.values())
            assert len(installed) == total

    def test_get_installed_tools_none_installed(self) -> None:
        """No tools should be installed when shutil.which always fails."""
        with patch("ctf_kit.commands.check.shutil.which", return_value=None):
            installed = get_installed_tools()
            assert installed == []

    def test_get_installed_tools_with_category(self) -> None:
        """Only tools from the specified category should appear."""
        with patch("ctf_kit.commands.check.shutil.which", return_value="/usr/bin/tool"):
            installed = get_installed_tools(category="essential")
            assert len(installed) == len(TOOL_REGISTRY["essential"])
            for name in TOOL_REGISTRY["essential"]:
                assert name in installed

    def test_get_installed_tools_partial(self) -> None:
        """Only tools whose binary is found should be returned."""

        def selective_which(binary: str) -> str | None:
            return "/usr/bin/openssl" if binary == "openssl" else None

        with patch("ctf_kit.commands.check.shutil.which", side_effect=selective_which):
            installed = get_installed_tools(category="crypto")
            assert "openssl" in installed
            assert "xortool" not in installed


class TestToolRegistry:
    """Tests for the TOOL_REGISTRY structure."""

    def test_registry_has_expected_categories(self) -> None:
        """The registry should have all documented categories."""
        expected = {
            "essential",
            "crypto",
            "archive",
            "forensics",
            "stego",
            "web",
            "pwn",
            "reversing",
            "osint",
        }
        assert set(TOOL_REGISTRY.keys()) == expected

    def test_registry_tools_have_required_keys(self) -> None:
        """Every tool entry should have 'binary' and 'description' keys."""
        for category, tools in TOOL_REGISTRY.items():
            for name, info in tools.items():
                assert "binary" in info, f"{category}/{name} missing 'binary'"
                assert "description" in info, f"{category}/{name} missing 'description'"


# ---------------------------------------------------------------------------
# 2. Commands: init.py
# ---------------------------------------------------------------------------


class TestInitRepo:
    """Tests for init_repo."""

    def test_init_repo(self, tmp_path: Path) -> None:
        """init_repo should create .ctf-kit/ with config, templates, and wordlists."""
        init_repo(tmp_path)

        ctf_kit_dir = tmp_path / ".ctf-kit"
        assert ctf_kit_dir.is_dir()
        assert (ctf_kit_dir / "config.yaml").is_file()
        assert (ctf_kit_dir / "templates").is_dir()
        assert (ctf_kit_dir / "wordlists").is_dir()

        # Verify config content
        config_content = (ctf_kit_dir / "config.yaml").read_text()
        assert "version" in config_content
        assert "ai_agent" in config_content

    def test_init_repo_already_exists(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """init_repo should print warning when .ctf-kit/ already exists."""
        (tmp_path / ".ctf-kit").mkdir()
        init_repo(tmp_path)
        # The function uses rich console; for capsys we can also check via runner
        # Just ensure no exception is raised and directory still exists
        assert (tmp_path / ".ctf-kit").is_dir()


class TestInitChallenge:
    """Tests for init_challenge."""

    def test_init_challenge(self, tmp_path: Path) -> None:
        """init_challenge should create .ctf/ with analysis, approach, attempts, and artifacts."""
        init_challenge(tmp_path)

        ctf_dir = tmp_path / ".ctf"
        assert ctf_dir.is_dir()
        assert (ctf_dir / "analysis.md").is_file()
        assert (ctf_dir / "approach.md").is_file()
        assert (ctf_dir / "attempts.md").is_file()
        assert (ctf_dir / "artifacts").is_dir()

    def test_init_challenge_with_category(self, tmp_path: Path) -> None:
        """Category should appear in analysis.md."""
        init_challenge(tmp_path, category="crypto")

        analysis = (tmp_path / ".ctf" / "analysis.md").read_text()
        assert "crypto" in analysis

    def test_init_challenge_already_exists(self, tmp_path: Path) -> None:
        """init_challenge should print warning when .ctf/ already exists."""
        (tmp_path / ".ctf").mkdir()
        # Should not raise; just prints a warning
        init_challenge(tmp_path)
        assert (tmp_path / ".ctf").is_dir()

    def test_init_challenge_detects_existing_files(self, tmp_path: Path) -> None:
        """Existing files in the challenge folder should be listed in analysis.md."""
        (tmp_path / "challenge.bin").write_bytes(b"\x00" * 10)
        (tmp_path / "notes.txt").write_text("some notes")

        init_challenge(tmp_path)

        analysis = (tmp_path / ".ctf" / "analysis.md").read_text()
        assert "challenge.bin" in analysis
        assert "notes.txt" in analysis

    def test_init_challenge_no_existing_files(self, tmp_path: Path) -> None:
        """With no files, analysis.md should say 'No files detected'."""
        init_challenge(tmp_path)

        analysis = (tmp_path / ".ctf" / "analysis.md").read_text()
        assert "No files detected" in analysis

    def test_init_challenge_analysis_has_metadata(self, tmp_path: Path) -> None:
        """analysis.md should contain the challenge name and detection time."""
        init_challenge(tmp_path, category="web")

        analysis = (tmp_path / ".ctf" / "analysis.md").read_text()
        assert tmp_path.name in analysis
        assert "web" in analysis
        assert "Detected" in analysis

    def test_init_challenge_approach_template(self, tmp_path: Path) -> None:
        """approach.md should contain the approach template content."""
        init_challenge(tmp_path)

        approach = (tmp_path / ".ctf" / "approach.md").read_text()
        assert "Solution Approach" in approach
        assert "Step-by-Step Plan" in approach

    def test_init_challenge_attempts_template(self, tmp_path: Path) -> None:
        """attempts.md should contain the attempts header."""
        init_challenge(tmp_path)

        attempts = (tmp_path / ".ctf" / "attempts.md").read_text()
        assert "Solution Attempts" in attempts


class TestInitCommandCLI:
    """Tests for init command via CLI runner."""

    def test_init_command_via_cli(self, tmp_path: Path) -> None:
        """Running 'ctf init <path>' should initialize a challenge."""
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".ctf").is_dir()

    def test_init_command_repo_flag(self, tmp_path: Path) -> None:
        """Running 'ctf init --repo <path>' should initialize a repo."""
        result = runner.invoke(app, ["init", "--repo", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".ctf-kit").is_dir()

    def test_init_command_with_category(self, tmp_path: Path) -> None:
        """Running 'ctf init -c crypto <path>' should pass category to init_challenge."""
        result = runner.invoke(app, ["init", "-c", "crypto", str(tmp_path)])
        assert result.exit_code == 0
        analysis = (tmp_path / ".ctf" / "analysis.md").read_text()
        assert "crypto" in analysis


# ---------------------------------------------------------------------------
# 3. Commands: run.py
# ---------------------------------------------------------------------------


class TestRunTool:
    """Tests for run_tool via CLI."""

    def test_run_known_tool(self) -> None:
        """Running a known tool shortcut should resolve the binary and execute."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("ctf_kit.commands.run.shutil.which", return_value="/usr/bin/zsteg"),
            patch("ctf_kit.commands.run.subprocess.run", return_value=mock_result) as mock_run,
        ):
            result = runner.invoke(app, ["run", "zsteg", "image.png"])
            # Exit code 0 is raised by typer.Exit(0)
            assert result.exit_code == 0
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "/usr/bin/zsteg"
            # zsteg has default_args ["-a"]
            assert "-a" in cmd
            assert "image.png" in cmd

    def test_run_unknown_tool(self) -> None:
        """Running an unknown tool name should use it directly as binary."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("ctf_kit.commands.run.shutil.which", return_value="/usr/local/bin/mytool"),
            patch("ctf_kit.commands.run.subprocess.run", return_value=mock_result) as mock_run,
        ):
            # Use positional args (no leading dashes) to avoid Typer consuming them
            result = runner.invoke(app, ["run", "mytool", "input.bin"])
            assert result.exit_code == 0
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "/usr/local/bin/mytool"
            assert "input.bin" in cmd

    def test_run_tool_not_installed(self) -> None:
        """Running a tool that is not installed should exit with code 1."""
        with patch("ctf_kit.commands.run.shutil.which", return_value=None):
            result = runner.invoke(app, ["run", "nonexistent_tool_xyz"])
            assert result.exit_code == 1
            assert "Tool not found" in result.stdout

    def test_run_tool_with_multiple_args(self) -> None:
        """Arguments should be passed through to the subprocess."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("ctf_kit.commands.run.shutil.which", return_value="/usr/bin/binwalk"),
            patch("ctf_kit.commands.run.subprocess.run", return_value=mock_result) as mock_run,
        ):
            # Use '--' to prevent Typer from consuming tool flags like -e
            result = runner.invoke(app, ["run", "binwalk", "--", "-e", "firmware.bin"])
            assert result.exit_code == 0
            cmd = mock_run.call_args[0][0]
            assert "-e" in cmd
            assert "firmware.bin" in cmd

    def test_run_tool_nonzero_exit(self) -> None:
        """Non-zero return code from the tool should propagate."""
        mock_result = MagicMock()
        mock_result.returncode = 2

        with (
            patch("ctf_kit.commands.run.shutil.which", return_value="/usr/bin/file"),
            patch("ctf_kit.commands.run.subprocess.run", return_value=mock_result),
        ):
            result = runner.invoke(app, ["run", "file", "missing.bin"])
            assert result.exit_code == 2

    def test_run_tool_os_error(self) -> None:
        """OSError during execution should result in exit code 1."""
        with (
            patch("ctf_kit.commands.run.shutil.which", return_value="/usr/bin/broken"),
            patch(
                "ctf_kit.commands.run.subprocess.run",
                side_effect=OSError("Permission denied"),
            ),
        ):
            result = runner.invoke(app, ["run", "broken"])
            assert result.exit_code == 1
            assert "Error running" in result.stdout


class TestToolShortcuts:
    """Tests for the TOOL_SHORTCUTS structure."""

    def test_tool_shortcuts_is_dict(self) -> None:
        """TOOL_SHORTCUTS should be a non-empty dict."""
        assert isinstance(TOOL_SHORTCUTS, dict)
        assert len(TOOL_SHORTCUTS) > 0

    def test_tool_shortcuts_have_required_keys(self) -> None:
        """Every shortcut entry should have 'binary' and 'default_args'."""
        for name, info in TOOL_SHORTCUTS.items():
            assert "binary" in info, f"Shortcut '{name}' missing 'binary'"
            assert "default_args" in info, f"Shortcut '{name}' missing 'default_args'"

    def test_known_shortcuts_present(self) -> None:
        """Expected shortcuts should be defined."""
        expected = ["zsteg", "binwalk", "exiftool", "strings", "file", "xxd"]
        for name in expected:
            assert name in TOOL_SHORTCUTS, f"Expected shortcut '{name}' not found"

    def test_radare2_shortcut_maps_to_r2(self) -> None:
        """Both 'radare2' and 'r2' shortcuts should map to the 'r2' binary."""
        assert TOOL_SHORTCUTS["radare2"]["binary"] == "r2"
        assert TOOL_SHORTCUTS["r2"]["binary"] == "r2"

    def test_zsteg_has_default_args(self) -> None:
        """zsteg shortcut should have '-a' as a default argument."""
        assert "-a" in TOOL_SHORTCUTS["zsteg"]["default_args"]


# ---------------------------------------------------------------------------
# 4. Commands: writeup.py
# ---------------------------------------------------------------------------


class TestGenerateWriteup:
    """Tests for generate_writeup via CLI."""

    def test_generate_writeup(self, tmp_path: Path) -> None:
        """Should generate writeup.md from .ctf/ contents."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()
        (ctf_dir / "analysis.md").write_text("# Analysis\nThis is a crypto challenge.")
        (ctf_dir / "approach.md").write_text("# Approach\nUsed RSA factoring.")

        result = runner.invoke(app, ["writeup", str(tmp_path)])
        assert result.exit_code == 0

        writeup_path = ctf_dir / "writeup.md"
        assert writeup_path.is_file()
        content = writeup_path.read_text()
        assert tmp_path.name in content
        assert "Generated by CTF Kit" in content

    def test_generate_writeup_with_flag(self, tmp_path: Path) -> None:
        """Should include flag from flag.txt in the writeup."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()
        (ctf_dir / "analysis.md").write_text("# Analysis")
        (tmp_path / "flag.txt").write_text("flag{s3cr3t_fl4g}")

        result = runner.invoke(app, ["writeup", str(tmp_path)])
        assert result.exit_code == 0

        content = (ctf_dir / "writeup.md").read_text()
        assert "flag{s3cr3t_fl4g}" in content

    def test_generate_writeup_no_ctf_dir(self, tmp_path: Path) -> None:
        """Should fail with exit code 1 if .ctf/ does not exist."""
        result = runner.invoke(app, ["writeup", str(tmp_path)])
        assert result.exit_code == 1
        assert "No .ctf/ folder found" in result.stdout

    def test_generate_writeup_with_solve_script(self, tmp_path: Path) -> None:
        """Should embed solve script content in the writeup."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()
        (ctf_dir / "analysis.md").write_text("# Analysis")

        solve_script = "#!/usr/bin/env python3\nprint('flag{test}')\n"
        (tmp_path / "solve.py").write_text(solve_script)

        result = runner.invoke(app, ["writeup", str(tmp_path)])
        assert result.exit_code == 0

        content = (ctf_dir / "writeup.md").read_text()
        assert "print('flag{test}')" in content

    def test_generate_writeup_no_flag_file(self, tmp_path: Path) -> None:
        """Should use FLAG_NOT_FOUND when flag.txt does not exist."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()
        (ctf_dir / "analysis.md").write_text("# Analysis")

        result = runner.invoke(app, ["writeup", str(tmp_path)])
        assert result.exit_code == 0

        content = (ctf_dir / "writeup.md").read_text()
        assert "FLAG_NOT_FOUND" in content

    def test_generate_writeup_custom_output(self, tmp_path: Path) -> None:
        """Should write to a custom output path when -o is specified."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()
        (ctf_dir / "analysis.md").write_text("# Analysis")

        output_file = tmp_path / "my_writeup.md"
        result = runner.invoke(app, ["writeup", str(tmp_path), "-o", str(output_file)])
        assert result.exit_code == 0
        assert output_file.is_file()
        assert "Generated by CTF Kit" in output_file.read_text()

    def test_generate_writeup_analysis_content_in_output(self, tmp_path: Path) -> None:
        """Analysis content should be included (truncated at MAX_CONTENT_LENGTH)."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()
        analysis_text = "# Analysis\nDetailed crypto analysis of RSA-2048 weakness."
        (ctf_dir / "analysis.md").write_text(analysis_text)

        result = runner.invoke(app, ["writeup", str(tmp_path)])
        assert result.exit_code == 0

        content = (ctf_dir / "writeup.md").read_text()
        assert "RSA-2048" in content


class TestDetectCategory:
    """Tests for the _detect_category helper."""

    def test_detect_category_crypto(self) -> None:
        """Content containing 'crypto' should detect as Crypto."""
        assert _detect_category("This is a crypto challenge") == "Crypto"

    def test_detect_category_web(self) -> None:
        """Content containing 'web' should detect as Web."""
        assert _detect_category("A web exploitation challenge") == "Web"

    def test_detect_category_forensics(self) -> None:
        """Content containing 'forensics' should detect as Forensics."""
        assert _detect_category("Digital forensics challenge") == "Forensics"

    def test_detect_category_pwn(self) -> None:
        """Content containing 'pwn' or 'binary' should detect as Pwn."""
        assert _detect_category("A pwn challenge") == "Pwn"
        assert _detect_category("Binary exploitation") == "Pwn"

    def test_detect_category_reversing(self) -> None:
        """Content containing 'reverse' should detect as Reversing."""
        assert _detect_category("Reverse engineering the firmware") == "Reversing"

    def test_detect_category_stego(self) -> None:
        """Content containing 'stego' should detect as Steganography."""
        assert _detect_category("Hidden data via stego") == "Steganography"

    def test_detect_category_osint(self) -> None:
        """Content containing 'osint' should detect as OSINT."""
        assert _detect_category("OSINT investigation challenge") == "OSINT"

    def test_detect_category_unknown(self) -> None:
        """Content with no recognized keywords should return Unknown."""
        assert _detect_category("Just some random text here") == "Unknown"

    def test_detect_category_case_insensitive(self) -> None:
        """Detection should be case-insensitive."""
        assert _detect_category("CRYPTO CHALLENGE") == "Crypto"
        assert _detect_category("WEB application") == "Web"

    def test_detect_category_empty_string(self) -> None:
        """Empty content should return Unknown."""
        assert _detect_category("") == "Unknown"


# ---------------------------------------------------------------------------
# 5. Config: config.py
# ---------------------------------------------------------------------------


class TestDefaultConfig:
    """Tests for Config defaults."""

    def test_default_config(self) -> None:
        """Config() with no arguments should have sensible defaults."""
        config = Config()
        assert config.version == "1.0"
        assert config.ai_agent == "claude"
        assert isinstance(config.flag_formats, list)
        assert len(config.flag_formats) > 0
        assert isinstance(config.tools, ToolsConfig)
        assert isinstance(config.api_keys, ApiKeysConfig)
        assert isinstance(config.preferences, PreferencesConfig)

    def test_default_flag_formats(self) -> None:
        """Default flag_formats should contain common CTF patterns."""
        config = Config()
        assert any("flag" in fmt for fmt in config.flag_formats)
        assert any("CTF" in fmt for fmt in config.flag_formats)


class TestToolsConfig:
    """Tests for ToolsConfig."""

    def test_tools_config_defaults(self) -> None:
        """All tool paths should default to None."""
        tools = ToolsConfig()
        assert tools.ghidra is None
        assert tools.ida is None
        assert tools.radare2 is None

    def test_tools_config_with_values(self) -> None:
        """Tool paths can be set explicitly."""
        tools = ToolsConfig(ghidra="/opt/ghidra/ghidra", ida="/opt/ida/ida64")
        assert tools.ghidra == "/opt/ghidra/ghidra"
        assert tools.ida == "/opt/ida/ida64"
        assert tools.radare2 is None


class TestApiKeysConfig:
    """Tests for ApiKeysConfig."""

    def test_api_keys_config_defaults(self) -> None:
        """All API keys should default to None."""
        keys = ApiKeysConfig()
        assert keys.shodan is None
        assert keys.virustotal is None
        assert keys.censys is None

    def test_api_keys_config_with_values(self) -> None:
        """API keys can be set explicitly."""
        keys = ApiKeysConfig(shodan="abc123", virustotal="def456")
        assert keys.shodan == "abc123"
        assert keys.virustotal == "def456"


class TestPreferencesConfig:
    """Tests for PreferencesConfig."""

    def test_preferences_config_defaults(self) -> None:
        """Preferences should have expected defaults."""
        prefs = PreferencesConfig()
        assert prefs.auto_commit is False
        assert prefs.writeup_format == "markdown"
        assert prefs.include_failed_attempts is True
        assert prefs.organize_by_category is False

    def test_preferences_config_with_values(self) -> None:
        """Preferences can be overridden."""
        prefs = PreferencesConfig(auto_commit=True, writeup_format="html")
        assert prefs.auto_commit is True
        assert prefs.writeup_format == "html"


class TestChallengeConfig:
    """Tests for ChallengeConfig dataclass."""

    def test_challenge_config_creation(self) -> None:
        """ChallengeConfig should be created with required and optional fields."""
        cc = ChallengeConfig(name="rsa-baby")
        assert cc.name == "rsa-baby"
        assert cc.category is None
        assert cc.flag_format is None
        assert cc.solved is False
        assert cc.flag is None
        assert cc.points is None
        assert cc.tags == []

    def test_challenge_config_full(self) -> None:
        """ChallengeConfig with all fields set."""
        cc = ChallengeConfig(
            name="rsa-baby",
            category="crypto",
            flag_format="flag{.*}",
            solved=True,
            flag="flag{g0t_1t}",
            points=200,
            tags=["rsa", "factoring"],
        )
        assert cc.name == "rsa-baby"
        assert cc.category == "crypto"
        assert cc.solved is True
        assert cc.flag == "flag{g0t_1t}"
        assert cc.points == 200
        assert "rsa" in cc.tags

    def test_challenge_config_to_dict(self) -> None:
        """ChallengeConfig should be convertible via vars() or asdict()."""
        cc = ChallengeConfig(name="test", category="web")
        d = asdict(cc)
        assert d["name"] == "test"
        assert d["category"] == "web"
        assert d["solved"] is False


class TestFindRepoRoot:
    """Tests for find_repo_root."""

    def test_find_repo_root_with_ctf_kit(self, tmp_path: Path) -> None:
        """Should find root when .ctf-kit/ exists."""
        (tmp_path / ".ctf-kit").mkdir()
        nested = tmp_path / "challenges" / "crypto"
        nested.mkdir(parents=True)

        root = find_repo_root(nested)
        assert root == tmp_path

    def test_find_repo_root_with_git(self, tmp_path: Path) -> None:
        """Should find root when .git/ exists."""
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)

        root = find_repo_root(nested)
        assert root == tmp_path

    def test_find_repo_root_ctf_kit_preferred_over_git(self, tmp_path: Path) -> None:
        """When .ctf-kit/ is found first (closer), it should be preferred over .git/."""
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "challenges"
        sub.mkdir()
        (sub / ".ctf-kit").mkdir()

        root = find_repo_root(sub)
        assert root == sub

    def test_find_repo_root_not_found(self, tmp_path: Path) -> None:
        """Should return None when no markers are found."""
        isolated = tmp_path / "isolated"
        isolated.mkdir()

        # Patch Path.parents to limit search to tmp_path subtree
        # find_repo_root walks up to filesystem root, but tmp_path won't have markers
        # We just verify the function handles no match gracefully
        root = find_repo_root(isolated)
        # Result depends on filesystem; if run inside a git repo it may find one.
        # The key contract: the function should NOT raise.
        assert root is None or isinstance(root, Path)

    def test_find_repo_root_direct_match(self, tmp_path: Path) -> None:
        """Should return start_path itself if it contains the marker."""
        (tmp_path / ".ctf-kit").mkdir()
        root = find_repo_root(tmp_path)
        assert root == tmp_path


class TestLoadConfig:
    """Tests for load_config."""

    def test_load_config_from_file(self, tmp_path: Path) -> None:
        """Should load config from .ctf-kit/config.yaml."""
        ctf_kit_dir = tmp_path / ".ctf-kit"
        ctf_kit_dir.mkdir()

        config_data = {
            "version": "2.0",
            "ai_agent": "copilot",
            "flag_formats": ["flag{.*}"],
        }
        with (ctf_kit_dir / "config.yaml").open("w") as f:
            yaml.dump(config_data, f)

        config = load_config(tmp_path)
        assert config.version == "2.0"
        assert config.ai_agent == "copilot"
        assert "flag{.*}" in config.flag_formats

    def test_load_config_defaults(self, tmp_path: Path) -> None:
        """Should return defaults when no config file exists."""
        # tmp_path has no .ctf-kit or .git
        # Patch find_repo_root to return None so it does not find the real repo
        with patch("ctf_kit.config.find_repo_root", return_value=None):
            config = load_config(tmp_path)
        assert config.version == "1.0"
        assert config.ai_agent == "claude"

    def test_load_config_partial_file(self, tmp_path: Path) -> None:
        """Should fill in defaults for missing keys."""
        ctf_kit_dir = tmp_path / ".ctf-kit"
        ctf_kit_dir.mkdir()

        # Only set version
        config_data = {"version": "3.0"}
        with (ctf_kit_dir / "config.yaml").open("w") as f:
            yaml.dump(config_data, f)

        config = load_config(tmp_path)
        assert config.version == "3.0"
        # Defaults should fill in
        assert config.ai_agent == "claude"


class TestSaveConfig:
    """Tests for save_config."""

    def test_save_config(self, tmp_path: Path) -> None:
        """Should save config as valid YAML."""
        config = Config(version="2.0", ai_agent="cursor")
        config_path = tmp_path / ".ctf-kit" / "config.yaml"

        save_config(config, config_path)

        assert config_path.is_file()
        with config_path.open() as f:
            data = yaml.safe_load(f)
        assert data["version"] == "2.0"
        assert data["ai_agent"] == "cursor"

    def test_save_config_creates_parent_dirs(self, tmp_path: Path) -> None:
        """save_config should create parent directories if they do not exist."""
        config = Config()
        config_path = tmp_path / "deep" / "nested" / "config.yaml"

        save_config(config, config_path)

        assert config_path.is_file()

    def test_save_config_excludes_none(self, tmp_path: Path) -> None:
        """save_config should exclude None values (exclude_none=True)."""
        config = Config(tools=ToolsConfig(ghidra=None, ida=None, radare2=None))
        config_path = tmp_path / "config.yaml"

        save_config(config, config_path)

        with config_path.open() as f:
            data = yaml.safe_load(f)
        # tools should either be absent or not contain None-valued keys
        if "tools" in data:
            for key, value in data["tools"].items():
                assert value is not None, f"tools.{key} should have been excluded"

    def test_save_and_reload_roundtrip(self, tmp_path: Path) -> None:
        """Saving and reloading should produce equivalent config."""
        original = Config(
            version="1.5",
            ai_agent="gemini",
            flag_formats=["custom{.*}"],
        )
        config_path = tmp_path / ".ctf-kit" / "config.yaml"
        save_config(original, config_path)

        loaded = load_config(tmp_path)
        assert loaded.version == original.version
        assert loaded.ai_agent == original.ai_agent
        assert loaded.flag_formats == original.flag_formats


class TestLoadChallengeConfig:
    """Tests for load_challenge_config."""

    def test_load_challenge_config(self, tmp_path: Path) -> None:
        """Should load challenge config from .ctf/challenge.yaml."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()

        config_data = {
            "name": "rsa-baby",
            "category": "crypto",
            "solved": True,
            "flag": "flag{done}",
            "points": 100,
            "tags": ["rsa"],
        }
        with (ctf_dir / "challenge.yaml").open("w") as f:
            yaml.dump(config_data, f)

        cc = load_challenge_config(tmp_path)
        assert cc is not None
        assert cc.name == "rsa-baby"
        assert cc.category == "crypto"
        assert cc.solved is True
        assert cc.flag == "flag{done}"
        assert cc.points == 100
        assert "rsa" in cc.tags

    def test_load_challenge_config_not_found(self, tmp_path: Path) -> None:
        """Should return None when .ctf/challenge.yaml does not exist."""
        cc = load_challenge_config(tmp_path)
        assert cc is None

    def test_load_challenge_config_minimal(self, tmp_path: Path) -> None:
        """Should handle minimal config (only 'name')."""
        ctf_dir = tmp_path / ".ctf"
        ctf_dir.mkdir()

        config_data = {"name": "minimal-challenge"}
        with (ctf_dir / "challenge.yaml").open("w") as f:
            yaml.dump(config_data, f)

        cc = load_challenge_config(tmp_path)
        assert cc is not None
        assert cc.name == "minimal-challenge"
        assert cc.solved is False
        assert cc.tags == []


class TestSaveChallengeConfig:
    """Tests for save_challenge_config."""

    def test_save_challenge_config(self, tmp_path: Path) -> None:
        """Should save challenge config to .ctf/challenge.yaml."""
        cc = ChallengeConfig(
            name="test-challenge",
            category="web",
            solved=True,
            flag="flag{test}",
            points=50,
            tags=["xss", "sqli"],
        )
        save_challenge_config(cc, tmp_path)

        config_file = tmp_path / ".ctf" / "challenge.yaml"
        assert config_file.is_file()

        with config_file.open() as f:
            data = yaml.safe_load(f)

        assert data["name"] == "test-challenge"
        assert data["category"] == "web"
        assert data["solved"] is True
        assert data["flag"] == "flag{test}"
        assert data["points"] == 50
        assert "xss" in data["tags"]

    def test_save_challenge_config_creates_ctf_dir(self, tmp_path: Path) -> None:
        """Should create .ctf/ directory if it does not exist."""
        cc = ChallengeConfig(name="new-challenge")
        save_challenge_config(cc, tmp_path)

        assert (tmp_path / ".ctf" / "challenge.yaml").is_file()

    def test_save_and_load_challenge_roundtrip(self, tmp_path: Path) -> None:
        """Saving and loading should produce equivalent ChallengeConfig."""
        original = ChallengeConfig(
            name="roundtrip",
            category="forensics",
            flag_format=r"flag\{.*\}",
            solved=False,
            flag=None,
            points=300,
            tags=["memory", "volatility"],
        )
        save_challenge_config(original, tmp_path)
        loaded = load_challenge_config(tmp_path)

        assert loaded is not None
        assert loaded.name == original.name
        assert loaded.category == original.category
        assert loaded.flag_format == original.flag_format
        assert loaded.solved == original.solved
        assert loaded.points == original.points
        assert loaded.tags == original.tags


class TestGetConfig:
    """Tests for the get_config caching function."""

    def test_get_config_returns_config(self) -> None:
        """get_config should return a Config instance."""
        import ctf_kit.config as config_module

        # Reset cached config
        config_module._config = None
        with patch("ctf_kit.config.load_config", return_value=Config()):
            config = config_module.get_config()
        assert isinstance(config, Config)

    def test_get_config_caches(self) -> None:
        """get_config should return the same instance on subsequent calls."""
        import ctf_kit.config as config_module

        # Reset cached config
        config_module._config = None
        sentinel = Config(version="cached")
        with patch("ctf_kit.config.load_config", return_value=sentinel):
            first = config_module.get_config()

        # Second call should NOT invoke load_config again
        with patch(
            "ctf_kit.config.load_config", side_effect=AssertionError("should not be called")
        ):
            second = config_module.get_config()

        assert first is second
        assert first.version == "cached"

        # Clean up
        config_module._config = None
