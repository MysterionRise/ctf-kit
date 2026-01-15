"""
Tests for the analyze command.
"""

from pathlib import Path
import tempfile

from typer.testing import CliRunner

from ctf_kit.cli import app
from ctf_kit.commands.analyze import get_analysis_summary

runner = CliRunner()


class TestAnalyzeCommand:
    """Test analyze CLI command."""

    def test_analyze_empty_directory(self) -> None:
        """Test analyzing an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["analyze", tmpdir])
            assert result.exit_code == 0
            assert "No files found" in result.stdout

    def test_analyze_with_text_file(self) -> None:
        """Test analyzing directory with a text file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "readme.txt").write_text("Hello World")
            result = runner.invoke(app, ["analyze", tmpdir])
            assert result.exit_code == 0
            assert "readme.txt" in result.stdout

    def test_analyze_single_file(self) -> None:
        """Test analyzing a single file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Test content")
            f.flush()
            path = Path(f.name)

        try:
            result = runner.invoke(app, ["analyze", str(path)])
            assert result.exit_code == 0
        finally:
            path.unlink()

    def test_analyze_verbose(self) -> None:
        """Test analyze with verbose output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.txt").write_text("Hello")
            result = runner.invoke(app, ["analyze", tmpdir, "-v"])
            assert result.exit_code == 0

    def test_analyze_markdown_output(self) -> None:
        """Test analyze with markdown output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.txt").write_text("Hello")
            result = runner.invoke(app, ["analyze", tmpdir, "-m"])
            assert result.exit_code == 0
            assert "# Challenge Analysis" in result.stdout

    def test_analyze_nonexistent_path(self) -> None:
        """Test analyzing nonexistent path."""
        result = runner.invoke(app, ["analyze", "/nonexistent/path"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()


class TestGetAnalysisSummary:
    """Test programmatic analysis summary."""

    def test_summary_empty_directory(self) -> None:
        """Test summary of empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = get_analysis_summary(Path(tmpdir))
            assert summary["file_count"] == 0
            assert summary["category"] == "misc"

    def test_summary_with_files(self) -> None:
        """Test summary with files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.txt").write_text("Hello")
            (Path(tmpdir) / "data.bin").write_bytes(b"\x00\x01\x02")

            summary = get_analysis_summary(Path(tmpdir))
            assert summary["file_count"] == 2
            assert isinstance(summary["tools"], list)

    def test_summary_crypto_files(self) -> None:
        """Test summary with crypto-related files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a .pem file - the extension triggers crypto category
            (Path(tmpdir) / "certificate.pem").write_text(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
            )

            summary = get_analysis_summary(Path(tmpdir))
            assert summary["category"] == "crypto"
