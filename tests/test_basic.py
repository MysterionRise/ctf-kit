"""
Tests for CTF Kit.
"""

from pathlib import Path
import tempfile
from typing import Any, ClassVar

from typer.testing import CliRunner

from ctf_kit.cli import app
from ctf_kit.integrations.base import BaseTool, ToolResult

runner = CliRunner()


class TestCLI:
    """Test CLI commands."""

    def test_version(self) -> None:
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "CTF Kit" in result.stdout

    def test_help(self) -> None:
        """Test help output."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "CTF Kit" in result.stdout

    def test_check_command(self) -> None:
        """Test check command runs."""
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_success_result(self) -> None:
        result = ToolResult(
            success=True,
            tool_name="test",
            command="test --version",
            stdout="test v1.0",
            stderr="",
        )
        assert result.success
        assert "test" in str(result)

    def test_failure_result(self) -> None:
        result = ToolResult(
            success=False,
            tool_name="test",
            command="test --fail",
            stdout="",
            stderr="error",
            error_message="Command failed",
        )
        assert not result.success
        assert "test" in str(result)

    def test_to_dict(self) -> None:
        # Use a real temp file path for testing
        with tempfile.NamedTemporaryFile(suffix=".txt") as tmp:
            tmp_path = Path(tmp.name)
            result = ToolResult(
                success=True,
                tool_name="test",
                command="test",
                stdout="output",
                stderr="",
                artifacts=[tmp_path],
            )
            data = result.to_dict()
            assert data["success"] is True
            assert data["tool_name"] == "test"
            assert str(tmp_path) in data["artifacts"]


class TestBaseTool:
    """Test BaseTool abstract class."""

    def test_tool_not_installed(self) -> None:
        """Test behavior when tool is not installed."""

        class FakeTool(BaseTool):
            name: ClassVar[str] = "nonexistent_tool_12345"
            binary_names: ClassVar[list[str]] = ["nonexistent_tool_12345"]

            def run(self, *args: Any, **kwargs: Any) -> ToolResult:
                return self._run_with_result([])

        tool = FakeTool()
        assert not tool.is_installed

    def test_tool_installed(self) -> None:
        """Test with a tool that should exist (python3)."""

        class PythonTool(BaseTool):
            name: ClassVar[str] = "python3"
            binary_names: ClassVar[list[str]] = ["python3", "python"]

            def run(self, *args: Any, **kwargs: Any) -> ToolResult:
                return self._run_with_result(["--version"])

        tool = PythonTool()
        assert tool.is_installed
        version = tool.get_version()
        assert version is not None
        assert "Python" in version or "python" in version.lower()
