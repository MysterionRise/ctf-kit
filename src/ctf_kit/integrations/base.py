"""
Base classes for tool integrations.

All tool wrappers inherit from BaseTool and return ToolResult.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import shutil
import subprocess  # nosec B404 - subprocess is required for tool execution
import sys
import time
from typing import Any, ClassVar


class ToolCategory(StrEnum):
    """Tool categories."""

    CRYPTO = "crypto"
    ARCHIVE = "archive"
    FORENSICS = "forensics"
    NETWORK = "network"
    STEGO = "stego"
    WEB = "web"
    PWN = "pwn"
    REVERSING = "reversing"
    OSINT = "osint"
    ENCODING = "encoding"
    MISC = "misc"


class ToolStatus(StrEnum):
    """Tool execution status."""

    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolResult:
    """
    Standard result format for all tool operations.

    All tool integrations return this format for consistency.
    """

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

    def __str__(self) -> str:
        status = "✅" if self.success else "❌"
        return f"{status} {self.tool_name}: {self.command}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "parsed_data": self.parsed_data,
            "artifacts": [str(p) for p in (self.artifacts or [])],
            "suggestions": self.suggestions,
            "error_message": self.error_message,
            "execution_time": self.execution_time,
        }


class BaseTool(ABC):
    """
    Base class for all tool integrations.

    Subclasses must define:
    - name: Tool name
    - description: What the tool does
    - category: ToolCategory
    - binary_names: List of possible binary names to search for

    Subclasses should implement:
    - run(): Main entry point with tool-specific arguments
    - parse_output(): Parse stdout/stderr into structured data
    """

    name: ClassVar[str] = "base_tool"
    description: ClassVar[str] = ""
    category: ClassVar[ToolCategory] = ToolCategory.MISC
    binary_names: ClassVar[list[str]] = []
    install_commands: ClassVar[dict[str, str]] = {}  # OS -> install command

    def __init__(self) -> None:
        self._binary_path: str | None = None

    @property
    def binary_path(self) -> str | None:
        """Find and cache the binary path."""
        if self._binary_path is None:
            self._binary_path = self._find_binary()
        return self._binary_path

    def _find_binary(self) -> str | None:
        """Locate the tool binary in PATH or venv."""
        for name in self.binary_names:
            # Check system PATH first
            path = shutil.which(name)
            if path:
                return path

            # Check current venv bin directory
            venv_bin = Path(sys.prefix) / "bin" / name
            if venv_bin.exists():
                return str(venv_bin)

        return None

    @property
    def is_installed(self) -> bool:
        """Check if the tool is installed."""
        return self.binary_path is not None

    def get_version(self) -> str | None:
        """Get tool version string."""
        binary = self.binary_path
        if binary is None:
            return None

        try:
            result = subprocess.run(  # nosec B603 - intentional tool execution
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            version = result.stdout.strip() or result.stderr.strip()
            # Take first line only
            return version.split("\n")[0] if version else "unknown"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return "unknown"

    def get_install_command(self) -> str:
        """Get installation command for current OS."""
        import platform

        system = platform.system().lower()

        if system in self.install_commands:
            return self.install_commands[system]

        return f"Please install {self.name} manually"

    def _run_command(
        self,
        args: list[str],
        timeout: int = 300,
        input_data: str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Execute the tool with given arguments.

        Args:
            args: Command line arguments (without the binary name)
            timeout: Timeout in seconds
            input_data: Data to send to stdin
            cwd: Working directory

        Returns:
            CompletedProcess with stdout, stderr, returncode

        Raises:
            RuntimeError: If tool is not installed
        """
        binary = self.binary_path
        if binary is None:
            msg = f"{self.name} is not installed"
            raise RuntimeError(msg)

        cmd: list[str] = [binary, *args]

        return subprocess.run(  # nosec B603 - intentional tool execution
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            cwd=cwd,
            check=False,
        )

    def _run_with_result(
        self,
        args: list[str],
        timeout: int = 300,
        input_data: str | None = None,
        cwd: Path | None = None,
    ) -> ToolResult:
        """
        Execute tool and return standardized ToolResult.

        Handles errors, timing, and output parsing.
        """
        if not self.is_installed:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"{self.name} {' '.join(args)}",
                stdout="",
                stderr="",
                error_message=f"{self.name} is not installed. Install with: {self.get_install_command()}",
            )

        start_time = time.time()

        try:
            result = self._run_command(args, timeout, input_data, cwd)
            execution_time = time.time() - start_time

            # Parse output
            parsed_data = self.parse_output(result.stdout, result.stderr)

            return ToolResult(
                success=result.returncode == 0,
                tool_name=self.name,
                command=f"{self.name} {' '.join(args)}",
                stdout=result.stdout,
                stderr=result.stderr,
                parsed_data=parsed_data,
                execution_time=execution_time,
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"{self.name} {' '.join(args)}",
                stdout="",
                stderr="",
                error_message=f"Command timed out after {timeout} seconds",
                execution_time=float(timeout),
            )

        except Exception as e:  # noqa: BLE001
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"{self.name} {' '.join(args)}",
                stdout="",
                stderr="",
                error_message=str(e),
                execution_time=time.time() - start_time,
            )

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> ToolResult:
        """
        Main entry point for the tool.

        Implement with tool-specific arguments.
        """

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """
        Parse tool output into structured data.

        Override in subclasses for tool-specific parsing.
        Default implementation returns raw output.
        """
        return {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
        }

    def __repr__(self) -> str:
        status = "✅" if self.is_installed else "❌"
        return f"{status} {self.name} ({self.category.value})"


class ToolChain:
    """
    Chain multiple tools together.

    Runs tools in sequence, passing artifacts from one to the next.
    """

    def __init__(self, tools: list[BaseTool]) -> None:
        self.tools = tools
        self.results: list[ToolResult] = []

    def run(self, initial_input: Path) -> list[ToolResult]:
        """
        Run tools in sequence.

        Args:
            initial_input: Starting file/path

        Returns:
            List of results from each tool
        """
        self.results = []
        current_input = initial_input

        for tool in self.tools:
            result = tool.run(current_input)
            self.results.append(result)

            if not result.success:
                break

            # Use first artifact as next input if available
            if result.artifacts:
                current_input = result.artifacts[0]

        return self.results

    @property
    def success(self) -> bool:
        """Check if all tools succeeded."""
        return all(r.success for r in self.results)

    @property
    def final_result(self) -> ToolResult | None:
        """Get the last result."""
        return self.results[-1] if self.results else None


# Tool registry for discovery
_tool_registry: dict[str, type[BaseTool]] = {}


def register_tool(cls: type[BaseTool]) -> type[BaseTool]:
    """Decorator to register a tool class."""
    _tool_registry[cls.name] = cls
    return cls


def get_tool(name: str) -> BaseTool | None:
    """Get a tool instance by name."""
    if name in _tool_registry:
        return _tool_registry[name]()
    return None


def get_all_tools() -> dict[str, BaseTool]:
    """Get all registered tools."""
    return {name: cls() for name, cls in _tool_registry.items()}


def get_tools_by_category(category: ToolCategory) -> dict[str, BaseTool]:
    """Get all tools in a category."""
    return {name: cls() for name, cls in _tool_registry.items() if cls.category == category}
