"""
Radare2 wrapper for CTF Kit.

Radare2 is a reverse engineering framework for disassembly and debugging.
"""

from pathlib import Path
import re
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)


@register_tool
class Radare2Tool(BaseTool):
    """
    Wrapper for the 'radare2' command.

    Radare2 provides disassembly, debugging, and analysis of binaries.
    """

    name: ClassVar[str] = "radare2"
    description: ClassVar[str] = "Reverse engineering and binary analysis"
    category: ClassVar[ToolCategory] = ToolCategory.REVERSING
    binary_names: ClassVar[list[str]] = ["r2", "radare2"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install radare2",
        "linux": "sudo apt install radare2",
        "windows": "Download from https://rada.re/n/radare2.html",
    }

    def run(
        self,
        binary_path: Path | str,
        commands: list[str] | None = None,
        analyze: bool = True,
        quiet: bool = True,
        timeout: int = 120,
    ) -> ToolResult:
        """
        Run radare2 commands on a binary.

        Args:
            binary_path: Path to binary file
            commands: List of r2 commands to run
            analyze: Run analysis first (aaa)
            quiet: Quiet mode
            timeout: Timeout in seconds

        Returns:
            ToolResult with analysis output
        """
        args: list[str] = []

        if quiet:
            args.append("-q")

        # Build command string
        cmd_list: list[str] = []
        if analyze:
            cmd_list.append("aaa")

        if commands:
            cmd_list.extend(commands)

        if cmd_list:
            args.extend(["-c", "; ".join(cmd_list)])

        args.append(str(binary_path))

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {}, commands)

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse radare2 output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "functions": [],
            "strings": [],
            "imports": [],
            "entry_point": None,
        }

        # Parse function list (from afl)
        func_pattern = re.compile(r"(0x[0-9a-fA-F]+)\s+\d+\s+\d+\s+(.+)")
        for match in func_pattern.finditer(stdout):
            parsed["functions"].append(
                {
                    "address": match.group(1),
                    "name": match.group(2).strip(),
                }
            )

        # Parse entry point (from ie)
        entry_pattern = re.compile(r"entry0\s+(0x[0-9a-fA-F]+)")
        entry_match = entry_pattern.search(stdout)
        if entry_match:
            parsed["entry_point"] = entry_match.group(1)

        # Parse imports (from ii)
        import_pattern = re.compile(r"\d+\s+(0x[0-9a-fA-F]+)\s+\w+\s+(\w+)\s+(\w+)")
        for match in import_pattern.finditer(stdout):
            parsed["imports"].append(
                {
                    "address": match.group(1),
                    "type": match.group(2),
                    "name": match.group(3),
                }
            )

        # Parse strings (from iz)
        string_pattern = re.compile(r"(0x[0-9a-fA-F]+)\s+\d+\s+\d+\s+\.\w+\s+\w+\s+(.+)")
        for match in string_pattern.finditer(stdout):
            parsed["strings"].append(
                {
                    "address": match.group(1),
                    "value": match.group(2).strip(),
                }
            )

        return parsed

    def _get_suggestions(
        self, parsed_data: dict[str, Any], commands: list[str] | None
    ) -> list[str]:
        """Get suggestions based on analysis."""
        suggestions: list[str] = []

        functions = parsed_data.get("functions", [])
        if functions:
            suggestions.append(f"Found {len(functions)} functions")

            # Look for interesting functions
            interesting = ["main", "win", "flag", "check", "verify", "password"]
            found = [f for f in functions if any(i in f["name"].lower() for i in interesting)]
            if found:
                suggestions.append("Interesting functions:")
                for f in found[:5]:
                    suggestions.append(f"  {f['address']}: {f['name']}")

        if parsed_data.get("entry_point"):
            suggestions.append(f"Entry point: {parsed_data['entry_point']}")

        if not commands:
            suggestions.extend(
                [
                    "Useful commands:",
                    "  afl - list functions",
                    "  pdf @ main - disassemble main",
                    "  pdc @ main - decompile main",
                    "  iz - list strings",
                    "  ii - list imports",
                ]
            )

        return suggestions

    def list_functions(self, binary_path: Path | str) -> ToolResult:
        """List all functions in the binary."""
        return self.run(binary_path, commands=["afl"])

    def disassemble(self, binary_path: Path | str, function: str = "main") -> ToolResult:
        """Disassemble a function."""
        return self.run(binary_path, commands=[f"pdf @ {function}"])

    def decompile(self, binary_path: Path | str, function: str = "main") -> ToolResult:
        """Decompile a function (pseudo-code)."""
        return self.run(binary_path, commands=[f"pdc @ {function}"])

    def list_strings(self, binary_path: Path | str) -> ToolResult:
        """List strings in the binary."""
        return self.run(binary_path, commands=["iz"])

    def list_imports(self, binary_path: Path | str) -> ToolResult:
        """List imported functions."""
        return self.run(binary_path, commands=["ii"])

    def get_entry_point(self, binary_path: Path | str) -> str | None:
        """Get the entry point address."""
        result = self.run(binary_path, commands=["ie"])
        if result.success and result.parsed_data:
            return result.parsed_data.get("entry_point")
        return None

    def search_string(self, binary_path: Path | str, pattern: str) -> ToolResult:
        """Search for strings matching a pattern."""
        return self.run(binary_path, commands=[f"/ {pattern}"])

    def cross_references(self, binary_path: Path | str, address: str) -> ToolResult:
        """Find cross-references to an address."""
        return self.run(binary_path, commands=[f"axt @ {address}"])
