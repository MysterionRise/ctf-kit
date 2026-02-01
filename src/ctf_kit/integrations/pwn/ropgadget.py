"""
ROPgadget wrapper for CTF Kit.

ROPgadget finds ROP gadgets in binaries for building ROP chains.
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
class RopgadgetTool(BaseTool):
    """
    Wrapper for the 'ROPgadget' command.

    ROPgadget searches for gadgets in binaries that can be used
    to build Return-Oriented Programming chains.
    """

    name: ClassVar[str] = "ropgadget"
    description: ClassVar[str] = "Find ROP gadgets in binaries"
    category: ClassVar[ToolCategory] = ToolCategory.PWN
    binary_names: ClassVar[list[str]] = ["ROPgadget", "ropgadget"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install ROPGadget",
        "linux": "pip install ROPGadget",
        "windows": "pip install ROPGadget",
    }

    def run(  # noqa: PLR0913
        self,
        binary_path: Path | str,
        depth: int = 10,
        grep: str | None = None,
        only: str | None = None,
        rop_chain: bool = False,
        no_multibr: bool = False,
        limit: int | None = None,
        timeout: int = 120,
    ) -> ToolResult:
        """
        Find ROP gadgets in a binary.

        Args:
            binary_path: Path to binary file
            depth: Maximum depth of gadgets
            grep: Filter gadgets by regex pattern
            only: Only show specific instruction types
            rop_chain: Generate a ROP chain
            no_multibr: No multiple branches (cleaner gadgets)
            limit: Limit number of gadgets returned
            timeout: Timeout in seconds

        Returns:
            ToolResult with gadgets found
        """
        args: list[str] = ["--binary", str(binary_path)]

        args.extend(["--depth", str(depth)])

        if grep:
            args.extend(["--re", grep])

        if only:
            args.extend(["--only", only])

        if rop_chain:
            args.append("--ropchain")

        if no_multibr:
            args.append("--multibr")

        result = self._run_with_result(args, timeout=timeout)

        # Limit output if requested
        if limit and result.parsed_data:
            gadgets = result.parsed_data.get("gadgets", [])
            result.parsed_data["gadgets"] = gadgets[:limit]

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse ROPgadget output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "gadgets": [],
            "unique_count": 0,
            "rop_chain": None,
        }

        # Parse gadgets
        # Format: 0x00401234 : pop rdi ; ret
        gadget_pattern = re.compile(r"(0x[0-9a-fA-F]+)\s*:\s*(.+)")

        for line in stdout.split("\n"):
            match = gadget_pattern.match(line.strip())
            if match:
                address = match.group(1)
                instructions = match.group(2).strip()
                parsed["gadgets"].append(
                    {
                        "address": address,
                        "instructions": instructions,
                    }
                )

        parsed["unique_count"] = len(parsed["gadgets"])

        # Check for ROP chain
        if "ROP chain generation" in stdout or "rop chain" in stdout.lower():
            chain_start = stdout.find("ROP chain")
            if chain_start != -1:
                parsed["rop_chain"] = stdout[chain_start:]

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on gadgets found."""
        suggestions: list[str] = []

        gadgets = parsed_data.get("gadgets", [])
        count = parsed_data.get("unique_count", 0)

        suggestions.append(f"Found {count} unique gadgets")

        # Look for useful gadgets
        useful_patterns = [
            ("pop rdi", "x64 first argument"),
            ("pop rsi", "x64 second argument"),
            ("pop rdx", "x64 third argument"),
            ("syscall", "system call"),
            ("pop eax", "x86 syscall number"),
            ("int 0x80", "x86 syscall"),
            ("leave", "stack pivot"),
            ("ret", "return gadget"),
        ]

        found_useful: list[str] = []
        for gadget in gadgets:
            instructions = gadget["instructions"].lower()
            for pattern, desc in useful_patterns:
                if pattern in instructions:
                    found_useful.append(f"{pattern} ({desc})")
                    break

        if found_useful:
            unique_useful = list(set(found_useful))[:5]
            suggestions.append(f"Useful gadgets: {', '.join(unique_useful)}")

        # Specific suggestions
        has_pop_rdi = any("pop rdi" in g["instructions"].lower() for g in gadgets)
        has_syscall = any("syscall" in g["instructions"].lower() for g in gadgets)

        if has_pop_rdi:
            suggestions.append("'pop rdi ; ret' found - good for x64 function calls")

        if has_syscall:
            suggestions.append("syscall gadget found - SROP may be possible")

        if parsed_data.get("rop_chain"):
            suggestions.append("Auto-generated ROP chain available")

        return suggestions

    def find_gadget(self, binary_path: Path | str, pattern: str) -> ToolResult:
        """Find gadgets matching a pattern."""
        return self.run(binary_path, grep=pattern)

    def find_pop_gadgets(self, binary_path: Path | str) -> ToolResult:
        """Find all pop gadgets."""
        return self.run(binary_path, only="pop|ret")

    def find_syscall_gadgets(self, binary_path: Path | str) -> ToolResult:
        """Find syscall-related gadgets."""
        return self.run(binary_path, grep="syscall|int 0x80")

    def generate_chain(self, binary_path: Path | str) -> ToolResult:
        """Generate an automatic ROP chain."""
        return self.run(binary_path, rop_chain=True)

    def get_gadget_addresses(self, binary_path: Path | str, pattern: str) -> list[str]:
        """Get addresses of gadgets matching a pattern."""
        result = self.run(binary_path, grep=pattern)
        if result.success and result.parsed_data:
            return [g["address"] for g in result.parsed_data.get("gadgets", [])]
        return []
