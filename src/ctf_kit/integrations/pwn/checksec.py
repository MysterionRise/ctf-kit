"""
Checksec wrapper for CTF Kit.

Checksec checks binary security properties (RELRO, Stack Canary, NX, PIE, etc.).
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
class ChecksecTool(BaseTool):
    """
    Wrapper for the 'checksec' command.

    Checksec analyzes binaries to determine security properties
    like RELRO, stack canaries, NX bit, and PIE.
    """

    name: ClassVar[str] = "checksec"
    description: ClassVar[str] = "Check binary security properties"
    category: ClassVar[ToolCategory] = ToolCategory.PWN
    binary_names: ClassVar[list[str]] = ["checksec", "checksec.sh"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install checksec",
        "linux": "sudo apt install checksec",
        "windows": "Use WSL with checksec",
    }

    def run(
        self,
        binary_path: Path | str,
        format_type: str = "json",
        timeout: int = 30,
    ) -> ToolResult:
        """
        Check binary security properties.

        Args:
            binary_path: Path to binary file
            format_type: Output format (json, csv, xml)
            timeout: Timeout in seconds

        Returns:
            ToolResult with security properties
        """
        args: list[str] = ["--file", str(binary_path)]

        if format_type:
            args.extend(["--output", format_type])

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions based on protections
        if result.success and result.parsed_data:
            result.suggestions = self._get_suggestions(result.parsed_data)

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse checksec output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "protections": {},
        }

        combined = stdout + stderr

        # Parse various protection status
        protection_patterns = [
            (r"RELRO\s*[:=]?\s*(Full|Partial|No)", "relro"),
            (r"Stack\s*(?:Canary|CANARY)\s*[:=]?\s*(Enabled|Disabled|No canary)", "canary"),
            (r"NX\s*[:=]?\s*(Enabled|Disabled|NX disabled)", "nx"),
            (r"PIE\s*[:=]?\s*(Enabled|Disabled|No PIE|PIE enabled)", "pie"),
            (r"FORTIFY\s*[:=]?\s*(Enabled|Disabled)", "fortify"),
            (r"RPATH\s*[:=]?\s*(No|Yes)", "rpath"),
            (r"RUNPATH\s*[:=]?\s*(No|Yes)", "runpath"),
        ]

        for pattern, key in protection_patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                value = match.group(1).lower()
                # Normalize values
                if value in ["enabled", "full", "yes", "pie enabled"]:
                    parsed["protections"][key] = True
                elif value in ["disabled", "no", "partial", "no canary", "nx disabled", "no pie"]:
                    parsed["protections"][key] = False
                elif value == "partial":
                    parsed["protections"][key] = "partial"

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on security properties."""
        suggestions: list[str] = []
        protections = parsed_data.get("protections", {})

        # Analyze each protection
        if not protections.get("canary"):
            suggestions.append("No stack canary - buffer overflows may be exploitable")
        else:
            suggestions.append("Stack canary present - need to leak or bypass")

        if not protections.get("nx"):
            suggestions.append("NX disabled - shellcode injection possible")
        else:
            suggestions.append("NX enabled - use ROP/ret2libc instead of shellcode")

        if not protections.get("pie"):
            suggestions.append("No PIE - addresses are fixed, easier ROP")
        else:
            suggestions.append("PIE enabled - need address leak to bypass ASLR")

        relro = protections.get("relro")
        if relro == "partial" or not relro:
            suggestions.append("No/Partial RELRO - GOT overwrite possible")
        else:
            suggestions.append("Full RELRO - GOT is read-only")

        return suggestions

    def quick_check(self, binary_path: Path | str) -> dict[str, Any]:
        """Quick check returning just the protections dict."""
        result = self.run(binary_path)
        if result.success and result.parsed_data:
            protections: dict[str, Any] = result.parsed_data.get("protections", {})
            return protections
        return {}

    def is_exploitable(self, binary_path: Path | str) -> dict[str, bool]:
        """Check common exploitation vectors."""
        protections = self.quick_check(binary_path)

        return {
            "stack_overflow": not protections.get("canary", True),
            "shellcode": not protections.get("nx", True),
            "got_overwrite": protections.get("relro") != "full",
            "fixed_addresses": not protections.get("pie", True),
        }
