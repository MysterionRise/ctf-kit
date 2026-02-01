"""
Ghidra wrapper for CTF Kit.

Ghidra is a software reverse engineering suite from the NSA.
This wrapper uses Ghidra's headless analyzer.
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
class GhidraTool(BaseTool):
    """
    Wrapper for Ghidra's headless analyzer.

    Ghidra provides advanced decompilation and reverse engineering
    capabilities through its headless analysis mode.
    """

    name: ClassVar[str] = "ghidra"
    description: ClassVar[str] = "Advanced decompilation and reverse engineering"
    category: ClassVar[ToolCategory] = ToolCategory.REVERSING
    binary_names: ClassVar[list[str]] = ["analyzeHeadless", "analyzeHeadless.bat"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "Download from https://ghidra-sre.org/ and add to PATH",
        "linux": "Download from https://ghidra-sre.org/ and add to PATH",
        "windows": "Download from https://ghidra-sre.org/ and add to PATH",
    }

    def run(  # noqa: PLR0913
        self,
        binary_path: Path | str,
        project_dir: Path | str | None = None,
        project_name: str = "ctfkit_project",
        script: str | None = None,
        script_args: list[str] | None = None,
        import_only: bool = False,
        overwrite: bool = True,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run Ghidra headless analysis.

        Args:
            binary_path: Path to binary file
            project_dir: Directory for Ghidra project
            project_name: Name of the Ghidra project
            script: Script to run (e.g., ExportDecompiled.py)
            script_args: Arguments for the script
            import_only: Only import, don't analyze
            overwrite: Overwrite existing analysis
            timeout: Timeout in seconds

        Returns:
            ToolResult with analysis output
        """
        if project_dir is None:
            project_dir = Path(binary_path).parent / ".ghidra"

        Path(project_dir).mkdir(parents=True, exist_ok=True)

        args: list[str] = [
            str(project_dir),
            project_name,
            "-import",
            str(binary_path),
        ]

        if overwrite:
            args.append("-overwrite")

        if import_only:
            args.append("-noanalysis")

        if script:
            args.extend(["-postScript", script])
            if script_args:
                args.extend(script_args)

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse Ghidra output into structured data."""
        combined = stdout + stderr
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "analysis_complete": False,
            "functions_found": 0,
            "errors": [],
        }

        # Check for successful completion
        if "Import succeeded" in combined or "ANALYZING" in combined:
            parsed["analysis_complete"] = True

        # Parse function count
        func_match = re.search(r"(\d+)\s+functions", combined)
        if func_match:
            parsed["functions_found"] = int(func_match.group(1))

        # Collect errors
        error_pattern = re.compile(r"ERROR[:\s]+(.+)", re.IGNORECASE)
        for match in error_pattern.finditer(combined):
            parsed["errors"].append(match.group(1).strip())

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on analysis."""
        suggestions: list[str] = []

        if parsed_data.get("analysis_complete"):
            suggestions.append("Ghidra analysis complete")
            if parsed_data.get("functions_found"):
                suggestions.append(f"Found {parsed_data['functions_found']} functions")
        else:
            suggestions.append("Analysis may not have completed successfully")

        if parsed_data.get("errors"):
            for error in parsed_data["errors"][:3]:
                suggestions.append(f"Error: {error}")

        suggestions.extend(
            [
                "Open in Ghidra GUI for interactive analysis",
                "Use decompiler to understand function logic",
                "Check cross-references to find key functions",
            ]
        )

        return suggestions

    def analyze(self, binary_path: Path | str, project_dir: Path | str | None = None) -> ToolResult:
        """Analyze a binary with default settings."""
        return self.run(binary_path, project_dir=project_dir)

    def import_binary(self, binary_path: Path | str, project_dir: Path | str) -> ToolResult:
        """Import a binary without full analysis."""
        return self.run(binary_path, project_dir=project_dir, import_only=True)

    def run_script(
        self,
        binary_path: Path | str,
        script: str,
        project_dir: Path | str | None = None,
    ) -> ToolResult:
        """Run a Ghidra script on a binary."""
        return self.run(binary_path, project_dir=project_dir, script=script)
