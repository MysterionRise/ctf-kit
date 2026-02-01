"""
Volatility 3 wrapper for CTF Kit.

Volatility is a memory forensics framework for analyzing memory dumps.
"""

from pathlib import Path
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)


@register_tool
class VolatilityTool(BaseTool):
    """
    Wrapper for the 'volatility3' command.

    Volatility 3 analyzes memory dumps to extract processes,
    network connections, registry keys, and more.
    """

    name: ClassVar[str] = "volatility"
    description: ClassVar[str] = "Analyze memory dumps for forensic artifacts"
    category: ClassVar[ToolCategory] = ToolCategory.FORENSICS
    binary_names: ClassVar[list[str]] = ["vol", "vol3", "volatility3", "vol.py"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install volatility3",
        "linux": "pip install volatility3",
        "windows": "pip install volatility3",
    }

    # Common plugins organized by category
    PLUGINS: ClassVar[dict[str, list[str]]] = {
        "info": ["windows.info", "linux.info", "mac.info"],
        "processes": ["windows.pslist", "windows.pstree", "windows.psscan", "linux.pslist"],
        "network": ["windows.netscan", "windows.netstat", "linux.netstat"],
        "files": ["windows.filescan", "windows.dumpfiles", "linux.filescan"],
        "registry": ["windows.registry.hivelist", "windows.registry.printkey"],
        "memory": ["windows.memmap", "windows.vadinfo", "windows.malfind"],
        "credentials": ["windows.hashdump", "windows.lsadump", "windows.cachedump"],
        "cmd": ["windows.cmdline", "windows.consoles"],
    }

    def run(
        self,
        memory_file: Path | str,
        plugin: str = "windows.info",
        output_format: str = "text",
        plugin_args: dict[str, Any] | None = None,
        timeout: int = 600,
    ) -> ToolResult:
        """
        Run a volatility plugin on a memory dump.

        Args:
            memory_file: Path to memory dump file
            plugin: Plugin to run (e.g., windows.pslist, windows.netscan)
            output_format: Output format (text, json)
            plugin_args: Additional arguments for the plugin
            timeout: Timeout in seconds

        Returns:
            ToolResult with plugin output
        """
        args: list[str] = [
            "-f",
            str(memory_file),
            plugin,
        ]

        if output_format == "json":
            args.extend(["-r", "json"])

        # Add plugin-specific arguments
        if plugin_args:
            for key, value in plugin_args.items():
                if value is True:
                    args.append(f"--{key}")
                elif value is not False and value is not None:
                    args.append(f"--{key}")
                    args.append(str(value))

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions based on plugin
        if result.success:
            result.suggestions = self._get_suggestions(plugin, result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse volatility output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "rows": [],
            "columns": [],
        }

        lines = stdout.strip().split("\n")

        # Find header line (usually has column names)
        header_idx = -1
        for i, line in enumerate(lines):
            # Header lines typically have "PID" or "Offset" etc.
            if "PID" in line or "Offset" in line or "Name" in line:
                header_idx = i
                break

        if header_idx >= 0 and header_idx < len(lines):
            # Parse as table
            header = lines[header_idx]
            # Split by whitespace (volatility uses fixed-width columns)
            parsed["columns"] = header.split()

            for line in lines[header_idx + 1 :]:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("-"):
                    parts = stripped_line.split()
                    if parts:
                        parsed["rows"].append(parts)

        # Extract specific info based on common patterns
        # Process info
        parsed["processes"] = []
        for row in parsed["rows"]:
            if len(row) >= 2:
                try:
                    pid = int(row[0]) if row[0].isdigit() else None
                    name = row[1] if len(row) > 1 else ""
                    if pid is not None:
                        parsed["processes"].append(
                            {
                                "pid": pid,
                                "name": name,
                            }
                        )
                except (ValueError, IndexError):
                    pass

        return parsed

    def _get_suggestions(self, plugin: str, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on plugin and results."""
        suggestions: list[str] = []

        rows = parsed_data.get("rows", [])
        processes = parsed_data.get("processes", [])

        if rows:
            suggestions.append(f"Found {len(rows)} entries")

        # Plugin-specific suggestions
        if "pslist" in plugin or "pstree" in plugin:
            if processes:
                suggestions.append(f"Found {len(processes)} processes")
            suggestions.extend(
                [
                    "Look for suspicious process names",
                    "Check for processes with unusual parent PIDs",
                    "Try: windows.cmdline to see command lines",
                ]
            )

        elif "netscan" in plugin or "netstat" in plugin:
            suggestions.extend(
                [
                    "Look for unusual connections or ports",
                    "Check for connections to suspicious IPs",
                    "Note any established connections",
                ]
            )

        elif "filescan" in plugin:
            suggestions.extend(
                [
                    "Look for interesting file names",
                    "Use windows.dumpfiles to extract files",
                    "Search for flag-related filenames",
                ]
            )

        elif "malfind" in plugin:
            suggestions.extend(
                [
                    "Review injected code segments",
                    "Dump suspicious regions for analysis",
                    "Check process memory for malware indicators",
                ]
            )

        elif "hashdump" in plugin or "lsadump" in plugin:
            suggestions.extend(
                [
                    "Crack extracted hashes with hashcat/john",
                    "Look for NTLM hashes",
                ]
            )

        elif "info" in plugin:
            suggestions.extend(
                [
                    "Memory profile identified",
                    "Run process listing: windows.pslist",
                    "Check network: windows.netscan",
                ]
            )

        return suggestions

    def get_info(self, memory_file: Path | str) -> ToolResult:
        """Get memory dump information and identify profile."""
        return self.run(memory_file, plugin="windows.info")

    def list_processes(self, memory_file: Path | str) -> ToolResult:
        """List running processes."""
        return self.run(memory_file, plugin="windows.pslist")

    def process_tree(self, memory_file: Path | str) -> ToolResult:
        """Show process tree."""
        return self.run(memory_file, plugin="windows.pstree")

    def network_connections(self, memory_file: Path | str) -> ToolResult:
        """List network connections."""
        return self.run(memory_file, plugin="windows.netscan")

    def scan_files(self, memory_file: Path | str) -> ToolResult:
        """Scan for file objects in memory."""
        return self.run(memory_file, plugin="windows.filescan")

    def find_malware(self, memory_file: Path | str) -> ToolResult:
        """Scan for potential malware injections."""
        return self.run(memory_file, plugin="windows.malfind")

    def dump_hashes(self, memory_file: Path | str) -> ToolResult:
        """Dump password hashes."""
        return self.run(memory_file, plugin="windows.hashdump")

    def get_cmdlines(self, memory_file: Path | str) -> ToolResult:
        """Get command lines of processes."""
        return self.run(memory_file, plugin="windows.cmdline")
