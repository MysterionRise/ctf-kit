"""
Zsteg tool wrapper for CTF Kit.

Zsteg detects steganography hidden data in PNG and BMP files.
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
class ZstegTool(BaseTool):
    """
    Wrapper for the 'zsteg' command.

    Zsteg detects steganographic data hidden in PNG and BMP images.
    It checks LSB steganography, color order variations, and more.
    """

    name: ClassVar[str] = "zsteg"
    description: ClassVar[str] = "Detect LSB steganography in PNG and BMP images"
    category: ClassVar[ToolCategory] = ToolCategory.STEGO
    binary_names: ClassVar[list[str]] = ["zsteg"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "gem install zsteg",
        "linux": "gem install zsteg",
        "windows": "gem install zsteg",
    }

    def run(  # noqa: PLR0913
        self,
        path: Path | str,
        all_methods: bool = True,
        verbose: bool = False,
        bits: str | None = None,
        order: str | None = None,
        extract: str | None = None,
    ) -> ToolResult:
        """
        Analyze image for hidden data.

        Args:
            path: PNG or BMP image to analyze
            all_methods: Try all methods (-a)
            verbose: Verbose output (-v)
            bits: Specific bit configuration (e.g., "1b,lsb,xy")
            order: Channel order (e.g., "rgb", "bgr")
            extract: Extract specific data (e.g., "1b,lsb,xy")

        Returns:
            ToolResult with steganography findings
        """
        args: list[str] = []

        if all_methods:
            args.append("-a")

        if verbose:
            args.append("-v")

        if bits:
            args.extend(["-b", bits])

        if order:
            args.extend(["-o", order])

        if extract:
            args.extend(["-E", extract])

        args.append(str(path))

        result = self._run_with_result(args)

        # Add suggestions based on findings
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data)
            result.suggestions = suggestions

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse zsteg output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "findings": [],
            "has_hidden_data": False,
            "possible_flags": [],
        }

        # Parse zsteg output
        # Format: "b1,lsb,xy .. text: "hidden message""
        # or: "b1,rgb,lsb,xy .. file: PNG image"
        finding_pattern = re.compile(r"^([^\s]+)\s+\.\.\s+(.+)$", re.MULTILINE)

        for match in finding_pattern.finditer(stdout):
            channel_info = match.group(1)
            data_info = match.group(2).strip()

            finding: dict[str, Any] = {
                "channel": channel_info,
                "data": data_info,
            }

            # Determine data type
            data_lower = data_info.lower()
            if data_lower.startswith("text:"):
                finding["type"] = "text"
                finding["content"] = data_info[5:].strip().strip('"')
                parsed["has_hidden_data"] = True
            elif data_lower.startswith("file:"):
                finding["type"] = "file"
                finding["content"] = data_info[5:].strip()
                parsed["has_hidden_data"] = True
            elif "extradata:" in data_lower:
                finding["type"] = "extra"
                finding["content"] = data_info
            else:
                finding["type"] = "raw"
                finding["content"] = data_info

            # Check for flag patterns
            flag_patterns = [
                re.compile(r"flag\{[^}]+\}", re.I),
                re.compile(r"ctf\{[^}]+\}", re.I),
                re.compile(r"pico(?:ctf)?\{[^}]+\}", re.I),
            ]

            for pattern in flag_patterns:
                flags = pattern.findall(data_info)
                parsed["possible_flags"].extend(flags)

            parsed["findings"].append(finding)

        # Deduplicate flags
        parsed["possible_flags"] = list(set(parsed["possible_flags"]))

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on zsteg findings."""
        suggestions: list[str] = []

        findings = parsed_data.get("findings", [])
        flags = parsed_data.get("possible_flags", [])
        has_hidden = parsed_data.get("has_hidden_data", False)

        if flags:
            suggestions.append(f"Possible flag(s) found: {', '.join(flags)}")

        if has_hidden:
            text_findings = [f for f in findings if f.get("type") == "text"]
            file_findings = [f for f in findings if f.get("type") == "file"]

            if text_findings:
                suggestions.append(f"Found {len(text_findings)} hidden text strings")
                for tf in text_findings[:3]:
                    content = tf.get("content", "")[:100]
                    suggestions.append(f"  {tf['channel']}: {content}")

            if file_findings:
                suggestions.append(f"Found {len(file_findings)} embedded files")
                suggestions.append("Extract with: zsteg -E <channel> <image> > output")

        if not has_hidden and not flags:
            suggestions.append("No obvious LSB steganography detected")
            suggestions.append("Try other tools: steghide, stegsolve, outguess")
            suggestions.append("Check if image uses different stego method")

        return suggestions

    def extract_data(self, path: Path | str, channel: str, output: Path | str) -> ToolResult:
        """
        Extract hidden data from specific channel.

        Args:
            path: Image file
            channel: Channel specification (e.g., "b1,rgb,lsb,xy")
            output: Output file path

        Returns:
            ToolResult with extracted data
        """
        result = self.run(path, all_methods=False, extract=channel)

        if result.success and result.stdout:
            output_path = Path(output)
            output_path.write_bytes(result.stdout.encode("latin-1"))
            result.artifacts = [output_path]

        return result

    def quick_scan(self, path: Path | str) -> list[dict[str, Any]]:
        """
        Quick scan returning just the findings.

        Args:
            path: Image to scan

        Returns:
            List of findings with type, channel, and content
        """
        result = self.run(path)
        if result.success and result.parsed_data:
            findings: list[dict[str, Any]] = result.parsed_data.get("findings", [])
            return findings
        return []

    def find_flags(self, path: Path | str) -> list[str]:
        """
        Scan image specifically looking for CTF flags.

        Args:
            path: Image to scan

        Returns:
            List of found flag strings
        """
        result = self.run(path)
        if result.success and result.parsed_data:
            flags: list[str] = result.parsed_data.get("possible_flags", [])
            return flags
        return []
