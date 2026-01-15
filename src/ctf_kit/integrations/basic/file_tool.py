"""
File command wrapper for CTF Kit.

The 'file' command determines file type using magic bytes.
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
class FileTool(BaseTool):
    """
    Wrapper for the 'file' command.

    The file command tests each argument to classify it.
    It uses magic bytes, filesystem tests, and language tests.
    """

    name: ClassVar[str] = "file"
    description: ClassVar[str] = "Determine file type using magic bytes"
    category: ClassVar[ToolCategory] = ToolCategory.MISC
    binary_names: ClassVar[list[str]] = ["file"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install file",
        "linux": "apt-get install file",
        "windows": "choco install file",
    }

    def run(
        self,
        path: Path | str,
        brief: bool = True,
        mime: bool = False,
        keep_going: bool = False,
    ) -> ToolResult:
        """
        Run file command on a path.

        Args:
            path: File or directory to analyze
            brief: Show brief output without filename (default True)
            mime: Show MIME type instead of human-readable
            keep_going: Keep going after first match

        Returns:
            ToolResult with file type information
        """
        args: list[str] = []

        if brief:
            args.append("-b")

        if mime:
            args.append("--mime-type")

        if keep_going:
            args.append("-k")

        args.append(str(path))

        result = self._run_with_result(args)

        # Add suggestions based on file type
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data.get("file_type", ""))
            result.suggestions = suggestions

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse file command output."""
        file_type = stdout.strip()

        parsed: dict[str, Any] = {
            "file_type": file_type,
            "raw_stdout": stdout,
            "raw_stderr": stderr,
        }

        # Extract additional info
        self._parse_elf_info(file_type, parsed)
        self._parse_pe_info(file_type, parsed)
        self._parse_media_info(file_type, parsed)
        self._parse_text_info(file_type, parsed)

        return parsed

    def _parse_elf_info(self, file_type: str, parsed: dict[str, Any]) -> None:
        """Parse ELF binary info."""
        if "ELF" not in file_type:
            return

        parsed["is_elf"] = True
        parsed["is_executable"] = True
        if "32-bit" in file_type:
            parsed["architecture"] = "32-bit"
        elif "64-bit" in file_type:
            parsed["architecture"] = "64-bit"
        if "stripped" in file_type:
            parsed["stripped"] = True
        if "not stripped" in file_type:
            parsed["stripped"] = False

    def _parse_pe_info(self, file_type: str, parsed: dict[str, Any]) -> None:
        """Parse PE executable info."""
        if parsed.get("is_elf"):
            return
        if "PE32" not in file_type and "executable" not in file_type.lower():
            return

        parsed["is_executable"] = True
        if "PE32+" in file_type:
            parsed["architecture"] = "64-bit"
        elif "PE32" in file_type:
            parsed["architecture"] = "32-bit"

    def _parse_media_info(self, file_type: str, parsed: dict[str, Any]) -> None:
        """Parse media file info."""
        file_type_lower = file_type.lower()

        if "image" in file_type_lower or any(
            img in file_type_lower for img in ["png", "jpeg", "gif", "bmp"]
        ):
            parsed["is_image"] = True
            # Try to extract dimensions
            dim_match = re.search(r"(\d+)\s*x\s*(\d+)", file_type)
            if dim_match:
                parsed["width"] = int(dim_match.group(1))
                parsed["height"] = int(dim_match.group(2))

        elif "audio" in file_type_lower or any(
            audio in file_type_lower for audio in ["mp3", "wav", "flac", "ogg"]
        ):
            parsed["is_audio"] = True

        elif "video" in file_type_lower or any(
            video in file_type_lower for video in ["mp4", "avi", "mkv"]
        ):
            parsed["is_video"] = True

        elif any(archive in file_type_lower for archive in ["zip", "tar", "gzip", "rar", "7z"]):
            parsed["is_archive"] = True

    def _parse_text_info(self, file_type: str, parsed: dict[str, Any]) -> None:
        """Parse text file info."""
        file_type_lower = file_type.lower()
        if "text" in file_type_lower or "ascii" in file_type_lower:
            parsed["is_text"] = True

    def _get_suggestions(self, file_type: str) -> list[str]:
        """Get tool suggestions based on file type."""
        suggestions: list[str] = []
        file_type_lower = file_type.lower()

        if "elf" in file_type_lower:
            suggestions.extend(
                [
                    "Run 'strings' to extract readable strings",
                    "Use 'objdump -d' to disassemble",
                    "Try 'checksec' to check security features",
                    "Load in Ghidra or radare2 for analysis",
                ]
            )

        elif "pe32" in file_type_lower or (
            "executable" in file_type_lower and "windows" in file_type_lower
        ):
            suggestions.extend(
                [
                    "Run 'strings' to extract readable strings",
                    "Use PE analysis tools (pestudio, pe-bear)",
                    "Load in Ghidra or IDA for analysis",
                ]
            )

        elif "image" in file_type_lower or any(
            img in file_type_lower for img in ["png", "jpeg", "gif", "bmp"]
        ):
            suggestions.extend(
                [
                    "Run 'exiftool' to check metadata",
                    "Try 'zsteg' for PNG/BMP steganography",
                    "Use 'steghide' for JPEG steganography",
                    "Check with 'binwalk' for embedded data",
                ]
            )

        elif "audio" in file_type_lower:
            suggestions.extend(
                [
                    "Check with 'exiftool' for metadata",
                    "View spectrogram in Audacity or Sonic Visualiser",
                    "Try 'binwalk' for embedded data",
                ]
            )

        elif any(archive in file_type_lower for archive in ["zip", "tar", "gzip", "rar", "7z"]):
            suggestions.extend(
                [
                    "List contents to see what's inside",
                    "Check if password protected",
                    "Try 'binwalk -e' to extract recursively",
                ]
            )

        elif "pcap" in file_type_lower:
            suggestions.extend(
                [
                    "Open in Wireshark for analysis",
                    "Use 'tshark' for command-line analysis",
                    "Extract files with 'foremost' or Wireshark export",
                ]
            )

        elif "text" in file_type_lower or "ascii" in file_type_lower:
            suggestions.extend(
                [
                    "Check encoding (base64, hex, etc.)",
                    "Look for patterns or flags",
                    "Try CyberChef for decoding",
                ]
            )

        elif "pdf" in file_type_lower:
            suggestions.extend(
                [
                    "Check with 'pdfinfo' for metadata",
                    "Try 'pdftotext' to extract text",
                    "Use 'pdf-parser' for structure analysis",
                ]
            )

        return suggestions

    def get_mime_type(self, path: Path | str) -> str | None:
        """Get just the MIME type of a file."""
        result = self.run(path, brief=True, mime=True)
        if result.success:
            return result.stdout.strip()
        return None
