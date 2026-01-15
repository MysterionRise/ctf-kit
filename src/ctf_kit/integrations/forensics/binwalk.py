"""
Binwalk tool wrapper for CTF Kit.

Binwalk is a firmware analysis tool for scanning and extracting embedded files.
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
class BinwalkTool(BaseTool):
    """
    Wrapper for the 'binwalk' command.

    Binwalk scans binary files for embedded files and executable code.
    It can identify file signatures and extract embedded content.
    """

    name: ClassVar[str] = "binwalk"
    description: ClassVar[str] = "Scan and extract firmware images and embedded files"
    category: ClassVar[ToolCategory] = ToolCategory.FORENSICS
    binary_names: ClassVar[list[str]] = ["binwalk"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install binwalk",
        "linux": "pip install binwalk",
        "windows": "pip install binwalk",
    }

    def run(  # noqa: PLR0913
        self,
        path: Path | str,
        extract: bool = False,
        signature: bool = True,
        entropy: bool = False,
        matryoshka: bool = False,
        directory: Path | str | None = None,
    ) -> ToolResult:
        """
        Scan file for embedded content.

        Args:
            path: File to analyze
            extract: Extract identified files (-e)
            signature: Scan for file signatures (default True)
            entropy: Show entropy analysis (-E)
            matryoshka: Recursively extract files (-M)
            directory: Extraction directory (-C)

        Returns:
            ToolResult with identified files and signatures
        """
        args: list[str] = []

        if extract:
            args.append("-e")

        if matryoshka:
            args.append("-M")

        if entropy:
            args.append("-E")

        if directory:
            args.extend(["-C", str(directory)])

        if signature:
            # Default behavior, no flag needed
            pass

        args.append(str(path))

        result = self._run_with_result(args)

        # Find extracted files
        if extract and result.success:
            artifacts = self._find_extracted_files(Path(path), directory)
            if artifacts:
                result.artifacts = artifacts

        # Add suggestions based on findings
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data)
            result.suggestions = suggestions

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse binwalk output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "signatures": [],
            "file_types": set(),
        }

        # Parse signature scan output
        # Format: "DECIMAL    HEXADECIMAL    DESCRIPTION"
        sig_pattern = re.compile(r"(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)")

        for raw_line in stdout.strip().split("\n"):
            line = raw_line.strip()
            if not line or line.startswith("DECIMAL"):
                continue

            match = sig_pattern.match(line)
            if match:
                offset_dec = int(match.group(1))
                offset_hex = match.group(2)
                description = match.group(3).strip()

                signature_info: dict[str, Any] = {
                    "offset": offset_dec,
                    "offset_hex": offset_hex,
                    "description": description,
                }

                # Extract file type from description
                file_type = self._extract_file_type(description)
                if file_type:
                    signature_info["file_type"] = file_type
                    parsed["file_types"].add(file_type)

                parsed["signatures"].append(signature_info)

        # Convert set to list for JSON serialization
        parsed["file_types"] = list(parsed["file_types"])

        return parsed

    def _extract_file_type(self, description: str) -> str | None:
        """Extract file type from binwalk description."""
        desc_lower = description.lower()

        type_keywords = {
            "zip archive": "zip",
            "gzip compressed": "gzip",
            "tar archive": "tar",
            "rar archive": "rar",
            "7-zip": "7zip",
            "png image": "png",
            "jpeg image": "jpeg",
            "gif image": "gif",
            "bmp": "bmp",
            "elf": "elf",
            "pe32": "pe",
            "pdf document": "pdf",
            "sqlite": "sqlite",
            "zlib": "zlib",
            "lzma": "lzma",
            "squashfs": "squashfs",
            "cramfs": "cramfs",
            "jffs2": "jffs2",
            "linux kernel": "linux",
            "u-boot": "uboot",
            "certificate": "cert",
            "private key": "key",
            "openssh": "ssh",
        }

        for keyword, file_type in type_keywords.items():
            if keyword in desc_lower:
                return file_type

        return None

    def _find_extracted_files(
        self, original_path: Path, custom_dir: Path | str | None
    ) -> list[Path]:
        """Find files extracted by binwalk."""
        if custom_dir:
            extract_dir = Path(custom_dir)
        else:
            # Default binwalk extraction directory
            extract_dir = original_path.parent / f"_{original_path.name}.extracted"

        if not extract_dir.exists():
            return []

        return list(extract_dir.rglob("*"))

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on binwalk findings."""
        suggestions: list[str] = []

        signatures = parsed_data.get("signatures", [])
        file_types = parsed_data.get("file_types", [])

        if not signatures:
            suggestions.append("No embedded files detected - may need entropy analysis")
            suggestions.append("Try: binwalk -E <file> for entropy visualization")
            return suggestions

        suggestions.append(f"Found {len(signatures)} embedded signatures")

        if "zip" in file_types or "gzip" in file_types:
            suggestions.append("Archive found - extract with: binwalk -e <file>")

        if "elf" in file_types or "pe" in file_types:
            suggestions.append("Executable found - analyze with strings or disassembler")

        if "png" in file_types or "jpeg" in file_types:
            suggestions.append("Image found - check for steganography (zsteg, steghide)")

        if "squashfs" in file_types or "cramfs" in file_types:
            suggestions.append("Filesystem found - use firmware-mod-kit or sasquatch")

        if len(signatures) > 1:
            suggestions.append("Multiple files found - use -M for recursive extraction")

        return suggestions

    def entropy_scan(self, path: Path | str) -> ToolResult:
        """Run entropy analysis on file."""
        return self.run(path, entropy=True, signature=False)

    def extract_all(self, path: Path | str, output_dir: Path | str | None = None) -> ToolResult:
        """Extract all embedded files recursively."""
        return self.run(path, extract=True, matryoshka=True, directory=output_dir)

    def quick_scan(self, path: Path | str) -> list[dict[str, Any]]:
        """Quick scan returning just the signatures found."""
        result = self.run(path)
        if result.success and result.parsed_data:
            signatures: list[dict[str, Any]] = result.parsed_data.get("signatures", [])
            return signatures
        return []
