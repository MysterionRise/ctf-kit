"""
Steghide wrapper for CTF Kit.

Steghide is a steganography tool for hiding data in JPEG and other images.
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
class SteghideTool(BaseTool):
    """
    Wrapper for the 'steghide' command.

    Steghide hides and extracts data from JPEG, BMP, WAV, and AU files
    using encryption.
    """

    name: ClassVar[str] = "steghide"
    description: ClassVar[str] = "Hide and extract data from images and audio"
    category: ClassVar[ToolCategory] = ToolCategory.STEGO
    binary_names: ClassVar[list[str]] = ["steghide"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install steghide",
        "linux": "sudo apt install steghide",
        "windows": "Download from https://steghide.sourceforge.net/",
    }

    def run(  # noqa: PLR0913
        self,
        cover_file: Path | str,
        mode: str = "info",
        password: str = "",
        embed_file: Path | str | None = None,
        extract_file: Path | str | None = None,
        force: bool = True,
        timeout: int = 60,
    ) -> ToolResult:
        """
        Run steghide operations.

        Args:
            cover_file: Cover file (image/audio)
            mode: Operation mode (info, extract, embed)
            password: Password for encryption/decryption
            embed_file: File to embed (for embed mode)
            extract_file: Output file for extraction
            force: Overwrite existing files
            timeout: Timeout in seconds

        Returns:
            ToolResult with operation results
        """
        args: list[str] = []

        if mode == "info":
            args.extend(["info", str(cover_file)])
            if password:
                args.extend(["-p", password])

        elif mode == "extract":
            args.extend(["extract", "-sf", str(cover_file)])
            args.extend(["-p", password])  # Empty password if none
            if extract_file:
                args.extend(["-xf", str(extract_file)])
            if force:
                args.append("-f")

        elif mode == "embed":
            if not embed_file:
                return ToolResult(
                    success=False,
                    tool_name=self.name,
                    command="steghide embed",
                    stdout="",
                    stderr="",
                    error_message="embed_file required for embed mode",
                )
            args.extend(["embed", "-cf", str(cover_file)])
            args.extend(["-ef", str(embed_file)])
            if password:
                args.extend(["-p", password])
            if force:
                args.append("-f")

        result = self._run_with_result(args, timeout=timeout)

        # Find extracted files
        if mode == "extract" and result.success:
            if extract_file:
                extracted = Path(extract_file)
                if extracted.exists():
                    result.artifacts = [extracted]
            else:
                # Check for default extraction
                cover_path = Path(cover_file)
                possible_extracted = cover_path.parent / "secret.txt"
                if possible_extracted.exists():
                    result.artifacts = [possible_extracted]

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(mode, result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse steghide output into structured data."""
        combined = stdout + stderr
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "has_embedded": False,
            "embedded_size": None,
            "encryption_algorithm": None,
            "compression": None,
        }

        # Check for embedded data
        if "embedded file" in combined.lower():
            parsed["has_embedded"] = True

        # Parse embedded size
        size_match = re.search(r"capacity:\s*([\d.]+)\s*(\w+)", combined, re.IGNORECASE)
        if size_match:
            parsed["capacity"] = f"{size_match.group(1)} {size_match.group(2)}"

        # Parse encryption algorithm
        algo_match = re.search(r"algorithm:\s*(\S+)", combined, re.IGNORECASE)
        if algo_match:
            parsed["encryption_algorithm"] = algo_match.group(1)

        # Check if extraction succeeded
        if "wrote extracted data" in combined.lower():
            parsed["extraction_success"] = True

        # Check for errors
        if "could not extract" in combined.lower() or "error" in combined.lower():
            parsed["error"] = True
            if "passphrase" in combined.lower():
                parsed["wrong_password"] = True

        return parsed

    def _get_suggestions(self, mode: str, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on operation."""
        suggestions: list[str] = []

        if mode == "info":
            if parsed_data.get("has_embedded"):
                suggestions.append("Embedded data detected!")
                suggestions.append("Try extracting with: steghide extract -sf <file>")
            else:
                suggestions.append("No obvious embedded data")
                suggestions.append("May still contain data with password")

        elif mode == "extract":
            if parsed_data.get("extraction_success"):
                suggestions.append("Data extracted successfully!")
            elif parsed_data.get("wrong_password"):
                suggestions.append("Wrong password - try different passwords")
                suggestions.append("Common passwords: password, steghide, secret, ''")
            else:
                suggestions.append("Extraction failed")
                suggestions.append("Try with password guessing")

        return suggestions

    def info(self, cover_file: Path | str, password: str = "") -> ToolResult:
        """Get info about a file."""
        return self.run(cover_file, mode="info", password=password)

    def extract(
        self,
        cover_file: Path | str,
        password: str = "",
        output_file: Path | str | None = None,
    ) -> ToolResult:
        """Extract hidden data."""
        return self.run(cover_file, mode="extract", password=password, extract_file=output_file)

    def embed(
        self,
        cover_file: Path | str,
        data_file: Path | str,
        password: str = "",
    ) -> ToolResult:
        """Embed data into a file."""
        return self.run(cover_file, mode="embed", password=password, embed_file=data_file)

    def try_passwords(
        self, cover_file: Path | str, passwords: list[str] | None = None
    ) -> ToolResult:
        """Try multiple passwords for extraction."""
        if passwords is None:
            passwords = [
                "",
                "password",
                "steghide",
                "secret",
                "hidden",
                "flag",
                "admin",
                "123456",
            ]

        for password in passwords:
            result = self.extract(cover_file, password=password)
            parsed = result.parsed_data or {}
            if result.success and not parsed.get("wrong_password"):
                result.suggestions = [f"Password found: '{password}'"]
                return result

        return ToolResult(
            success=False,
            tool_name=self.name,
            command=f"steghide extract (tried {len(passwords)} passwords)",
            stdout="",
            stderr="",
            error_message="No valid password found",
            suggestions=["Try more passwords or custom wordlist"],
        )
