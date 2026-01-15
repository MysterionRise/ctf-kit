"""
Exiftool wrapper for CTF Kit.

Exiftool reads and writes metadata in image and media files.
"""

import json
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
class ExiftoolTool(BaseTool):
    """
    Wrapper for the 'exiftool' command.

    Exiftool is a platform-independent Perl library plus a command-line
    application for reading, writing and editing meta information in
    a wide variety of files. Often used in CTF steganography challenges.
    """

    name: ClassVar[str] = "exiftool"
    description: ClassVar[str] = "Read and write metadata in images and media files"
    category: ClassVar[ToolCategory] = ToolCategory.STEGO
    binary_names: ClassVar[list[str]] = ["exiftool"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install exiftool",
        "linux": "apt-get install libimage-exiftool-perl",
        "windows": "choco install exiftool",
    }

    def run(
        self,
        path: Path | str,
        json_output: bool = True,
        all_tags: bool = True,
        extract_binary: bool = False,
    ) -> ToolResult:
        """
        Read metadata from file.

        Args:
            path: File to analyze
            json_output: Output in JSON format (-j)
            all_tags: Show all tags including duplicates (-a)
            extract_binary: Extract binary data (-b)

        Returns:
            ToolResult with metadata information
        """
        args: list[str] = []

        if json_output:
            args.append("-j")

        if all_tags:
            args.append("-a")

        if extract_binary:
            args.append("-b")

        args.append(str(path))

        result = self._run_with_result(args)

        # Add suggestions based on metadata
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data)
            result.suggestions = suggestions

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse exiftool output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "metadata": {},
            "interesting_fields": [],
        }

        # Try to parse JSON output
        try:
            json_data = json.loads(stdout)
            if isinstance(json_data, list) and json_data:
                parsed["metadata"] = json_data[0]
            elif isinstance(json_data, dict):
                parsed["metadata"] = json_data
        except json.JSONDecodeError:
            # Fall back to line-by-line parsing
            parsed["metadata"] = self._parse_text_output(stdout)

        # Find interesting fields for CTF
        parsed["interesting_fields"] = self._find_interesting_fields(parsed["metadata"])

        return parsed

    def _parse_text_output(self, stdout: str) -> dict[str, str]:
        """Parse non-JSON exiftool output."""
        metadata: dict[str, str] = {}

        for line in stdout.strip().split("\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                metadata[key.strip()] = value.strip()

        return metadata

    def _find_interesting_fields(self, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        """Find fields that might contain CTF flags or clues."""
        interesting: list[dict[str, Any]] = []

        # Fields commonly used to hide data in CTF
        ctf_relevant_keys = [
            "comment",
            "usercomment",
            "author",
            "artist",
            "copyright",
            "description",
            "title",
            "subject",
            "keywords",
            "software",
            "make",
            "model",
            "gps",
            "thumbnailimage",
            "xmp",
            "iptc",
        ]

        # Flag patterns to look for
        flag_patterns = [
            re.compile(r"flag\{[^}]+\}", re.I),
            re.compile(r"ctf\{[^}]+\}", re.I),
            re.compile(r"[A-Za-z0-9+/=]{20,}"),  # Base64-like
            re.compile(r"[0-9a-f]{32,}", re.I),  # Hex/hash-like
        ]

        for key, value in metadata.items():
            key_lower = key.lower()
            value_str = str(value)

            # Check if key is CTF-relevant
            is_relevant = any(k in key_lower for k in ctf_relevant_keys)

            # Check if value matches flag patterns
            has_flag_pattern = any(p.search(value_str) for p in flag_patterns)

            # Check for unusually long values
            is_suspicious_length = len(value_str) > 100

            if is_relevant or has_flag_pattern or is_suspicious_length:
                interesting.append(
                    {
                        "field": key,
                        "value": value_str[:500],  # Truncate very long values
                        "reason": self._get_interest_reason(
                            key_lower, value_str, is_relevant, has_flag_pattern
                        ),
                    }
                )

        return interesting

    def _get_interest_reason(
        self,
        _key: str,
        value: str,
        is_relevant: bool,
        has_pattern: bool,
    ) -> str:
        """Explain why a field is interesting."""
        reasons = []

        if has_pattern:
            if "flag" in value.lower() or "ctf" in value.lower():
                reasons.append("Contains flag-like pattern")
            elif len(value) > 20 and value.replace("=", "").isalnum():
                reasons.append("Possible encoded data")

        if is_relevant:
            reasons.append("Common CTF metadata field")

        if len(value) > 100:
            reasons.append("Unusually long value")

        return "; ".join(reasons) if reasons else "Potential interest"

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on metadata analysis."""
        suggestions: list[str] = []

        metadata = parsed_data.get("metadata", {})
        interesting = parsed_data.get("interesting_fields", [])

        if not metadata:
            suggestions.append("No metadata found - file may be stripped")
            return suggestions

        # Check for GPS data
        gps_keys = [k for k in metadata if "gps" in k.lower()]
        if gps_keys:
            suggestions.append("GPS coordinates found - may be location-based challenge")

        # Check for embedded thumbnail
        if any("thumbnail" in k.lower() for k in metadata):
            suggestions.append("Thumbnail found - extract with: exiftool -b -ThumbnailImage")

        # Check for comments
        if interesting:
            suggestions.append(f"Found {len(interesting)} potentially interesting fields")
            suggestions.extend(
                f"Check '{item['field']}': {item['reason']}" for item in interesting[:3]
            )

        # General suggestions
        suggestions.append("Try: strings <file> | grep -i flag")
        suggestions.append("Check for steganography: zsteg, steghide, stegsolve")

        return suggestions

    def extract_thumbnail(self, path: Path | str, output: Path | str) -> ToolResult:
        """Extract embedded thumbnail image."""
        args = ["-b", "-ThumbnailImage", str(path)]
        result = self._run_with_result(args)

        if result.success and result.stdout:
            output_path = Path(output)
            output_path.write_bytes(result.stdout.encode("latin-1"))
            result.artifacts = [output_path]

        return result

    def get_gps_coordinates(self, path: Path | str) -> dict[str, float] | None:
        """Extract GPS coordinates if present."""
        result = self.run(path)

        if not result.success or not result.parsed_data:
            return None

        metadata = result.parsed_data.get("metadata", {})

        lat = metadata.get("GPSLatitude")
        lon = metadata.get("GPSLongitude")

        if lat and lon:
            return {"latitude": self._parse_gps(lat), "longitude": self._parse_gps(lon)}

        return None

    def _parse_gps(self, gps_str: str) -> float:
        """Parse GPS coordinate string to decimal."""
        try:
            # Try direct float conversion
            return float(gps_str)
        except (ValueError, TypeError):
            # Parse DMS format: "40 deg 26' 46.80" N"
            match = re.match(r"(\d+)\s*deg\s*(\d+)'?\s*([\d.]+)\"?\s*([NSEW])?", str(gps_str))
            if match:
                degrees = float(match.group(1))
                minutes = float(match.group(2))
                seconds = float(match.group(3))
                direction = match.group(4)

                decimal = degrees + minutes / 60 + seconds / 3600
                if direction in ("S", "W"):
                    decimal = -decimal
                return decimal
        return 0.0
