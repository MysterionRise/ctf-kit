"""
Xortool wrapper for CTF Kit.

Xortool is used to analyze multi-byte XOR ciphers.
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
class XortoolTool(BaseTool):
    """
    Wrapper for the 'xortool' command.

    Xortool analyzes files encrypted with repeating-key XOR.
    It can determine the key length and attempt to find the key.
    """

    name: ClassVar[str] = "xortool"
    description: ClassVar[str] = "Analyze XOR-encrypted files to find key length and key"
    category: ClassVar[ToolCategory] = ToolCategory.CRYPTO
    binary_names: ClassVar[list[str]] = ["xortool"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install xortool",
        "linux": "pip install xortool",
        "windows": "pip install xortool",
    }

    def run(
        self,
        path: Path | str,
        key_length: int | None = None,
        most_frequent: str | None = None,
        brute_chars: bool = False,
        hex_input: bool = False,
    ) -> ToolResult:
        """
        Analyze XOR-encrypted file.

        Args:
            path: File to analyze
            key_length: Known or suspected key length (-l)
            most_frequent: Most frequent character in plaintext (-c), e.g. "00", "20" (space)
            brute_chars: Try all possible frequent characters (-b)
            hex_input: Input is hex encoded (-x)

        Returns:
            ToolResult with XOR analysis
        """
        args: list[str] = []

        if key_length is not None:
            args.extend(["-l", str(key_length)])

        if most_frequent:
            args.extend(["-c", most_frequent])

        if brute_chars:
            args.append("-b")

        if hex_input:
            args.append("-x")

        args.append(str(path))

        result = self._run_with_result(args)

        # Add suggestions based on analysis
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data)
            result.suggestions = suggestions

            # Check for output files
            output_dir = Path(path).parent / "xortool_out"
            if output_dir.exists():
                artifacts = list(output_dir.glob("*"))
                result.artifacts = artifacts

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse xortool output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "probable_key_lengths": [],
            "key": None,
            "key_hex": None,
        }

        # Parse key length probabilities
        # Format: "Key-length can be X*N with XXX.X% confidence"
        key_length_pattern = re.compile(
            r"Key-length can be\s+(\d+)(?:\*(\d+))?\s+with\s+([\d.]+)%\s+confidence"
        )
        for match in key_length_pattern.finditer(stdout):
            base_len = int(match.group(1))
            multiplier = int(match.group(2)) if match.group(2) else 1
            confidence = float(match.group(3))
            parsed["probable_key_lengths"].append(
                {
                    "length": base_len * multiplier,
                    "base": base_len,
                    "multiplier": multiplier,
                    "confidence": confidence,
                }
            )

        # Parse found key
        # Format: "Key: somekey" or "Key (hex): XX XX XX"
        key_match = re.search(r"Key:\s*([^\n]+)", stdout)
        if key_match:
            parsed["key"] = key_match.group(1).strip()

        hex_key_match = re.search(r"Key \(hex\):\s*([^\n]+)", stdout)
        if hex_key_match:
            parsed["key_hex"] = hex_key_match.group(1).strip()

        # Parse most probable key lengths if present
        # Format: "The most probable key lengths are: X, Y, Z"
        probable_match = re.search(r"most probable key lengths?[^:]*:\s*([^\n]+)", stdout, re.I)
        if probable_match:
            lengths_str = probable_match.group(1)
            lengths = [int(x.strip()) for x in re.findall(r"\d+", lengths_str)]
            if lengths and not parsed["probable_key_lengths"]:
                parsed["probable_key_lengths"] = [
                    {"length": length, "confidence": 0} for length in lengths[:5]
                ]

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on XOR analysis."""
        suggestions: list[str] = []

        key_lengths = parsed_data.get("probable_key_lengths", [])
        key = parsed_data.get("key")

        if key:
            suggestions.append(f"Found key: {key!r} - use it to decrypt")
            suggestions.append("Verify decryption produces readable output")
        elif key_lengths:
            best_length = key_lengths[0]["length"] if key_lengths else None
            if best_length:
                suggestions.append(f"Most likely key length: {best_length}")
                suggestions.append(
                    f"Try: xortool -l {best_length} -c 20 <file>  (assuming space is common)"
                )
                suggestions.append(
                    f"Try: xortool -l {best_length} -c 00 <file>  (assuming null is common)"
                )
                suggestions.append("Try: xortool -b <file>  (brute force common chars)")
        else:
            suggestions.extend(
                [
                    "No clear key length found - data may not be XOR encrypted",
                    "Try different input formats: -x for hex input",
                    "Consider if the XOR key is single byte (use xor-analyze)",
                ]
            )

        return suggestions

    def xor_single_byte(self, path: Path | str, key: int) -> ToolResult:
        """
        XOR file with a single byte key.

        Uses xortool-xor for simple single-byte XOR.
        """
        args = ["-x", f"{key:02x}", "-f", str(path)]
        return self._run_with_result(args)

    def analyze_key_length_only(self, path: Path | str) -> list[dict[str, Any]]:
        """
        Only analyze key length without attempting decryption.

        Returns list of probable key lengths sorted by confidence.
        """
        result = self.run(path)
        if result.success and result.parsed_data:
            lengths = result.parsed_data.get("probable_key_lengths", [])
            return sorted(lengths, key=lambda x: x.get("confidence", 0), reverse=True)
        return []
