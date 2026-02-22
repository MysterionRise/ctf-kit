"""
Zbarimg wrapper for CTF Kit.

Zbarimg scans and decodes barcodes and QR codes from images.
"""

import re
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)


@register_tool
class ZbarimgTool(BaseTool):
    """
    Wrapper for the 'zbarimg' command.

    Zbarimg reads and decodes barcodes and QR codes from image files.
    Supports QR Code, EAN, UPC, ISBN, Code 128, Code 39, and more.
    """

    name: ClassVar[str] = "zbarimg"
    description: ClassVar[str] = "Scan and decode QR codes and barcodes from images"
    category: ClassVar[ToolCategory] = ToolCategory.MISC
    binary_names: ClassVar[list[str]] = ["zbarimg"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install zbar",
        "linux": "apt-get install zbar-tools",
        "windows": "choco install zbar",
    }

    def run(
        self,
        path: str,
        quiet: bool = True,
        raw: bool = False,
        timeout: int = 30,
    ) -> ToolResult:
        """
        Scan an image for barcodes and QR codes.

        Args:
            path: Path to image file
            quiet: Suppress warnings
            raw: Output raw barcode data without type prefix
            timeout: Timeout in seconds

        Returns:
            ToolResult with decoded barcode/QR data
        """
        args: list[str] = []

        if quiet:
            args.append("--quiet")

        if raw:
            args.append("--raw")

        args.append(str(path))

        result = self._run_with_result(args, timeout=timeout)

        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse zbarimg output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "codes": [],
            "qr_codes": [],
            "barcodes": [],
        }

        # zbarimg output format: TYPE:DATA
        # e.g., QR-Code:https://example.com
        #        EAN-13:1234567890123
        code_pattern = re.compile(r"^(\S+?):(.+)$", re.MULTILINE)

        for match in code_pattern.finditer(stdout):
            code_type = match.group(1)
            code_data = match.group(2).strip()

            code_entry = {
                "type": code_type,
                "data": code_data,
            }

            parsed["codes"].append(code_entry)

            if "qr" in code_type.lower():
                parsed["qr_codes"].append(code_entry)
            else:
                parsed["barcodes"].append(code_entry)

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on decoded results."""
        suggestions: list[str] = []

        codes = parsed_data.get("codes", [])

        if codes:
            suggestions.append(f"Decoded {len(codes)} code(s):")
            for code in codes[:5]:
                data_preview = code["data"][:80]
                suggestions.append(f"  [{code['type']}] {data_preview}")

            # Check for common CTF patterns in decoded data
            for code in codes:
                data = code["data"]
                if re.search(r"flag\{[^}]+\}", data, re.IGNORECASE):
                    suggestions.append(f"FLAG FOUND in {code['type']}: {data}")
                elif data.startswith("http"):
                    suggestions.append(f"URL found - visit or fetch: {data}")
                elif re.match(r"^[A-Za-z0-9+/]{4,}={0,2}$", data):
                    suggestions.append("Data appears to be base64 encoded - try decoding")
        else:
            suggestions.extend(
                [
                    "No barcodes or QR codes found in image",
                    "Try adjusting image contrast or cropping",
                    "Check if image contains a different encoding method",
                ]
            )

        return suggestions

    def decode(self, path: str) -> ToolResult:
        """Decode barcodes/QR codes from an image."""
        return self.run(path)

    def get_qr_data(self, path: str) -> list[str]:
        """Get decoded QR code data from an image."""
        result = self.run(path)
        if result.success and result.parsed_data:
            return [qr["data"] for qr in result.parsed_data.get("qr_codes", [])]
        return []
