"""
Qrencode wrapper for CTF Kit.

Qrencode generates QR code images from text data.
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
class QrencodeTool(BaseTool):
    """
    Wrapper for the 'qrencode' command.

    Qrencode generates QR code images from input text or data.
    Useful for encoding flags, URLs, or data into QR format.
    """

    name: ClassVar[str] = "qrencode"
    description: ClassVar[str] = "Generate QR code images from text data"
    category: ClassVar[ToolCategory] = ToolCategory.MISC
    binary_names: ClassVar[list[str]] = ["qrencode"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install qrencode",
        "linux": "apt-get install qrencode",
        "windows": "choco install qrencode",
    }

    def run(  # noqa: PLR0913
        self,
        data: str,
        output: str | None = None,
        size: int = 10,
        output_type: str = "PNG",
        level: str = "L",
        timeout: int = 10,
    ) -> ToolResult:
        """
        Generate a QR code image.

        Args:
            data: Text data to encode
            output: Output file path (default: stdout)
            size: Module size in pixels
            output_type: Output type (PNG, SVG, UTF8, ANSI, ASCII)
            level: Error correction level (L, M, Q, H)
            timeout: Timeout in seconds

        Returns:
            ToolResult with generated QR code info
        """
        args: list[str] = [
            "-s",
            str(size),
            "-t",
            output_type,
            "-l",
            level,
        ]

        if output:
            args.extend(["-o", output])

        result = self._run_with_result(args, timeout=timeout, input_data=data)

        # Track output file as artifact
        if result.success and output:
            output_path = Path(output)
            if output_path.exists():
                result.artifacts = [output_path]

        if result.success:
            result.suggestions = self._get_suggestions(output, output_type)

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse qrencode output."""
        return {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "generated": not stderr or "error" not in stderr.lower(),
        }

    def _get_suggestions(self, output: str | None, output_type: str) -> list[str]:
        """Get suggestions after QR generation."""
        suggestions: list[str] = []

        if output:
            suggestions.append(f"QR code saved to: {output}")
            suggestions.append("Verify with: zbarimg " + output)
        else:
            suggestions.append(f"QR code generated to stdout ({output_type} format)")

        return suggestions

    def encode(self, data: str, output: str) -> ToolResult:
        """Encode data into a QR code image file."""
        return self.run(data, output=output)

    def encode_to_terminal(self, data: str) -> ToolResult:
        """Encode data and display QR code in terminal."""
        return self.run(data, output_type="UTF8")
