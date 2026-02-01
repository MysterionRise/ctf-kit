"""
Foremost wrapper for CTF Kit.

Foremost is a file carving tool that extracts files from disk images.
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
class ForemostTool(BaseTool):
    """
    Wrapper for the 'foremost' command.

    Foremost carves files from disk images and memory dumps
    based on file headers and footers.
    """

    name: ClassVar[str] = "foremost"
    description: ClassVar[str] = "Carve files from disk images and data streams"
    category: ClassVar[ToolCategory] = ToolCategory.FORENSICS
    binary_names: ClassVar[list[str]] = ["foremost"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install foremost",
        "linux": "sudo apt install foremost",
        "windows": "Use WSL with: sudo apt install foremost",
    }

    def run(  # noqa: PLR0913
        self,
        input_file: Path | str,
        output_dir: Path | str | None = None,
        file_types: list[str] | None = None,
        verbose: bool = False,
        indirect: bool = False,
        timeout: int = 600,
    ) -> ToolResult:
        """
        Carve files from input.

        Args:
            input_file: Input file to carve
            output_dir: Output directory (default: ./output)
            file_types: File types to carve (e.g., ["jpg", "png", "pdf"])
            verbose: Verbose output
            indirect: Indirect block detection (for fragmented files)
            timeout: Timeout in seconds

        Returns:
            ToolResult with carving results
        """
        args: list[str] = []

        if output_dir:
            args.extend(["-o", str(output_dir)])

        if file_types:
            args.extend(["-t", ",".join(file_types)])

        if verbose:
            args.append("-v")

        if indirect:
            args.append("-i")

        # Input file must be last
        args.extend(["-i", str(input_file)])

        result = self._run_with_result(args, timeout=timeout)

        # Find extracted files
        if result.success and output_dir:
            artifacts = self._find_carved_files(Path(output_dir))
            if artifacts:
                result.artifacts = artifacts

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {}, result.artifacts)

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse foremost output into structured data."""
        combined = stdout + stderr
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "files_found": {},
            "total_files": 0,
        }

        # Parse file counts
        # Format: "jpg:= 5"
        count_pattern = re.compile(r"(\w+):\s*=\s*(\d+)")
        for match in count_pattern.finditer(combined):
            file_type = match.group(1)
            count = int(match.group(2))
            if count > 0:
                parsed["files_found"][file_type] = count
                parsed["total_files"] += count

        # Also try parsing from summary
        summary_pattern = re.compile(r"(\d+)\s+files?\s+extracted")
        summary_match = summary_pattern.search(combined)
        if summary_match:
            parsed["total_files"] = int(summary_match.group(1))

        return parsed

    def _find_carved_files(self, output_dir: Path) -> list[Path]:
        """Find all carved files in output directory."""
        if not output_dir.exists():
            return []

        files: list[Path] = []
        for item in output_dir.rglob("*"):
            if item.is_file() and not item.name.startswith("."):
                files.append(item)

        return files

    def _get_suggestions(
        self, parsed_data: dict[str, Any], artifacts: list[Path] | None
    ) -> list[str]:
        """Get suggestions based on carving results."""
        suggestions: list[str] = []

        files_found = parsed_data.get("files_found", {})
        total = parsed_data.get("total_files", 0)

        if total > 0:
            suggestions.append(f"Carved {total} files total")

        if files_found:
            for file_type, count in files_found.items():
                suggestions.append(f"  - {file_type}: {count} files")

        if artifacts:
            # Group by type
            types: dict[str, int] = {}
            for path in artifacts:
                ext = path.suffix.lower() or "unknown"
                types[ext] = types.get(ext, 0) + 1

            suggestions.append(f"Found {len(artifacts)} files:")
            for ext, count in sorted(types.items(), key=lambda x: -x[1])[:5]:
                suggestions.append(f"  - {ext}: {count}")

        if not files_found and not artifacts:
            suggestions.extend(
                [
                    "No files carved",
                    "Try with different file types: -t all",
                    "May need indirect mode for fragmented data: -i",
                    "Check if input is a valid image/dump",
                ]
            )
        else:
            suggestions.append("Analyze carved files for flags/hidden data")

        return suggestions

    def carve_all(self, input_file: Path | str, output_dir: Path | str) -> ToolResult:
        """Carve all supported file types."""
        return self.run(input_file, output_dir=output_dir, file_types=["all"])

    def carve_images(self, input_file: Path | str, output_dir: Path | str) -> ToolResult:
        """Carve image files."""
        return self.run(
            input_file,
            output_dir=output_dir,
            file_types=["jpg", "png", "gif", "bmp"],
        )

    def carve_documents(self, input_file: Path | str, output_dir: Path | str) -> ToolResult:
        """Carve document files."""
        return self.run(
            input_file,
            output_dir=output_dir,
            file_types=["pdf", "doc", "docx", "xls", "ppt"],
        )

    def carve_archives(self, input_file: Path | str, output_dir: Path | str) -> ToolResult:
        """Carve archive files."""
        return self.run(
            input_file,
            output_dir=output_dir,
            file_types=["zip", "rar", "tar", "gz"],
        )
