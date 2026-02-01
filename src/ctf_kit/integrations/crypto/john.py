"""
John the Ripper wrapper for CTF Kit.

John the Ripper is a password cracking tool supporting many hash types.
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
class JohnTool(BaseTool):
    """
    Wrapper for the 'john' (John the Ripper) command.

    John the Ripper cracks password hashes using wordlists,
    rules, and brute force attacks.
    """

    name: ClassVar[str] = "john"
    description: ClassVar[str] = "Crack password hashes with wordlists and rules"
    category: ClassVar[ToolCategory] = ToolCategory.CRYPTO
    binary_names: ClassVar[list[str]] = ["john", "john-the-ripper"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install john-jumbo",
        "linux": "sudo apt install john",
        "windows": "Download from https://www.openwall.com/john/",
    }

    def run(  # noqa: PLR0913
        self,
        hash_file: Path | str,
        wordlist: Path | str | None = None,
        format_type: str | None = None,
        rules: str | None = None,
        incremental: bool = False,
        show: bool = False,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Crack password hashes.

        Args:
            hash_file: File containing hashes to crack
            wordlist: Wordlist file to use
            format_type: Hash format (e.g., raw-md5, raw-sha256)
            rules: Rules to apply to wordlist
            incremental: Use incremental (brute force) mode
            show: Show cracked passwords
            timeout: Timeout in seconds

        Returns:
            ToolResult with cracking results
        """
        args: list[str] = []

        if show:
            args.append("--show")
            args.append(str(hash_file))
            result = self._run_with_result(args, timeout=timeout)
            if result.success:
                result.suggestions = ["Showing previously cracked passwords"]
            return result

        if wordlist:
            args.extend([f"--wordlist={wordlist}"])

        if format_type:
            args.extend([f"--format={format_type}"])

        if rules:
            args.extend([f"--rules={rules}"])

        if incremental:
            args.append("--incremental")

        args.append(str(hash_file))

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse john output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "cracked": [],
            "guesses": 0,
            "format_detected": None,
        }

        # Parse cracked passwords (from --show output)
        # Format: username:password
        for line in stdout.split("\n"):
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 2 and parts[1]:
                    parsed["cracked"].append(
                        {
                            "hash": parts[0],
                            "password": parts[1],
                        }
                    )

        # Parse cracking progress
        guesses_match = re.search(r"(\d+)g\s+", stdout + stderr)
        if guesses_match:
            parsed["guesses"] = int(guesses_match.group(1))

        # Detect format
        format_match = re.search(r"Loaded.*?type:\s*(\S+)", stdout + stderr)
        if format_match:
            parsed["format_detected"] = format_match.group(1)

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on cracking results."""
        suggestions: list[str] = []

        cracked = parsed_data.get("cracked", [])
        if cracked:
            suggestions.append(f"Cracked {len(cracked)} password(s)!")
            for c in cracked[:3]:
                suggestions.append(f"  {c['hash']}: {c['password']}")

        if not cracked:
            suggestions.extend(
                [
                    "No passwords cracked yet",
                    "Try a larger wordlist (rockyou.txt)",
                    "Try with rules: --rules=best64",
                    "Try incremental mode for short passwords",
                ]
            )

        return suggestions

    def show_cracked(self, hash_file: Path | str) -> ToolResult:
        """Show previously cracked passwords."""
        return self.run(hash_file, show=True)

    def crack_with_rockyou(
        self, hash_file: Path | str, format_type: str | None = None
    ) -> ToolResult:
        """Crack using rockyou wordlist."""
        # Common rockyou locations
        rockyou_paths = [
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
            Path.home() / "wordlists" / "rockyou.txt",
        ]

        wordlist = None
        for path in rockyou_paths:
            if path.exists():
                wordlist = path
                break

        return self.run(hash_file, wordlist=wordlist, format_type=format_type)

    def identify_format(self, hash_file: Path | str) -> str | None:
        """Identify the hash format."""
        result = self.run(hash_file, timeout=10)
        if result.parsed_data:
            return result.parsed_data.get("format_detected")
        return None
