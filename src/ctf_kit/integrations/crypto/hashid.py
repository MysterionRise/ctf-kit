"""
HashID tool wrapper for CTF Kit.

HashID identifies the type of hash from a given input.
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
class HashIDTool(BaseTool):
    """
    Wrapper for the 'hashid' command.

    HashID identifies different types of hashes used to encrypt data,
    especially passwords. Useful for CTF challenges involving hash cracking.
    """

    name: ClassVar[str] = "hashid"
    description: ClassVar[str] = "Identify hash types from input"
    category: ClassVar[ToolCategory] = ToolCategory.CRYPTO
    binary_names: ClassVar[list[str]] = ["hashid"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install hashid",
        "linux": "pip install hashid",
        "windows": "pip install hashid",
    }

    def run(
        self,
        hash_value: str,
        extended: bool = False,
        john_format: bool = False,
        hashcat_mode: bool = False,
    ) -> ToolResult:
        """
        Identify hash type.

        Args:
            hash_value: The hash string to identify
            extended: Show extended info (-e)
            john_format: Show John the Ripper format (-j)
            hashcat_mode: Show Hashcat mode number (-m)

        Returns:
            ToolResult with identified hash types
        """
        args: list[str] = []

        if extended:
            args.append("-e")

        if john_format:
            args.append("-j")

        if hashcat_mode:
            args.append("-m")

        args.append(hash_value)

        result = self._run_with_result(args)

        # Add suggestions based on identified hashes
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data.get("hash_types", []))
            result.suggestions = suggestions

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse hashid output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "hash_types": [],
        }

        # Parse the hash types from output
        # hashid output format: "[+] HashType [Hashcat Mode: X] [JtR Format: Y]"
        hash_pattern = re.compile(
            r"\[?\+?\]?\s*([A-Za-z0-9\s\-/]+?)(?:\s*\[Hashcat Mode:\s*(\d+)\])?"
            r"(?:\s*\[JtR Format:\s*([^\]]+)\])?\s*$"
        )

        for raw_line in stdout.strip().split("\n"):
            line = raw_line.strip()
            if not line or line.startswith("Analyzing"):
                continue

            match = hash_pattern.match(line)
            if match:
                hash_type = match.group(1).strip()
                hashcat_mode = match.group(2)
                jtr_format = match.group(3)

                if hash_type:
                    hash_info: dict[str, Any] = {"type": hash_type}
                    if hashcat_mode:
                        hash_info["hashcat_mode"] = int(hashcat_mode)
                    if jtr_format:
                        hash_info["jtr_format"] = jtr_format
                    parsed["hash_types"].append(hash_info)

        # Determine most likely hash type
        if parsed["hash_types"]:
            parsed["most_likely"] = parsed["hash_types"][0]["type"]

        return parsed

    def _get_suggestions(self, hash_types: list[dict[str, Any]]) -> list[str]:
        """Get cracking suggestions based on hash types."""
        suggestions: list[str] = []

        if not hash_types:
            suggestions.append("Unable to identify hash type - may be encoded or custom")
            return suggestions

        # Get most likely hash type
        most_likely = hash_types[0].get("type", "").lower() if hash_types else ""

        # Common hash type suggestions
        if "md5" in most_likely:
            suggestions.extend(
                [
                    "Try hashcat with -m 0 for MD5",
                    "Check CrackStation or hashes.com for known hashes",
                    "Use rockyou.txt wordlist for common passwords",
                ]
            )
        elif "sha1" in most_likely:
            suggestions.extend(
                [
                    "Try hashcat with -m 100 for SHA1",
                    "Check online rainbow tables",
                    "Consider salted variants (SHA1($pass.$salt))",
                ]
            )
        elif "sha256" in most_likely or "sha-256" in most_likely:
            suggestions.extend(
                [
                    "Try hashcat with -m 1400 for SHA256",
                    "May need powerful GPU for brute force",
                    "Check for known plaintext patterns",
                ]
            )
        elif "sha512" in most_likely or "sha-512" in most_likely:
            suggestions.extend(
                [
                    "Try hashcat with -m 1700 for SHA512",
                    "Consider if this is Linux /etc/shadow format",
                ]
            )
        elif "bcrypt" in most_likely:
            suggestions.extend(
                [
                    "bcrypt is slow to crack - need targeted wordlist",
                    "Try hashcat with -m 3200",
                    "Cost factor matters - check $2a$XX$",
                ]
            )
        elif "ntlm" in most_likely:
            suggestions.extend(
                [
                    "Try hashcat with -m 1000 for NTLM",
                    "Check for pass-the-hash opportunities",
                    "Windows hashes crack fast with GPU",
                ]
            )
        elif "mysql" in most_likely:
            suggestions.extend(
                [
                    "MySQL 4.x uses -m 200, MySQL 5.x uses -m 300",
                    "Database dumps often have weak passwords",
                ]
            )
        else:
            suggestions.extend(
                [
                    "Try hashcat with detected mode number",
                    "Search for hash format documentation",
                    "Consider if multiple encodings were applied",
                ]
            )

        # Add general suggestions
        suggestions.append("Always try common wordlists first (rockyou, common-passwords)")

        return suggestions

    def identify_multiple(self, hashes: list[str]) -> dict[str, ToolResult]:
        """Identify multiple hashes at once."""
        results: dict[str, ToolResult] = {}
        for hash_value in hashes:
            results[hash_value] = self.run(hash_value)
        return results
