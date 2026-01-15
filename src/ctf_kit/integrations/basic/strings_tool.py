"""
Strings command wrapper for CTF Kit.

The 'strings' command extracts printable strings from files.
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
class StringsTool(BaseTool):
    """
    Wrapper for the 'strings' command.

    Extracts printable character sequences from binary files.
    Essential for initial analysis of executables and unknown files.
    """

    name: ClassVar[str] = "strings"
    description: ClassVar[str] = "Extract printable strings from binary files"
    category: ClassVar[ToolCategory] = ToolCategory.MISC
    binary_names: ClassVar[list[str]] = ["strings"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install binutils",
        "linux": "apt-get install binutils",
        "windows": "choco install binutils",
    }

    # Common patterns to look for in strings
    INTERESTING_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"flag\{[^}]+\}", "Flag format"),
        (r"CTF\{[^}]+\}", "CTF flag format"),
        (r"picoCTF\{[^}]+\}", "picoCTF flag format"),
        (r"https?://[^\s]+", "URL"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email address"),
        (r"/etc/passwd", "Passwd reference"),
        (r"/bin/sh|/bin/bash", "Shell reference"),
        (r"password|passwd|secret|key|token", "Sensitive keyword"),
        (r"-----BEGIN .* KEY-----", "Cryptographic key"),
        (r"[A-Za-z0-9+/]{40,}={0,2}", "Base64 string"),
        (r"[0-9a-f]{32}", "MD5-like hash"),
        (r"[0-9a-f]{40}", "SHA1-like hash"),
        (r"[0-9a-f]{64}", "SHA256-like hash"),
        (r"SELECT .* FROM", "SQL query"),
        (r"INSERT INTO", "SQL insert"),
        (r"<\?php", "PHP code"),
        (r"import os|import sys|import subprocess", "Python imports"),
        (r"#include <", "C/C++ include"),
    ]

    def run(
        self,
        path: Path | str,
        min_length: int = 4,
        encoding: str | None = None,
        offset: bool = False,
        all_sections: bool = False,
    ) -> ToolResult:
        """
        Run strings command on a file.

        Args:
            path: File to extract strings from
            min_length: Minimum string length (default 4)
            encoding: Character encoding (s=7-bit, S=8-bit, b=16-bit BE, etc.)
            offset: Print offset with each string
            all_sections: Scan entire file, not just data sections

        Returns:
            ToolResult with extracted strings and analysis
        """
        args: list[str] = []

        args.extend(["-n", str(min_length)])

        if encoding:
            args.extend(["-e", encoding])

        if offset:
            args.append("-t")
            args.append("x")  # Hex offset

        if all_sections:
            args.append("-a")

        args.append(str(path))

        result = self._run_with_result(args)

        # Add suggestions based on findings
        if result.success and result.parsed_data:
            suggestions = self._get_suggestions(result.parsed_data)
            result.suggestions = suggestions

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse strings output and find interesting patterns."""
        lines = stdout.strip().split("\n") if stdout.strip() else []

        parsed: dict[str, Any] = {
            "total_strings": len(lines),
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "interesting": [],
            "flags": [],
            "urls": [],
            "emails": [],
            "hashes": [],
            "keys": [],
            "base64": [],
        }

        for line in lines:
            for pattern, description in self.INTERESTING_PATTERNS:
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    item = {
                        "string": line.strip()[:200],  # Limit length
                        "pattern": description,
                        "matches": matches[:10],  # Limit matches
                    }
                    parsed["interesting"].append(item)

                    # Categorize
                    if "flag" in description.lower():
                        parsed["flags"].extend(matches)
                    elif "url" in description.lower():
                        parsed["urls"].extend(matches)
                    elif "email" in description.lower():
                        parsed["emails"].extend(matches)
                    elif "hash" in description.lower():
                        parsed["hashes"].extend(matches)
                    elif "key" in description.lower():
                        parsed["keys"].extend(matches)
                    elif "base64" in description.lower():
                        parsed["base64"].extend(matches)

        # Deduplicate
        parsed["flags"] = list(set(parsed["flags"]))
        parsed["urls"] = list(set(parsed["urls"]))
        parsed["emails"] = list(set(parsed["emails"]))
        parsed["hashes"] = list(set(parsed["hashes"]))

        return parsed

    def _get_suggestions(self, parsed: dict[str, Any]) -> list[str]:
        """Generate suggestions based on findings."""
        suggestions: list[str] = []

        if parsed.get("flags"):
            suggestions.append(f"Found potential flag(s): {', '.join(parsed['flags'][:3])}")

        if parsed.get("urls"):
            suggestions.append(f"Found {len(parsed['urls'])} URL(s) - investigate endpoints")

        if parsed.get("base64"):
            suggestions.append(
                f"Found {len(parsed['base64'])} base64-like string(s) - try decoding"
            )

        if parsed.get("hashes"):
            suggestions.append(
                f"Found {len(parsed['hashes'])} hash-like string(s) - try identifying with hashid"
            )

        if parsed.get("keys"):
            suggestions.append("Found cryptographic key markers - extract and analyze")

        interesting = parsed.get("interesting", [])
        if any("sql" in item.get("pattern", "").lower() for item in interesting):
            suggestions.append("SQL patterns detected - may contain injection hints")

        if any("php" in item.get("pattern", "").lower() for item in interesting):
            suggestions.append("PHP code detected - check for vulnerabilities")

        if not suggestions:
            total = parsed.get("total_strings", 0)
            if total > 0:
                suggestions.append(f"Extracted {total} strings - search for patterns manually")
            else:
                suggestions.append("No printable strings found - try different encoding")

        return suggestions

    def find_flags(
        self,
        path: Path | str,
        patterns: list[str] | None = None,
    ) -> list[str]:
        """
        Search for flag patterns in strings.

        Args:
            path: File to search
            patterns: Custom flag patterns (regex)

        Returns:
            List of matched strings
        """
        if patterns is None:
            patterns = [
                r"flag\{[^}]+\}",
                r"CTF\{[^}]+\}",
                r"picoCTF\{[^}]+\}",
            ]

        result = self.run(path)
        if not result.success:
            return []

        flags: list[str] = []
        for pattern in patterns:
            matches = re.findall(pattern, result.stdout, re.IGNORECASE)
            flags.extend(matches)

        return list(set(flags))

    def search(
        self,
        path: Path | str,
        pattern: str,
        case_insensitive: bool = True,
    ) -> list[str]:
        """
        Search strings output for a pattern.

        Args:
            path: File to search
            pattern: Regex pattern to match
            case_insensitive: Case-insensitive search

        Returns:
            List of matching strings
        """
        result = self.run(path)
        if not result.success:
            return []

        flags = re.IGNORECASE if case_insensitive else 0
        lines = result.stdout.strip().split("\n")
        return [line for line in lines if re.search(pattern, line, flags)]
