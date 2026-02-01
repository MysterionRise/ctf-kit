"""
Sherlock wrapper for CTF Kit.

Sherlock searches for usernames across social networks.
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
class SherlockTool(BaseTool):
    """
    Wrapper for the 'sherlock' command.

    Sherlock searches for usernames across many social networks
    and websites.
    """

    name: ClassVar[str] = "sherlock"
    description: ClassVar[str] = "Search for usernames across social networks"
    category: ClassVar[ToolCategory] = ToolCategory.OSINT
    binary_names: ClassVar[list[str]] = ["sherlock"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install sherlock-project",
        "linux": "pip install sherlock-project",
        "windows": "pip install sherlock-project",
    }

    def run(
        self,
        username: str,
        site: str | None = None,
        output_folder: str | None = None,
        print_found: bool = True,
        timeout: int = 120,
    ) -> ToolResult:
        """
        Search for a username across social networks.

        Args:
            username: Username to search for
            site: Specific site to check
            output_folder: Folder to save results
            print_found: Only print found accounts
            timeout: Timeout in seconds

        Returns:
            ToolResult with found profiles
        """
        args: list[str] = [username]

        if site:
            args.extend(["--site", site])

        if output_folder:
            args.extend(["--folderoutput", output_folder])

        if print_found:
            args.append("--print-found")

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse sherlock output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "profiles": [],
            "not_found": [],
            "errors": [],
        }

        # Parse found profiles
        # Format: [+] Site: https://site.com/username
        found_pattern = re.compile(r"\[\+\]\s*(\w+):\s*(https?://\S+)")
        for match in found_pattern.finditer(stdout):
            parsed["profiles"].append(
                {
                    "site": match.group(1),
                    "url": match.group(2),
                }
            )

        # Parse not found
        not_found_pattern = re.compile(r"\[-\]\s*(\w+):")
        for match in not_found_pattern.finditer(stdout):
            parsed["not_found"].append(match.group(1))

        # Parse errors
        error_pattern = re.compile(r"\[!\]\s*(\w+):\s*(.+)")
        for match in error_pattern.finditer(stdout):
            parsed["errors"].append(
                {
                    "site": match.group(1),
                    "error": match.group(2),
                }
            )

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on search results."""
        suggestions: list[str] = []

        profiles = parsed_data.get("profiles", [])

        if profiles:
            suggestions.append(f"Found {len(profiles)} profiles:")
            for p in profiles[:10]:
                suggestions.append(f"  [{p['site']}] {p['url']}")

            if len(profiles) > 10:
                suggestions.append(f"  ... and {len(profiles) - 10} more")

            suggestions.append("Visit profiles to gather more information")
        else:
            suggestions.extend(
                [
                    "No profiles found for this username",
                    "Try alternative usernames or spellings",
                    "Check manually on popular sites",
                ]
            )

        return suggestions

    def search(self, username: str) -> ToolResult:
        """Search for a username."""
        return self.run(username)

    def search_site(self, username: str, site: str) -> ToolResult:
        """Search for a username on a specific site."""
        return self.run(username, site=site)

    def get_profiles(self, username: str) -> list[dict[str, str]]:
        """Get list of found profiles."""
        result = self.run(username)
        if result.success and result.parsed_data:
            profiles: list[dict[str, str]] = result.parsed_data.get("profiles", [])
            return profiles
        return []
