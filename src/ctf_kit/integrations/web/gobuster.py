"""
Gobuster wrapper for CTF Kit.

Gobuster is a directory/file/DNS/vhost busting tool.
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
class GobusterTool(BaseTool):
    """
    Wrapper for the 'gobuster' command.

    Gobuster brute-forces URIs (directories and files), DNS subdomains,
    and virtual host names.
    """

    name: ClassVar[str] = "gobuster"
    description: ClassVar[str] = "Directory and file brute-forcing"
    category: ClassVar[ToolCategory] = ToolCategory.WEB
    binary_names: ClassVar[list[str]] = ["gobuster"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install gobuster",
        "linux": "sudo apt install gobuster",
        "windows": "go install github.com/OJ/gobuster/v3@latest",
    }

    def run(  # noqa: PLR0913
        self,
        url: str,
        mode: str = "dir",
        wordlist: Path | str | None = None,
        extensions: list[str] | None = None,
        status_codes: list[int] | None = None,
        threads: int = 10,
        timeout: int = 300,
        follow_redirect: bool = False,
        cookies: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> ToolResult:
        """
        Run directory/file enumeration.

        Args:
            url: Target URL
            mode: Mode (dir, dns, vhost)
            wordlist: Path to wordlist
            extensions: File extensions to search (e.g., ["php", "html"])
            status_codes: Status codes to match (default: 200,204,301,302,307,401,403)
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
            follow_redirect: Follow redirects
            cookies: Cookies to send
            headers: Additional headers

        Returns:
            ToolResult with enumeration results
        """
        args: list[str] = [mode, "-u", url]

        if wordlist:
            args.extend(["-w", str(wordlist)])
        else:
            # Try common wordlist locations
            wordlists = [
                Path("/usr/share/wordlists/dirb/common.txt"),
                Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
                Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
            ]
            for wl in wordlists:
                if wl.exists():
                    args.extend(["-w", str(wl)])
                    break

        if extensions:
            args.extend(["-x", ",".join(extensions)])

        if status_codes:
            args.extend(["-s", ",".join(str(c) for c in status_codes)])

        args.extend(["-t", str(threads)])

        if follow_redirect:
            args.append("-r")

        if cookies:
            args.extend(["-c", cookies])

        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        # Quiet mode for cleaner output
        args.append("-q")

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse gobuster output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "found_paths": [],
            "by_status": {},
        }

        # Parse directory findings
        # Format: /path (Status: 200) [Size: 1234]
        path_pattern = re.compile(r"(/[^\s]*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")

        for match in path_pattern.finditer(stdout):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3)) if match.group(3) else None

            finding = {
                "path": path,
                "status": status,
                "size": size,
            }
            parsed["found_paths"].append(finding)

            # Group by status
            if status not in parsed["by_status"]:
                parsed["by_status"][status] = []
            parsed["by_status"][status].append(path)

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on results."""
        suggestions: list[str] = []

        found_paths = parsed_data.get("found_paths", [])
        by_status = parsed_data.get("by_status", {})

        if found_paths:
            suggestions.append(f"Found {len(found_paths)} paths")

            # Highlight interesting ones
            interesting = [p for p in found_paths if p["status"] in [200, 301, 302]]
            if interesting:
                for p in interesting[:5]:
                    suggestions.append(f"  {p['path']} ({p['status']})")

        if 403 in by_status:
            count = len(by_status[403])
            suggestions.append(f"{count} forbidden paths - may need auth")

        if 401 in by_status:
            count = len(by_status[401])
            suggestions.append(f"{count} paths requiring authentication")

        if not found_paths:
            suggestions.extend(
                [
                    "No paths found with current wordlist",
                    "Try a larger wordlist",
                    "Try different extensions: -x php,html,txt",
                    "Check if target is responding",
                ]
            )
        else:
            suggestions.append("Visit discovered paths for further analysis")

        return suggestions

    def scan_dirs(self, url: str, wordlist: Path | str | None = None) -> ToolResult:
        """Scan for directories."""
        return self.run(url, mode="dir", wordlist=wordlist)

    def scan_files(
        self, url: str, extensions: list[str], wordlist: Path | str | None = None
    ) -> ToolResult:
        """Scan for files with specific extensions."""
        return self.run(url, mode="dir", wordlist=wordlist, extensions=extensions)

    def scan_dns(self, domain: str, wordlist: Path | str | None = None) -> ToolResult:
        """Scan for DNS subdomains."""
        return self.run(domain, mode="dns", wordlist=wordlist)

    def scan_vhost(self, url: str, wordlist: Path | str | None = None) -> ToolResult:
        """Scan for virtual hosts."""
        return self.run(url, mode="vhost", wordlist=wordlist)
