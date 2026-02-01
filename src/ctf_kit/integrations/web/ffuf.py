"""
FFUF wrapper for CTF Kit.

FFUF is a fast web fuzzer written in Go.
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
class FfufTool(BaseTool):
    """
    Wrapper for the 'ffuf' command.

    FFUF (Fuzz Faster U Fool) is a fast web fuzzer for
    directory discovery, parameter fuzzing, and more.
    """

    name: ClassVar[str] = "ffuf"
    description: ClassVar[str] = "Fast web fuzzer for directories and parameters"
    category: ClassVar[ToolCategory] = ToolCategory.WEB
    binary_names: ClassVar[list[str]] = ["ffuf"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install ffuf",
        "linux": "go install github.com/ffuf/ffuf@latest",
        "windows": "go install github.com/ffuf/ffuf@latest",
    }

    def run(  # noqa: PLR0913
        self,
        url: str,
        wordlist: Path | str | None = None,
        data: str | None = None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: str | None = None,
        filter_status: list[int] | None = None,
        match_status: list[int] | None = None,
        filter_size: list[int] | None = None,
        filter_words: int | None = None,
        threads: int = 40,
        timeout: int = 300,
        output_format: str = "json",  # noqa: ARG002
    ) -> ToolResult:
        """
        Run web fuzzing.

        Args:
            url: Target URL with FUZZ keyword
            wordlist: Path to wordlist
            data: POST data (use FUZZ keyword)
            method: HTTP method
            headers: Additional headers
            cookies: Cookies to send
            filter_status: Filter out these status codes
            match_status: Match only these status codes
            filter_size: Filter out these response sizes
            filter_words: Filter out responses with this word count
            threads: Number of concurrent threads
            timeout: Total timeout in seconds
            output_format: Output format (json, csv, html)

        Returns:
            ToolResult with fuzzing results
        """
        args: list[str] = ["-u", url]

        if wordlist:
            args.extend(["-w", str(wordlist)])
        else:
            # Try common wordlist locations
            wordlists = [
                Path("/usr/share/wordlists/dirb/common.txt"),
                Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
            ]
            for wl in wordlists:
                if wl.exists():
                    args.extend(["-w", str(wl)])
                    break

        if data:
            args.extend(["-d", data])
            if method == "GET":
                method = "POST"

        args.extend(["-X", method])

        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        if cookies:
            args.extend(["-H", f"Cookie: {cookies}"])

        if filter_status:
            args.extend(["-fc", ",".join(str(c) for c in filter_status)])

        if match_status:
            args.extend(["-mc", ",".join(str(c) for c in match_status)])

        if filter_size:
            args.extend(["-fs", ",".join(str(s) for s in filter_size)])

        if filter_words is not None:
            args.extend(["-fw", str(filter_words)])

        args.extend(["-t", str(threads)])

        # Silent mode for cleaner output
        args.append("-s")

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse ffuf output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "results": [],
            "by_status": {},
        }

        # Parse results
        # Format varies, try multiple patterns
        # JSON output: {"input":{"FUZZ":"admin"},"position":1,"status":200,...}
        # Text output: path [Status: 200, Size: 1234, Words: 56, Lines: 7]

        # Try text format
        result_pattern = re.compile(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")

        for match in result_pattern.finditer(stdout):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))

            finding = {
                "input": path,
                "status": status,
                "size": size,
            }
            parsed["results"].append(finding)

            if status not in parsed["by_status"]:
                parsed["by_status"][status] = []
            parsed["by_status"][status].append(path)

        # Also try simpler line format
        if not parsed["results"]:
            for line in stdout.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("["):
                    parts = line.split()
                    if parts:
                        parsed["results"].append(
                            {
                                "input": parts[0],
                                "status": None,
                                "size": None,
                            }
                        )

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on results."""
        suggestions: list[str] = []

        results = parsed_data.get("results", [])
        by_status = parsed_data.get("by_status", {})

        if results:
            suggestions.append(f"Found {len(results)} results")

            # Show top results
            for r in results[:5]:
                status = f" ({r['status']})" if r.get("status") else ""
                suggestions.append(f"  {r['input']}{status}")

        if 200 in by_status:
            count = len(by_status[200])
            suggestions.append(f"{count} valid paths (200 OK)")

        if 301 in by_status or 302 in by_status:
            count = len(by_status.get(301, [])) + len(by_status.get(302, []))
            suggestions.append(f"{count} redirects found")

        if not results:
            suggestions.extend(
                [
                    "No results found",
                    "Try different wordlist",
                    "Adjust filters: -fc 404 to filter 404s",
                    "Check if FUZZ keyword is in URL",
                ]
            )
        else:
            suggestions.append("Visit discovered paths for analysis")

        return suggestions

    def fuzz_dirs(self, url: str, wordlist: Path | str | None = None) -> ToolResult:
        """Fuzz for directories."""
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        return self.run(url, wordlist=wordlist, filter_status=[404])

    def fuzz_params(
        self, url: str, param_name: str, wordlist: Path | str | None = None
    ) -> ToolResult:
        """Fuzz a GET parameter."""
        if "?" not in url:
            url = f"{url}?{param_name}=FUZZ"
        elif "FUZZ" not in url:
            url = f"{url}&{param_name}=FUZZ"
        return self.run(url, wordlist=wordlist)

    def fuzz_post(self, url: str, data: str, wordlist: Path | str | None = None) -> ToolResult:
        """Fuzz POST data."""
        return self.run(url, wordlist=wordlist, data=data, method="POST")

    def fuzz_headers(
        self, url: str, header_name: str, wordlist: Path | str | None = None
    ) -> ToolResult:
        """Fuzz a header value."""
        return self.run(url, wordlist=wordlist, headers={header_name: "FUZZ"})
