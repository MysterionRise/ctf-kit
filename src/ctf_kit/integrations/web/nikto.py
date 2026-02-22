"""
Nikto wrapper for CTF Kit.

Nikto is an open-source web server scanner that tests for dangerous files,
outdated server software, and other vulnerabilities.
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
class NiktoTool(BaseTool):
    """
    Wrapper for the 'nikto' command.

    Nikto scans web servers for known vulnerabilities, misconfigurations,
    outdated software, and dangerous files/programs.
    """

    name: ClassVar[str] = "nikto"
    description: ClassVar[str] = "Web server vulnerability scanner"
    category: ClassVar[ToolCategory] = ToolCategory.WEB
    binary_names: ClassVar[list[str]] = ["nikto", "nikto.pl"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install nikto",
        "linux": "sudo apt install nikto",
        "windows": "Download from https://github.com/sullo/nikto",
    }

    def run(  # noqa: PLR0913
        self,
        host: str,
        port: int | None = None,
        ssl: bool = False,
        plugins: str | None = None,
        tuning: str | None = None,
        output_file: str | None = None,
        output_format: str | None = None,
        no_lookups: bool = True,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Scan a web server for vulnerabilities.

        Args:
            host: Target host (URL or hostname)
            port: Target port
            ssl: Force SSL mode
            plugins: Specific plugins to run (comma-separated)
            tuning: Scan tuning options (e.g., "123" for specific tests)
            output_file: Path for output file
            output_format: Output format (csv, htm, txt, xml)
            no_lookups: Skip DNS lookups
            timeout: Timeout in seconds

        Returns:
            ToolResult with vulnerability findings

        Tuning options:
            1 - Interesting File / Seen in logs
            2 - Misconfiguration / Default File
            3 - Information Disclosure
            4 - Injection (XSS/Script/HTML)
            5 - Remote File Retrieval - Inside Web Root
            6 - Denial of Service
            7 - Remote File Retrieval - Server Wide
            8 - Command Execution / Remote Shell
            9 - SQL Injection
            0 - File Upload
            a - Authentication Bypass
            b - Software Identification
            c - Remote source inclusion
        """
        args: list[str] = ["-h", host]

        if port:
            args.extend(["-p", str(port)])

        if ssl:
            args.append("-ssl")

        if plugins:
            args.extend(["-Plugins", plugins])

        if tuning:
            args.extend(["-Tuning", tuning])

        if output_file:
            args.extend(["-o", output_file])
            if output_format:
                args.extend(["-Format", output_format])

        if no_lookups:
            args.append("-nointeractive")

        result = self._run_with_result(args, timeout=timeout)

        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse nikto output into structured data."""
        combined = stdout + stderr
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "vulnerabilities": [],
            "server_info": {},
            "interesting_findings": [],
            "total_items_found": 0,
        }

        # Parse server info
        server_match = re.search(r"Server:\s*(.+)", combined)
        if server_match:
            parsed["server_info"]["server"] = server_match.group(1).strip()

        target_match = re.search(r"Target IP:\s*(.+)", combined)
        if target_match:
            parsed["server_info"]["ip"] = target_match.group(1).strip()

        hostname_match = re.search(r"Target Hostname:\s*(.+)", combined)
        if hostname_match:
            parsed["server_info"]["hostname"] = hostname_match.group(1).strip()

        port_match = re.search(r"Target Port:\s*(\d+)", combined)
        if port_match:
            parsed["server_info"]["port"] = int(port_match.group(1))

        # Parse OSVDB/vulnerability entries
        vuln_pattern = re.compile(r"\+\s*(OSVDB-\d+|[A-Z]+-\d+)?:?\s*(/[^\s:]*)?:?\s*(.+)")
        for line in combined.split("\n"):
            line = line.strip()
            if not line.startswith("+"):
                continue
            # Skip info lines
            if any(
                skip in line
                for skip in [
                    "Target IP:",
                    "Target Hostname:",
                    "Target Port:",
                    "Start Time:",
                    "End Time:",
                ]
            ):
                continue

            match = vuln_pattern.match(line)
            if match:
                vuln: dict[str, str | None] = {
                    "id": match.group(1),
                    "path": match.group(2),
                    "description": match.group(3).strip() if match.group(3) else line,
                }
                parsed["vulnerabilities"].append(vuln)

        parsed["total_items_found"] = len(parsed["vulnerabilities"])

        # Categorize interesting findings
        for vuln in parsed["vulnerabilities"]:
            desc = (vuln.get("description") or "").lower()
            path = (vuln.get("path") or "").lower()
            combined_text = f"{desc} {path}"
            if any(
                keyword in combined_text
                for keyword in [
                    "directory listing",
                    "default file",
                    "backup",
                    "config",
                    ".git",
                    ".svn",
                    ".env",
                    "phpinfo",
                    "admin",
                    "robots.txt",
                ]
            ):
                parsed["interesting_findings"].append(vuln)

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on scan results."""
        suggestions: list[str] = []
        vulns = parsed_data.get("vulnerabilities", [])
        interesting = parsed_data.get("interesting_findings", [])

        if vulns:
            suggestions.append(f"Found {len(vulns)} items during scan")
        else:
            suggestions.append("No vulnerabilities found with current scan settings")
            suggestions.append("Try broader tuning: -Tuning 123489ab")

        if interesting:
            suggestions.append(f"Found {len(interesting)} interesting findings worth investigating")
            for finding in interesting[:3]:
                path = finding.get("path", "")
                desc = finding.get("description", "")
                if path:
                    suggestions.append(f"Check: {path} - {desc[:60]}")

        server = parsed_data.get("server_info", {}).get("server", "")
        if server:
            suggestions.append(f"Server: {server}")
            suggestions.append("Search for known CVEs for this server version")

        return suggestions

    def quick_scan(self, host: str, timeout: int = 120) -> ToolResult:
        """Run a quick scan with default settings."""
        return self.run(host, timeout=timeout)

    def full_scan(self, host: str, timeout: int = 600) -> ToolResult:
        """Run a comprehensive scan with all tuning options."""
        return self.run(host, tuning="123456789abc", timeout=timeout)

    def scan_for_sqli(self, host: str, timeout: int = 300) -> ToolResult:
        """Scan specifically for SQL injection vulnerabilities."""
        return self.run(host, tuning="9", timeout=timeout)
