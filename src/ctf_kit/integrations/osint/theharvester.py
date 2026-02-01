"""
TheHarvester wrapper for CTF Kit.

TheHarvester gathers emails, names, subdomains, IPs, and URLs.
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
class TheHarvesterTool(BaseTool):
    """
    Wrapper for the 'theHarvester' command.

    TheHarvester gathers emails, names, subdomains, IPs, and URLs
    from various public sources.
    """

    name: ClassVar[str] = "theharvester"
    description: ClassVar[str] = "Gather emails, subdomains, and IPs from public sources"
    category: ClassVar[ToolCategory] = ToolCategory.OSINT
    binary_names: ClassVar[list[str]] = ["theHarvester", "theharvester"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install theHarvester",
        "linux": "pip install theHarvester",
        "windows": "pip install theHarvester",
    }

    def run(  # noqa: PLR0913
        self,
        domain: str,
        source: str = "all",
        limit: int = 500,
        start: int = 0,
        dns_lookup: bool = True,
        virtual_host: bool = False,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Harvest information about a domain.

        Args:
            domain: Target domain
            source: Data source (google, bing, linkedin, all, etc.)
            limit: Number of results to gather
            start: Start result number
            dns_lookup: Perform DNS resolution
            virtual_host: Perform virtual host verification
            timeout: Timeout in seconds

        Returns:
            ToolResult with harvested data
        """
        args: list[str] = [
            "-d",
            domain,
            "-b",
            source,
            "-l",
            str(limit),
            "-S",
            str(start),
        ]

        if dns_lookup:
            args.append("-n")

        if virtual_host:
            args.append("-v")

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse theHarvester output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "emails": [],
            "hosts": [],
            "ips": [],
            "subdomains": [],
        }

        # Parse emails
        email_pattern = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
        emails = email_pattern.findall(stdout)
        parsed["emails"] = list(set(emails))

        # Parse hosts/subdomains
        # Usually listed under "[*] Hosts found:"
        if "Hosts found:" in stdout or "hosts" in stdout.lower():
            host_section = stdout.split("Hosts found:")[-1] if "Hosts found:" in stdout else stdout
            host_pattern = re.compile(r"([\w.-]+\.[a-zA-Z]{2,})")
            hosts = host_pattern.findall(host_section)
            parsed["hosts"] = list(set(hosts))

        # Parse IPs
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        ips = ip_pattern.findall(stdout)
        parsed["ips"] = list(set(ips))

        # Parse subdomains
        subdomain_section = ""
        if "Subdomains found:" in stdout:
            subdomain_section = stdout.split("Subdomains found:")[-1].split("[")[0]
            subdomain_pattern = re.compile(r"([\w.-]+)")
            subdomains = subdomain_pattern.findall(subdomain_section)
            parsed["subdomains"] = [s for s in subdomains if "." in s and len(s) > 3]

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on harvested data."""
        suggestions: list[str] = []

        emails = parsed_data.get("emails", [])
        hosts = parsed_data.get("hosts", [])
        ips = parsed_data.get("ips", [])

        if emails:
            suggestions.append(f"Found {len(emails)} email addresses:")
            for email in emails[:5]:
                suggestions.append(f"  {email}")
            if len(emails) > 5:
                suggestions.append(f"  ... and {len(emails) - 5} more")

        if hosts:
            suggestions.append(f"Found {len(hosts)} hosts/subdomains")

        if ips:
            suggestions.append(f"Found {len(ips)} IP addresses")

        if not any([emails, hosts, ips]):
            suggestions.extend(
                [
                    "No data found",
                    "Try different sources: -b google,bing,linkedin",
                    "Increase limit: -l 1000",
                    "Try with different domain variations",
                ]
            )
        else:
            suggestions.append("Cross-reference findings for more intel")

        return suggestions

    def harvest(self, domain: str, source: str = "all") -> ToolResult:
        """Harvest data from a domain."""
        return self.run(domain, source=source)

    def get_emails(self, domain: str) -> list[str]:
        """Get emails for a domain."""
        result = self.run(domain)
        if result.success and result.parsed_data:
            emails: list[str] = result.parsed_data.get("emails", [])
            return emails
        return []

    def get_subdomains(self, domain: str) -> list[str]:
        """Get subdomains for a domain."""
        result = self.run(domain)
        if result.success and result.parsed_data:
            hosts: list[str] = result.parsed_data.get("hosts", [])
            return hosts
        return []
