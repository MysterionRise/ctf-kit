"""
Shodan CLI wrapper for CTF Kit.

Shodan searches for internet-connected devices and services.
"""

import json
import re
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)


@register_tool
class ShodanTool(BaseTool):
    """
    Wrapper for the 'shodan' CLI command.

    Shodan queries the Shodan search engine for information about
    internet-connected devices, open ports, banners, and vulnerabilities.
    Requires a Shodan API key configured via 'shodan init <API_KEY>'.
    """

    name: ClassVar[str] = "shodan"
    description: ClassVar[str] = "Search for internet-connected devices and services"
    category: ClassVar[ToolCategory] = ToolCategory.OSINT
    binary_names: ClassVar[list[str]] = ["shodan"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install shodan",
        "linux": "pip install shodan",
        "windows": "pip install shodan",
    }

    def run(
        self,
        command: str,
        target: str | None = None,
        query: str | None = None,
        timeout: int = 60,
    ) -> ToolResult:
        """
        Run a Shodan CLI command.

        Args:
            command: Shodan subcommand (host, search, info, domain, etc.)
            target: Target IP or hostname (for host/domain commands)
            query: Search query (for search command)
            timeout: Timeout in seconds

        Returns:
            ToolResult with parsed Shodan data
        """
        args: list[str] = [command]

        if command == "host" and target:
            args.append(target)
        elif command == "search" and query:
            args.append(query)
        elif command == "domain" and target:
            args.append(target)
        elif command == "info":
            pass  # No additional args needed
        elif target:
            args.append(target)

        result = self._run_with_result(args, timeout=timeout)

        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {}, command)

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse Shodan CLI output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "ip": None,
            "hostnames": [],
            "ports": [],
            "services": [],
            "vulns": [],
            "os": None,
            "org": None,
            "country": None,
        }

        # Try JSON parsing first (some commands output JSON)
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                parsed.update(
                    {
                        "ip": data.get("ip_str", data.get("ip")),
                        "hostnames": data.get("hostnames", []),
                        "ports": data.get("ports", []),
                        "os": data.get("os"),
                        "org": data.get("org"),
                        "country": data.get("country_name", data.get("country_code")),
                        "vulns": data.get("vulns", []),
                    }
                )
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

        # Parse text output from 'shodan host' command
        for line in stdout.splitlines():
            line = line.strip()

            if line.startswith("IP:"):
                parsed["ip"] = line.split(":", maxsplit=1)[1].strip()
            elif line.startswith("Hostnames:"):
                hostnames_str = line.split(":", maxsplit=1)[1].strip()
                if hostnames_str:
                    parsed["hostnames"] = [h.strip() for h in hostnames_str.split(",")]
            elif line.startswith("Ports:"):
                ports_str = line.split(":", maxsplit=1)[1].strip()
                if ports_str:
                    parsed["ports"] = [
                        int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()
                    ]
            elif line.startswith("OS:"):
                parsed["os"] = line.split(":", maxsplit=1)[1].strip()
            elif line.startswith("Organization:"):
                parsed["org"] = line.split(":", maxsplit=1)[1].strip()
            elif line.startswith("Country:"):
                parsed["country"] = line.split(":", maxsplit=1)[1].strip()
            elif line.startswith(("Vulnerabilities:", "CVE-")):
                if line.startswith("Vulnerabilities:"):
                    vulns_str = line.split(":", maxsplit=1)[1].strip()
                    if vulns_str:
                        parsed["vulns"] = [v.strip() for v in vulns_str.split(",")]
                else:
                    parsed["vulns"].append(line.strip())

            # Parse port/service banners (indented lines with port info)
            port_match = re.match(r"(\d+)/(\w+)\s+(.*)", line)
            if port_match:
                parsed["services"].append(
                    {
                        "port": int(port_match.group(1)),
                        "protocol": port_match.group(2),
                        "banner": port_match.group(3).strip(),
                    }
                )

        return parsed

    def _get_suggestions(
        self,
        parsed_data: dict[str, Any],
        command: str = "host",  # noqa: ARG002
    ) -> list[str]:
        """Get suggestions based on Shodan results."""
        suggestions: list[str] = []

        ip = parsed_data.get("ip")
        ports = parsed_data.get("ports", [])
        vulns = parsed_data.get("vulns", [])
        services = parsed_data.get("services", [])
        hostnames = parsed_data.get("hostnames", [])
        org = parsed_data.get("org")

        if ip:
            suggestions.append(f"Target IP: {ip}")

        if org:
            suggestions.append(f"Organization: {org}")

        if hostnames:
            suggestions.append(f"Hostnames: {', '.join(hostnames[:5])}")

        if ports:
            suggestions.append(f"Open ports: {', '.join(str(p) for p in sorted(ports)[:10])}")

        if vulns:
            suggestions.append(f"Known vulnerabilities: {', '.join(vulns[:5])}")
            suggestions.append("Research CVEs for potential exploits")

        if services:
            for svc in services[:5]:
                suggestions.append(f"  Port {svc['port']}/{svc['protocol']}: {svc['banner'][:60]}")

        if not any([ip, ports, services]):
            suggestions.extend(
                [
                    "No data returned",
                    "Verify Shodan API key: shodan init <API_KEY>",
                    "Try: shodan host <IP> or shodan search <query>",
                ]
            )

        return suggestions

    def host_info(self, ip: str) -> ToolResult:
        """Get information about a specific IP."""
        return self.run("host", target=ip)

    def search(self, query: str) -> ToolResult:
        """Search Shodan with a query string."""
        return self.run("search", query=query)

    def domain_info(self, domain: str) -> ToolResult:
        """Get DNS information for a domain."""
        return self.run("domain", target=domain)

    def get_ports(self, ip: str) -> list[int]:
        """Get open ports for an IP."""
        result = self.run("host", target=ip)
        if result.success and result.parsed_data:
            ports: list[int] = result.parsed_data.get("ports", [])
            return ports
        return []
