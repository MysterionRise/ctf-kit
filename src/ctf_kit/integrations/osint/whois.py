"""
WHOIS wrapper for CTF Kit.

WHOIS queries domain registration information.
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
class WhoisTool(BaseTool):
    """
    Wrapper for the 'whois' command.

    WHOIS queries domain registration databases for ownership,
    registrar, nameserver, and contact information.
    """

    name: ClassVar[str] = "whois"
    description: ClassVar[str] = "Query domain registration and ownership information"
    category: ClassVar[ToolCategory] = ToolCategory.OSINT
    binary_names: ClassVar[list[str]] = ["whois"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install whois",
        "linux": "apt-get install whois",
        "windows": "choco install whois",
    }

    def run(
        self,
        target: str,
        server: str | None = None,
        timeout: int = 30,
    ) -> ToolResult:
        """
        Query WHOIS information for a domain or IP.

        Args:
            target: Domain name or IP address to query
            server: Specific WHOIS server to query
            timeout: Timeout in seconds

        Returns:
            ToolResult with parsed registration data
        """
        args: list[str] = []

        if server:
            args.extend(["-h", server])

        args.append(target)

        result = self._run_with_result(args, timeout=timeout)

        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse WHOIS output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "status": [],
            "registrant": {},
            "emails": [],
            "dnssec": None,
        }

        # Parse key-value pairs (case-insensitive)
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(("%", "#")):
                continue

            if ":" not in line:
                continue

            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if not value:
                continue

            if "registrar" in key and "registrar" not in key.replace("registrar", "", 1):
                parsed["registrar"] = value
            elif key in ("creation date", "created", "created date", "registration date"):
                parsed["creation_date"] = value
            elif key in (
                "expiration date",
                "expiry date",
                "registry expiry date",
                "registrar registration expiration date",
            ):
                parsed["expiration_date"] = value
            elif key in ("updated date", "last updated", "last modified"):
                parsed["updated_date"] = value
            elif key in ("name server", "nameserver", "nserver"):
                parsed["nameservers"].append(value.lower())
            elif key in ("domain status", "status"):
                parsed["status"].append(value)
            elif key in ("registrant name", "registrant organization", "registrant"):
                parsed["registrant"]["name"] = value
            elif key in ("registrant email", "registrant contact email"):
                parsed["registrant"]["email"] = value
            elif "dnssec" in key:
                parsed["dnssec"] = value

        # Extract emails from full output
        email_pattern = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
        parsed["emails"] = list(set(email_pattern.findall(stdout)))

        # Deduplicate nameservers
        parsed["nameservers"] = list(set(parsed["nameservers"]))

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on WHOIS results."""
        suggestions: list[str] = []

        registrar = parsed_data.get("registrar")
        if registrar:
            suggestions.append(f"Registrar: {registrar}")

        creation = parsed_data.get("creation_date")
        if creation:
            suggestions.append(f"Domain created: {creation}")

        nameservers = parsed_data.get("nameservers", [])
        if nameservers:
            suggestions.append(f"Nameservers: {', '.join(nameservers[:3])}")

        emails = parsed_data.get("emails", [])
        if emails:
            suggestions.append(f"Found {len(emails)} email(s): {', '.join(emails[:3])}")

        registrant = parsed_data.get("registrant", {})
        if registrant.get("name"):
            suggestions.append(f"Registrant: {registrant['name']}")

        if not any([registrar, creation, nameservers, emails]):
            suggestions.extend(
                [
                    "No detailed WHOIS data found",
                    "Try querying a specific WHOIS server with --server",
                    "Domain may have privacy protection enabled",
                ]
            )

        return suggestions

    def lookup(self, domain: str) -> ToolResult:
        """Look up WHOIS data for a domain."""
        return self.run(domain)

    def get_registrar(self, domain: str) -> str | None:
        """Get registrar for a domain."""
        result = self.run(domain)
        if result.success and result.parsed_data:
            registrar: str | None = result.parsed_data.get("registrar")
            return registrar
        return None

    def get_nameservers(self, domain: str) -> list[str]:
        """Get nameservers for a domain."""
        result = self.run(domain)
        if result.success and result.parsed_data:
            ns: list[str] = result.parsed_data.get("nameservers", [])
            return ns
        return []
