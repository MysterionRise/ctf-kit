"""
Dig wrapper for CTF Kit.

Dig performs DNS lookups and zone transfers.
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
class DigTool(BaseTool):
    """
    Wrapper for the 'dig' command.

    Dig queries DNS servers for records including A, AAAA, MX, NS,
    TXT, CNAME, SOA, and attempts zone transfers (AXFR).
    """

    name: ClassVar[str] = "dig"
    description: ClassVar[str] = "DNS lookup and enumeration tool"
    category: ClassVar[ToolCategory] = ToolCategory.OSINT
    binary_names: ClassVar[list[str]] = ["dig"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install bind",
        "linux": "apt-get install dnsutils",
        "windows": "choco install bind-toolsonly",
    }

    def run(  # noqa: PLR0913
        self,
        domain: str,
        record_type: str = "ANY",
        server: str | None = None,
        short: bool = False,
        trace: bool = False,
        timeout: int = 30,
    ) -> ToolResult:
        """
        Perform a DNS lookup.

        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY, AXFR)
            server: DNS server to query (e.g. 8.8.8.8)
            short: Short output mode
            trace: Enable trace mode
            timeout: Timeout in seconds

        Returns:
            ToolResult with parsed DNS records
        """
        args: list[str] = []

        if server:
            args.append(f"@{server}")

        args.append(domain)
        args.append(record_type)

        if short:
            args.append("+short")

        if trace:
            args.append("+trace")

        result = self._run_with_result(args, timeout=timeout)

        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse dig output into structured DNS records."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "records": [],
            "authority": [],
            "additional": [],
            "query_time": None,
            "server": None,
            "status": None,
        }

        # Parse status from header
        status_match = re.search(r"status:\s*(\w+)", stdout)
        if status_match:
            parsed["status"] = status_match.group(1)

        # Parse query time
        time_match = re.search(r"Query time:\s*(\d+)\s*msec", stdout)
        if time_match:
            parsed["query_time"] = int(time_match.group(1))

        # Parse server
        server_match = re.search(r"SERVER:\s*([^\s#]+)", stdout)
        if server_match:
            parsed["server"] = server_match.group(1)

        current_section = "answer"

        for line in stdout.splitlines():
            line = line.strip()

            # Track sections
            if ";; ANSWER SECTION:" in line:
                current_section = "answer"
                continue
            if ";; AUTHORITY SECTION:" in line:
                current_section = "authority"
                continue
            if ";; ADDITIONAL SECTION:" in line:
                current_section = "additional"
                continue

            # Skip comments and empty lines
            if not line or line.startswith(";"):
                continue

            # Parse DNS record lines: name TTL class type data
            record_match = re.match(
                r"(\S+)\s+(\d+)?\s*(?:IN)?\s*(A|AAAA|MX|NS|TXT|CNAME|SOA|PTR|SRV|CAA)\s+(.+)",
                line,
            )
            if record_match:
                record = {
                    "name": record_match.group(1),
                    "ttl": int(record_match.group(2)) if record_match.group(2) else None,
                    "type": record_match.group(3),
                    "value": record_match.group(4).strip().strip('"'),
                }

                if current_section == "answer":
                    parsed["records"].append(record)
                elif current_section == "authority":
                    parsed["authority"].append(record)
                elif current_section == "additional":
                    parsed["additional"].append(record)

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on DNS results."""
        suggestions: list[str] = []

        records = parsed_data.get("records", [])
        status = parsed_data.get("status")

        if status == "NXDOMAIN":
            suggestions.append("Domain does not exist (NXDOMAIN)")
            suggestions.append("Check for typos or try subdomains")
            return suggestions

        if status == "REFUSED":
            suggestions.append("Query refused by server")
            suggestions.append("Try a different DNS server: @8.8.8.8")
            return suggestions

        # Group records by type
        record_types: dict[str, list[dict[str, Any]]] = {}
        for r in records:
            rtype = r["type"]
            if rtype not in record_types:
                record_types[rtype] = []
            record_types[rtype].append(r)

        for rtype, recs in record_types.items():
            values = [r["value"] for r in recs]
            if rtype == "TXT":
                suggestions.append("TXT records found - check for SPF, DKIM, verification tokens")
                for v in values[:3]:
                    suggestions.append(f"  TXT: {v[:80]}")
            elif rtype == "MX":
                suggestions.append(f"Mail servers: {', '.join(values[:3])}")
            elif rtype == "NS":
                suggestions.append(f"Nameservers: {', '.join(values[:3])}")
            elif rtype == "A":
                suggestions.append(f"IP addresses: {', '.join(values[:5])}")
            elif rtype == "CNAME":
                suggestions.append(f"CNAME aliases: {', '.join(values[:3])}")

        if not records:
            suggestions.extend(
                [
                    "No records found",
                    "Try specific record types: A, MX, NS, TXT",
                    "Try zone transfer: AXFR",
                ]
            )
        else:
            suggestions.append("Try zone transfer with AXFR for full enumeration")

        return suggestions

    def lookup(self, domain: str, record_type: str = "ANY") -> ToolResult:
        """Look up DNS records for a domain."""
        return self.run(domain, record_type=record_type)

    def zone_transfer(self, domain: str, server: str | None = None) -> ToolResult:
        """Attempt a zone transfer (AXFR)."""
        return self.run(domain, record_type="AXFR", server=server)

    def get_a_records(self, domain: str) -> list[str]:
        """Get A records (IPv4 addresses) for a domain."""
        result = self.run(domain, record_type="A")
        if result.success and result.parsed_data:
            return [r["value"] for r in result.parsed_data.get("records", []) if r["type"] == "A"]
        return []

    def get_txt_records(self, domain: str) -> list[str]:
        """Get TXT records for a domain."""
        result = self.run(domain, record_type="TXT")
        if result.success and result.parsed_data:
            return [r["value"] for r in result.parsed_data.get("records", []) if r["type"] == "TXT"]
        return []
