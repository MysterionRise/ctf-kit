"""
Tshark wrapper for CTF Kit.

Tshark is the command-line version of Wireshark for packet analysis.
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
class TsharkTool(BaseTool):
    """
    Wrapper for the 'tshark' command.

    Tshark analyzes network packet captures (PCAP files)
    to extract protocols, conversations, and data.
    """

    name: ClassVar[str] = "tshark"
    description: ClassVar[str] = "Analyze network packet captures"
    category: ClassVar[ToolCategory] = ToolCategory.FORENSICS
    binary_names: ClassVar[list[str]] = ["tshark"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install wireshark",
        "linux": "sudo apt install tshark",
        "windows": "Download Wireshark from https://www.wireshark.org/",
    }

    def run(  # noqa: PLR0913
        self,
        pcap_file: Path | str,
        mode: str = "summary",
        display_filter: str | None = None,
        fields: list[str] | None = None,
        follow_stream: tuple[str, int] | None = None,
        export_objects: tuple[str, Path | str] | None = None,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Analyze a PCAP file.

        Args:
            pcap_file: Path to PCAP file
            mode: Analysis mode (summary, statistics, fields, follow, export)
            display_filter: Wireshark display filter
            fields: Fields to extract (for fields mode)
            follow_stream: (protocol, stream_index) to follow
            export_objects: (protocol, output_dir) to export objects
            timeout: Timeout in seconds

        Returns:
            ToolResult with analysis results
        """
        args: list[str] = ["-r", str(pcap_file)]

        if display_filter:
            args.extend(["-Y", display_filter])

        if mode == "summary":
            # Default summary mode
            args.extend(["-q", "-z", "io,stat,0"])

        elif mode == "statistics":
            # Protocol hierarchy
            args.extend(["-q", "-z", "io,phs"])

        elif mode == "conversations":
            # Show conversations
            args.extend(["-q", "-z", "conv,tcp"])

        elif mode == "fields" and fields:
            # Extract specific fields
            args.extend(["-T", "fields"])
            for field in fields:
                args.extend(["-e", field])

        elif mode == "follow" and follow_stream:
            protocol, stream_idx = follow_stream
            args.extend(["-q", "-z", f"follow,{protocol},ascii,{stream_idx}"])

        elif mode == "export" and export_objects:
            protocol, output_dir = export_objects
            args.extend(["--export-objects", f"{protocol},{output_dir}"])

        elif mode == "packets":
            # List packets
            args.extend(["-T", "text"])

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(mode, result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse tshark output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "protocols": [],
            "conversations": [],
            "stream_data": None,
            "statistics": {},
        }

        # Parse protocol hierarchy
        if "Protocol Hierarchy Statistics" in stdout:
            protocol_pattern = re.compile(r"\s+(\S+)\s+frames:(\d+)\s+bytes:(\d+)")
            for match in protocol_pattern.finditer(stdout):
                parsed["protocols"].append(
                    {
                        "name": match.group(1),
                        "frames": int(match.group(2)),
                        "bytes": int(match.group(3)),
                    }
                )

        # Parse conversations
        conv_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)")
        for match in conv_pattern.finditer(stdout):
            parsed["conversations"].append(
                {
                    "src_ip": match.group(1),
                    "src_port": int(match.group(2)),
                    "dst_ip": match.group(3),
                    "dst_port": int(match.group(4)),
                }
            )

        # Parse follow stream output
        if "Follow:" in stdout or "====" in stdout:
            # Extract stream content
            stream_parts = stdout.split("====")
            if len(stream_parts) > 1:
                parsed["stream_data"] = stream_parts[1].strip()

        # Parse IO stats
        io_pattern = re.compile(r"Interval.*?(\d+)\s+frames")
        io_match = io_pattern.search(stdout)
        if io_match:
            parsed["statistics"]["total_frames"] = int(io_match.group(1))

        return parsed

    def _get_suggestions(self, _mode: str, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on analysis."""
        suggestions: list[str] = []

        protocols = parsed_data.get("protocols", [])
        conversations = parsed_data.get("conversations", [])

        if protocols:
            # Find interesting protocols
            interesting = ["http", "ftp", "smtp", "dns", "telnet", "ssh"]
            found_interesting = [
                p for p in protocols if any(i in p["name"].lower() for i in interesting)
            ]
            if found_interesting:
                names = [p["name"] for p in found_interesting[:5]]
                suggestions.append(f"Interesting protocols: {', '.join(names)}")

            # Check for HTTP
            if any("http" in p["name"].lower() for p in protocols):
                suggestions.append(
                    "HTTP traffic found - export objects with: tshark --export-objects http,output_dir"
                )

            # Check for FTP
            if any("ftp" in p["name"].lower() for p in protocols):
                suggestions.append("FTP traffic found - look for file transfers and credentials")

            # Check for DNS
            if any("dns" in p["name"].lower() for p in protocols):
                suggestions.append(
                    "DNS traffic found - check for exfiltration: -Y 'dns' -T fields -e dns.qry.name"
                )

        if conversations:
            suggestions.append(f"Found {len(conversations)} TCP conversations")
            suggestions.append("Follow streams to see conversation content")

        if not suggestions:
            suggestions = [
                "Get protocol statistics: -q -z io,phs",
                "List HTTP requests: -Y http.request",
                "Follow TCP stream: -z follow,tcp,ascii,0",
                "Extract files: --export-objects http,./output",
            ]

        return suggestions

    def get_protocol_hierarchy(self, pcap_file: Path | str) -> ToolResult:
        """Get protocol statistics."""
        return self.run(pcap_file, mode="statistics")

    def get_conversations(self, pcap_file: Path | str) -> ToolResult:
        """List TCP conversations."""
        return self.run(pcap_file, mode="conversations")

    def follow_tcp_stream(self, pcap_file: Path | str, stream_index: int = 0) -> ToolResult:
        """Follow a TCP stream."""
        return self.run(pcap_file, mode="follow", follow_stream=("tcp", stream_index))

    def export_http_objects(self, pcap_file: Path | str, output_dir: Path | str) -> ToolResult:
        """Export HTTP objects (files)."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return self.run(pcap_file, mode="export", export_objects=("http", output_dir))

    def filter_packets(self, pcap_file: Path | str, display_filter: str) -> ToolResult:
        """Filter packets with display filter."""
        return self.run(pcap_file, mode="packets", display_filter=display_filter)

    def extract_credentials(self, pcap_file: Path | str) -> ToolResult:
        """Look for credentials in common protocols."""
        # Try to extract usernames/passwords from various protocols
        filters = [
            "ftp.request.command == USER || ftp.request.command == PASS",
            "http.authorization",
            "smtp.auth.password",
        ]
        return self.run(pcap_file, mode="packets", display_filter=" || ".join(filters))
