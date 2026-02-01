"""
Forensics skill for CTF Kit.

Orchestrates forensics tools for memory analysis, disk forensics,
network packet analysis, and file carving.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from ctf_kit.skills.base import BaseSkill, SkillResult, register_skill
from ctf_kit.utils.file_detection import (
    FileInfo,
    detect_file_type,
)

if TYPE_CHECKING:
    from ctf_kit.integrations.base import ToolResult


@register_skill
class ForensicsSkill(BaseSkill):
    """
    Skill for forensics challenge analysis.

    Identifies forensics artifacts, analyzes memory dumps, network captures,
    and disk images. Orchestrates tools like volatility3, tshark, binwalk,
    foremost, and sleuthkit.
    """

    name: ClassVar[str] = "forensics"
    description: ClassVar[str] = (
        "Analyze forensics challenges including memory dumps, network captures, "
        "disk images, and embedded file extraction"
    )
    category: ClassVar[str] = "forensics"
    tool_names: ClassVar[list[str]] = [
        "binwalk",
        "strings",
        "file",
        "exiftool",
        "volatility",
        "tshark",
        "foremost",
    ]

    # File type indicators for different forensics subcategories
    MEMORY_INDICATORS: ClassVar[list[str]] = [
        "vmem",
        "raw",
        "dmp",
        "mem",
        "hiberfil",
        "pagefile",
    ]

    NETWORK_INDICATORS: ClassVar[list[str]] = [
        "pcap",
        "pcapng",
        "cap",
        "netflow",
    ]

    DISK_INDICATORS: ClassVar[list[str]] = [
        "e01",
        "dd",
        "raw",
        "img",
        "ad1",
        "001",
    ]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a forensics challenge.

        Args:
            path: Path to challenge file or directory

        Returns:
            SkillResult with forensics analysis
        """
        analysis: dict[str, Any] = {
            "forensics_type": None,
            "file_info": {},
            "embedded_files": [],
            "interesting_strings": [],
            "metadata": {},
            "extracted_artifacts": [],
            "timeline_entries": [],
        }
        tool_results: list[ToolResult] = []
        suggestions: list[str] = []
        artifacts: list[Path] = []

        # Handle directory vs file
        if path.is_dir():
            files = [f for f in path.iterdir() if f.is_file() and not f.name.startswith(".")]
        else:
            files = [path]

        if not files:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis=analysis,
                suggestions=["No files found to analyze"],
                confidence=0.0,
            )

        # Analyze each file
        for file_path in files:
            file_analysis = self._analyze_forensics_file(file_path)

            # Update main analysis
            if not analysis["forensics_type"] and file_analysis.get("forensics_type"):
                analysis["forensics_type"] = file_analysis["forensics_type"]

            analysis["file_info"][str(file_path)] = file_analysis.get("file_info", {})
            analysis["embedded_files"].extend(file_analysis.get("embedded_files", []))
            analysis["interesting_strings"].extend(file_analysis.get("interesting_strings", []))

            if file_analysis.get("metadata"):
                analysis["metadata"][str(file_path)] = file_analysis["metadata"]

            tool_results.extend(file_analysis.get("tool_results", []))
            artifacts.extend(file_analysis.get("artifacts", []))

        # Generate suggestions based on analysis
        suggestions = self._generate_suggestions(analysis)
        next_steps = self._generate_next_steps(analysis)

        # Calculate confidence
        confidence = self._calculate_confidence(analysis)

        return SkillResult(
            success=True,
            skill_name=self.name,
            analysis=analysis,
            suggestions=suggestions,
            next_steps=next_steps,
            tool_results=tool_results,
            artifacts=artifacts,
            confidence=confidence,
        )

    def _analyze_forensics_file(self, path: Path) -> dict[str, Any]:
        """Analyze a single forensics file."""
        file_analysis: dict[str, Any] = {
            "path": str(path),
            "forensics_type": None,
            "file_info": {},
            "embedded_files": [],
            "interesting_strings": [],
            "metadata": {},
            "tool_results": [],
            "artifacts": [],
        }

        # Get file info
        try:
            file_info: FileInfo = detect_file_type(path)
            file_analysis["file_info"] = {
                "name": file_info.name,
                "size": file_info.size,
                "file_type": file_info.file_type,
                "mime_type": file_info.mime_type,
            }
        except Exception:  # noqa: BLE001
            file_analysis["file_info"] = {"name": path.name, "error": "detection failed"}

        # Determine forensics subtype
        forensics_type = self._detect_forensics_type(
            path, file_info if "file_info" in dir() else None
        )
        file_analysis["forensics_type"] = forensics_type

        # Run binwalk for embedded file detection
        binwalk = self.get_tool("binwalk")
        if binwalk and binwalk.is_installed:
            result = binwalk.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                sigs = result.parsed_data.get("signatures", [])
                file_analysis["embedded_files"] = sigs[:15]

        # Run strings for interesting content
        strings_tool = self.get_tool("strings")
        if strings_tool and strings_tool.is_installed:
            result = strings_tool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                interesting = result.parsed_data.get("interesting_strings", [])
                file_analysis["interesting_strings"] = interesting[:30]

        # Run exiftool for metadata
        exiftool = self.get_tool("exiftool")
        if exiftool and exiftool.is_installed:
            result = exiftool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                file_analysis["metadata"] = result.parsed_data.get("metadata", {})

        # Type-specific analysis
        if forensics_type == "memory":
            self._analyze_memory_dump(path, file_analysis)
        elif forensics_type == "network":
            self._analyze_network_capture(path, file_analysis)
        elif forensics_type == "disk":
            self._analyze_disk_image(path, file_analysis)

        return file_analysis

    def _detect_forensics_type(self, path: Path, file_info: FileInfo | None) -> str:
        """Detect the type of forensics challenge."""
        name_lower = path.name.lower()
        suffix_lower = path.suffix.lower().lstrip(".")

        # Check memory indicators
        for indicator in self.MEMORY_INDICATORS:
            if indicator in name_lower or suffix_lower == indicator:
                return "memory"

        # Check network indicators
        for indicator in self.NETWORK_INDICATORS:
            if indicator in name_lower or suffix_lower == indicator:
                return "network"

        # Check disk indicators
        for indicator in self.DISK_INDICATORS:
            if indicator in name_lower or suffix_lower == indicator:
                return "disk"

        # Check file type from detection
        if file_info:
            file_type_lower = file_info.file_type.lower()
            if "pcap" in file_type_lower or "capture" in file_type_lower:
                return "network"
            if any(mem in file_type_lower for mem in ["memory", "dump", "vmem"]):
                return "memory"

        return "general"

    def _analyze_memory_dump(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Run memory-specific analysis."""
        volatility = self.get_tool("volatility")
        if volatility and volatility.is_installed:
            # Run basic volatility info
            result = volatility.run(path, plugin="windows.info")
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                file_analysis["memory_info"] = result.parsed_data

    def _analyze_network_capture(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Run network-specific analysis."""
        tshark = self.get_tool("tshark")
        if tshark and tshark.is_installed:
            # Get protocol statistics
            result = tshark.run(path, mode="statistics")
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                file_analysis["network_stats"] = result.parsed_data

    def _analyze_disk_image(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Run disk-specific analysis."""
        # For now, binwalk extraction is the main approach
        # Future: add sleuthkit integration

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on forensics analysis."""
        suggestions: list[str] = []
        forensics_type = analysis.get("forensics_type")

        # Type-specific suggestions
        if forensics_type == "memory":
            suggestions.extend(
                [
                    "Run volatility3 with windows.pslist to list processes",
                    "Check for suspicious processes with windows.pstree",
                    "Look for network connections with windows.netscan",
                    "Dump process memory with windows.memmap",
                    "Search for malware with windows.malfind",
                    "Extract command history with windows.cmdline",
                ]
            )
        elif forensics_type == "network":
            suggestions.extend(
                [
                    "Extract HTTP objects: tshark -r file.pcap --export-objects http,output_dir",
                    "Look for credentials in clear text protocols (FTP, HTTP, Telnet)",
                    "Check for DNS exfiltration or tunneling",
                    "Follow TCP streams to reconstruct conversations",
                    "Export transferred files from FTP/SMB",
                    "Look for suspicious user-agents or unusual ports",
                ]
            )
        elif forensics_type == "disk":
            suggestions.extend(
                [
                    "Mount the image and explore the filesystem",
                    "Look for deleted files with photorec or foremost",
                    "Check for alternate data streams (NTFS)",
                    "Analyze the $MFT for file timeline",
                    "Look for hidden partitions or unallocated space",
                ]
            )
        else:
            suggestions.extend(
                [
                    "Run binwalk -e to extract embedded files",
                    "Check for steganography in images",
                    "Look for encrypted volumes or containers",
                    "Analyze file metadata with exiftool",
                ]
            )

        # Add suggestions based on findings
        if analysis.get("embedded_files"):
            count = len(analysis["embedded_files"])
            suggestions.insert(0, f"Found {count} embedded signatures - extract with binwalk -e")

        if analysis.get("interesting_strings"):
            suggestions.insert(0, "Review interesting strings found in the file")

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []
        forensics_type = analysis.get("forensics_type")

        steps.append("Review file metadata and interesting strings")

        if forensics_type == "memory":
            steps.extend(
                [
                    "Identify the memory profile (Windows version)",
                    "List running processes and network connections",
                    "Look for suspicious or hidden processes",
                    "Dump suspicious process memory",
                    "Search for flags in memory with strings/grep",
                ]
            )
        elif forensics_type == "network":
            steps.extend(
                [
                    "Get protocol hierarchy and statistics",
                    "Follow TCP streams for interesting conversations",
                    "Extract files transferred over HTTP/FTP/SMB",
                    "Look for encoded or encrypted data",
                    "Check for DNS queries that might hide data",
                ]
            )
        elif forensics_type == "disk":
            steps.extend(
                [
                    "Mount or extract the filesystem",
                    "Look for recently modified/accessed files",
                    "Search for deleted files",
                    "Check common flag locations (Desktop, Documents)",
                    "Analyze browser history and downloads",
                ]
            )
        else:
            steps.extend(
                [
                    "Extract embedded files with binwalk",
                    "Analyze extracted files recursively",
                    "Check for hidden data or encryption",
                ]
            )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        # Has forensics type detected
        if analysis.get("forensics_type") and analysis["forensics_type"] != "general":
            confidence += 0.3

        # Has file info
        if analysis.get("file_info"):
            confidence += 0.2

        # Found embedded files
        if analysis.get("embedded_files"):
            confidence += 0.2

        # Found interesting strings
        if analysis.get("interesting_strings"):
            confidence += 0.15

        # Has metadata
        if analysis.get("metadata"):
            confidence += 0.15

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def extract_embedded(self, path: Path, output_dir: Path | None = None) -> SkillResult:
        """Extract all embedded files from a forensics artifact."""
        binwalk = self.get_tool("binwalk")
        if not binwalk or not binwalk.is_installed:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis={"error": "binwalk not installed"},
                suggestions=["Install binwalk: pip install binwalk"],
            )

        result = binwalk.run(path, extract=True, matryoshka=True, directory=output_dir)

        return SkillResult(
            success=result.success,
            skill_name=self.name,
            analysis={
                "extracted": result.artifacts or [],
                "signatures": result.parsed_data.get("signatures", [])
                if result.parsed_data
                else [],
            },
            tool_results=[result],
            artifacts=result.artifacts or [],
            suggestions=result.suggestions or [],
        )
