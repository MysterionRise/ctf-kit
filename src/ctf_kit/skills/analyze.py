"""
Analyze skill for CTF Kit.

Orchestrates initial challenge analysis across multiple tools.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from ctf_kit.skills.base import BaseSkill, SkillResult, register_skill

if TYPE_CHECKING:
    from ctf_kit.integrations.base import ToolResult

from ctf_kit.utils.file_detection import (
    CTFCategory,
    FileInfo,
    detect_file_type,
    suggest_category,
)


@register_skill
class AnalyzeSkill(BaseSkill):
    """
    Skill for initial challenge analysis.

    Analyzes files to determine challenge type and suggest next steps.
    Uses file detection, strings extraction, and basic analysis tools.
    """

    name: ClassVar[str] = "analyze"
    description: ClassVar[str] = "Analyze challenge files to determine type and suggest approaches"
    category: ClassVar[str] = "misc"
    tool_names: ClassVar[list[str]] = ["file", "strings", "binwalk", "exiftool"]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a challenge file or directory.

        Args:
            path: Path to file or directory to analyze

        Returns:
            SkillResult with file analysis and suggestions
        """
        analysis: dict[str, Any] = {
            "files": [],
            "detected_category": None,
            "file_types": [],
            "interesting_strings": [],
            "embedded_files": [],
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
            file_analysis = self._analyze_file(file_path)
            analysis["files"].append(file_analysis)

            # Collect tool results
            tool_results.extend(file_analysis.get("tool_results", []))

            # Collect interesting strings
            analysis["interesting_strings"].extend(file_analysis.get("interesting_strings", []))

            # Collect embedded files
            analysis["embedded_files"].extend(file_analysis.get("embedded_files", []))

        # Determine overall category
        categories = [
            f.get("suggested_category") for f in analysis["files"] if f.get("suggested_category")
        ]
        if categories:
            # Most common category
            analysis["detected_category"] = max(set(categories), key=categories.count)

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

    def _analyze_file(self, path: Path) -> dict[str, Any]:
        """Analyze a single file."""
        file_analysis: dict[str, Any] = {
            "path": str(path),
            "name": path.name,
            "size": path.stat().st_size,
            "tool_results": [],
            "interesting_strings": [],
            "embedded_files": [],
        }

        # Use file detection utility
        try:
            file_info: FileInfo = detect_file_type(path)
            file_analysis["file_type"] = file_info.file_type
            file_analysis["mime_type"] = file_info.mime_type
            file_analysis["extension"] = file_info.extension

            # Suggest category
            category = suggest_category(file_info)
            file_analysis["suggested_category"] = category.value
        except Exception:  # noqa: BLE001
            file_analysis["file_type"] = "unknown"

        # Run file tool if available
        file_tool = self.get_tool("file")
        if file_tool and file_tool.is_installed:
            result = file_tool.run(path)
            file_analysis["tool_results"].append(result)
            if result.suggestions:
                file_analysis["file_suggestions"] = result.suggestions

        # Run strings tool if available
        strings_tool = self.get_tool("strings")
        if strings_tool and strings_tool.is_installed:
            result = strings_tool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                interesting = result.parsed_data.get("interesting_strings", [])
                file_analysis["interesting_strings"] = interesting[:20]  # Limit

        # Run binwalk for binary files
        binwalk_tool = self.get_tool("binwalk")
        should_run_binwalk = file_analysis.get("suggested_category") in [
            CTFCategory.FORENSICS.value,
            CTFCategory.STEGO.value,
        ] or file_analysis.get("file_type", "").lower() in ["data", "unknown"]
        if binwalk_tool and binwalk_tool.is_installed and should_run_binwalk:
            result = binwalk_tool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                sigs = result.parsed_data.get("signatures", [])
                file_analysis["embedded_files"] = sigs[:10]

        # Run exiftool for images
        exiftool = self.get_tool("exiftool")
        is_stego = file_analysis.get("suggested_category") == CTFCategory.STEGO.value
        if exiftool and exiftool.is_installed and is_stego:
            result = exiftool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                interesting = result.parsed_data.get("interesting_fields", [])
                file_analysis["metadata_findings"] = interesting

        return file_analysis

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on analysis."""
        suggestions: list[str] = []
        category = analysis.get("detected_category")

        # Category-specific suggestions
        category_suggestions: dict[str, list[str]] = {
            CTFCategory.CRYPTO.value: [
                "Check for common ciphers (Caesar, Vigenere, XOR)",
                "Try frequency analysis if it looks like substitution cipher",
                "Look for RSA parameters (n, e, c) in the data",
                "Use hashid if you see hash-like strings",
            ],
            CTFCategory.FORENSICS.value: [
                "Extract embedded files with binwalk -e",
                "Check for deleted files or hidden partitions",
                "Look at file metadata with exiftool",
                "Analyze memory dumps with volatility3",
            ],
            CTFCategory.STEGO.value: [
                "Run zsteg on PNG/BMP images",
                "Try steghide on JPEG images",
                "Check LSB encoding with stegsolve",
                "Look for appended data after EOF",
            ],
            CTFCategory.PWN.value: [
                "Check binary protections with checksec",
                "Look for format string vulnerabilities",
                "Identify buffer overflow opportunities",
                "Find ROP gadgets with ropper or ROPgadget",
            ],
            CTFCategory.REVERSING.value: [
                "Disassemble with Ghidra or radare2",
                "Check for anti-debugging techniques",
                "Look for hardcoded strings and keys",
                "Trace execution with ltrace/strace",
            ],
            CTFCategory.WEB.value: [
                "Check robots.txt and common paths",
                "Look for SQL injection points",
                "Test for XSS vulnerabilities",
                "Examine cookies and headers",
            ],
        }

        if category and category in category_suggestions:
            suggestions.extend(category_suggestions[category])

        # Add suggestions based on interesting strings
        if analysis.get("interesting_strings"):
            strings_preview = analysis["interesting_strings"][:3]
            suggestions.append(f"Found interesting strings: {strings_preview}")

        # Add suggestions based on embedded files
        if analysis.get("embedded_files"):
            count = len(analysis["embedded_files"])
            suggestions.append(f"Found {count} embedded files - try extraction")

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []
        category = analysis.get("detected_category")

        # Common first steps
        steps.append("Review the interesting strings found")
        steps.append("Check file metadata for hidden clues")

        # Category-specific next steps
        if category == CTFCategory.CRYPTO.value:
            steps.extend(
                [
                    "Identify the cipher/encoding type",
                    "Look for keys or parameters",
                    "Apply appropriate decryption",
                ]
            )
        elif category == CTFCategory.FORENSICS.value:
            steps.extend(
                [
                    "Extract any embedded files",
                    "Analyze extracted files recursively",
                    "Check for steganography in images",
                ]
            )
        elif category == CTFCategory.STEGO.value:
            steps.extend(
                [
                    "Run appropriate stego tool (zsteg/steghide)",
                    "Check different color channels",
                    "Look for data appended after file end",
                ]
            )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        # Has detected category
        if analysis.get("detected_category"):
            confidence += 0.3

        # Has file type info
        if analysis.get("files") and any(f.get("file_type") for f in analysis["files"]):
            confidence += 0.2

        # Found interesting strings
        if analysis.get("interesting_strings"):
            confidence += 0.2

        # Found embedded files
        if analysis.get("embedded_files"):
            confidence += 0.2

        # Multiple tools ran successfully
        tool_count = sum(len(f.get("tool_results", [])) for f in analysis.get("files", []))
        if tool_count >= 2:
            confidence += 0.1

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)
