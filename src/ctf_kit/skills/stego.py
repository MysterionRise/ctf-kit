"""
Stego skill for CTF Kit.

Orchestrates steganography tools for detecting and extracting
hidden data in images, audio, and other media files.
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
class StegoSkill(BaseSkill):
    """
    Skill for steganography challenge analysis.

    Detects and extracts hidden data from images, audio files,
    and other media. Orchestrates tools like zsteg, steghide,
    stegsolve, exiftool, and binwalk.
    """

    name: ClassVar[str] = "stego"
    description: ClassVar[str] = (
        "Analyze steganography challenges to detect and extract hidden data "
        "in images, audio, and other media files"
    )
    category: ClassVar[str] = "stego"
    tool_names: ClassVar[list[str]] = [
        "zsteg",
        "steghide",
        "exiftool",
        "binwalk",
        "strings",
        "file",
        "stegsolve",
    ]

    # Stego-friendly image formats
    IMAGE_FORMATS: ClassVar[dict[str, list[str]]] = {
        "lsb_capable": [".png", ".bmp", ".gif"],  # Lossless, good for LSB
        "jpeg": [".jpg", ".jpeg"],  # Lossy, needs special techniques
        "other_image": [".tiff", ".webp", ".ico"],
    }

    # Audio formats for stego
    AUDIO_FORMATS: ClassVar[list[str]] = [
        ".wav",
        ".mp3",
        ".flac",
        ".ogg",
        ".aiff",
    ]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a steganography challenge.

        Args:
            path: Path to challenge file or directory

        Returns:
            SkillResult with stego analysis
        """
        analysis: dict[str, Any] = {
            "media_type": None,
            "file_info": {},
            "metadata_findings": [],
            "lsb_findings": [],
            "embedded_data": [],
            "appended_data": False,
            "suspicious_indicators": [],
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
            file_analysis = self._analyze_stego_file(file_path)

            # Update main analysis
            if not analysis["media_type"] and file_analysis.get("media_type"):
                analysis["media_type"] = file_analysis["media_type"]

            analysis["file_info"][str(file_path)] = file_analysis.get("file_info", {})
            analysis["metadata_findings"].extend(file_analysis.get("metadata_findings", []))
            analysis["lsb_findings"].extend(file_analysis.get("lsb_findings", []))
            analysis["embedded_data"].extend(file_analysis.get("embedded_data", []))
            analysis["suspicious_indicators"].extend(file_analysis.get("suspicious_indicators", []))

            if file_analysis.get("appended_data"):
                analysis["appended_data"] = True

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

    def _analyze_stego_file(self, path: Path) -> dict[str, Any]:
        """Analyze a single file for steganography."""
        file_analysis: dict[str, Any] = {
            "path": str(path),
            "media_type": None,
            "file_info": {},
            "metadata_findings": [],
            "lsb_findings": [],
            "embedded_data": [],
            "appended_data": False,
            "suspicious_indicators": [],
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

        # Determine media type
        media_type = self._detect_media_type(path)
        file_analysis["media_type"] = media_type

        # Run exiftool for metadata analysis (all media types)
        exiftool = self.get_tool("exiftool")
        if exiftool and exiftool.is_installed:
            result = exiftool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                interesting = result.parsed_data.get("interesting_fields", [])
                file_analysis["metadata_findings"] = interesting
                # Check for suspicious metadata
                self._check_metadata_anomalies(result.parsed_data, file_analysis)

        # Run binwalk to check for appended/embedded data
        binwalk = self.get_tool("binwalk")
        if binwalk and binwalk.is_installed:
            result = binwalk.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                sigs = result.parsed_data.get("signatures", [])
                if len(sigs) > 1:
                    file_analysis["embedded_data"] = sigs
                    file_analysis["suspicious_indicators"].append(
                        f"Multiple signatures found: {len(sigs)} files embedded"
                    )
                # Check for data appended after expected EOF
                self._check_appended_data(path, sigs, file_analysis)

        # Run format-specific analysis
        if media_type == "png" or media_type == "bmp":
            self._analyze_lsb_image(path, file_analysis)
        elif media_type == "jpeg":
            self._analyze_jpeg(path, file_analysis)
        elif media_type == "audio":
            self._analyze_audio(path, file_analysis)

        # Run strings to look for hidden text
        strings_tool = self.get_tool("strings")
        if strings_tool and strings_tool.is_installed:
            result = strings_tool.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                interesting = result.parsed_data.get("interesting_strings", [])
                if interesting:
                    file_analysis["suspicious_indicators"].append(
                        f"Found {len(interesting)} interesting strings"
                    )

        return file_analysis

    def _detect_media_type(self, path: Path) -> str:
        """Detect the media type for stego analysis."""
        suffix = path.suffix.lower()

        for fmt in self.IMAGE_FORMATS["lsb_capable"]:
            if suffix == fmt:
                return "png" if fmt == ".png" else "bmp" if fmt == ".bmp" else "gif"

        if suffix in self.IMAGE_FORMATS["jpeg"]:
            return "jpeg"

        if suffix in self.IMAGE_FORMATS["other_image"]:
            return "image"

        if suffix in self.AUDIO_FORMATS:
            return "audio"

        return "unknown"

    def _analyze_lsb_image(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Analyze PNG/BMP images for LSB steganography."""
        zsteg = self.get_tool("zsteg")
        if zsteg and zsteg.is_installed:
            result = zsteg.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                findings = result.parsed_data.get("findings", [])
                file_analysis["lsb_findings"] = findings[:20]
                if findings:
                    file_analysis["suspicious_indicators"].append(
                        f"zsteg found {len(findings)} potential LSB encodings"
                    )

    def _analyze_jpeg(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Analyze JPEG images for steganography."""
        # JPEG uses lossy compression, so LSB doesn't work well
        # Instead, try steghide (DCT-based stego)
        steghide = self.get_tool("steghide")
        if steghide and steghide.is_installed:
            # Try extraction with empty password first
            result = steghide.run(path, mode="extract", password="")
            file_analysis["tool_results"].append(result)
            if result.success and result.artifacts:
                file_analysis["embedded_data"].extend(
                    [{"type": "steghide", "file": str(a)} for a in result.artifacts]
                )
                file_analysis["suspicious_indicators"].append(
                    "Steghide extracted data with empty password!"
                )

    def _analyze_audio(self, _path: Path, file_analysis: dict[str, Any]) -> None:
        """Analyze audio files for steganography."""
        # Audio stego often uses:
        # - LSB encoding in WAV
        # - Spectrum hiding (visual patterns in spectrogram)
        # - Morse code in audio
        file_analysis["suspicious_indicators"].append(
            "Audio file - check spectrogram with Audacity/Sonic Visualizer"
        )
        file_analysis["suspicious_indicators"].append(
            "Listen for morse code or hidden audio channels"
        )

    def _check_metadata_anomalies(
        self, parsed_data: dict[str, Any], file_analysis: dict[str, Any]
    ) -> None:
        """Check for suspicious metadata."""
        metadata = parsed_data.get("metadata", {})

        # Check for comments or custom fields
        suspicious_fields = ["Comment", "UserComment", "XMP", "EXIF:UserComment"]
        for field in suspicious_fields:
            if field in metadata:
                file_analysis["suspicious_indicators"].append(
                    f"Found {field} metadata: {str(metadata[field])[:50]}..."
                )

        # Check for unusual dimensions or color depth
        if "ImageWidth" in metadata and "ImageHeight" in metadata:
            width = metadata.get("ImageWidth", 0)
            height = metadata.get("ImageHeight", 0)
            # Check for unusual aspect ratios or specific sizes
            if width == height and width in [256, 512, 1024]:
                file_analysis["suspicious_indicators"].append(
                    f"Square image with power-of-2 dimensions: {width}x{height}"
                )

    def _check_appended_data(
        self, path: Path, signatures: list[dict[str, Any]], file_analysis: dict[str, Any]
    ) -> None:
        """Check if data is appended after the expected file end."""
        if not signatures:
            return

        file_size = path.stat().st_size

        # Look for signatures that appear after expected content
        for sig in signatures:
            offset = sig.get("offset", 0)
            description = sig.get("description", "").lower()

            # If we find a signature significantly into the file, flag it
            if offset > 1000 and "zip" in description:
                file_analysis["appended_data"] = True
                file_analysis["suspicious_indicators"].append(
                    f"ZIP archive found at offset {offset} (appended to image?)"
                )
            elif offset > file_size * 0.9:  # Last 10% of file
                file_analysis["suspicious_indicators"].append(
                    f"Data found near end of file at offset {offset}: {sig.get('description', 'unknown')}"
                )

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on stego analysis."""
        suggestions: list[str] = []
        media_type = analysis.get("media_type")

        # Media-specific suggestions
        if media_type in ["png", "bmp", "gif"]:
            suggestions.extend(
                [
                    "Run zsteg for LSB analysis: zsteg -a image.png",
                    "Use stegsolve to examine color planes and bit layers",
                    "Check for data in alpha channel (PNG)",
                    "Try extracting with binwalk -e",
                ]
            )
        elif media_type == "jpeg":
            suggestions.extend(
                [
                    "Try steghide: steghide extract -sf image.jpg",
                    "JPEG uses lossy compression - LSB won't work",
                    "Check EXIF data for hidden comments",
                    "Try jsteg or outguess for JPEG-specific stego",
                ]
            )
        elif media_type == "audio":
            suggestions.extend(
                [
                    "Open in Audacity and view spectrogram",
                    "Check for morse code or SSTV signals",
                    "Try LSB extraction for WAV files",
                    "Look for hidden audio in different channels",
                ]
            )
        else:
            suggestions.extend(
                [
                    "Identify the file format first",
                    "Check for embedded files with binwalk",
                    "Look at hex dump for anomalies",
                ]
            )

        # Add suggestions based on findings
        if analysis.get("lsb_findings"):
            suggestions.insert(0, "LSB data detected - extract with zsteg")

        if analysis.get("appended_data"):
            suggestions.insert(0, "Data appended after file - extract with binwalk -e")

        if analysis.get("metadata_findings"):
            suggestions.insert(0, "Check interesting metadata fields found")

        if analysis.get("suspicious_indicators"):
            for indicator in analysis["suspicious_indicators"][:3]:
                suggestions.insert(0, indicator)

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []
        media_type = analysis.get("media_type")

        steps.append("Review file metadata with exiftool")

        if media_type in ["png", "bmp"]:
            steps.extend(
                [
                    "Run zsteg -a for comprehensive LSB analysis",
                    "Use stegsolve to examine each color plane",
                    "Check for data after EOF with binwalk",
                    "Try strings to find readable text",
                ]
            )
        elif media_type == "jpeg":
            steps.extend(
                [
                    "Try steghide with common passwords",
                    "Check for hidden EXIF data",
                    "Try jsteg/outguess tools",
                    "Look for appended data after JPEG EOF marker",
                ]
            )
        elif media_type == "audio":
            steps.extend(
                [
                    "View spectrogram in Audacity",
                    "Check for morse code (listen at different speeds)",
                    "Try audio LSB tools for WAV",
                    "Look for hidden channels",
                ]
            )
        else:
            steps.extend(
                [
                    "Identify exact file format",
                    "Extract embedded data with binwalk",
                    "Try format-specific stego tools",
                ]
            )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        # Has media type detected
        if analysis.get("media_type") and analysis["media_type"] != "unknown":
            confidence += 0.2

        # Has file info
        if analysis.get("file_info"):
            confidence += 0.1

        # Found LSB data
        if analysis.get("lsb_findings"):
            confidence += 0.3

        # Found embedded data
        if analysis.get("embedded_data"):
            confidence += 0.2

        # Has metadata findings
        if analysis.get("metadata_findings"):
            confidence += 0.1

        # Has suspicious indicators
        if analysis.get("suspicious_indicators"):
            confidence += 0.1

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def extract_lsb(self, path: Path, _channel: str = "all") -> SkillResult:
        """Extract LSB data from an image."""
        zsteg = self.get_tool("zsteg")
        if not zsteg or not zsteg.is_installed:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis={"error": "zsteg not installed"},
                suggestions=["Install zsteg: gem install zsteg"],
            )

        result = zsteg.run(path, all_modes=True)

        return SkillResult(
            success=result.success,
            skill_name=self.name,
            analysis={
                "findings": result.parsed_data.get("findings", []) if result.parsed_data else [],
            },
            tool_results=[result],
            suggestions=result.suggestions or [],
        )
