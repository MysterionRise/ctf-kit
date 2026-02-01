"""
Misc skill for CTF Kit.

Handles miscellaneous challenges including encoding chains,
esoteric languages, QR codes, logic puzzles, and more.
"""

from __future__ import annotations

import base64
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, ClassVar

from ctf_kit.skills.base import BaseSkill, SkillResult, register_skill
from ctf_kit.utils.file_detection import (
    FileInfo,
    detect_file_type,
)

if TYPE_CHECKING:
    from ctf_kit.integrations.base import ToolResult


@register_skill
class MiscSkill(BaseSkill):
    """
    Skill for miscellaneous CTF challenges.

    Handles encoding chains, esoteric programming languages,
    QR codes, barcodes, logic puzzles, and general-purpose analysis.
    """

    name: ClassVar[str] = "misc"
    description: ClassVar[str] = (
        "Analyze miscellaneous challenges including encoding chains, "
        "esoteric languages, QR codes, and logic puzzles"
    )
    category: ClassVar[str] = "misc"
    tool_names: ClassVar[list[str]] = [
        "file",
        "strings",
        "binwalk",
        "exiftool",
        "zbarimg",  # QR code reader
    ]

    # Encoding patterns
    ENCODING_PATTERNS: ClassVar[dict[str, tuple[str, str]]] = {
        "base64": (r"^[A-Za-z0-9+/]{4,}={0,2}$", "Base64"),
        "base32": (r"^[A-Z2-7]{8,}={0,6}$", "Base32"),
        "base16": (r"^[0-9A-Fa-f]{2,}$", "Hexadecimal"),
        "binary": (r"^[01]{8,}$", "Binary"),
        "octal": (r"^[0-7]{3,}(\s[0-7]{3})*$", "Octal"),
        "decimal": (r"^\d{2,3}(\s\d{2,3})+$", "Decimal ASCII"),
        "url": (r"%[0-9A-Fa-f]{2}", "URL encoding"),
        "unicode": (r"\\u[0-9A-Fa-f]{4}", "Unicode escape"),
        "html": (r"&#\d+;|&#x[0-9A-Fa-f]+;", "HTML entities"),
    }

    # Esoteric language patterns
    ESOTERIC_PATTERNS: ClassVar[dict[str, tuple[str, str]]] = {
        "brainfuck": (r"^[+\-<>\[\].,]+$", "Brainfuck"),
        "ook": (r"Ook[.!?]", "Ook!"),
        "whitespace": (r"^[\s\t\n]+$", "Whitespace"),
        "jsfuck": (r"^\[|\]|\(|\)|!|\+]+$", "JSFuck"),
        "malbolge": (r"^[D'`~_!@#$%^&*\(\)]+", "Malbolge"),
        "piet": (r"\.png$|\.gif$", "Piet (image-based)"),
        "cow": (r"moo|MOO|MoO", "COW"),
    }

    # Flag format patterns
    FLAG_PATTERNS: ClassVar[list[str]] = [
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"picoCTF\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"DUCTF\{[^}]+\}",
        r"corctf\{[^}]+\}",
    ]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a miscellaneous challenge.

        Args:
            path: Path to challenge file or directory

        Returns:
            SkillResult with misc analysis
        """
        analysis: dict[str, Any] = {
            "file_info": {},
            "detected_encodings": [],
            "esoteric_language": None,
            "qr_codes": [],
            "flags_found": [],
            "interesting_patterns": [],
            "decoded_attempts": [],
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

            # Aggregate findings
            analysis["detected_encodings"].extend(file_analysis.get("encodings", []))
            analysis["flags_found"].extend(file_analysis.get("flags", []))
            analysis["interesting_patterns"].extend(file_analysis.get("patterns", []))
            analysis["decoded_attempts"].extend(file_analysis.get("decoded", []))

            if file_analysis.get("esoteric_language"):
                analysis["esoteric_language"] = file_analysis["esoteric_language"]

            if file_analysis.get("qr_codes"):
                analysis["qr_codes"].extend(file_analysis["qr_codes"])

            analysis["file_info"][str(file_path)] = file_analysis.get("file_info", {})
            tool_results.extend(file_analysis.get("tool_results", []))

        # Generate suggestions
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
        """Analyze a single file for misc patterns."""
        file_analysis: dict[str, Any] = {
            "path": str(path),
            "file_info": {},
            "encodings": [],
            "esoteric_language": None,
            "qr_codes": [],
            "flags": [],
            "patterns": [],
            "decoded": [],
            "tool_results": [],
        }

        # Get file info
        try:
            file_info: FileInfo = detect_file_type(path)
            file_analysis["file_info"] = {
                "name": file_info.name,
                "size": file_info.size,
                "file_type": file_info.file_type,
            }
        except Exception:  # noqa: BLE001
            file_analysis["file_info"] = {"name": path.name}

        # Check if image (might be QR code)
        suffix = path.suffix.lower()
        if suffix in [".png", ".jpg", ".jpeg", ".gif", ".bmp"]:
            self._analyze_qr_code(path, file_analysis)

        # Read and analyze content
        try:
            content = path.read_text(errors="ignore")
            self._analyze_text_content(content, file_analysis)
        except Exception:  # noqa: BLE001
            # Try as binary
            try:
                with path.open("rb") as f:
                    binary_content = f.read()
                # Check for embedded text
                self._analyze_binary_content(binary_content, file_analysis)
            except Exception:  # noqa: BLE001
                pass

        # Run strings tool
        strings_tool = self.get_tool("strings")
        if strings_tool and strings_tool.is_installed:
            result = strings_tool.run(path)
            file_analysis["tool_results"].append(result)
            if result.stdout:
                # Check strings for flags
                for flag_pattern in self.FLAG_PATTERNS:
                    flags = re.findall(flag_pattern, result.stdout)
                    file_analysis["flags"].extend(flags)

        return file_analysis

    def _analyze_text_content(self, content: str, file_analysis: dict[str, Any]) -> None:
        """Analyze text content for encodings and patterns."""
        lines = content.strip().split("\n")

        # Check for flags
        for flag_pattern in self.FLAG_PATTERNS:
            flags = re.findall(flag_pattern, content)
            file_analysis["flags"].extend(flags)

        # Check each line for encoding patterns
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            # Check encoding patterns
            for encoding_name, (pattern, description) in self.ENCODING_PATTERNS.items():
                if re.match(pattern, line):
                    file_analysis["encodings"].append(
                        {
                            "type": encoding_name,
                            "description": description,
                            "sample": line[:50] + "..." if len(line) > 50 else line,
                        }
                    )

                    # Try to decode
                    decoded = self._try_decode(line, encoding_name)
                    if decoded:
                        file_analysis["decoded"].append(
                            {
                                "encoding": encoding_name,
                                "original": line[:30],
                                "decoded": decoded[:100],
                            }
                        )
                    break

        # Check for esoteric languages (whole content)
        content_stripped = content.strip()
        for lang_name, (pattern, description) in self.ESOTERIC_PATTERNS.items():
            if re.match(pattern, content_stripped) or re.search(pattern, content_stripped):
                file_analysis["esoteric_language"] = {
                    "type": lang_name,
                    "description": description,
                }
                break

    def _analyze_binary_content(self, content: bytes, file_analysis: dict[str, Any]) -> None:
        """Analyze binary content for patterns."""
        # Try to find ASCII strings
        ascii_pattern = re.compile(b"[\x20-\x7e]{4,}")
        matches = ascii_pattern.findall(content)

        for match in matches[:20]:
            try:
                text = match.decode("ascii")
                # Check for flags
                for flag_pattern in self.FLAG_PATTERNS:
                    flags = re.findall(flag_pattern, text)
                    file_analysis["flags"].extend(flags)
            except UnicodeDecodeError:
                pass

    def _analyze_qr_code(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Analyze image for QR codes."""
        # Try zbarimg if available
        zbarimg = self.get_tool("zbarimg")
        if zbarimg and zbarimg.is_installed:
            result = zbarimg.run(path)
            file_analysis["tool_results"].append(result)
            if result.parsed_data:
                qr_data = result.parsed_data.get("data", [])
                file_analysis["qr_codes"].extend(qr_data)
                # Check if QR data contains flag
                for data in qr_data:
                    for flag_pattern in self.FLAG_PATTERNS:
                        flags = re.findall(flag_pattern, str(data))
                        file_analysis["flags"].extend(flags)

    def _try_decode(self, text: str, encoding_type: str) -> str | None:
        """Try to decode text with the detected encoding."""
        try:
            if encoding_type == "base64":
                # Check if valid base64 length
                if len(text) % 4 == 0 or text.endswith("="):
                    decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
                    if decoded and self._is_readable(decoded):
                        return decoded

            elif encoding_type == "base32":
                if len(text) % 8 == 0 or text.endswith("="):
                    decoded = base64.b32decode(text).decode("utf-8", errors="ignore")
                    if decoded and self._is_readable(decoded):
                        return decoded

            elif encoding_type == "base16":
                decoded = bytes.fromhex(text).decode("utf-8", errors="ignore")
                if decoded and self._is_readable(decoded):
                    return decoded

            elif encoding_type == "binary":
                # Convert binary to ASCII
                chars = []
                for i in range(0, len(text), 8):
                    byte = text[i : i + 8]
                    if len(byte) == 8:
                        chars.append(chr(int(byte, 2)))
                decoded = "".join(chars)
                if decoded and self._is_readable(decoded):
                    return decoded

            elif encoding_type == "decimal":
                chars = [chr(int(x)) for x in text.split() if x.isdigit() and 32 <= int(x) <= 126]
                decoded = "".join(chars)
                if decoded and self._is_readable(decoded):
                    return decoded

            elif encoding_type == "octal":
                chars = [chr(int(x, 8)) for x in text.split() if 32 <= int(x, 8) <= 126]
                decoded = "".join(chars)
                if decoded and self._is_readable(decoded):
                    return decoded

        except Exception:  # noqa: BLE001
            pass

        return None

    def _is_readable(self, text: str) -> bool:
        """Check if text is reasonably readable (mostly printable)."""
        if not text:
            return False
        printable_count = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return printable_count / len(text) > 0.7

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on analysis."""
        suggestions: list[str] = []

        # Flag found!
        if analysis.get("flags_found"):
            for flag in analysis["flags_found"][:3]:
                suggestions.insert(0, f"FLAG FOUND: {flag}")

        # QR code data
        if analysis.get("qr_codes"):
            suggestions.append(f"QR code decoded: {analysis['qr_codes'][0][:50]}...")

        # Encoding suggestions
        if analysis.get("detected_encodings"):
            encodings = [e["type"] for e in analysis["detected_encodings"]]
            unique_encodings = list(set(encodings))
            suggestions.append(f"Detected encodings: {', '.join(unique_encodings)}")

            # Suggest decoding chain
            if len(unique_encodings) > 1:
                suggestions.append("Try decoding in different orders (encoding chain)")

        # Successfully decoded
        if analysis.get("decoded_attempts"):
            for decoded in analysis["decoded_attempts"][:2]:
                suggestions.append(f"Decoded {decoded['encoding']}: {decoded['decoded'][:50]}...")

        # Esoteric language
        if analysis.get("esoteric_language"):
            lang = analysis["esoteric_language"]
            suggestions.append(f"Esoteric language detected: {lang['description']}")
            if lang["type"] == "brainfuck":
                suggestions.append("Run with a Brainfuck interpreter")
            elif lang["type"] == "ook":
                suggestions.append("Convert Ook! to Brainfuck, then run")
            elif lang["type"] == "whitespace":
                suggestions.append("Use a Whitespace interpreter")

        # General suggestions
        if not suggestions:
            suggestions = [
                "Try CyberChef 'Magic' operation for auto-detection",
                "Check for multi-layer encoding",
                "Look for patterns in the data",
                "Consider esoteric programming languages",
            ]

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []

        if analysis.get("flags_found"):
            steps.append("Verify the flag format and submit")
            return steps

        if analysis.get("detected_encodings"):
            steps.append("Decode detected encodings")
            steps.append("Check if decoded output needs further processing")

        if analysis.get("esoteric_language"):
            steps.append("Run through appropriate interpreter")
            steps.append("Check output for flag")

        if analysis.get("qr_codes"):
            steps.append("Analyze QR code content")

        steps.extend(
            [
                "Try common encoding combinations",
                "Use CyberChef for experimentation",
                "Look for patterns or hints in the challenge description",
            ]
        )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        if analysis.get("flags_found"):
            return 1.0  # Flag found!

        if analysis.get("qr_codes"):
            confidence += 0.3

        if analysis.get("detected_encodings"):
            confidence += 0.2

        if analysis.get("decoded_attempts"):
            confidence += 0.3

        if analysis.get("esoteric_language"):
            confidence += 0.25

        if analysis.get("interesting_patterns"):
            confidence += 0.1

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def decode_chain(self, text: str, encodings: list[str]) -> str:
        """Decode text through a chain of encodings."""
        result = text

        for encoding in encodings:
            decoded = self._try_decode(result, encoding)
            if decoded:
                result = decoded
            else:
                break

        return result

    def identify_encoding(self, text: str) -> list[dict[str, Any]]:
        """Identify possible encodings for a text."""
        matches: list[dict[str, Any]] = []

        for encoding_name, (pattern, description) in self.ENCODING_PATTERNS.items():
            if re.match(pattern, text.strip()):
                matches.append(
                    {
                        "type": encoding_name,
                        "description": description,
                        "confidence": 0.8,
                    }
                )

        return matches
