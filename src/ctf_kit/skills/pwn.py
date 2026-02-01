"""
Pwn skill for CTF Kit.

Orchestrates binary exploitation tools for analyzing and exploiting
vulnerable binaries, including buffer overflows, format strings,
ROP chains, and heap exploitation.
"""

from __future__ import annotations

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
class PwnSkill(BaseSkill):
    """
    Skill for binary exploitation challenges.

    Analyzes ELF binaries for vulnerabilities, identifies protections,
    finds gadgets for ROP chains, and helps develop exploits.
    Orchestrates tools like checksec, ROPgadget, pwntools, and gdb.
    """

    name: ClassVar[str] = "pwn"
    description: ClassVar[str] = (
        "Analyze binary exploitation challenges including buffer overflows, "
        "format strings, ROP chains, and heap exploitation"
    )
    category: ClassVar[str] = "pwn"
    tool_names: ClassVar[list[str]] = [
        "checksec",
        "ropgadget",
        "file",
        "strings",
        "objdump",
        "readelf",
    ]

    # Common vulnerability patterns in binary strings
    VULN_PATTERNS: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "buffer_overflow": [
            (r"gets\b", "gets() - no bounds checking"),
            (r"strcpy\b", "strcpy() - no bounds checking"),
            (r"strcat\b", "strcat() - no bounds checking"),
            (r"sprintf\b", "sprintf() - no bounds checking"),
            (r"scanf\b", "scanf() - potential overflow"),
            (r"read\b.*0x[0-9a-f]{3,}", "read() with large buffer"),
        ],
        "format_string": [
            (r"printf\(.*\)", "printf() with user input"),
            (r"fprintf\b", "fprintf() potential format string"),
            (r"sprintf\b", "sprintf() potential format string"),
            (r"snprintf\b", "snprintf() potential format string"),
        ],
        "use_after_free": [
            (r"free\b", "free() - check for UAF"),
            (r"malloc\b", "malloc() - heap allocation"),
            (r"realloc\b", "realloc() - heap resize"),
        ],
        "command_injection": [
            (r"system\b", "system() - command execution"),
            (r"execve\b", "execve() - program execution"),
            (r"popen\b", "popen() - command pipe"),
        ],
    }

    # Binary protection abbreviations
    PROTECTION_NAMES: ClassVar[dict[str, str]] = {
        "RELRO": "Relocation Read-Only",
        "STACK CANARY": "Stack Canary",
        "NX": "No-Execute",
        "PIE": "Position Independent Executable",
        "FORTIFY": "Fortify Source",
        "ASLR": "Address Space Layout Randomization",
    }

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a binary exploitation challenge.

        Args:
            path: Path to binary file or directory

        Returns:
            SkillResult with binary analysis
        """
        analysis: dict[str, Any] = {
            "binary_info": {},
            "protections": {},
            "vulnerabilities": [],
            "gadgets": [],
            "interesting_functions": [],
            "interesting_strings": [],
            "symbols": [],
        }
        tool_results: list[ToolResult] = []
        suggestions: list[str] = []
        artifacts: list[Path] = []

        # Handle directory vs file
        if path.is_dir():
            files = [f for f in path.iterdir() if f.is_file() and not f.name.startswith(".")]
            # Filter to likely ELF binaries
            files = [f for f in files if self._is_likely_binary(f)]
        else:
            files = [path]

        if not files:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis=analysis,
                suggestions=["No binary files found to analyze"],
                confidence=0.0,
            )

        # Analyze primary binary (first one)
        primary_binary = files[0]
        binary_analysis = self._analyze_binary(primary_binary)

        analysis.update(binary_analysis)
        tool_results.extend(binary_analysis.get("tool_results", []))

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

    def _is_likely_binary(self, path: Path) -> bool:
        """Check if file is likely an ELF binary."""
        # Check by extension (or lack thereof)
        if path.suffix in [".c", ".h", ".py", ".txt", ".md"]:
            return False

        # Check magic bytes
        try:
            with path.open("rb") as f:
                magic = f.read(4)
                return magic == b"\x7fELF"
        except OSError:
            return False

    def _analyze_binary(self, path: Path) -> dict[str, Any]:
        """Analyze a single binary file."""
        binary_analysis: dict[str, Any] = {
            "path": str(path),
            "binary_info": {},
            "protections": {},
            "vulnerabilities": [],
            "gadgets": [],
            "interesting_functions": [],
            "interesting_strings": [],
            "symbols": [],
            "tool_results": [],
        }

        # Get file info
        try:
            file_info: FileInfo = detect_file_type(path)
            binary_analysis["binary_info"] = {
                "name": file_info.name,
                "size": file_info.size,
                "file_type": file_info.file_type,
                "arch": self._extract_arch(file_info.file_type),
            }
        except Exception:  # noqa: BLE001
            binary_analysis["binary_info"] = {"name": path.name}

        # Run checksec for protections
        checksec = self.get_tool("checksec")
        if checksec and checksec.is_installed:
            result = checksec.run(path)
            binary_analysis["tool_results"].append(result)
            if result.parsed_data:
                binary_analysis["protections"] = result.parsed_data.get("protections", {})

        # Run strings for interesting content
        strings_tool = self.get_tool("strings")
        if strings_tool and strings_tool.is_installed:
            result = strings_tool.run(path)
            binary_analysis["tool_results"].append(result)
            if result.parsed_data:
                interesting = result.parsed_data.get("interesting_strings", [])
                binary_analysis["interesting_strings"] = interesting[:30]

                # Scan strings for vulnerability indicators
                all_strings = result.stdout if result.stdout else ""
                vulns = self._scan_for_vulnerabilities(all_strings)
                binary_analysis["vulnerabilities"].extend(vulns)

        # Look for interesting symbols/functions
        binary_analysis["interesting_functions"] = self._find_interesting_functions(path)

        # Get ROP gadgets (limited)
        ropgadget = self.get_tool("ropgadget")
        if ropgadget and ropgadget.is_installed:
            result = ropgadget.run(path, depth=3, limit=20)
            binary_analysis["tool_results"].append(result)
            if result.parsed_data:
                binary_analysis["gadgets"] = result.parsed_data.get("gadgets", [])[:20]

        return binary_analysis

    def _extract_arch(self, file_type: str) -> str:
        """Extract architecture from file type string."""
        file_type_lower = file_type.lower()

        if "64-bit" in file_type_lower or "x86-64" in file_type_lower:
            return "x86_64"
        if "32-bit" in file_type_lower or "i386" in file_type_lower:
            return "x86"
        if "arm64" in file_type_lower or "aarch64" in file_type_lower:
            return "arm64"
        if "arm" in file_type_lower:
            return "arm"
        if "mips" in file_type_lower:
            return "mips"

        return "unknown"

    def _scan_for_vulnerabilities(self, strings_output: str) -> list[dict[str, Any]]:
        """Scan strings for vulnerability patterns."""
        vulnerabilities: list[dict[str, Any]] = []

        for vuln_type, patterns in self.VULN_PATTERNS.items():
            for pattern, description in patterns:
                if re.search(pattern, strings_output, re.IGNORECASE):
                    vulnerabilities.append(
                        {
                            "type": vuln_type,
                            "indicator": description,
                        }
                    )

        return vulnerabilities

    def _find_interesting_functions(self, path: Path) -> list[str]:
        """Find interesting functions in the binary."""
        interesting: list[str] = []

        try:
            # Use nm or readelf to get symbols
            import subprocess  # nosec B404

            result = subprocess.run(  # nosec B603
                ["nm", "-C", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                # Try without -C for stripped binaries
                result = subprocess.run(  # nosec B603
                    ["nm", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

            dangerous_funcs = [
                "gets",
                "strcpy",
                "strcat",
                "sprintf",
                "vsprintf",
                "scanf",
                "printf",
                "system",
                "execve",
                "popen",
                "main",
                "win",
                "flag",
                "shell",
                "backdoor",
                "secret",
            ]

            for line in result.stdout.split("\n"):
                for func in dangerous_funcs:
                    if func in line.lower():
                        interesting.append(line.strip())
                        break

        except Exception:  # noqa: BLE001
            pass

        return interesting[:20]

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on binary analysis."""
        suggestions: list[str] = []
        protections = analysis.get("protections", {})
        vulnerabilities = analysis.get("vulnerabilities", [])
        arch = analysis.get("binary_info", {}).get("arch", "unknown")

        # Protection-based suggestions
        if not protections.get("canary"):
            suggestions.append("No stack canary - buffer overflow may be exploitable")

        if not protections.get("nx"):
            suggestions.append("NX disabled - shellcode injection possible")

        if not protections.get("pie"):
            suggestions.append("No PIE - addresses are fixed (easier ROP)")

        if protections.get("relro") == "Partial":
            suggestions.append("Partial RELRO - GOT overwrite possible")
        elif not protections.get("relro"):
            suggestions.append("No RELRO - GOT overwrite easy")

        # Vulnerability-based suggestions
        vuln_types = {v["type"] for v in vulnerabilities}

        if "buffer_overflow" in vuln_types:
            suggestions.append("Buffer overflow functions detected (gets, strcpy, etc.)")
            if not protections.get("canary"):
                suggestions.append("Stack overflow likely exploitable - no canary protection")

        if "format_string" in vuln_types:
            suggestions.append("Format string vulnerability likely - check printf usage")
            suggestions.append("Use %p to leak addresses, %n to write")

        if "use_after_free" in vuln_types:
            suggestions.append("Heap functions detected - check for UAF/double-free")

        if "command_injection" in vuln_types:
            suggestions.append("system() or execve() found - target for exploitation")

        # Architecture-specific suggestions
        if arch == "x86_64":
            suggestions.append("64-bit binary - look for pop rdi; ret gadgets for ROP")
        elif arch == "x86":
            suggestions.append("32-bit binary - arguments on stack for function calls")

        # Gadget suggestions
        if analysis.get("gadgets"):
            suggestions.append(f"Found {len(analysis['gadgets'])} ROP gadgets")

        # Interesting functions
        if analysis.get("interesting_functions"):
            funcs = analysis["interesting_functions"]
            if any("win" in f.lower() or "flag" in f.lower() for f in funcs):
                suggestions.append("Found win/flag function - redirect execution there!")

        if not suggestions:
            suggestions = [
                "Run the binary to understand its behavior",
                "Check for vulnerabilities with dynamic analysis",
                "Use gdb to debug and find vulnerabilities",
            ]

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []
        protections = analysis.get("protections", {})

        steps.append("Run the binary to understand its behavior")
        steps.append("Identify input points and their handling")

        # Exploitation strategy based on protections
        if not protections.get("canary") and not protections.get("nx"):
            steps.append("Buffer overflow with shellcode injection")
        elif not protections.get("canary"):
            steps.append("Buffer overflow with ROP chain")
        elif not protections.get("pie"):
            steps.append("Format string attack for address leak + GOT overwrite")
        else:
            steps.append("Find info leak for PIE bypass, then exploit")

        steps.extend(
            [
                "Find offset to return address with pattern_create/pattern_offset",
                "Build exploit with pwntools",
                "Test locally then against remote",
            ]
        )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        if analysis.get("binary_info"):
            confidence += 0.15

        if analysis.get("protections"):
            confidence += 0.25

        if analysis.get("vulnerabilities"):
            confidence += 0.25

        if analysis.get("gadgets"):
            confidence += 0.15

        if analysis.get("interesting_functions"):
            confidence += 0.1

        if analysis.get("interesting_strings"):
            confidence += 0.1

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def find_gadgets(self, path: Path, pattern: str | None = None) -> SkillResult:
        """Find ROP gadgets in a binary."""
        ropgadget = self.get_tool("ropgadget")
        if not ropgadget or not ropgadget.is_installed:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis={"error": "ROPgadget not installed"},
                suggestions=["Install ROPgadget: pip install ropgadget"],
            )

        result = ropgadget.run(path, grep=pattern)

        gadgets = result.parsed_data.get("gadgets", []) if result.parsed_data else []

        return SkillResult(
            success=result.success,
            skill_name=self.name,
            analysis={"gadgets": gadgets},
            tool_results=[result],
            suggestions=[
                "Look for pop rdi; ret for x64 function arguments",
                "Find leave; ret for stack pivoting",
                "Search syscall; ret for SROP",
            ],
        )

    def check_protections(self, path: Path) -> dict[str, Any]:
        """Check binary security protections."""
        checksec = self.get_tool("checksec")
        if checksec and checksec.is_installed:
            result = checksec.run(path)
            if result.success and result.parsed_data:
                protections: dict[str, Any] = result.parsed_data.get("protections", {})
                return protections
        return {}
