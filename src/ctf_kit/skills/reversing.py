"""
Reversing skill for CTF Kit.

Orchestrates reverse engineering tools for analyzing binaries,
understanding program logic, and extracting hidden functionality.
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
class ReversingSkill(BaseSkill):
    """
    Skill for reverse engineering challenges.

    Analyzes binaries to understand program logic, extract algorithms,
    defeat anti-debugging, and find hidden functionality.
    Orchestrates tools like radare2, Ghidra, objdump, and ltrace.
    """

    name: ClassVar[str] = "reversing"
    description: ClassVar[str] = (
        "Analyze reverse engineering challenges including ELF/PE binaries, "
        "algorithm identification, anti-debugging, and code deobfuscation"
    )
    category: ClassVar[str] = "reversing"
    tool_names: ClassVar[list[str]] = [
        "radare2",
        "ghidra",
        "file",
        "strings",
        "objdump",
        "readelf",
        "ltrace",
        "strace",
    ]

    # File type patterns for different executable formats
    BINARY_TYPES: ClassVar[dict[str, list[str]]] = {
        "elf": [".elf", ".so", ".o", ""],
        "pe": [".exe", ".dll", ".sys"],
        "macho": [".dylib", ".app"],
        "java": [".jar", ".class"],
        "python": [".pyc", ".pyo"],
        "dotnet": [".exe", ".dll"],  # .NET uses PE format
        "wasm": [".wasm"],
        "android": [".apk", ".dex"],
    }

    # Anti-debugging indicators
    ANTI_DEBUG_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"ptrace", "ptrace anti-debugging"),
        (r"IsDebuggerPresent", "Windows debugger detection"),
        (r"CheckRemoteDebuggerPresent", "Remote debugger detection"),
        (r"NtQueryInformationProcess", "Process info query"),
        (r"getppid", "Parent process check"),
        (r"SIGTRAP", "Signal-based anti-debug"),
        (r"int\s+3", "INT3 breakpoint"),
        (r"0xCC", "INT3 opcode"),
        (r"rdtsc", "Timing-based anti-debug"),
    ]

    # Interesting function patterns
    INTERESTING_FUNCS: ClassVar[list[str]] = [
        "main",
        "check",
        "verify",
        "validate",
        "encrypt",
        "decrypt",
        "flag",
        "win",
        "secret",
        "password",
        "key",
        "auth",
        "login",
        "strcmp",
        "strncmp",
        "memcmp",
        "hash",
        "xor",
        "base64",
    ]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a reverse engineering challenge.

        Args:
            path: Path to binary file or directory

        Returns:
            SkillResult with reversing analysis
        """
        analysis: dict[str, Any] = {
            "binary_type": None,
            "file_info": {},
            "architecture": None,
            "anti_debug": [],
            "interesting_functions": [],
            "interesting_strings": [],
            "imports": [],
            "exports": [],
            "sections": [],
            "entry_point": None,
        }
        tool_results: list[ToolResult] = []
        suggestions: list[str] = []
        artifacts: list[Path] = []

        # Handle directory vs file
        if path.is_dir():
            files = [f for f in path.iterdir() if f.is_file() and not f.name.startswith(".")]
            # Filter to executables
            files = [f for f in files if self._is_executable(f)]
        else:
            files = [path]

        if not files:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis=analysis,
                suggestions=["No executable files found to analyze"],
                confidence=0.0,
            )

        # Analyze primary binary
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

    def _is_executable(self, path: Path) -> bool:
        """Check if file is an executable."""
        suffix = path.suffix.lower()

        # Check known extensions
        for extensions in self.BINARY_TYPES.values():
            if suffix in extensions:
                return True

        # Check magic bytes
        try:
            with path.open("rb") as f:
                magic = f.read(4)
                # ELF
                if magic == b"\x7fELF":
                    return True
                # PE
                if magic[:2] == b"MZ":
                    return True
                # Mach-O
                if magic in [b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce"]:
                    return True
                # Java class
                if magic == b"\xca\xfe\xba\xbe":
                    return True
                # Python bytecode
                if len(magic) >= 2 and magic[2:4] == b"\r\n":
                    return True
        except OSError:
            pass

        return False

    def _analyze_binary(self, path: Path) -> dict[str, Any]:
        """Analyze a single binary file."""
        binary_analysis: dict[str, Any] = {
            "path": str(path),
            "binary_type": None,
            "file_info": {},
            "architecture": None,
            "anti_debug": [],
            "interesting_functions": [],
            "interesting_strings": [],
            "imports": [],
            "exports": [],
            "sections": [],
            "entry_point": None,
            "tool_results": [],
        }

        # Get file info
        try:
            file_info: FileInfo = detect_file_type(path)
            binary_analysis["file_info"] = {
                "name": file_info.name,
                "size": file_info.size,
                "file_type": file_info.file_type,
            }
            binary_analysis["binary_type"] = self._detect_binary_type(path, file_info)
            binary_analysis["architecture"] = self._extract_architecture(file_info.file_type)
        except Exception:  # noqa: BLE001
            binary_analysis["file_info"] = {"name": path.name}

        # Run strings analysis
        strings_tool = self.get_tool("strings")
        if strings_tool and strings_tool.is_installed:
            result = strings_tool.run(path)
            binary_analysis["tool_results"].append(result)
            if result.parsed_data:
                binary_analysis["interesting_strings"] = result.parsed_data.get(
                    "interesting_strings", []
                )[:30]

            # Check for anti-debugging indicators
            if result.stdout:
                binary_analysis["anti_debug"] = self._find_anti_debug(result.stdout)

        # Get imports and interesting functions
        binary_analysis["imports"] = self._get_imports(path)
        binary_analysis["interesting_functions"] = self._find_interesting_functions(path)
        binary_analysis["sections"] = self._get_sections(path)

        # Use radare2 for deeper analysis if available
        radare2 = self.get_tool("radare2")
        if radare2 and radare2.is_installed:
            result = radare2.run(path, commands=["aaa", "afl", "ie"])
            binary_analysis["tool_results"].append(result)
            if result.parsed_data:
                binary_analysis["entry_point"] = result.parsed_data.get("entry_point")
                funcs = result.parsed_data.get("functions", [])
                binary_analysis["interesting_functions"].extend(funcs[:20])

        return binary_analysis

    def _detect_binary_type(self, path: Path, file_info: FileInfo) -> str:
        """Detect the type of binary."""
        suffix = path.suffix.lower()
        file_type_lower = file_info.file_type.lower()

        if "elf" in file_type_lower:
            return "elf"
        if "pe32" in file_type_lower or "windows" in file_type_lower:
            return "pe"
        if "mach-o" in file_type_lower:
            return "macho"

        # Check by extension
        for binary_type, extensions in self.BINARY_TYPES.items():
            if suffix in extensions:
                return binary_type

        return "unknown"

    def _extract_architecture(self, file_type: str) -> str:
        """Extract architecture from file type."""
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

    def _find_anti_debug(self, strings_output: str) -> list[dict[str, str]]:
        """Find anti-debugging indicators in strings."""
        anti_debug: list[dict[str, str]] = []

        for pattern, description in self.ANTI_DEBUG_PATTERNS:
            if re.search(pattern, strings_output, re.IGNORECASE):
                anti_debug.append(
                    {
                        "pattern": pattern,
                        "description": description,
                    }
                )

        return anti_debug

    def _get_imports(self, path: Path) -> list[str]:
        """Get imported functions from binary."""
        imports: list[str] = []

        try:
            import subprocess  # nosec B404

            # Try objdump for ELF
            result = subprocess.run(  # nosec B603
                ["objdump", "-T", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "*UND*" in line:  # Undefined = imported
                        parts = line.split()
                        if parts:
                            imports.append(parts[-1])
        except Exception:  # noqa: BLE001
            pass

        return imports[:50]

    def _find_interesting_functions(self, path: Path) -> list[str]:
        """Find interesting functions in the binary."""
        interesting: list[str] = []

        try:
            import subprocess  # nosec B404

            # Use nm for symbols
            result = subprocess.run(  # nosec B603
                ["nm", "-C", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                result = subprocess.run(  # nosec B603
                    ["nm", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

            for line in result.stdout.split("\n"):
                line_lower = line.lower()
                for func in self.INTERESTING_FUNCS:
                    if func in line_lower:
                        interesting.append(line.strip())
                        break

        except Exception:  # noqa: BLE001
            pass

        return list(set(interesting))[:30]

    def _get_sections(self, path: Path) -> list[dict[str, Any]]:
        """Get binary sections."""
        sections: list[dict[str, Any]] = []

        try:
            import subprocess  # nosec B404

            result = subprocess.run(  # nosec B603
                ["readelf", "-S", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Parse section lines
                    if line.strip().startswith("["):
                        parts = line.split()
                        if len(parts) >= 3:
                            sections.append(
                                {
                                    "name": parts[1] if len(parts) > 1 else "",
                                    "type": parts[2] if len(parts) > 2 else "",
                                }
                            )

        except Exception:  # noqa: BLE001
            pass

        return sections[:20]

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on analysis."""
        suggestions: list[str] = []
        binary_type = analysis.get("binary_type")
        arch = analysis.get("architecture")
        anti_debug = analysis.get("anti_debug", [])

        # Binary type suggestions
        if binary_type == "elf":
            suggestions.append("ELF binary - use Ghidra or IDA for decompilation")
            suggestions.append("Try: r2 -A binary; afl; pdf @ main")
        elif binary_type == "pe":
            suggestions.append("Windows PE - use IDA or x64dbg")
            suggestions.append("Check for .NET with dnSpy if IL code")
        elif binary_type == "java":
            suggestions.append("Java - decompile with jadx or cfr")
            suggestions.append("Extract with: unzip file.jar")
        elif binary_type == "python":
            suggestions.append("Python bytecode - decompile with uncompyle6 or pycdc")
        elif binary_type == "android":
            suggestions.append("Android APK - use jadx or apktool")
            suggestions.append("Extract: apktool d file.apk")

        # Anti-debugging suggestions
        if anti_debug:
            suggestions.append("Anti-debugging detected! Patches needed:")
            for ad in anti_debug[:3]:
                suggestions.append(f"  - Bypass {ad['description']}")

        # Architecture suggestions
        if arch == "x86_64":
            suggestions.append("64-bit - check registers: rdi, rsi, rdx for arguments")
        elif arch == "x86":
            suggestions.append("32-bit - arguments on stack")

        # Interesting functions
        funcs = analysis.get("interesting_functions", [])
        if funcs:
            check_funcs = [
                f for f in funcs if any(k in f.lower() for k in ["check", "verify", "validate"])
            ]
            if check_funcs:
                suggestions.append("Validation functions found - analyze input checking logic")

            win_funcs = [f for f in funcs if any(k in f.lower() for k in ["win", "flag", "secret"])]
            if win_funcs:
                suggestions.append("Win/flag function found - find path to reach it")

        # String suggestions
        strings = analysis.get("interesting_strings", [])
        if strings:
            suggestions.append(
                f"Found {len(strings)} interesting strings - look for hardcoded keys/passwords"
            )

        if not suggestions:
            suggestions = [
                "Load in Ghidra or IDA for static analysis",
                "Run ltrace/strace to trace library calls",
                "Use gdb for dynamic analysis",
            ]

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []
        binary_type = analysis.get("binary_type", "unknown")

        steps.append("Run the binary to understand expected behavior")
        steps.append("Load in disassembler/decompiler (Ghidra, IDA)")
        steps.append("Find main() or entry point")

        if analysis.get("anti_debug"):
            steps.append("Identify and patch anti-debugging checks")

        if binary_type == "elf":
            steps.extend(
                [
                    "Analyze main function logic",
                    "Trace interesting function calls",
                    "Identify algorithm (XOR, custom crypto, etc.)",
                ]
            )
        elif binary_type in ["java", "python", "android"]:
            steps.extend(
                [
                    "Decompile to source code",
                    "Analyze main class/function",
                    "Look for obfuscation and deobfuscate",
                ]
            )

        steps.extend(
            [
                "Understand the validation/check logic",
                "Write keygen or patch binary",
            ]
        )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        if analysis.get("binary_type") and analysis["binary_type"] != "unknown":
            confidence += 0.2

        if analysis.get("architecture") and analysis["architecture"] != "unknown":
            confidence += 0.1

        if analysis.get("interesting_functions"):
            confidence += 0.2

        if analysis.get("interesting_strings"):
            confidence += 0.15

        if analysis.get("imports"):
            confidence += 0.15

        if analysis.get("sections"):
            confidence += 0.1

        if analysis.get("anti_debug"):
            confidence += 0.1  # Knowing about anti-debug is valuable

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def decompile(self, path: Path, function: str | None = None) -> SkillResult:
        """Decompile a binary or specific function."""
        radare2 = self.get_tool("radare2")
        if radare2 and radare2.is_installed:
            commands = ["aaa"]
            if function:
                commands.append(f"s {function}")
                commands.append("pdc")
            else:
                commands.append("pdc @ main")

            result = radare2.run(path, commands=commands)
            return SkillResult(
                success=result.success,
                skill_name=self.name,
                analysis={"decompiled": result.stdout},
                tool_results=[result],
            )

        return SkillResult(
            success=False,
            skill_name=self.name,
            analysis={"error": "No decompiler available"},
            suggestions=["Install radare2 or use Ghidra manually"],
        )
