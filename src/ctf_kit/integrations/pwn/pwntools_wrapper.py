"""
pwntools wrapper for CTF Kit.

pwntools is a CTF framework and exploit development library providing
binary analysis, ROP chain building, shellcode generation, and more.

Unlike other tools, pwntools is a Python library rather than a CLI binary.
"""

from pathlib import Path
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)


@register_tool
class PwntoolsTool(BaseTool):
    """
    Wrapper for the 'pwntools' Python library.

    Provides binary analysis, ROP gadget finding, cyclic pattern
    generation, and exploit template creation for CTF challenges.
    """

    name: ClassVar[str] = "pwntools"
    description: ClassVar[str] = "Exploit development framework"
    category: ClassVar[ToolCategory] = ToolCategory.PWN
    binary_names: ClassVar[list[str]] = []  # Python library, no binary
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install pwntools",
        "linux": "pip install pwntools",
        "windows": "pip install pwntools (limited support)",
    }

    @property
    def is_installed(self) -> bool:
        """Check if pwntools is importable."""
        try:
            import pwn  # noqa: F401
        except ImportError:
            return False
        else:
            return True

    def run(
        self,
        binary_path: Path | str,
        action: str = "checksec",
        pattern_length: int | None = None,
        crash_value: int | None = None,
        timeout: int = 60,  # noqa: ARG002
    ) -> ToolResult:
        """
        Run a pwntools operation.

        Args:
            binary_path: Path to binary file (for checksec/gadgets)
            action: Operation to perform (checksec, gadgets, cyclic, find_offset)
            pattern_length: Length for cyclic pattern generation
            crash_value: Crash value for offset finding
            timeout: Timeout in seconds

        Returns:
            ToolResult with analysis data
        """
        if action == "checksec":
            return self.checksec(binary_path)
        if action == "gadgets":
            return self.find_gadgets(binary_path)
        if action == "cyclic" and pattern_length:
            return self.create_cyclic_pattern(pattern_length)
        if action == "find_offset" and crash_value is not None:
            return self.find_offset(crash_value)

        return ToolResult(
            success=False,
            tool_name=self.name,
            command=f"pwntools {action}",
            stdout="",
            stderr="",
            error_message=f"Unknown action: {action}. Use: checksec, gadgets, cyclic, find_offset",
        )

    def checksec(self, binary_path: Path | str) -> ToolResult:
        """Check binary security properties using pwntools ELF."""
        if not self.is_installed:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"checksec {binary_path}",
                stdout="",
                stderr="",
                error_message=f"pwntools is not installed. Install with: {self.get_install_command()}",
            )

        try:
            from pwn import ELF

            elf = ELF(str(binary_path), checksec=False)

            security: dict[str, Any] = {
                "arch": elf.arch,
                "bits": elf.bits,
                "endian": elf.endian,
                "canary": elf.canary,
                "nx": elf.nx,
                "pie": elf.pie,
                "relro": elf.relro,
                "rpath": bool(elf.rpath),
                "runpath": bool(elf.runpath),
            }

            suggestions = self._get_checksec_suggestions(security)

            return ToolResult(
                success=True,
                tool_name=self.name,
                command=f"checksec {binary_path}",
                stdout=str(security),
                stderr="",
                parsed_data=security,
                suggestions=suggestions,
            )

        except Exception as e:  # noqa: BLE001
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"checksec {binary_path}",
                stdout="",
                stderr="",
                error_message=str(e),
            )

    def find_gadgets(self, binary_path: Path | str) -> ToolResult:
        """Find common ROP gadgets using pwntools."""
        if not self.is_installed:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"find_gadgets {binary_path}",
                stdout="",
                stderr="",
                error_message=f"pwntools is not installed. Install with: {self.get_install_command()}",
            )

        try:
            from pwn import ELF, ROP

            elf = ELF(str(binary_path), checksec=False)
            rop = ROP(elf)

            gadgets: dict[str, str | None] = {
                "pop_rdi": None,
                "pop_rsi": None,
                "pop_rdx": None,
                "pop_rax": None,
                "ret": None,
                "syscall": None,
                "leave_ret": None,
            }

            gadget_searches = {
                "pop_rdi": ["pop rdi", "ret"],
                "pop_rsi": ["pop rsi", "ret"],
                "pop_rdx": ["pop rdx", "ret"],
                "pop_rax": ["pop rax", "ret"],
                "ret": ["ret"],
                "syscall": ["syscall"],
                "leave_ret": ["leave", "ret"],
            }

            for name, instructions in gadget_searches.items():
                try:
                    addr = rop.find_gadget(instructions)
                    if addr:
                        gadgets[name] = hex(addr[0])
                except (ValueError, IndexError):
                    pass

            found = {k: v for k, v in gadgets.items() if v is not None}
            suggestions = [f"Found {len(found)} ROP gadgets"]
            if found.get("pop_rdi"):
                suggestions.append(
                    f"pop rdi; ret at {found['pop_rdi']} - useful for calling functions with arguments"
                )
            if found.get("ret"):
                suggestions.append(f"ret at {found['ret']} - useful for stack alignment")

            return ToolResult(
                success=True,
                tool_name=self.name,
                command=f"find_gadgets {binary_path}",
                stdout=str(gadgets),
                stderr="",
                parsed_data={"gadgets": gadgets, "found_count": len(found)},
                suggestions=suggestions,
            )

        except Exception as e:  # noqa: BLE001
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"find_gadgets {binary_path}",
                stdout="",
                stderr="",
                error_message=str(e),
            )

    def create_cyclic_pattern(self, length: int) -> ToolResult:
        """Generate a cyclic pattern for finding buffer overflow offsets."""
        if not self.is_installed:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"cyclic({length})",
                stdout="",
                stderr="",
                error_message=f"pwntools is not installed. Install with: {self.get_install_command()}",
            )

        try:
            from pwn import cyclic

            pattern = cyclic(length)

            return ToolResult(
                success=True,
                tool_name=self.name,
                command=f"cyclic({length})",
                stdout=pattern.decode("latin-1"),
                stderr="",
                parsed_data={"pattern_length": length},
                suggestions=[
                    f"Generated {length}-byte cyclic pattern",
                    "Send this pattern to the binary and note the crash value",
                    "Use find_offset with the crash value to determine the offset",
                ],
            )

        except Exception as e:  # noqa: BLE001
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"cyclic({length})",
                stdout="",
                stderr="",
                error_message=str(e),
            )

    def find_offset(self, crash_value: int) -> ToolResult:
        """Find the offset in a cyclic pattern from a crash value."""
        if not self.is_installed:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"cyclic_find({hex(crash_value)})",
                stdout="",
                stderr="",
                error_message=f"pwntools is not installed. Install with: {self.get_install_command()}",
            )

        try:
            from pwn import cyclic_find

            offset = cyclic_find(crash_value)

            return ToolResult(
                success=offset != -1,
                tool_name=self.name,
                command=f"cyclic_find({hex(crash_value)})",
                stdout=str(offset),
                stderr="",
                parsed_data={"offset": offset, "crash_value": hex(crash_value)},
                suggestions=[
                    f"Buffer overflow offset: {offset} bytes"
                    if offset != -1
                    else "Offset not found - crash value may not be from a cyclic pattern",
                ],
            )

        except Exception as e:  # noqa: BLE001
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"cyclic_find({hex(crash_value)})",
                stdout="",
                stderr="",
                error_message=str(e),
            )

    def generate_exploit_template(
        self,
        binary_path: Path | str,
        vuln_type: str = "buffer_overflow",
        offset: int | None = None,
    ) -> str:
        """
        Generate an exploit template script.

        Args:
            binary_path: Path to the target binary
            vuln_type: Type of vulnerability (buffer_overflow, format_string, ret2libc)
            offset: Buffer overflow offset if known

        Returns:
            Python exploit script as a string
        """
        template = f"""#!/usr/bin/env python3
from pwn import *

# Binary setup
binary_path = "{binary_path}"
elf = ELF(binary_path)
context.binary = elf
context.log_level = "info"

# Remote connection (update as needed)
# HOST = "challenge.ctf.com"
# PORT = 1337

def exploit():
    # p = remote(HOST, PORT)
    p = process(binary_path)

"""

        if vuln_type == "buffer_overflow":
            offset_val = offset if offset else "OFFSET"
            template += f"""    # Buffer overflow exploit
    offset = {offset_val}

    # Build payload
    payload = b"A" * offset
    # payload += p64(elf.symbols["win"])  # Overwrite return address

    p.sendline(payload)
    p.interactive()
"""
        elif vuln_type == "format_string":
            template += """    # Format string exploit
    # Leak addresses
    payload = b"%p." * 20
    p.sendline(payload)
    leaks = p.recvline()
    print(f"Leaks: {leaks}")

    p.interactive()
"""
        elif vuln_type == "ret2libc":
            template += """    # ret2libc exploit
    # Leak libc address
    rop = ROP(elf)
    # rop.call("puts", [elf.got["puts"]])
    # rop.call(elf.symbols["main"])

    # payload = b"A" * OFFSET + rop.chain()
    # p.sendline(payload)

    p.interactive()
"""

        template += """

if __name__ == "__main__":
    exploit()
"""
        return template

    def _get_checksec_suggestions(self, security: dict[str, Any]) -> list[str]:
        """Get exploit suggestions based on security properties."""
        suggestions: list[str] = []

        if not security.get("canary"):
            suggestions.append("No stack canary - buffer overflows are exploitable")
        else:
            suggestions.append("Stack canary present - need leak or brute force to bypass")

        if not security.get("nx"):
            suggestions.append("NX disabled - shellcode injection possible")
        else:
            suggestions.append("NX enabled - use ROP/ret2libc instead of shellcode")

        if not security.get("pie"):
            suggestions.append("No PIE - addresses are fixed, easier for ROP")
        else:
            suggestions.append("PIE enabled - need address leak to defeat ASLR")

        relro = security.get("relro")
        if relro == "Partial" or not relro:
            suggestions.append("Partial/No RELRO - GOT overwrite possible")
        elif relro == "Full":
            suggestions.append("Full RELRO - GOT is read-only")

        return suggestions
