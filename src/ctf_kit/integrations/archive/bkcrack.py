"""
bkcrack wrapper for CTF Kit.

bkcrack cracks legacy ZIP encryption (ZipCrypto) using known-plaintext attacks.
Requires at least 12 bytes of known plaintext to recover internal keys.
"""

from pathlib import Path
import re
import tempfile
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)

# Common file headers useful as known plaintext
KNOWN_HEADERS: dict[str, bytes] = {
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "pdf": b"%PDF-1.",
    "zip": b"PK\x03\x04",
    "gzip": b"\x1f\x8b\x08",
    "xml": b'<?xml version="1.0"',
    "html": b"<!DOCTYPE html>",
    "elf": b"\x7fELF",
}


@register_tool
class BkcrackTool(BaseTool):
    """
    Wrapper for the 'bkcrack' command.

    bkcrack performs known-plaintext attacks on legacy ZIP encryption
    (ZipCrypto) to recover internal encryption keys.
    """

    name: ClassVar[str] = "bkcrack"
    description: ClassVar[str] = "ZIP known-plaintext attack (ZipCrypto)"
    category: ClassVar[ToolCategory] = ToolCategory.ARCHIVE
    binary_names: ClassVar[list[str]] = ["bkcrack"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install bkcrack",
        "linux": (
            "git clone https://github.com/kimci86/bkcrack && "
            "cd bkcrack && cmake -S . -B build && "
            "cmake --build build && "
            "sudo cp build/src/bkcrack /usr/local/bin/"
        ),
        "windows": "Download from https://github.com/kimci86/bkcrack/releases",
    }

    def run(  # noqa: PLR0913
        self,
        cipher_zip: Path | str,
        cipher_entry: str | None = None,
        plain_file: Path | str | None = None,
        plain_zip: Path | str | None = None,
        plain_entry: str | None = None,
        plaintext_bytes: bytes | None = None,
        offset: int = 0,
        keys: tuple[int, int, int] | None = None,
        output_zip: Path | str | None = None,
        list_entries: bool = False,
        recover_password: bool = False,
        max_length: int = 10,
        timeout: int = 7200,
    ) -> ToolResult:
        """
        Run bkcrack with the specified operation.

        Args:
            cipher_zip: Path to encrypted ZIP file
            cipher_entry: Entry name within the encrypted ZIP
            plain_file: Path to known plaintext file
            plain_zip: Path to ZIP containing known plaintext
            plain_entry: Entry name within the plaintext ZIP
            plaintext_bytes: Raw known plaintext bytes
            offset: Offset of plaintext within the encrypted entry
            keys: Recovered internal keys (key0, key1, key2)
            output_zip: Path for decrypted output ZIP
            list_entries: List ZIP entries with encryption info
            recover_password: Attempt to recover password from keys
            max_length: Max password length for recovery
            timeout: Timeout in seconds (default 2h for attacks)

        Returns:
            ToolResult with attack results
        """
        args: list[str] = []

        if list_entries:
            args.extend(["-L", str(cipher_zip)])
            result = self._run_with_result(args, timeout=30)
            if result.success:
                result.parsed_data = self._parse_list_output(result.stdout)
                result.suggestions = self._get_list_suggestions(result.parsed_data)
            return result

        if keys and output_zip:
            # Decrypt with known keys
            args.extend(
                [
                    "-C",
                    str(cipher_zip),
                    "-k",
                    hex(keys[0]),
                    hex(keys[1]),
                    hex(keys[2]),
                    "-D",
                    str(output_zip),
                ]
            )
            result = self._run_with_result(args, timeout=60)
            output_path = Path(output_zip)
            if output_path.exists():
                result.artifacts = [output_path]
                result.success = True
            return result

        if keys and recover_password:
            # Recover password from keys
            args.extend(
                [
                    "-k",
                    hex(keys[0]),
                    hex(keys[1]),
                    hex(keys[2]),
                    "-r",
                    str(max_length),
                    "?a",
                ]
            )
            result = self._run_with_result(args, timeout=3600)
            if result.success:
                result.parsed_data = self._parse_password_output(result.stdout)
            return result

        # Known-plaintext attack
        args.extend(["-C", str(cipher_zip)])
        if cipher_entry:
            args.extend(["-c", cipher_entry])

        if plain_zip:
            args.extend(["-P", str(plain_zip)])
            if plain_entry:
                args.extend(["-p", plain_entry])
        elif plain_file:
            args.extend(["-p", str(plain_file)])
        elif plaintext_bytes is not None:
            # Write plaintext bytes to temp file
            tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
                delete=False, suffix=".bin"
            )
            tmp.write(plaintext_bytes)
            tmp.close()
            args.extend(["-p", tmp.name])

        if offset:
            args.extend(["-o", str(offset)])

        result = self._run_with_result(args, timeout=timeout)
        if result.parsed_data is None:
            result.parsed_data = {}
        attack_data = self._parse_attack_output(result.stdout)
        result.parsed_data.update(attack_data)
        if attack_data.get("keys"):
            result.success = True
        result.suggestions = self._get_attack_suggestions(result.parsed_data)
        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse bkcrack output."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
        }

        # Check for keys in output
        attack_data = self._parse_attack_output(stdout)
        parsed.update(attack_data)

        return parsed

    def _parse_list_output(self, stdout: str) -> dict[str, Any]:
        """Parse ZIP entry listing."""
        entries: list[dict[str, Any]] = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith(("Index", "---")):
                continue
            parts = line.split()
            if len(parts) >= 2:
                entry: dict[str, Any] = {
                    "name": parts[-1],
                    "encrypted": "ZipCrypto" in line,
                }
                # Try to extract size
                for part in parts:
                    if part.isdigit():
                        entry["size"] = int(part)
                        break
                entries.append(entry)
        return {"entries": entries, "entry_count": len(entries)}

    def _parse_attack_output(self, stdout: str) -> dict[str, Any]:
        """Parse attack output for recovered keys."""
        result: dict[str, Any] = {"keys": None, "key_found": False}

        key_pattern = re.compile(r"Keys:\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)")
        match = key_pattern.search(stdout)
        if match:
            result["keys"] = (
                int(match.group(1), 16),
                int(match.group(2), 16),
                int(match.group(3), 16),
            )
            result["key_found"] = True

        return result

    def _parse_password_output(self, stdout: str) -> dict[str, Any]:
        """Parse password recovery output."""
        result: dict[str, Any] = {"password": None, "password_found": False}

        password_pattern = re.compile(r"Password:\s*(.+)")
        match = password_pattern.search(stdout)
        if match:
            result["password"] = match.group(1).strip()
            result["password_found"] = True

        return result

    def _get_list_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions after listing entries."""
        suggestions: list[str] = []
        entries = parsed_data.get("entries", [])
        encrypted = [e for e in entries if e.get("encrypted")]

        if encrypted:
            suggestions.append(f"Found {len(encrypted)} encrypted entries using ZipCrypto")
            suggestions.append(
                "Identify files with known headers (PNG, PDF, XML) for plaintext attack"
            )
            suggestions.append("Need at least 12 bytes of known plaintext for successful attack")
        else:
            suggestions.append("No ZipCrypto-encrypted entries found")
            suggestions.append("bkcrack only works on legacy ZipCrypto encryption, not AES")

        return suggestions

    def _get_attack_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions after attack."""
        suggestions: list[str] = []

        if parsed_data.get("key_found"):
            suggestions.append("Internal keys recovered!")
            suggestions.append("Decrypt the archive: bkcrack -C <zip> -k <keys> -D <output.zip>")
            suggestions.append("Optionally recover password: bkcrack -k <keys> -r <max_length>")
        else:
            suggestions.append("Attack did not find keys")
            suggestions.append("Ensure at least 12 contiguous bytes of known plaintext")
            suggestions.append("Verify the correct entry name and plaintext offset")
            suggestions.append("Try common file headers: PNG (89504E47), PDF (25504446)")

        return suggestions

    def list_zip(self, zip_path: Path | str) -> ToolResult:
        """List entries in a ZIP file with encryption info."""
        return self.run(zip_path, list_entries=True)

    def attack_with_file(
        self,
        cipher_zip: Path | str,
        cipher_entry: str,
        plain_file: Path | str,
        offset: int = 0,
    ) -> ToolResult:
        """Attack using a known plaintext file."""
        return self.run(
            cipher_zip,
            cipher_entry=cipher_entry,
            plain_file=plain_file,
            offset=offset,
        )

    def attack_with_bytes(
        self,
        cipher_zip: Path | str,
        cipher_entry: str,
        plaintext: bytes,
        offset: int = 0,
    ) -> ToolResult:
        """Attack using known plaintext bytes (e.g., file headers)."""
        return self.run(
            cipher_zip,
            cipher_entry=cipher_entry,
            plaintext_bytes=plaintext,
            offset=offset,
        )

    def decrypt(
        self,
        cipher_zip: Path | str,
        keys: tuple[int, int, int],
        output_zip: Path | str,
    ) -> ToolResult:
        """Decrypt a ZIP file using recovered internal keys."""
        return self.run(cipher_zip, keys=keys, output_zip=output_zip)
