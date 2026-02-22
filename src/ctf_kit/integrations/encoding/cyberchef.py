"""
CyberChef-like encoding/decoding wrapper for CTF Kit.

Implements common data transformation operations in pure Python,
providing CyberChef-like encoding chains without external dependencies.
"""

import base64
import binascii
import codecs
import html
from typing import Any, ClassVar
import urllib.parse

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)

# Supported operations for reference
SUPPORTED_OPERATIONS = [
    "base64_encode",
    "base64_decode",
    "base32_encode",
    "base32_decode",
    "base85_encode",
    "base85_decode",
    "hex_encode",
    "hex_decode",
    "url_encode",
    "url_decode",
    "html_encode",
    "html_decode",
    "rot13",
    "rot_n",
    "reverse",
    "xor",
    "atbash",
    "morse_decode",
    "morse_encode",
    "binary_to_text",
    "text_to_binary",
    "decimal_to_text",
]


@register_tool
class CyberChefTool(BaseTool):
    """
    CyberChef-like data transformation tool.

    Implements common encoding/decoding operations in pure Python.
    No external binary required.
    """

    name: ClassVar[str] = "cyberchef"
    description: ClassVar[str] = "Data encoding/decoding transformations"
    category: ClassVar[ToolCategory] = ToolCategory.ENCODING
    binary_names: ClassVar[list[str]] = []  # Pure Python implementation
    install_commands: ClassVar[dict[str, str]] = {}

    @property
    def is_installed(self) -> bool:
        """Always available - pure Python implementation."""
        return True

    def run(
        self,
        data: str | bytes,
        operation: str = "magic",
        key: str | bytes | None = None,
        n: int | None = None,
        timeout: int = 30,  # noqa: ARG002
    ) -> ToolResult:
        """
        Apply a single transformation operation.

        Args:
            data: Input data (string or bytes)
            operation: Operation name (see SUPPORTED_OPERATIONS)
            key: Key for XOR or other keyed operations
            n: Rotation amount for rot_n
            timeout: Timeout in seconds

        Returns:
            ToolResult with transformed data
        """
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        try:
            result_data = self._apply_operation(data_bytes, operation, key=key, n=n)
            output = self._safe_decode(result_data)

            return ToolResult(
                success=True,
                tool_name=self.name,
                command=f"cyberchef {operation}",
                stdout=output,
                stderr="",
                parsed_data={
                    "operation": operation,
                    "input_length": len(data_bytes),
                    "output_length": len(result_data),
                    "output_bytes": result_data,
                },
            )
        except Exception as e:  # noqa: BLE001
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=f"cyberchef {operation}",
                stdout="",
                stderr="",
                error_message=f"Operation '{operation}' failed: {e}",
            )

    def decode_chain(
        self,
        data: str | bytes,
        operations: list[str],
    ) -> ToolResult:
        """
        Apply a chain of decode operations sequentially.

        Args:
            data: Input data
            operations: List of operation names to apply in order

        Returns:
            ToolResult with final decoded data and step details
        """
        if isinstance(data, str):
            current = data.encode("utf-8")
        else:
            current = data

        steps: list[dict[str, Any]] = []

        for op in operations:
            try:
                result = self._apply_operation(current, op)
                steps.append(
                    {
                        "operation": op,
                        "input_length": len(current),
                        "output_length": len(result),
                        "output_preview": self._safe_decode(result[:100]),
                    }
                )
                current = result
            except Exception as e:  # noqa: BLE001
                steps.append({"operation": op, "error": str(e)})
                return ToolResult(
                    success=False,
                    tool_name=self.name,
                    command=f"decode_chain: {' -> '.join(operations)}",
                    stdout="",
                    stderr="",
                    parsed_data={"steps": steps, "failed_at": op},
                    error_message=f"Chain failed at '{op}': {e}",
                )

        output = self._safe_decode(current)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"decode_chain: {' -> '.join(operations)}",
            stdout=output,
            stderr="",
            parsed_data={
                "steps": steps,
                "final_output": output,
                "final_bytes": current,
            },
            suggestions=self._check_for_flags(output),
        )

    def magic(self, data: str | bytes) -> ToolResult:
        """
        Auto-detect and attempt all decodings on the input data.

        Tries common encodings and reports which ones produce valid output.
        """
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        decodings: list[dict[str, Any]] = []

        attempts = [
            ("base64_decode", "Base64"),
            ("base32_decode", "Base32"),
            ("base85_decode", "Base85"),
            ("hex_decode", "Hex"),
            ("url_decode", "URL"),
            ("html_decode", "HTML entities"),
            ("rot13", "ROT13"),
            ("reverse", "Reversed"),
            ("binary_to_text", "Binary"),
            ("decimal_to_text", "Decimal"),
            ("morse_decode", "Morse code"),
        ]

        for op, label in attempts:
            try:
                decoded = self._apply_operation(data_bytes, op)
                if decoded and decoded != data_bytes:
                    output = self._safe_decode(decoded)
                    # Filter out garbage results
                    if self._looks_meaningful(output):
                        decodings.append(
                            {
                                "encoding": label,
                                "operation": op,
                                "decoded": output[:200],
                                "has_flag": self._contains_flag(output),
                            }
                        )
            except Exception:  # noqa: BLE001
                pass

        suggestions: list[str] = []
        if decodings:
            suggestions.append(f"Found {len(decodings)} possible decodings")
            for d in decodings:
                prefix = "[FLAG!] " if d["has_flag"] else ""
                suggestions.append(f"{prefix}{d['encoding']}: {d['decoded'][:80]}")
        else:
            suggestions.append("No standard encodings detected")
            suggestions.append("Try XOR with common keys or custom operations")

        return ToolResult(
            success=len(decodings) > 0,
            tool_name=self.name,
            command="magic decode",
            stdout=str(decodings),
            stderr="",
            parsed_data={"decodings": decodings},
            suggestions=suggestions,
        )

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse output (identity for this tool since we construct results directly)."""
        return {"raw_stdout": stdout, "raw_stderr": stderr}

    def _apply_operation(
        self,
        data: bytes,
        operation: str,
        key: str | bytes | None = None,
        n: int | None = None,
    ) -> bytes:
        """Apply a single transformation operation."""
        ops: dict[str, Any] = {
            "base64_encode": base64.b64encode,
            "base64_decode": lambda d: base64.b64decode(d, validate=True),
            "base32_encode": base64.b32encode,
            "base32_decode": base64.b32decode,
            "base85_encode": base64.b85encode,
            "base85_decode": base64.b85decode,
            "hex_encode": binascii.hexlify,
            "hex_decode": lambda d: bytes.fromhex(d.decode().strip()),
            "url_encode": lambda d: urllib.parse.quote(d.decode()).encode(),
            "url_decode": lambda d: urllib.parse.unquote(d.decode()).encode(),
            "html_encode": lambda d: html.escape(d.decode()).encode(),
            "html_decode": lambda d: html.unescape(d.decode()).encode(),
            "rot13": lambda d: codecs.decode(d.decode(), "rot_13").encode(),
            "reverse": lambda d: d[::-1],
            "binary_to_text": self._binary_to_text,
            "text_to_binary": self._text_to_binary,
            "decimal_to_text": self._decimal_to_text,
            "morse_decode": self._morse_decode,
            "morse_encode": self._morse_encode,
            "atbash": self._atbash,
        }

        if operation == "rot_n":
            return self._rot_n(data, n or 13)
        if operation == "xor":
            return self._xor(data, key or b"\x00")

        if operation not in ops:
            msg = f"Unknown operation: {operation}"
            raise ValueError(msg)

        return ops[operation](data)

    def _xor(self, data: bytes, key: str | bytes) -> bytes:
        """XOR data with a repeating key."""
        if isinstance(key, str):
            key = key.encode("utf-8")
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def _rot_n(self, data: bytes, n: int) -> bytes:
        """Rotate letters by n positions."""
        text = data.decode("utf-8")
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base + n) % 26 + base))
            else:
                result.append(ch)
        return "".join(result).encode("utf-8")

    def _atbash(self, data: bytes) -> bytes:
        """Atbash cipher (reverse alphabet)."""
        text = data.decode("utf-8")
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr(25 - (ord(ch) - base) + base))
            else:
                result.append(ch)
        return "".join(result).encode("utf-8")

    def _binary_to_text(self, data: bytes) -> bytes:
        """Convert binary string (e.g., '01001000 01101001') to text."""
        text = data.decode("utf-8").strip()
        bits = text.replace(" ", "").replace("\n", "")
        if len(bits) % 8 != 0:
            msg = "Binary string length must be a multiple of 8"
            raise ValueError(msg)
        chars = [chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8)]
        return "".join(chars).encode("utf-8")

    def _text_to_binary(self, data: bytes) -> bytes:
        """Convert text to binary string."""
        text = data.decode("utf-8")
        return " ".join(f"{ord(c):08b}" for c in text).encode("utf-8")

    def _decimal_to_text(self, data: bytes) -> bytes:
        """Convert space-separated decimal values to text."""
        text = data.decode("utf-8").strip()
        parts = text.split()
        chars = [chr(int(p)) for p in parts if p.isdigit()]
        return "".join(chars).encode("utf-8")

    _MORSE_CODE: ClassVar[dict[str, str]] = {
        ".-": "A",
        "-...": "B",
        "-.-.": "C",
        "-..": "D",
        ".": "E",
        "..-.": "F",
        "--.": "G",
        "....": "H",
        "..": "I",
        ".---": "J",
        "-.-": "K",
        ".-..": "L",
        "--": "M",
        "-.": "N",
        "---": "O",
        ".--.": "P",
        "--.-": "Q",
        ".-.": "R",
        "...": "S",
        "-": "T",
        "..-": "U",
        "...-": "V",
        ".--": "W",
        "-..-": "X",
        "-.--": "Y",
        "--..": "Z",
        "-----": "0",
        ".----": "1",
        "..---": "2",
        "...--": "3",
        "....-": "4",
        ".....": "5",
        "-....": "6",
        "--...": "7",
        "---..": "8",
        "----.": "9",
    }

    _MORSE_ENCODE_MAP: ClassVar[dict[str, str]] = {}  # Built at class level below

    def _morse_decode(self, data: bytes) -> bytes:
        """Decode Morse code to text."""
        text = data.decode("utf-8").strip()
        # Handle word separation (/ or multiple spaces)
        words = text.replace("/", "  ").split("  ")
        decoded_words = []
        for word in words:
            letters = word.strip().split(" ")
            decoded = "".join(
                self._MORSE_CODE.get(letter.strip(), "?") for letter in letters if letter.strip()
            )
            decoded_words.append(decoded)
        return " ".join(decoded_words).encode("utf-8")

    def _morse_encode(self, data: bytes) -> bytes:
        """Encode text to Morse code."""
        encode_map = {v: k for k, v in self._MORSE_CODE.items()}
        text = data.decode("utf-8").upper().strip()
        result = []
        for ch in text:
            if ch == " ":
                result.append("/")
            elif ch in encode_map:
                result.append(encode_map[ch])
        return " ".join(result).encode("utf-8")

    def _safe_decode(self, data: bytes) -> str:
        """Safely decode bytes to string."""
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")

    def _looks_meaningful(self, text: str) -> bool:
        """Check if decoded text looks like it could be meaningful."""
        if not text or len(text) < 2:
            return False
        # Count printable ASCII characters
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        ratio = printable / len(text) if text else 0
        return ratio > 0.7

    def _contains_flag(self, text: str) -> bool:
        """Check if text contains a CTF flag pattern."""
        import re

        flag_patterns = [
            r"flag\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"ctf\{[^}]+\}",
        ]
        return any(re.search(p, text) for p in flag_patterns)

    def _check_for_flags(self, text: str) -> list[str]:
        """Check for flag patterns and return suggestions."""
        import re

        suggestions: list[str] = []
        for pattern in [r"(flag\{[^}]+\})", r"(CTF\{[^}]+\})", r"(FLAG\{[^}]+\})"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                suggestions.append(f"Flag found: {match}")
        return suggestions
