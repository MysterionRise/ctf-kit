"""
RsaCtfTool wrapper for CTF Kit.

RsaCtfTool is used to attack weak RSA keys and recover private keys/plaintexts.
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
class RsaCtfToolTool(BaseTool):
    """
    Wrapper for the 'RsaCtfTool' command.

    RsaCtfTool attacks weak RSA keys using various known attacks
    including factorization, Wiener's attack, Fermat factorization,
    and many others.
    """

    name: ClassVar[str] = "rsactftool"
    description: ClassVar[str] = "Attack weak RSA keys with multiple vulnerability checks"
    category: ClassVar[ToolCategory] = ToolCategory.CRYPTO
    binary_names: ClassVar[list[str]] = ["RsaCtfTool", "rsactftool", "RsaCtfTool.py"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install rsactftool",
        "linux": "pip install rsactftool",
        "windows": "pip install rsactftool",
    }

    def run(  # noqa: PLR0913
        self,
        *,
        n: int | str | None = None,
        e: int | str | None = None,
        c: int | str | None = None,
        p: int | str | None = None,
        q: int | str | None = None,
        d: int | str | None = None,
        key_file: Path | str | None = None,
        cipher_file: Path | str | None = None,
        uncipher: bool = False,  # noqa: ARG002
        private: bool = False,
        attack: str | None = None,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run RSA attack with given parameters.

        Args:
            n: RSA modulus
            e: RSA public exponent
            c: Ciphertext to decrypt
            p: First prime factor (if known)
            q: Second prime factor (if known)
            d: Private exponent (if known)
            key_file: Path to public key file
            cipher_file: Path to ciphertext file
            uncipher: Attempt to decrypt ciphertext
            private: Output private key
            attack: Specific attack to use
            timeout: Timeout in seconds

        Returns:
            ToolResult with attack results
        """
        args: list[str] = []

        if n is not None:
            args.extend(["-n", str(n)])

        if e is not None:
            args.extend(["-e", str(e)])

        if c is not None:
            args.extend(["--uncipher", str(c)])

        if p is not None:
            args.extend(["-p", str(p)])

        if q is not None:
            args.extend(["-q", str(q)])

        if d is not None:
            args.extend(["-d", str(d)])

        if key_file is not None:
            args.extend(["--publickey", str(key_file)])

        if cipher_file is not None:
            args.extend(["--uncipherfile", str(cipher_file)])

        if private:
            args.append("--private")

        if attack:
            args.extend(["--attack", attack])

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions based on results
        if result.success and result.parsed_data:
            result.suggestions = self._get_suggestions(result.parsed_data)

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse RsaCtfTool output into structured data."""
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "attack_used": None,
            "private_key": None,
            "plaintext": None,
            "factors": {},
        }

        # Parse attack used
        attack_match = re.search(r"Attack:\s*(\w+)", stdout)
        if attack_match:
            parsed["attack_used"] = attack_match.group(1)

        # Parse factors found
        p_match = re.search(r"p\s*[=:]\s*(\d+)", stdout)
        if p_match:
            parsed["factors"]["p"] = p_match.group(1)

        q_match = re.search(r"q\s*[=:]\s*(\d+)", stdout)
        if q_match:
            parsed["factors"]["q"] = q_match.group(1)

        d_match = re.search(r"d\s*[=:]\s*(\d+)", stdout)
        if d_match:
            parsed["factors"]["d"] = d_match.group(1)

        # Parse private key
        if "-----BEGIN RSA PRIVATE KEY-----" in stdout:
            key_match = re.search(
                r"(-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----)",
                stdout,
                re.DOTALL,
            )
            if key_match:
                parsed["private_key"] = key_match.group(1)

        # Parse plaintext
        plaintext_match = re.search(r"Unciphered data.*?:\s*(.+)", stdout, re.DOTALL)
        if plaintext_match:
            parsed["plaintext"] = plaintext_match.group(1).strip()

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on attack results."""
        suggestions: list[str] = []

        if parsed_data.get("private_key"):
            suggestions.append("Private key recovered! Use it to decrypt messages")

        if parsed_data.get("plaintext"):
            suggestions.append(f"Decrypted: {parsed_data['plaintext'][:50]}...")

        if parsed_data.get("factors"):
            suggestions.append("Factors found - key is broken")

        if parsed_data.get("attack_used"):
            suggestions.append(f"Successful attack: {parsed_data['attack_used']}")

        if not suggestions:
            suggestions = [
                "No immediate vulnerability found",
                "Try with different attacks: wiener, fermat, small_e",
                "Check if parameters are correctly extracted",
            ]

        return suggestions

    def attack_public_key(self, key_path: Path | str) -> ToolResult:
        """Attack a public key file."""
        return self.run(key_file=key_path, private=True)

    def decrypt_with_key(self, key_path: Path | str, cipher_path: Path | str) -> ToolResult:
        """Decrypt ciphertext using a public key (by breaking it first)."""
        return self.run(key_file=key_path, cipher_file=cipher_path)

    def factor_n(self, n: int | str, e: int | str = 65537) -> ToolResult:
        """Attempt to factor n."""
        return self.run(n=n, e=e, private=True)
