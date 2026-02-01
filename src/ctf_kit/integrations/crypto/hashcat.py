"""
Hashcat wrapper for CTF Kit.

Hashcat is a GPU-accelerated password cracking tool.
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
class HashcatTool(BaseTool):
    """
    Wrapper for the 'hashcat' command.

    Hashcat is a fast password cracker supporting GPU acceleration
    and many hash types.
    """

    name: ClassVar[str] = "hashcat"
    description: ClassVar[str] = "GPU-accelerated password cracking"
    category: ClassVar[ToolCategory] = ToolCategory.CRYPTO
    binary_names: ClassVar[list[str]] = ["hashcat", "hashcat64.bin", "hashcat.exe"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "brew install hashcat",
        "linux": "sudo apt install hashcat",
        "windows": "Download from https://hashcat.net/hashcat/",
    }

    # Common hash modes
    HASH_MODES: ClassVar[dict[str, int]] = {
        "md5": 0,
        "sha1": 100,
        "sha256": 1400,
        "sha512": 1700,
        "ntlm": 1000,
        "bcrypt": 3200,
        "md5crypt": 500,
        "sha256crypt": 7400,
        "sha512crypt": 1800,
        "mysql": 300,
        "mssql": 1731,
        "wordpress": 400,
        "phpass": 400,
        "wpa2": 22000,
        "kerberos": 18200,
    }

    def run(  # noqa: PLR0913
        self,
        hash_file: Path | str,
        wordlist: Path | str | None = None,
        hash_mode: int | str | None = None,
        attack_mode: int = 0,
        rules: Path | str | None = None,
        mask: str | None = None,
        outfile: Path | str | None = None,
        show: bool = False,
        force: bool = False,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Crack password hashes.

        Args:
            hash_file: File containing hashes to crack
            wordlist: Wordlist file for dictionary attack
            hash_mode: Hash type mode (0=MD5, 100=SHA1, 1000=NTLM, etc.)
            attack_mode: Attack mode (0=dictionary, 3=brute-force, 6=hybrid)
            rules: Rules file for dictionary mutations
            mask: Mask for brute-force attack (e.g., ?a?a?a?a)
            outfile: Output file for cracked hashes
            show: Show cracked passwords
            force: Force run even if warnings
            timeout: Timeout in seconds

        Returns:
            ToolResult with cracking results
        """
        args: list[str] = []

        # Resolve hash mode from name
        if isinstance(hash_mode, str) and hash_mode.lower() in self.HASH_MODES:
            hash_mode = self.HASH_MODES[hash_mode.lower()]

        if hash_mode is not None:
            args.extend(["-m", str(hash_mode)])

        if show:
            args.append("--show")
            args.append(str(hash_file))
            return self._run_with_result(args, timeout=timeout)

        args.extend(["-a", str(attack_mode)])

        if outfile:
            args.extend(["-o", str(outfile)])

        if force:
            args.append("--force")

        # Add hash file
        args.append(str(hash_file))

        # Add wordlist or mask based on attack mode
        if attack_mode == 0:  # Dictionary
            if wordlist:
                args.append(str(wordlist))
            if rules:
                args.extend(["-r", str(rules)])
        elif attack_mode == 3:  # Brute-force
            if mask:
                args.append(mask)
        elif attack_mode == 6:  # Hybrid (wordlist + mask)
            if wordlist:
                args.append(str(wordlist))
            if mask:
                args.append(mask)

        result = self._run_with_result(args, timeout=timeout)

        # Check for results
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse hashcat output into structured data."""
        combined = stdout + stderr
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "cracked": [],
            "recovered": 0,
            "total": 0,
            "status": None,
        }

        # Parse cracked passwords
        # Format: hash:password
        for line in stdout.split("\n"):
            if ":" in line and not line.startswith("#"):
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    parsed["cracked"].append(
                        {
                            "hash": parts[0],
                            "password": ":".join(parts[1:]),  # Handle : in password
                        }
                    )

        # Parse status
        status_match = re.search(r"Status\.*:\s*(\w+)", combined)
        if status_match:
            parsed["status"] = status_match.group(1)

        # Parse recovered count
        recovered_match = re.search(r"Recovered\.+:\s*(\d+)/(\d+)", combined)
        if recovered_match:
            parsed["recovered"] = int(recovered_match.group(1))
            parsed["total"] = int(recovered_match.group(2))

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on results."""
        suggestions: list[str] = []

        cracked = parsed_data.get("cracked", [])
        recovered = parsed_data.get("recovered", 0)
        total = parsed_data.get("total", 0)

        if cracked:
            suggestions.append(f"Cracked {len(cracked)} password(s)!")
            for c in cracked[:3]:
                pwd = c["password"]
                if len(pwd) > 30:
                    pwd = pwd[:30] + "..."
                suggestions.append(f"  {c['hash'][:20]}...: {pwd}")
        elif recovered > 0:
            suggestions.append(f"Recovered {recovered}/{total} hashes")

        if not cracked and not recovered:
            suggestions.extend(
                [
                    "No passwords cracked",
                    "Try a different wordlist or attack mode",
                    "Consider rules: hashcat -r rules/best64.rule",
                    "For brute-force: hashcat -a 3 hashes.txt ?a?a?a?a",
                ]
            )

        return suggestions

    def show_cracked(self, hash_file: Path | str, hash_mode: int | None = None) -> ToolResult:
        """Show previously cracked passwords."""
        return self.run(hash_file, hash_mode=hash_mode, show=True)

    def crack_dictionary(
        self,
        hash_file: Path | str,
        wordlist: Path | str,
        hash_mode: int | str | None = None,
        rules: Path | str | None = None,
    ) -> ToolResult:
        """Run dictionary attack."""
        return self.run(
            hash_file,
            wordlist=wordlist,
            hash_mode=hash_mode,
            attack_mode=0,
            rules=rules,
        )

    def crack_bruteforce(
        self,
        hash_file: Path | str,
        mask: str,
        hash_mode: int | str | None = None,
    ) -> ToolResult:
        """Run brute-force attack with mask."""
        return self.run(
            hash_file,
            hash_mode=hash_mode,
            attack_mode=3,
            mask=mask,
        )

    @classmethod
    def get_mode_for_hash(cls, hash_type: str) -> int | None:
        """Get hashcat mode for a hash type name."""
        return cls.HASH_MODES.get(hash_type.lower())
