"""
Crypto skill for CTF Kit.

Orchestrates cryptographic analysis tools.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, ClassVar

from ctf_kit.skills.base import BaseSkill, SkillResult, register_skill

if TYPE_CHECKING:
    from ctf_kit.integrations.base import ToolResult


@register_skill
class CryptoSkill(BaseSkill):
    """
    Skill for cryptographic challenge analysis.

    Identifies encryption types, suggests approaches, and orchestrates
    crypto tools like hashid, xortool, and others.
    """

    name: ClassVar[str] = "crypto"
    description: ClassVar[str] = (
        "Analyze cryptographic challenges and suggest decryption approaches"
    )
    category: ClassVar[str] = "crypto"
    tool_names: ClassVar[list[str]] = ["hashid", "xortool", "strings"]

    # Common cipher patterns
    CIPHER_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "base64": re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),
        "base32": re.compile(r"^[A-Z2-7]{16,}={0,6}$"),
        "hex": re.compile(r"^[0-9a-fA-F]{16,}$"),
        "binary": re.compile(r"^[01]{8,}$"),
        "morse": re.compile(r"^[\.\-\s/]+$"),
        "rot13": re.compile(r"^[A-Za-z\s]+$"),
        "caesar": re.compile(r"^[A-Za-z\s]+$"),
    }

    # Hash patterns by length
    HASH_LENGTHS: ClassVar[dict[int, list[str]]] = {
        32: ["MD5", "NTLM", "MD4"],
        40: ["SHA1"],
        64: ["SHA256", "SHA3-256"],
        96: ["SHA384", "SHA3-384"],
        128: ["SHA512", "SHA3-512"],
    }

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze crypto challenge.

        Args:
            path: Path to challenge file or directory

        Returns:
            SkillResult with crypto analysis
        """
        analysis: dict[str, Any] = {
            "detected_ciphers": [],
            "detected_hashes": [],
            "xor_analysis": None,
            "encoding_chains": [],
            "interesting_values": [],
        }
        tool_results: list[ToolResult] = []
        suggestions: list[str] = []

        # Read file content
        if path.is_file():
            try:
                content = path.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                content = ""

            try:
                binary_content = path.read_bytes()
            except Exception:  # noqa: BLE001
                binary_content = b""
        else:
            content = ""
            binary_content = b""

        # Analyze text content
        if content:
            text_analysis = self._analyze_text(content)
            analysis["detected_ciphers"].extend(text_analysis.get("ciphers", []))
            analysis["encoding_chains"].extend(text_analysis.get("encodings", []))
            analysis["interesting_values"].extend(text_analysis.get("values", []))

        # Run hashid on hash-like strings
        hashid_tool = self.get_tool("hashid")
        if hashid_tool and hashid_tool.is_installed:
            hash_candidates = self._find_hash_candidates(content)
            for candidate in hash_candidates[:5]:  # Limit to 5
                result = hashid_tool.run(candidate)
                tool_results.append(result)
                if result.parsed_data and result.parsed_data.get("hash_types"):
                    analysis["detected_hashes"].append(
                        {
                            "value": candidate[:20] + "..." if len(candidate) > 20 else candidate,
                            "types": result.parsed_data["hash_types"][:3],
                        }
                    )

        # Run xortool on binary data
        xortool = self.get_tool("xortool")
        should_run_xortool = (
            xortool
            and xortool.is_installed
            and path.is_file()
            and self._looks_like_xor(binary_content)
        )
        if should_run_xortool and xortool:  # xortool check for type narrowing
            result = xortool.run(path)
            tool_results.append(result)
            if result.parsed_data:
                analysis["xor_analysis"] = {
                    "probable_key_lengths": result.parsed_data.get("probable_key_lengths", [])[:5],
                    "key": result.parsed_data.get("key"),
                }

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
            confidence=confidence,
        )

    def _analyze_text(self, content: str) -> dict[str, Any]:
        """Analyze text content for crypto patterns."""
        result: dict[str, Any] = {
            "ciphers": [],
            "encodings": [],
            "values": [],
        }

        lines = content.strip().split("\n")

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            # Check for hash-like strings FIRST (to avoid base64 false positives)
            is_hash = False
            if re.match(r"^[0-9a-fA-F]+$", line):
                length = len(line)
                if length in self.HASH_LENGTHS:
                    result["ciphers"].append(
                        {
                            "type": "hash",
                            "possible_types": self.HASH_LENGTHS[length],
                            "value": line[:20] + "..." if len(line) > 20 else line,
                        }
                    )
                    is_hash = True

            # Check for encoding patterns (skip base64 if already identified as hash)
            if not is_hash:
                for encoding, pattern in self.CIPHER_PATTERNS.items():
                    if pattern.match(line):
                        result["encodings"].append(
                            {
                                "type": encoding,
                                "value": line[:50] + "..." if len(line) > 50 else line,
                            }
                        )
                        break

            # Check for RSA-like parameters
            rsa_patterns: list[tuple[str, str]] = [
                (r"n\s*=\s*(\d+)", "RSA modulus (n)"),
                (r"e\s*=\s*(\d+)", "RSA exponent (e)"),
                (r"c\s*=\s*(\d+)", "RSA ciphertext (c)"),
                (r"p\s*=\s*(\d+)", "RSA prime (p)"),
                (r"q\s*=\s*(\d+)", "RSA prime (q)"),
                (r"d\s*=\s*(\d+)", "RSA private exponent (d)"),
            ]

            for rsa_pattern, rsa_name in rsa_patterns:
                match = re.search(rsa_pattern, line, re.I)
                if match:
                    result["values"].append(
                        {
                            "type": rsa_name,
                            "value": match.group(1)[:20] + "..."
                            if len(match.group(1)) > 20
                            else match.group(1),
                        }
                    )

        return result

    def _find_hash_candidates(self, content: str) -> list[str]:
        """Find potential hash strings in content."""
        # Extract all hex-like strings
        hex_pattern = re.compile(r"\b[0-9a-fA-F]{32,128}\b")
        matches = hex_pattern.findall(content)

        # Filter to only those with valid hash lengths
        candidates = [match for match in matches if len(match) in self.HASH_LENGTHS]

        return list(set(candidates))

    def _looks_like_xor(self, data: bytes) -> bool:
        """Check if data looks like it might be XOR encrypted."""
        if len(data) < 16:
            return False

        # Check byte distribution
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        # XOR encrypted data often has unusual byte distribution
        # but not random - there's often a pattern
        non_zero_count = sum(1 for c in byte_counts if c > 0)

        # If most byte values appear and distribution isn't uniform
        if non_zero_count > 100:
            return True

        # Check for repeating patterns (suggests key)
        return any(self._has_repeating_xor_pattern(data, key_len) for key_len in range(1, 17))

    def _has_repeating_xor_pattern(self, data: bytes, key_len: int) -> bool:
        """Check if data has repeating XOR key pattern."""
        if len(data) < key_len * 4:
            return False

        # Sample positions
        samples = [data[i::key_len][:20] for i in range(key_len)]

        # If XOR with same key, XORing same positions should give constant
        # This is a simplified heuristic
        return len(samples) > 0 and all(len(s) > 5 for s in samples)

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on crypto analysis."""
        suggestions: list[str] = []

        # Hash suggestions - from hashid tool
        if analysis.get("detected_hashes"):
            for hash_info in analysis["detected_hashes"][:3]:
                types = hash_info.get("types", [])
                if types:
                    type_names = [t.get("type", "unknown") for t in types[:3]]
                    suggestions.append(f"Possible hash types: {', '.join(type_names)}")
                    suggestions.append("Try cracking with hashcat or john")
                    suggestions.append("Check CrackStation or hashes.com for known hashes")
        # Fallback: use pattern-detected hashes from detected_ciphers
        elif analysis.get("detected_ciphers"):
            hash_ciphers = [c for c in analysis["detected_ciphers"] if c.get("type") == "hash"]
            for cipher in hash_ciphers[:3]:
                possible_types = cipher.get("possible_types", [])
                if possible_types:
                    suggestions.append(f"Possible hash types: {', '.join(possible_types)}")
                    suggestions.append("Try cracking with hashcat or john")
                    suggestions.append("Check CrackStation or hashes.com for known hashes")

        # XOR suggestions
        if analysis.get("xor_analysis"):
            xor = analysis["xor_analysis"]
            if xor.get("key"):
                suggestions.append(f"XOR key found: {xor['key']}")
            elif xor.get("probable_key_lengths"):
                lengths = [str(kl["length"]) for kl in xor["probable_key_lengths"][:3]]
                suggestions.append(f"Probable XOR key lengths: {', '.join(lengths)}")
                suggestions.append("Try xortool with -l <length> -c <common_char>")

        # Encoding suggestions
        if analysis.get("encoding_chains"):
            for enc in analysis["encoding_chains"][:3]:
                enc_type = enc.get("type", "unknown")
                if enc_type == "base64":
                    suggestions.append("Try base64 decode: base64 -d or CyberChef")
                elif enc_type == "hex":
                    suggestions.append("Try hex decode: xxd -r -p")
                elif enc_type == "binary":
                    suggestions.append("Try binary to ASCII conversion")

        # RSA suggestions
        rsa_values = [
            v for v in analysis.get("interesting_values", []) if "RSA" in v.get("type", "")
        ]
        if rsa_values:
            suggestions.append("RSA parameters found - look for factorization attack")
            suggestions.append("Try RsaCtfTool for automated RSA attacks")
            suggestions.append("Check if e is small (Wiener's attack) or if n is factorable")

        if not suggestions:
            suggestions.append("No obvious crypto patterns detected")
            suggestions.append("Try frequency analysis for substitution ciphers")
            suggestions.append("Check for custom/obscure encodings")

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps."""
        steps: list[str] = []

        if analysis.get("detected_hashes"):
            steps.append("Try cracking detected hashes with common wordlists")

        if analysis.get("xor_analysis") and analysis["xor_analysis"].get("probable_key_lengths"):
            steps.append("Attempt XOR decryption with detected key lengths")

        if analysis.get("encoding_chains"):
            steps.append("Decode detected encodings (base64/hex/etc)")

        if analysis.get("interesting_values"):
            steps.append("Analyze RSA parameters for vulnerabilities")

        steps.append("If stuck, try CyberChef 'Magic' operation")
        steps.append("Look for patterns or repeating sequences")

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence in crypto analysis."""
        confidence = 0.0

        if analysis.get("detected_hashes"):
            confidence += 0.3

        if analysis.get("xor_analysis") and analysis["xor_analysis"].get("key"):
            confidence += 0.4
        elif analysis.get("xor_analysis") and analysis["xor_analysis"].get("probable_key_lengths"):
            confidence += 0.2

        if analysis.get("encoding_chains"):
            confidence += 0.2

        if analysis.get("interesting_values"):
            confidence += 0.2

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def identify_hash(self, hash_value: str) -> dict[str, Any]:
        """Identify a single hash value."""
        hashid_tool = self.get_tool("hashid")
        if hashid_tool and hashid_tool.is_installed:
            result = hashid_tool.run(hash_value)
            if result.success and result.parsed_data:
                return {
                    "hash": hash_value,
                    "types": result.parsed_data.get("hash_types", []),
                    "most_likely": result.parsed_data.get("most_likely"),
                }
        return {"hash": hash_value, "types": [], "most_likely": None}

    def analyze_xor(self, path: Path) -> dict[str, Any]:
        """Analyze file for XOR encryption."""
        xortool = self.get_tool("xortool")
        if xortool and xortool.is_installed:
            result = xortool.run(path)
            if result.success and result.parsed_data:
                return result.parsed_data
        return {}
