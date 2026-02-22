#!/usr/bin/env python3
"""Parse hashid output into structured JSON with cracking suggestions."""

import json
import re
import sys

# Hashcat mode mappings for common hash types
HASHCAT_MODES = {
    "md5": 0,
    "md4": 900,
    "ntlm": 1000,
    "sha1": 100,
    "sha256": 1400,
    "sha384": 10800,
    "sha512": 1700,
    "sha3-256": 17400,
    "sha3-512": 17600,
    "bcrypt": 3200,
    "mysql": 300,
    "mysql5": 300,
    "postgresql": 12,
    "apache md5": 1600,
    "wordpress": 400,
    "phpass": 400,
    "crc32": 11500,
    "keccak-256": 17800,
}

# JTR format names
JTR_FORMATS = {
    "md5": "raw-md5",
    "sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "sha512": "raw-sha512",
    "ntlm": "nt",
    "bcrypt": "bcrypt",
    "mysql": "mysql",
    "phpass": "phpass",
}


def identify_by_length(hash_str: str) -> list[dict]:
    """Fallback identification by hash length."""
    length_map = {
        32: [
            {"type": "MD5", "hashcat": 0, "jtr": "raw-md5"},
            {"type": "NTLM", "hashcat": 1000, "jtr": "nt"},
        ],
        40: [{"type": "SHA1", "hashcat": 100, "jtr": "raw-sha1"}],
        56: [{"type": "SHA224", "hashcat": 1300, "jtr": "raw-sha224"}],
        64: [
            {"type": "SHA256", "hashcat": 1400, "jtr": "raw-sha256"},
            {"type": "SHA3-256", "hashcat": 17400, "jtr": "raw-sha3"},
        ],
        96: [{"type": "SHA384", "hashcat": 10800, "jtr": "raw-sha384"}],
        128: [
            {"type": "SHA512", "hashcat": 1700, "jtr": "raw-sha512"},
            {"type": "SHA3-512", "hashcat": 17600, "jtr": "raw-sha3"},
        ],
    }
    clean = hash_str.strip()
    if re.match(r"^[0-9a-fA-F]+$", clean):
        return length_map.get(len(clean), [{"type": f"Unknown (length {len(clean)})"}])
    if clean.startswith("$2"):
        return [{"type": "bcrypt", "hashcat": 3200, "jtr": "bcrypt"}]
    if clean.startswith("$1$"):
        return [{"type": "MD5 Unix", "hashcat": 500, "jtr": "md5crypt"}]
    if clean.startswith("$6$"):
        return [{"type": "SHA512 Unix", "hashcat": 1800, "jtr": "sha512crypt"}]
    return [{"type": "Unknown format"}]


def parse_hashid(raw: str, input_hash: str = "") -> dict:
    """Parse hashid output."""
    hashes = []
    current_hash = ""
    current_types = []

    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # hashid output format: "Analyzing 'hash'" or "[+] Type"
        analyze_match = re.match(r"Analyzing '([^']+)'", line)
        if analyze_match:
            if current_hash and current_types:
                hashes.append({"hash": current_hash, "types": current_types})
            current_hash = analyze_match.group(1)
            current_types = []
            continue

        type_match = re.match(r"\[.\]\s+(.+)", line)
        if type_match:
            type_name = type_match.group(1).strip()
            type_lower = type_name.lower()
            entry = {"type": type_name}
            for key, mode in HASHCAT_MODES.items():
                if key in type_lower:
                    entry["hashcat_mode"] = mode
                    break
            for key, fmt in JTR_FORMATS.items():
                if key in type_lower:
                    entry["jtr_format"] = fmt
                    break
            current_types.append(entry)

    if current_hash and current_types:
        hashes.append({"hash": current_hash, "types": current_types})

    # If no hashid output, try length-based detection
    if not hashes and input_hash:
        types = identify_by_length(input_hash)
        hashes.append({"hash": input_hash, "types": types})

    # Suggestions
    suggestions = []
    for h in hashes:
        if h["types"]:
            top = h["types"][0]
            hash_preview = h["hash"][:20] + "..." if len(h["hash"]) > 20 else h["hash"]
            suggestions.append(f"Hash {hash_preview}: most likely {top['type']}")
            if "hashcat_mode" in top:
                suggestions.append(
                    f"Crack with hashcat: hashcat -m {top['hashcat_mode']} -a 0 hash.txt rockyou.txt"
                )
            if "jtr_format" in top:
                suggestions.append(
                    f"Crack with john: john --format={top['jtr_format']} --wordlist=rockyou.txt hash.txt"
                )

    return {
        "tool": "hashid",
        "input": input_hash,
        "hashes": hashes,
        "hash_count": len(hashes),
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    input_hash = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_hashid(raw, input_hash), indent=2) + "\n")
