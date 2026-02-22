#!/usr/bin/env python3
"""Parse strings output into structured JSON with pattern detection."""

import json
import re
import sys

# Interesting patterns for CTF analysis
PATTERNS = [
    (r"(?:flag|ctf|picoctf|htb)\{[^}]+\}", "flag"),
    (r"https?://\S+", "url"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email"),
    (r"-----BEGIN [A-Z ]+ KEY-----", "crypto_key"),
    (r"-----BEGIN CERTIFICATE-----", "certificate"),
    (r"[0-9a-f]{32}", "hash_md5"),
    (r"[0-9a-f]{40}", "hash_sha1"),
    (r"[0-9a-f]{64}", "hash_sha256"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "base64"),
    (r"SELECT\s.+\sFROM", "sql"),
    (r"INSERT\s+INTO", "sql"),
    (r"<\?php", "php_code"),
    (r"/etc/passwd", "system_ref"),
    (r"/bin/(?:ba)?sh", "shell_ref"),
    (r"(?:password|passwd|secret|token|api_key)\s*[:=]", "credential_hint"),
]


def parse_strings(raw: str, file_path: str = "") -> dict:
    lines = [ln for ln in raw.strip().split("\n") if ln.strip()] if raw.strip() else []

    findings = {
        "flags": [],
        "urls": [],
        "emails": [],
        "hashes": [],
        "base64_strings": [],
        "crypto_keys": [],
        "sql_patterns": [],
        "credential_hints": [],
        "other_interesting": [],
    }
    category_map = {
        "flag": "flags",
        "url": "urls",
        "email": "emails",
        "hash_md5": "hashes",
        "hash_sha1": "hashes",
        "hash_sha256": "hashes",
        "base64": "base64_strings",
        "crypto_key": "crypto_keys",
        "certificate": "crypto_keys",
        "sql": "sql_patterns",
        "credential_hint": "credential_hints",
    }

    for line in lines:
        for pattern, category in PATTERNS:
            matches = re.findall(pattern, line, re.IGNORECASE)
            if matches:
                bucket = category_map.get(category, "other_interesting")
                for match in matches:
                    entry = match if isinstance(match, str) else match[0]
                    if entry not in findings[bucket]:
                        findings[bucket].append(entry[:500])

    # Suggestions based on findings
    suggestions = []
    if findings["flags"]:
        suggestions.append(f"FLAG FOUND: {', '.join(findings['flags'][:3])}")
    if findings["hashes"]:
        suggestions.append(
            f"Found {len(findings['hashes'])} hash(es) - identify with: hashid <hash>"
        )
    if findings["base64_strings"]:
        suggestions.append(
            f"Found {len(findings['base64_strings'])} base64 string(s) - try: echo '<str>' | base64 -d"
        )
    if findings["crypto_keys"]:
        suggestions.append("Cryptographic key material found - extract and analyze")
    if findings["urls"]:
        suggestions.append(f"Found {len(findings['urls'])} URL(s) - investigate endpoints")
    if findings["sql_patterns"]:
        suggestions.append("SQL patterns detected - check for injection or database clues")
    if findings["credential_hints"]:
        suggestions.append("Credential hints found - look for passwords/tokens nearby")
    if not suggestions and lines:
        suggestions.append(f"Extracted {len(lines)} strings - no obvious patterns, search manually")

    return {
        "tool": "strings",
        "file": file_path,
        "total_strings": len(lines),
        "findings": findings,
        "suggestions": suggestions,
        "has_flag": bool(findings["flags"]),
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_strings(raw, file_path), indent=2) + "\n")
