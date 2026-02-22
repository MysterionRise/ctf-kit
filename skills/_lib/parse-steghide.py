#!/usr/bin/env python3
"""Parse steghide output into structured JSON."""

import json
import re
import sys


def parse_steghide(raw: str, file_path: str = "") -> dict:
    extracted_file = None
    password_used = None
    has_data = False
    embedded_info = {}

    # Parse "steghide info" output
    # format: "  size: 1234 bytes" or "  embedded file \"secret.txt\""
    size_match = re.search(r"embedded data.*?(\d+)\s*bytes", raw, re.I)
    if size_match:
        embedded_info["size_bytes"] = int(size_match.group(1))
        has_data = True

    file_match = re.search(r'embedded file\s+"([^"]+)"', raw, re.I)
    if file_match:
        embedded_info["filename"] = file_match.group(1)
        has_data = True

    algo_match = re.search(r"encryption algorithm:\s*(.+)", raw, re.I)
    if algo_match:
        embedded_info["encryption"] = algo_match.group(1).strip()

    # Parse extraction output
    extract_match = re.search(r'extracted data.*?"([^"]+)"', raw, re.I)
    if not extract_match:
        extract_match = re.search(r'wrote extracted data to\s+"([^"]+)"', raw, re.I)
    if extract_match:
        extracted_file = extract_match.group(1)

    # Check for success with password
    success_match = re.search(r"SUCCESS with password:\s*'([^']*)'", raw, re.I)
    if success_match:
        password_used = success_match.group(1)

    # Suggestions
    suggestions = []
    if extracted_file:
        suggestions.append(f"Data extracted to: {extracted_file}")
        if password_used is not None:
            suggestions.append(f"Password was: '{password_used}'")
        suggestions.append(
            f"Analyze extracted file: file {extracted_file} && strings {extracted_file}"
        )
    elif has_data:
        suggestions.append("Embedded data detected but not yet extracted")
        suggestions.append("Try common passwords: steghide extract -sf <file> -p '<password>'")
        suggestions.append("Common passwords: (empty), password, steghide, secret, hidden, flag")
    else:
        if "could not extract" in raw.lower() or "could not" in raw.lower():
            suggestions.append("Extraction failed - wrong password or no embedded data")
        suggestions.append(
            "No steghide data found - try zsteg (for PNG/BMP) or binwalk (appended data)"
        )

    return {
        "tool": "steghide",
        "file": file_path,
        "has_embedded_data": has_data,
        "embedded_info": embedded_info,
        "extracted_file": extracted_file,
        "password_used": password_used,
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_steghide(raw, file_path), indent=2) + "\n")
