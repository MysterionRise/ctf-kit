#!/usr/bin/env python3
"""Parse xortool output into structured JSON."""

import json
from pathlib import Path
import re
import sys


def parse_xortool(raw: str, file_path: str = "") -> dict:
    key_lengths = []
    best_key_length = None
    key_found = None
    decrypted_files = []

    # Parse key length analysis
    # Format: "   2:   5.2%"  or "The most probable key length is: 8"
    kl_pattern = re.compile(r"^\s*(\d+):\s+([\d.]+)%")
    best_kl_pattern = re.compile(r"most probable key length(?:s)?\s*(?:is)?[:\s]+(\d+)", re.I)
    key_pattern = re.compile(r"key:\s*['\"]?([^'\"]+)['\"]?", re.I)

    for line in raw.strip().split("\n"):
        m = kl_pattern.match(line)
        if m:
            key_lengths.append(
                {
                    "length": int(m.group(1)),
                    "probability": float(m.group(2)),
                }
            )

        m = best_kl_pattern.search(line)
        if m:
            best_key_length = int(m.group(1))

        m = key_pattern.search(line)
        if m:
            key_found = m.group(1).strip()

    # Sort by probability
    key_lengths.sort(key=lambda x: x["probability"], reverse=True)

    # Check for output directory
    xortool_dir = Path("xortool_out")
    if xortool_dir.is_dir():
        for p in sorted(xortool_dir.iterdir()):
            decrypted_files.append(str(p))

    # Suggestions
    suggestions = []
    if key_found:
        suggestions.append(f"XOR key found: {key_found}")
        suggestions.append(f"Decrypt with: xortool-xor -n -s '{key_found}' <file>")
    elif best_key_length:
        suggestions.append(f"Most probable key length: {best_key_length}")
        suggestions.append(
            f"Try: xortool -l {best_key_length} -c 20 <file>  (assuming space is most frequent)"
        )
        suggestions.append(
            f"Try: xortool -l {best_key_length} -c 00 <file>  (assuming null is most frequent)"
        )
    elif key_lengths:
        top = key_lengths[0]
        suggestions.append(f"Top key length candidate: {top['length']} ({top['probability']}%)")
        suggestions.append(f"Try: xortool -l {top['length']} -c 20 <file>")
    else:
        suggestions.append("No key length detected - file may not be XOR encrypted")

    if decrypted_files:
        suggestions.append(f"Check {len(decrypted_files)} decrypted candidate(s) in xortool_out/")

    return {
        "tool": "xortool",
        "file": file_path,
        "key_lengths": key_lengths,
        "best_key_length": best_key_length,
        "key_found": key_found,
        "decrypted_files": decrypted_files,
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_xortool(raw, file_path), indent=2) + "\n")
