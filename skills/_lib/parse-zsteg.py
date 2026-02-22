#!/usr/bin/env python3
"""Parse zsteg output into structured JSON."""

import json
import re
import sys

FLAG_PATTERNS = [
    re.compile(r"(?:flag|ctf|picoctf|htb)\{[^}]+\}", re.I),
]


def parse_zsteg(raw: str, file_path: str = "") -> dict:
    findings = []
    flags_found = []

    # zsteg output format: "b1,r,lsb,xy .. text: "hidden message""
    # or: "b1,rgb,lsb,xy .. file: PNG image data"
    line_pattern = re.compile(r"^([\w,]+)\s+\.\.\s+(\w+):\s+(.+)", re.M)

    for m in line_pattern.finditer(raw):
        channel = m.group(1)
        data_type = m.group(2)
        content = m.group(3).strip().strip('"')

        finding = {
            "channel": channel,
            "type": data_type,
            "content": content[:500],
        }

        # Check for flags
        for fp in FLAG_PATTERNS:
            flag_matches = fp.findall(content)
            if flag_matches:
                finding["has_flag"] = True
                flags_found.extend(flag_matches)

        # Filter out noise (very short or common false positives)
        if data_type == "text" and len(content) < 4:
            continue

        findings.append(finding)

    # Categorize findings
    text_findings = [f for f in findings if f["type"] == "text"]
    file_findings = [f for f in findings if f["type"] == "file"]
    # Suggestions
    suggestions = []
    if flags_found:
        suggestions.append(f"FLAG FOUND: {', '.join(set(flags_found))}")
    if text_findings:
        suggestions.append(f"Found {len(text_findings)} hidden text string(s)")
        for tf in text_findings[:3]:
            suggestions.append(f"  Channel {tf['channel']}: {tf['content'][:80]}")
    if file_findings:
        suggestions.append(f"Found {len(file_findings)} embedded file(s)")
        for ff in file_findings[:3]:
            suggestions.append(f"  Channel {ff['channel']}: {ff['content'][:80]}")
        suggestions.append("Extract with: zsteg -E <channel> <image> > extracted_file")
    if not findings:
        suggestions.append("No LSB steganography detected in PNG/BMP")
        suggestions.append("Try: steghide (for JPEG), exiftool (metadata), binwalk (appended data)")

    return {
        "tool": "zsteg",
        "file": file_path,
        "finding_count": len(findings),
        "findings": findings,
        "text_findings": text_findings,
        "file_findings": file_findings,
        "flags": list(set(flags_found)),
        "has_flag": bool(flags_found),
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_zsteg(raw, file_path), indent=2) + "\n")
