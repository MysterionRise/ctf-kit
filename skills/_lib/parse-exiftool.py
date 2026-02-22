#!/usr/bin/env python3
"""Parse exiftool output into structured JSON with CTF-relevant field detection."""

import json
import re
import sys

# Fields commonly used to hide data in CTF challenges
CTF_RELEVANT_KEYS = {
    "comment",
    "usercomment",
    "author",
    "artist",
    "copyright",
    "description",
    "title",
    "subject",
    "keywords",
    "software",
    "make",
    "model",
    "gps",
    "thumbnailimage",
    "xmp",
    "iptc",
    "imagedescription",
    "xpcomment",
    "xpkeywords",
}

FLAG_PATTERNS = [
    re.compile(r"(flag|ctf|picoctf|htb)\{[^}]+\}", re.I),
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),  # Base64-like
    re.compile(r"[0-9a-f]{32,}", re.I),  # Hex/hash-like
]


def parse_exiftool(raw: str, file_path: str = "") -> dict:
    # Try JSON first (exiftool -j output)
    metadata = {}
    try:
        data = json.loads(raw)
        if isinstance(data, list) and data:
            metadata = data[0]
        elif isinstance(data, dict):
            metadata = data
    except json.JSONDecodeError:
        # Parse text output: "Key  : Value"
        for line in raw.strip().split("\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                metadata[key.strip()] = value.strip()

    # Find interesting fields
    interesting = []
    for key, value in metadata.items():
        key_lower = key.lower().replace(" ", "")
        value_str = str(value)

        is_relevant = any(k in key_lower for k in CTF_RELEVANT_KEYS)
        has_flag = any(p.search(value_str) for p in FLAG_PATTERNS)
        is_long = len(value_str) > 100

        if is_relevant or has_flag or is_long:
            reasons = []
            if has_flag and ("flag" in value_str.lower() or "ctf" in value_str.lower()):
                reasons.append("Contains flag-like pattern")
            elif has_flag:
                reasons.append("Possible encoded data")
            if is_relevant:
                reasons.append("Common CTF metadata field")
            if is_long:
                reasons.append("Unusually long value")

            interesting.append(
                {
                    "field": key,
                    "value": value_str[:500],
                    "reason": "; ".join(reasons) if reasons else "Potential interest",
                }
            )

    # GPS detection
    gps_data = {}
    gps_keys = [k for k in metadata if "gps" in k.lower()]
    if gps_keys:
        for k in gps_keys:
            gps_data[k] = str(metadata[k])

    # Suggestions
    suggestions = []
    flags_found = []
    for field in interesting:
        for p in FLAG_PATTERNS[:1]:  # Just check flag{} pattern
            matches = p.findall(field["value"])
            flags_found.extend(matches)

    if flags_found:
        suggestions.append(f"FLAG FOUND in metadata: {', '.join(flags_found[:3])}")
    if gps_data:
        suggestions.append("GPS coordinates found - may be location-based challenge")
    if any("thumbnail" in k.lower() for k in metadata):
        suggestions.append("Thumbnail found - extract: exiftool -b -ThumbnailImage <file>")
    if interesting:
        suggestions.append(f"Found {len(interesting)} potentially interesting metadata field(s)")
    if not suggestions:
        if metadata:
            suggestions.append("Standard metadata found - check for steganography next")
        else:
            suggestions.append("No metadata found - file may be stripped")

    return {
        "tool": "exiftool",
        "file": file_path,
        "field_count": len(metadata),
        "interesting_fields": interesting,
        "gps_data": gps_data,
        "has_flag": bool(flags_found),
        "flags": flags_found,
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_exiftool(raw, file_path), indent=2) + "\n")
