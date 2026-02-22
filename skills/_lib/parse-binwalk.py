#!/usr/bin/env python3
"""Parse binwalk output into structured JSON."""

import json
from pathlib import Path
import re
import sys


def parse_binwalk(raw: str, file_path: str = "", extracted_dir: str = "") -> dict:
    sig_pattern = re.compile(r"(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)")
    type_map = {
        "zip archive": "zip",
        "gzip": "gzip",
        "tar archive": "tar",
        "rar archive": "rar",
        "7-zip": "7zip",
        "png image": "png",
        "jpeg": "jpeg",
        "gif image": "gif",
        "elf": "elf",
        "pe32": "pe",
        "pdf": "pdf",
        "sqlite": "sqlite",
        "squashfs": "squashfs",
        "cramfs": "cramfs",
        "jffs2": "jffs2",
        "zlib": "zlib",
        "lzma": "lzma",
        "certificate": "cert",
        "private key": "key",
    }

    signatures = []
    file_types = set()
    for line in raw.strip().split("\n"):
        m = sig_pattern.match(line.strip())
        if m:
            desc = m.group(3).strip()
            ftype = next((v for k, v in type_map.items() if k in desc.lower()), None)
            sig = {"offset": int(m.group(1)), "offset_hex": m.group(2), "description": desc}
            if ftype:
                sig["type"] = ftype
                file_types.add(ftype)
            signatures.append(sig)

    suggestions = []
    if not signatures:
        suggestions.append("No embedded files detected - try entropy analysis: binwalk -E <file>")
    else:
        suggestions.append(f"Found {len(signatures)} embedded signature(s)")
        for ft in file_types:
            if ft in ("zip", "gzip", "tar", "rar", "7zip"):
                suggestions.append(f"Archive ({ft}) found - extract with: binwalk -e <file>")
            elif ft in ("elf", "pe"):
                suggestions.append(f"Executable ({ft}) found - analyze with strings/disassembler")
            elif ft in ("png", "jpeg", "gif"):
                suggestions.append(f"Image ({ft}) found - check for steganography")
            elif ft in ("squashfs", "cramfs", "jffs2"):
                suggestions.append(f"Filesystem ({ft}) found - use firmware-mod-kit")
        if len(signatures) > 1:
            suggestions.append("Multiple signatures - use binwalk -eM for recursive extraction")

    extracted = []
    if extracted_dir and Path(extracted_dir).is_dir():
        for p in Path(extracted_dir).rglob("*"):
            if p.is_file():
                extracted.append(str(p))

    return {
        "tool": "binwalk",
        "file": file_path,
        "signature_count": len(signatures),
        "signatures": signatures,
        "file_types": sorted(file_types),
        "extracted_files": extracted,
        "suggestions": suggestions,
        "next_steps": {
            "has_archives": bool(file_types & {"zip", "gzip", "tar", "rar", "7zip"}),
            "has_executables": bool(file_types & {"elf", "pe"}),
            "has_images": bool(file_types & {"png", "jpeg", "gif"}),
            "has_filesystems": bool(file_types & {"squashfs", "cramfs", "jffs2"}),
        },
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    extracted_dir = sys.argv[2] if len(sys.argv) > 2 else ""
    sys.stdout.write(json.dumps(parse_binwalk(raw, file_path, extracted_dir), indent=2) + "\n")
