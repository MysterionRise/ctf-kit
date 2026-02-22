#!/usr/bin/env python3
"""Parse checksec output into structured JSON with exploitation suggestions."""

import json
import re
import sys


def _parse_protections(raw_lower: str) -> dict:
    """Extract protection statuses from checksec output."""
    protections = {
        "relro": "unknown",
        "stack_canary": "unknown",
        "nx": "unknown",
        "pie": "unknown",
        "rpath": "unknown",
        "runpath": "unknown",
        "symbols": "unknown",
        "fortify": "unknown",
    }

    # Map: (search_string, field, value)
    # IMPORTANT: more specific (negative) rules must come before positive ones
    # because "no canary found" also contains "canary found"
    rules = [
        ("full relro", "relro", "full"),
        ("partial relro", "relro", "partial"),
        ("no relro", "relro", "none"),
        ("no canary", "stack_canary", "disabled"),
        ("canary found", "stack_canary", "enabled"),
        ("nx disabled", "nx", "disabled"),
        ("nx enabled", "nx", "enabled"),
        ("no pie", "pie", "disabled"),
        ("pie enabled", "pie", "enabled"),
    ]
    for needle, field, value in rules:
        if needle in raw_lower and protections[field] == "unknown":
            protections[field] = value

    return protections


def _build_suggestions(protections: dict) -> tuple[list, list]:
    """Build exploitation suggestions and attack vectors from protections."""
    suggestions = []
    attack_vectors = []

    if protections["stack_canary"] == "disabled":
        suggestions.append("No stack canary - buffer overflow is viable")
        attack_vectors.append("buffer_overflow")

    if protections["nx"] == "disabled":
        suggestions.append("NX disabled - shellcode injection is possible")
        attack_vectors.append("shellcode")
    else:
        suggestions.append("NX enabled - need ROP chain or ret2libc")
        attack_vectors.append("rop")

    if protections["pie"] == "disabled":
        suggestions.append("No PIE - addresses are fixed, ROP gadgets at known locations")
        suggestions.append("Find gadgets: ROPgadget --binary <file>")
        attack_vectors.append("fixed_addresses")
    else:
        suggestions.append("PIE enabled - need info leak for base address")
        attack_vectors.append("info_leak_needed")

    if protections["relro"] in ("none", "partial"):
        suggestions.append(f"{protections['relro'].title()} RELRO - GOT overwrite may be possible")
        attack_vectors.append("got_overwrite")

    # Summary attack strategy
    has_bof = "buffer_overflow" in attack_vectors
    if has_bof and "shellcode" in attack_vectors:
        suggestions.insert(0, "STRATEGY: Classic buffer overflow with shellcode injection")
    elif has_bof and "fixed_addresses" in attack_vectors:
        suggestions.insert(0, "STRATEGY: Buffer overflow + ROP chain (fixed addresses)")
    elif has_bof:
        suggestions.insert(0, "STRATEGY: Buffer overflow + ROP/ret2libc (need address leak)")

    return suggestions, attack_vectors


def parse_checksec(raw: str, file_path: str = "") -> dict:
    raw_lower = raw.lower()
    protections = _parse_protections(raw_lower)

    arch = "unknown"
    arch_match = re.search(r"Arch:\s*(\S+)", raw)
    if arch_match:
        arch = arch_match.group(1)

    suggestions, attack_vectors = _build_suggestions(protections)

    return {
        "tool": "checksec",
        "file": file_path,
        "arch": arch,
        "protections": protections,
        "attack_vectors": attack_vectors,
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(parse_checksec(raw, file_path), indent=2) + "\n")
