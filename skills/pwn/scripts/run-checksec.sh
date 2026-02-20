#!/usr/bin/env bash
# Run checksec on a binary to check protections
# Usage: run-checksec.sh <binary>
set -euo pipefail

BINARY="${1:?Usage: run-checksec.sh <binary>}"

if command -v checksec &>/dev/null; then
    echo "=== Binary Protections: $BINARY ==="
    checksec --file="$BINARY"
elif command -v pwn &>/dev/null; then
    echo "=== Binary Protections (via pwntools): $BINARY ==="
    pwn checksec "$BINARY"
else
    echo "ERROR: checksec not installed." >&2
    echo "  Install: pip install checksec.py" >&2
    echo "  Or:      pip install pwntools" >&2
    exit 1
fi
