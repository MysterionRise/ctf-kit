#!/usr/bin/env bash
# Run checksec on a binary to check protections.
# Outputs raw results followed by a structured JSON summary.
# Usage: run-checksec.sh <binary>
set -euo pipefail

BINARY="${1:?Usage: run-checksec.sh <binary>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

RAW=""

if command -v checksec &>/dev/null; then
    echo "=== Binary Protections: $BINARY ==="
    RAW=$(checksec --file="$BINARY" 2>&1) || true
    echo "$RAW"
elif command -v pwn &>/dev/null; then
    echo "=== Binary Protections (via pwntools): $BINARY ==="
    RAW=$(pwn checksec "$BINARY" 2>&1) || true
    echo "$RAW"
else
    echo "ERROR: checksec not installed." >&2
    echo "  Install: pip install checksec.py" >&2
    echo "  Or:      pip install pwntools" >&2
    exit 1
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-checksec.py" "$BINARY"
