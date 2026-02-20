#!/usr/bin/env bash
# Run xortool analysis on an encrypted file
# Usage: run-xortool.sh <file> [key-length] [most-frequent-char]
set -euo pipefail

FILE="${1:?Usage: run-xortool.sh <file> [key-length] [most-frequent-char]}"
KEY_LEN="${2:-}"
FREQ_CHAR="${3:-}"

if ! command -v xortool &>/dev/null; then
    echo "ERROR: xortool not installed. Install: pip install xortool" >&2
    exit 1
fi

ARGS=()
[ -n "$KEY_LEN" ] && ARGS+=(-l "$KEY_LEN")
[ -n "$FREQ_CHAR" ] && ARGS+=(-c "$FREQ_CHAR")

echo "=== XOR Analysis: $FILE ==="
xortool "${ARGS[@]}" "$FILE"

# Check for output directory
if [ -d "xortool_out" ]; then
    echo ""
    echo "=== Decrypted candidates ==="
    ls -la xortool_out/
    echo ""
    echo "Check xortool_out/ for decrypted files"
fi
