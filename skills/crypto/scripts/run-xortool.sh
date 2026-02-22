#!/usr/bin/env bash
# Run xortool analysis on an encrypted file.
# Outputs raw results followed by a structured JSON summary.
# Usage: run-xortool.sh <file> [key-length] [most-frequent-char]
set -euo pipefail

FILE="${1:?Usage: run-xortool.sh <file> [key-length] [most-frequent-char]}"
KEY_LEN="${2:-}"
FREQ_CHAR="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v xortool &>/dev/null; then
    echo "ERROR: xortool not installed. Install: pip install xortool" >&2
    exit 1
fi

ARGS=()
[ -n "$KEY_LEN" ] && ARGS+=(-l "$KEY_LEN")
[ -n "$FREQ_CHAR" ] && ARGS+=(-c "$FREQ_CHAR")

echo "=== XOR Analysis: $FILE ==="
RAW=$(xortool "${ARGS[@]}" "$FILE" 2>&1) || true
echo "$RAW"

# Check for output directory
if [ -d "xortool_out" ]; then
    echo ""
    echo "=== Decrypted candidates ==="
    ls -la xortool_out/
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-xortool.py" "$FILE"
