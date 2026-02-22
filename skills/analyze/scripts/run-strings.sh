#!/usr/bin/env bash
# Run strings with pattern detection and structured output.
# Usage: run-strings.sh <file> [min-length]
set -euo pipefail

FILE="${1:?Usage: run-strings.sh <file> [min-length]}"
MIN_LEN="${2:-4}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v strings &>/dev/null; then
    echo "ERROR: strings not installed. Install: brew install binutils / apt install binutils" >&2
    exit 1
fi

echo "=== Strings Analysis: $FILE (min length: $MIN_LEN) ==="
RAW=$(strings -n "$MIN_LEN" "$FILE" 2>&1) || true

# Show total count and preview
TOTAL=$(echo "$RAW" | wc -l | tr -d ' ')
echo "Total strings found: $TOTAL"
echo ""
echo "=== First 50 strings ==="
echo "$RAW" | head -50
echo ""
if [ "$TOTAL" -gt 50 ]; then
    echo "... ($((TOTAL - 50)) more strings)"
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-strings.py" "$FILE"
