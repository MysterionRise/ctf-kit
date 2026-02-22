#!/usr/bin/env bash
# Run exiftool metadata extraction with structured output.
# Usage: run-exiftool.sh <file>
set -euo pipefail

FILE="${1:?Usage: run-exiftool.sh <file>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v exiftool &>/dev/null; then
    echo "ERROR: exiftool not installed. Install: brew install exiftool / apt install libimage-exiftool-perl" >&2
    exit 1
fi

echo "=== Exiftool Metadata: $FILE ==="
# Run text output for display
exiftool "$FILE" 2>&1 || true

# Run JSON output for parsing
echo ""
echo "=== PARSED RESULTS (JSON) ==="
exiftool -j -a "$FILE" 2>/dev/null | python3 "$LIB_DIR/parse-exiftool.py" "$FILE"
