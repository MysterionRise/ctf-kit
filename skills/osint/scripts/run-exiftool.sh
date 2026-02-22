#!/usr/bin/env bash
# Run exiftool for OSINT metadata extraction (GPS, camera, timestamps).
# Usage: run-exiftool.sh <file>
set -euo pipefail

FILE="${1:?Usage: run-exiftool.sh <file>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v exiftool &>/dev/null; then
    echo "ERROR: exiftool not installed. Install: brew install exiftool / apt install libimage-exiftool-perl" >&2
    exit 1
fi

echo "=== OSINT Metadata: $FILE ==="
exiftool "$FILE" 2>&1 || true

echo ""
echo "=== GPS Coordinates ==="
GPS=$(exiftool -gps:all -n "$FILE" 2>&1) || true
echo "$GPS"

echo ""
echo "=== PARSED RESULTS (JSON) ==="
exiftool -j -a "$FILE" 2>/dev/null | python3 "$LIB_DIR/parse-exiftool.py" "$FILE"
