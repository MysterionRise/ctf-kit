#!/usr/bin/env bash
# Run binwalk to scan and optionally extract embedded files.
# Outputs raw results followed by a structured JSON summary.
# Usage: run-binwalk.sh <file> [--extract]
set -euo pipefail

FILE="${1:?Usage: run-binwalk.sh <file> [--extract]}"
EXTRACT="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v binwalk &>/dev/null; then
    echo "ERROR: binwalk not installed. Install: pip install binwalk" >&2
    exit 1
fi

echo "=== Binwalk Scan: $FILE ==="
RAW=$(binwalk "$FILE" 2>&1) || true
echo "$RAW"

EXTRACTED_DIR=""
if [ "$EXTRACT" = "--extract" ] || [ "$EXTRACT" = "-e" ]; then
    echo ""
    echo "=== Extracting embedded files ==="
    binwalk -e "$FILE" 2>&1 || true
    EXTRACTED_DIR="_$(basename "$FILE").extracted"
    if [ -d "$EXTRACTED_DIR" ]; then
        echo ""
        echo "=== Extracted files ==="
        find "$EXTRACTED_DIR" -type f -exec file {} \;
    fi
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-binwalk.py" "$FILE" "$EXTRACTED_DIR"
