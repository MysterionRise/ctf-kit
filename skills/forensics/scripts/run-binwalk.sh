#!/usr/bin/env bash
# Run binwalk to scan and optionally extract embedded files
# Usage: run-binwalk.sh <file> [--extract]
set -euo pipefail

FILE="${1:?Usage: run-binwalk.sh <file> [--extract]}"
EXTRACT="${2:-}"

if ! command -v binwalk &>/dev/null; then
    echo "ERROR: binwalk not installed. Install: pip install binwalk" >&2
    exit 1
fi

echo "=== Binwalk Scan: $FILE ==="
binwalk "$FILE"

if [ "$EXTRACT" = "--extract" ] || [ "$EXTRACT" = "-e" ]; then
    echo ""
    echo "=== Extracting embedded files ==="
    binwalk -e "$FILE"
    OUTDIR="_$(basename "$FILE").extracted"
    if [ -d "$OUTDIR" ]; then
        echo ""
        echo "=== Extracted files ==="
        find "$OUTDIR" -type f -exec file {} \;
    fi
fi
