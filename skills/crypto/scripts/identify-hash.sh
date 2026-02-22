#!/usr/bin/env bash
# Identify hash type from a hash string or file containing hashes.
# Outputs raw results followed by a structured JSON summary.
# Usage: identify-hash.sh <hash-or-file>
set -euo pipefail

INPUT="${1:?Usage: identify-hash.sh <hash-string-or-file>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

# Determine the hash string for the parser
if [ -f "$INPUT" ]; then
    HASH_STR=$(head -1 "$INPUT" | tr -d '[:space:]')
else
    HASH_STR="$INPUT"
fi

if ! command -v hashid &>/dev/null; then
    # Fallback: length-based detection via parser
    echo "hashid not installed (pip install hashid). Using length-based detection."
    echo ""
    echo "=== PARSED RESULTS (JSON) ==="
    echo "" | python3 "$LIB_DIR/parse-hashid.py" "$HASH_STR"
    exit 0
fi

if [ -f "$INPUT" ]; then
    echo "=== Hash Identification (from file) ==="
    RAW=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "--- $line ---"
        RESULT=$(hashid "$line" 2>&1) || true
        echo "$RESULT"
        RAW="${RAW}${RESULT}"$'\n'
        echo ""
    done < "$INPUT"
else
    echo "=== Hash Identification ==="
    RAW=$(hashid "$INPUT" 2>&1) || true
    echo "$RAW"
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-hashid.py" "$HASH_STR"
