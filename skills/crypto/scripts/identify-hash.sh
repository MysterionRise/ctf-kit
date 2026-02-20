#!/usr/bin/env bash
# Identify hash type from a hash string or file containing hashes
# Usage: identify-hash.sh <hash-or-file>
set -euo pipefail

INPUT="${1:?Usage: identify-hash.sh <hash-string-or-file>}"

if ! command -v hashid &>/dev/null; then
    # Fallback: identify by length
    echo "hashid not installed (pip install hashid). Falling back to length-based detection."
    if [ -f "$INPUT" ]; then
        HASH=$(head -1 "$INPUT" | tr -d '[:space:]')
    else
        HASH="$INPUT"
    fi
    LEN=${#HASH}
    case $LEN in
        32) echo "Length 32: likely MD5, NTLM, or MD4" ;;
        40) echo "Length 40: likely SHA1" ;;
        64) echo "Length 64: likely SHA256 or SHA3-256" ;;
        96) echo "Length 96: likely SHA384" ;;
        128) echo "Length 128: likely SHA512 or SHA3-512" ;;
        *) echo "Length $LEN: unknown hash type" ;;
    esac
    exit 0
fi

if [ -f "$INPUT" ]; then
    echo "=== Hash Identification (from file) ==="
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "--- $line ---"
        hashid "$line"
        echo ""
    done < "$INPUT"
else
    echo "=== Hash Identification ==="
    hashid "$INPUT"
fi
