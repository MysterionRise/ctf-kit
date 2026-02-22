#!/usr/bin/env bash
# Run steghide to extract hidden data from JPEG images.
# Outputs raw results followed by a structured JSON summary.
# Usage: run-steghide.sh <image> [password]
# Tries empty password by default, then common passwords.
set -euo pipefail

IMAGE="${1:?Usage: run-steghide.sh <image.jpg> [password]}"
PASSWORD="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v steghide &>/dev/null; then
    echo "ERROR: steghide not installed. Install: brew install steghide / apt install steghide" >&2
    exit 1
fi

RAW=""

echo "=== Steghide Info: $IMAGE ==="
INFO=$(steghide info "$IMAGE" -p "" 2>&1) || true
echo "$INFO"
RAW="${INFO}"

if [ -n "$PASSWORD" ]; then
    echo ""
    echo "=== Extracting with password ==="
    EXTRACT=$(steghide extract -sf "$IMAGE" -p "$PASSWORD" -f 2>&1) || true
    echo "$EXTRACT"
    RAW="${RAW}"$'\n'"${EXTRACT}"
else
    echo ""
    echo "=== Trying common passwords ==="
    for pw in "" "password" "steghide" "secret" "hidden" "flag"; do
        EXTRACT=$(steghide extract -sf "$IMAGE" -p "$pw" -f 2>&1) || true
        if echo "$EXTRACT" | grep -qi "wrote extracted"; then
            echo "SUCCESS with password: '$pw'"
            RAW="${RAW}"$'\n'"SUCCESS with password: '$pw'"$'\n'"${EXTRACT}"
            break
        fi
    done
    if ! echo "$RAW" | grep -qi "success"; then
        echo "No common password worked. Try: run-steghide.sh $IMAGE <password>"
    fi
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-steghide.py" "$IMAGE"
