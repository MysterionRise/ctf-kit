#!/usr/bin/env bash
# Run steghide to extract hidden data from JPEG images
# Usage: run-steghide.sh <image> [password]
# Tries empty password by default, then common passwords
set -euo pipefail

IMAGE="${1:?Usage: run-steghide.sh <image.jpg> [password]}"
PASSWORD="${2:-}"

if ! command -v steghide &>/dev/null; then
    echo "ERROR: steghide not installed. Install: brew install steghide / apt install steghide" >&2
    exit 1
fi

echo "=== Steghide Info: $IMAGE ==="
steghide info "$IMAGE" -p "" 2>/dev/null || true

if [ -n "$PASSWORD" ]; then
    echo ""
    echo "=== Extracting with password ==="
    steghide extract -sf "$IMAGE" -p "$PASSWORD" -f
else
    echo ""
    echo "=== Trying common passwords ==="
    for pw in "" "password" "steghide" "secret" "hidden" "flag"; do
        if steghide extract -sf "$IMAGE" -p "$pw" -f 2>/dev/null; then
            echo "SUCCESS with password: '$pw'"
            exit 0
        fi
    done
    echo "No common password worked. Try: run-steghide.sh $IMAGE <password>"
fi
