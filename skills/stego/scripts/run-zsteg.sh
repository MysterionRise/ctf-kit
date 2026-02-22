#!/usr/bin/env bash
# Run zsteg comprehensive analysis on PNG/BMP images.
# Outputs raw results followed by a structured JSON summary.
# Usage: run-zsteg.sh <image>
set -euo pipefail

IMAGE="${1:?Usage: run-zsteg.sh <image.png|image.bmp>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v zsteg &>/dev/null; then
    echo "ERROR: zsteg not installed. Install: gem install zsteg" >&2
    exit 1
fi

echo "=== zsteg Full Analysis: $IMAGE ==="
RAW=$(zsteg -a "$IMAGE" 2>&1) || true
echo "$RAW"

echo ""
echo "=== PARSED RESULTS (JSON) ==="
echo "$RAW" | python3 "$LIB_DIR/parse-zsteg.py" "$IMAGE"
