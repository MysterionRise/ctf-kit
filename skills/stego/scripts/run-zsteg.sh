#!/usr/bin/env bash
# Run zsteg comprehensive analysis on PNG/BMP images
# Usage: run-zsteg.sh <image>
set -euo pipefail

IMAGE="${1:?Usage: run-zsteg.sh <image.png|image.bmp>}"

if ! command -v zsteg &>/dev/null; then
    echo "ERROR: zsteg not installed. Install: gem install zsteg" >&2
    exit 1
fi

echo "=== zsteg Full Analysis: $IMAGE ==="
zsteg -a "$IMAGE"
