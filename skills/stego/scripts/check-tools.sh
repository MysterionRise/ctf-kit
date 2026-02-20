#!/usr/bin/env bash
# Check tools required for steganography challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Stego: Required Tools ==="
check zsteg         "gem install zsteg"
check steghide      "brew install steghide / apt install steghide"
check exiftool      "brew install exiftool / apt install libimage-exiftool-perl"
check binwalk       "pip install binwalk"
check stegsolve     "java -jar stegsolve.jar (manual download)"
check jsteg         "go install github.com/lukechampine/jsteg@latest"
