#!/usr/bin/env bash
# Check tools required for challenge analysis
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-12s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-12s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Analyze: Required Tools ==="
check file      "pre-installed on macOS/Linux"
check strings   "pre-installed (binutils)"
check xxd       "pre-installed (vim)"
check binwalk   "pip install binwalk"
check exiftool  "brew install exiftool / apt install libimage-exiftool-perl"
