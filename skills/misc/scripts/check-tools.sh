#!/usr/bin/env bash
# Check tools required for misc challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Misc: Required Tools ==="
check file          "pre-installed on macOS/Linux"
check strings       "pre-installed (binutils)"
check xxd           "pre-installed (vim)"
check base64        "pre-installed on macOS/Linux"
check zbarimg       "brew install zbar / apt install zbar-tools"
check python3       "required for custom decode scripts"
