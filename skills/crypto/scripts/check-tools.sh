#!/usr/bin/env bash
# Check tools required for crypto challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Crypto: Required Tools ==="
check hashid        "pip install hashid"
check xortool       "pip install xortool"
check hashcat       "brew install hashcat / apt install hashcat"
check john          "brew install john / apt install john"
check RsaCtfTool    "pip install rsactftool"
check openssl       "pre-installed on macOS/Linux"
