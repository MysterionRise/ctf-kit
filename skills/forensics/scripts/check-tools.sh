#!/usr/bin/env bash
# Check tools required for forensics challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Forensics: Required Tools ==="
check vol           "pip install volatility3"
check binwalk       "pip install binwalk"
check foremost      "brew install foremost / apt install foremost"
check tshark        "brew install wireshark / apt install tshark"
check mmls          "brew install sleuthkit / apt install sleuthkit"
check exiftool      "brew install exiftool / apt install libimage-exiftool-perl"
