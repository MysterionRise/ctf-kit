#!/usr/bin/env bash
# Check tools required for OSINT challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== OSINT: Required Tools ==="
check sherlock      "pip install sherlock-project"
check theHarvester  "pip install theHarvester"
check exiftool      "brew install exiftool / apt install libimage-exiftool-perl"
check whois         "pre-installed on macOS / apt install whois"
check dig           "pre-installed (dnsutils)"
