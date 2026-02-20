#!/usr/bin/env bash
# Check tools required for web challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Web: Required Tools ==="
check sqlmap        "pip install sqlmap"
check gobuster      "brew install gobuster / go install github.com/OJ/gobuster/v3@latest"
check ffuf          "brew install ffuf / go install github.com/ffuf/ffuf/v2@latest"
check nikto         "brew install nikto / apt install nikto"
check curl          "pre-installed on macOS/Linux"
