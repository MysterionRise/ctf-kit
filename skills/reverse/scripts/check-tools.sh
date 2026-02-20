#!/usr/bin/env bash
# Check tools required for reverse engineering challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Reverse Engineering: Required Tools ==="
check r2            "brew install radare2 / apt install radare2"
check ghidra        "brew install ghidra (or download from ghidra-sre.org)"
check objdump       "pre-installed (binutils)"
check ltrace        "apt install ltrace (Linux only)"
check strace        "apt install strace (Linux only)"
check jadx          "brew install jadx (for Java/Android)"
check uncompyle6    "pip install uncompyle6 (for Python .pyc)"
