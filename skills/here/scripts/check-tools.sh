#!/usr/bin/env bash
# Check that ctf-kit CLI is available
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-12s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-12s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== CTF Here: Required Tools ==="
check ctf "uv pip install -e .[dev]  (from ctf-kit repo)"
