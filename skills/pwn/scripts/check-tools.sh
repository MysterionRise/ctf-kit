#!/usr/bin/env bash
# Check tools required for pwn/binary exploitation challenges
set -euo pipefail

check() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  ✅ %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "  ❌ %-15s Install: %s\n" "$tool" "$install"
    fi
}

echo "=== Pwn: Required Tools ==="
check checksec      "pip install checksec.py"
check ROPgadget     "pip install ROPgadget"
check one_gadget    "gem install one_gadget"
check gdb           "brew install gdb / apt install gdb"
check python3       "required for pwntools (pip install pwntools)"

if [ "$(uname -s)" = "Darwin" ]; then
    echo ""
    echo "=== Pwn: Docker toolbox (macOS cannot run/debug Linux ELFs natively) ==="
    if docker image inspect ctf-pwn &>/dev/null; then
        printf "  ✅ %-15s %s\n" "ctf-pwn" "use scripts/pwn-docker.sh"
    else
        printf "  ❌ %-15s Build: %s\n" "ctf-pwn" "docker build --platform linux/amd64 -t ctf-pwn <ctf-kit>/docker/pwn"
    fi
fi
