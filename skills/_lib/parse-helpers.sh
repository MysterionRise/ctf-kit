#!/usr/bin/env bash
# Shared parsing helpers for CTF Kit skill scripts
# Source this from any script: source "$(dirname "$0")/../../_lib/parse-helpers.sh"

# Emit a JSON summary section from a Python dict literal.
# Usage: emit_json '{"tool": "binwalk", "count": 3}'
emit_json() {
    echo ""
    echo "=== PARSED RESULTS (JSON) ==="
    python3 -c "
import json, sys
data = json.loads(sys.argv[1])
print(json.dumps(data, indent=2))
" "$1" 2>/dev/null || echo "$1"
}

# Emit JSON from stdin (pipe raw output through a Python parser).
# Usage: echo "$RAW" | emit_json_via_parser 'parser_script.py_code'
emit_json_via_stdin() {
    echo ""
    echo "=== PARSED RESULTS (JSON) ==="
    python3 -c "$1" 2>/dev/null || echo '{"error": "parse failed"}'
}

# Extract flag-like patterns from text
# Usage: echo "$TEXT" | grep_flags
grep_flags() {
    grep -oEi '(flag|ctf|picoctf|htb)\{[^}]+\}' || true
}

# Check if a command exists, print status
check_tool() {
    local tool="$1" install="$2"
    if command -v "$tool" &>/dev/null; then
        printf "  OK %-15s %s\n" "$tool" "$(command -v "$tool")"
        return 0
    else
        printf "  MISSING %-15s Install: %s\n" "$tool" "$install" >&2
        return 1
    fi
}
