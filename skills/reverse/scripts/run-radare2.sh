#!/usr/bin/env bash
# Run radare2 initial analysis on a binary with structured output.
# Usage: run-radare2.sh <binary> [function]
# Default: analyze all and list functions
set -euo pipefail

BINARY="${1:?Usage: run-radare2.sh <binary> [function-name]}"
FUNC="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v r2 &>/dev/null; then
    echo "ERROR: radare2 not installed. Install: brew install radare2 / apt install radare2" >&2
    exit 1
fi

echo "=== Radare2 Analysis: $BINARY ==="

# Basic info
echo "--- Binary Info ---"
INFO=$(r2 -q -c "i" "$BINARY" 2>&1) || true
echo "$INFO"

# Function list
echo ""
echo "--- Functions ---"
FUNCS=$(r2 -q -c "aa; afl" "$BINARY" 2>&1) || true
echo "$FUNCS"

# Strings
echo ""
echo "--- Strings ---"
STRINGS=$(r2 -q -c "iz" "$BINARY" 2>&1) || true
echo "$STRINGS"

# Disassemble specific function if requested
DISASM=""
if [ -n "$FUNC" ]; then
    echo ""
    echo "--- Disassembly: $FUNC ---"
    DISASM=$(r2 -q -c "aa; pdf @ $FUNC" "$BINARY" 2>&1) || true
    echo "$DISASM"
fi

echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import json, re, sys

info = '''$(echo "$INFO" | sed "s/'/\\\\'/g")'''
funcs = '''$(echo "$FUNCS" | sed "s/'/\\\\'/g")'''
strings_out = '''$(echo "$STRINGS" | sed "s/'/\\\\'/g")'''
binary = '$BINARY'
func_name = '$FUNC'

# Parse binary info
bin_info = {}
for line in info.strip().split('\n'):
    if '~' not in line and ' ' in line:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            bin_info[parts[0]] = parts[1]

# Parse function list
functions = []
for line in funcs.strip().split('\n'):
    m = re.match(r'(0x[0-9a-f]+)\s+(\d+)\s+(\S+)', line.strip())
    if m:
        functions.append({'address': m.group(1), 'size': int(m.group(2)), 'name': m.group(3)})

# Find interesting functions
interesting_names = ['main', 'flag', 'win', 'check', 'verify', 'password', 'secret', 'decrypt', 'encode', 'decode']
interesting = [f for f in functions if any(n in f['name'].lower() for n in interesting_names)]

# Parse strings
str_list = []
for line in strings_out.strip().split('\n'):
    m = re.match(r'\d+\s+(0x[0-9a-f]+)\s+\d+\s+\d+\s+\.\w+\s+(.*)', line.strip())
    if m:
        str_list.append({'address': m.group(1), 'value': m.group(2)[:200]})

suggestions = []
if interesting:
    suggestions.append(f'Found {len(interesting)} interesting function(s):')
    for f in interesting[:5]:
        suggestions.append(f'  {f[\"name\"]} at {f[\"address\"]} ({f[\"size\"]} bytes)')
    suggestions.append('Decompile: r2 -c \"aa; pdc @ <function>\" <binary>')
if functions:
    suggestions.append(f'Total functions: {len(functions)}')
if str_list:
    suggestions.append(f'Found {len(str_list)} string(s) in binary')

result = {
    'tool': 'radare2',
    'file': binary,
    'info': bin_info,
    'function_count': len(functions),
    'functions': functions[:50],
    'interesting_functions': interesting,
    'strings': str_list[:50],
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
"
