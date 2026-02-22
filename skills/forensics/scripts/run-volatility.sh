#!/usr/bin/env bash
# Run volatility3 analysis on a memory dump.
# Outputs raw results followed by a structured JSON summary.
# Usage: run-volatility.sh <memory-dump> [plugin]
# Default plugin: windows.info (system info)
set -euo pipefail

DUMP="${1:?Usage: run-volatility.sh <memory-dump> [plugin]}"
PLUGIN="${2:-windows.info}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v vol &>/dev/null; then
    echo "ERROR: volatility3 not installed. Install: pip install volatility3" >&2
    exit 1
fi

echo "=== Volatility3: $PLUGIN on $DUMP ==="
RAW=$(vol -f "$DUMP" "$PLUGIN" 2>&1) || true
echo "$RAW"

# JSON summary via inline Python (volatility output varies by plugin)
echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import json, re, sys

raw = sys.stdin.read()
plugin = '$PLUGIN'
dump = '$DUMP'

# Parse table output (common volatility format)
lines = [l for l in raw.strip().split('\n') if l.strip()]
headers = []
rows = []

for i, line in enumerate(lines):
    # Skip separator lines
    if set(line.strip()) <= {'-', '*', '=', ' '}:
        continue
    # First non-separator line with tabs/multi-spaces is header
    if not headers and '\t' in line or '  ' in line:
        headers = [h.strip() for h in re.split(r'\t+|\s{2,}', line) if h.strip()]
        continue
    if headers:
        cols = [c.strip() for c in re.split(r'\t+|\s{2,}', line) if c.strip()]
        if cols:
            row = {}
            for j, col in enumerate(cols):
                key = headers[j] if j < len(headers) else f'col_{j}'
                row[key] = col
            rows.append(row)

# Extract interesting items based on plugin
interesting = []
if 'pslist' in plugin or 'pstree' in plugin:
    for row in rows:
        name = row.get('Name', row.get('ImageFileName', ''))
        if name and any(s in name.lower() for s in ['cmd', 'powershell', 'python', 'nc', 'ncat', 'flag', 'secret']):
            interesting.append({'process': name, 'pid': row.get('PID', ''), 'reason': 'Suspicious process'})
elif 'netscan' in plugin:
    for row in rows:
        port = row.get('LocalPort', row.get('ForeignPort', ''))
        if port and port not in ('0', '*'):
            interesting.append({'connection': str(row), 'reason': 'Network connection'})

suggestions = []
if 'info' in plugin:
    suggestions.append('Next: vol -f <dump> windows.pslist  (list processes)')
    suggestions.append('Next: vol -f <dump> windows.netscan  (network connections)')
    suggestions.append('Next: vol -f <dump> windows.cmdline  (command history)')
elif 'pslist' in plugin:
    suggestions.append('Next: vol -f <dump> windows.cmdline  (see command lines)')
    suggestions.append('Dump suspicious process: vol -f <dump> windows.dumpfiles --pid <PID>')
    if interesting:
        suggestions.append(f'Found {len(interesting)} suspicious process(es)')
elif 'netscan' in plugin:
    suggestions.append('Investigate connections with tshark if PCAP available')
    suggestions.append('Check processes behind connections with pslist')

result = {
    'tool': 'volatility3',
    'file': dump,
    'plugin': plugin,
    'row_count': len(rows),
    'headers': headers,
    'rows': rows[:50],  # Limit output
    'interesting': interesting,
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
" <<< "$RAW"
